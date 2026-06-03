# Terminal-MITM

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)

```
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
```

**Terminal-MITM** is an interactive, menu-driven Man-in-the-Middle framework for network security auditing and educational pentesting in controlled environments.

---

## Disclaimer

This tool is intended for **educational and authorized security testing only**. Using it on networks or systems without explicit written permission is illegal. The author is not responsible for any misuse or damage caused by this program. Always respect privacy and the law.

---

## What's New (v2)

- **Guided attacks** — every attack that requires input now shows a step-by-step screen with explanations, tips, and warnings before starting
- **Drag-and-drop** file input — drag any image or file into the terminal window to use it (no need to copy files manually)
- **Pre-built injection payloads** — 7 ready-to-use JS/HTML payloads accessible from the injection submenu
- **Self-contained attacks** — ARP spoofing and the HTTP server are managed automatically; no manual prerequisites
- **Multi-target workflow** — release a target and rescan the network without restarting the app
- **HTTP Traffic Logger** — passively logs URLs, cookies, and POST data
- **Captive Portal** — DNS-based credential harvesting page (works regardless of HTTPS)
- **Custom File Replace** — intercept any HTTP download and silently replace it with your file (no Metasploit required)
- **True packet interception on Linux** — JS injection uses NFQUEUE (real replacement) instead of passive sniff+resend
- **Clean TUI** — fixed-layout screen with services panel, attack status grid, and live log buffer; no overlapping output

---

## Features

### Network Discovery
- Scans the local network via ARP and lists all connected devices with IP, MAC, and hostname
- OS fingerprinting via TTL analysis
- Hardware vendor lookup (macvendors.com API)

### Auto-Managed Services
These run transparently in the background — you never need to start them manually:

| Service | Description |
|---|---|
| ARP Spoofing | Positions the attacker between target and gateway; starts automatically when any attack needs it and stops when none do |
| HTTP Server | Serves payloads and captured files on port 8000; managed automatically by attacks that require it |

### Attack Menu

| Key | Attack | Platform | Auto-starts |
|---|---|---|---|
| `1` | **Packet Capture** | Linux / Windows | — |
| `2` | **Credential Sniffer** | Linux / Windows | ARP |
| `3` | **DNS Spoofing** | Linux / Windows | ARP |
| `4` | **JS Keylogger** | Linux / Windows | ARP + HTTP |
| `5` | **Webcam Capture** | Linux / Windows | ARP + HTTP |
| `6` | **Screen Capture** | Linux / Windows | ARP + HTTP |
| `7` | **Image Replace** | Linux / Windows | ARP + HTTP |
| `8` | **JS/HTML Injection** | Linux / Windows | ARP + HTTP |
| `9` | **SSL Stripping** | Linux only | ARP |
| `0` | **Metasploit Delivery** | Linux only | ARP + HTTP |
| `A` | **HTTP Traffic Logger** | Linux / Windows | ARP |
| `B` | **Captive Portal** | Linux / Windows | ARP + DNS |
| `C` | **Custom File Replace** | Linux only | ARP + HTTP |
| `R` | **Release target** | — | — |
| `Q` | **Quit** | — | — |

---

### Guided Attack Details

#### `[1]` Packet Capture
Captures all traffic to/from the target and saves it to a `.pcap` file. Open in Wireshark for analysis.

#### `[2]` Credential Sniffer
Sniffs HTTP POST requests for usernames, passwords, emails, and session tokens. Results are shown live and saved to `credentials.log`.

#### `[3]` DNS Spoofing
Intercepts every DNS query from the target and responds with the attacker IP. Use standalone for misdirection or combined with **Captive Portal** for credential harvesting.

#### `[4]` JS Keylogger
Injects a keylogger script into every HTTP page the target visits. Captured keystrokes are sent every 3 seconds and appended to `keylog.txt`.

> ⚠ Browser APIs restrict this to HTTP-only pages — HTTPS pages are not affected.

#### `[5]` Webcam Capture
Injects JavaScript that requests camera access. If the target accepts the browser permission prompt, a photo is captured and saved as `webcam_<timestamp>.jpg`.

> ⚠ Modern browsers require HTTPS for `getUserMedia` — works on HTTP-only pages only.

#### `[6]` Screen Capture
Injects JavaScript that requests screen-sharing access (`getDisplayMedia`). A signal is logged every 5 seconds while the target shares their screen.

> ⚠ Modern browsers require HTTPS for `getDisplayMedia` — works on HTTP-only pages only.

#### `[7]` Image Replace
Replaces every `<img>` tag on every HTTP page with an image of your choice. **Drag your image file into the terminal** — any format supported.

#### `[8]` JS/HTML Injection — Pre-built Payloads
A guided submenu with 7 ready-to-use payloads. On Linux, uses NFQUEUE for true packet replacement (not a passive re-send):

| # | Payload | What it does |
|---|---|---|
| 1 | **Full-page image overlay** | Covers the entire browser window with your image (drag to provide) |
| 2 | **Fake alert popup** | Shows a JavaScript `alert()` dialog with a custom message |
| 3 | **Page redirect** | Silently redirects the target to any URL after a configurable delay |
| 4 | **Scrolling banner** | Displays a red scrolling banner at the bottom of every page |
| 5 | **Freeze page** | Disables all clicks, scrolling, and keyboard input |
| 6 | **Fake browser update** | Shows an "Update Now" card that links to a file you serve |
| 7 | **Load from file** | Inject raw HTML/JS from a local file (drag to provide) |

#### `[9]` SSL Stripping *(Linux only)*
Intercepts HTTP responses and downgrades `https://` links to `http://`. Combine with Credential Sniffer `[2]` or Keylogger `[4]` for maximum effect.

> ⚠ HSTS-preloaded domains (Google, Facebook, most major sites) are immune.

#### `[0]` Metasploit Payload Delivery *(Linux only)*
Generates a Meterpreter reverse shell with `msfvenom` and automatically intercepts matching file downloads. Supports Windows (`.exe`), Android (`.apk`), and Linux (`.elf`) targets. Launches a listener in a new terminal window.

**Requirements:** Metasploit Framework must be installed.

#### `[A]` HTTP Traffic Logger
Passively logs every HTTP request the target makes — URLs, cookies, `Authorization` headers, `Referer`, `User-Agent`, and POST bodies. Saved to `http_log.txt` in real time. No JS injection required.

#### `[B]` Captive Portal
Spoofs all DNS queries to the attacker's IP and serves a convincing "Network Sign-In" login page on port 80. Captured credentials are saved to `portal_creds.log` and shown live in the log panel.

- Works on **any browser**, including those that enforce HTTPS — the redirect happens at DNS level, before any TLS handshake
- Auto-manages DNS spoofing and stops it cleanly when the portal is closed

#### `[C]` Custom File Replace *(Linux only)*
Intercepts any HTTP download whose file extension matches what you specify and silently replaces it with your file. **Drag your replacement file into the terminal** — the extension is auto-detected from the file.

No Metasploit required. Supports any file type: `.pdf`, `.zip`, `.exe`, `.apk`, etc.

---

## Multi-Target Workflow

```
Start app
  └─► Network discovery (auto-scan)
        └─► Choose target [ID]
              └─► Attack menu
                    ├─► Toggle attacks on/off
                    ├─► [R] Release target
                    │     ├─► Stops all active attacks
                    │     ├─► Restores target's ARP tables
                    │     └─► Returns to discovery (rescan)
                    └─► [Q] Full shutdown
```

Pressing `[R]` stops everything cleanly, restores the network for the current target, and lets you immediately pick a new device without restarting the app.

---

## Output Files

| File | Created by |
|---|---|
| `capture_<timestamp>.pcap` | Packet Capture `[1]` |
| `credentials.log` | Credential Sniffer `[2]` |
| `keylog.txt` | JS Keylogger `[4]` |
| `webcam_<timestamp>.jpg` | Webcam Capture `[5]` |
| `http_log.txt` | HTTP Traffic Logger `[A]` |
| `portal_creds.log` | Captive Portal `[B]` |

---

## Installation

### Prerequisites

- Python 3.8+
- `pip`
- **Linux recommended** — some features require Linux kernel capabilities (NFQUEUE)
- **Metasploit Framework** — required only for Metasploit Delivery `[0]`

### Linux (Recommended — Kali, Parrot, Ubuntu)

```bash
# Clone
git clone https://github.com/your-username/Terminal-MITM.git
cd Terminal-MITM

# System dependencies (Debian/Ubuntu/Kali)
sudo apt-get update
sudo apt-get install python3-dev libnetfilter-queue-dev

# Python packages
pip install -r requirements.txt
```

### Windows

Core features work (ARP Spoofing, Credential Sniffer, DNS Spoofing, HTTP Logger, Captive Portal).
Features requiring NFQUEUE (SSL Stripping `[9]`, Custom File Replace `[C]`, Metasploit Delivery `[0]`, and reliable JS Injection) are **not available on Windows**.

```bash
git clone https://github.com/your-username/Terminal-MITM.git
cd Terminal-MITM
pip install -r requirements.txt
```

> On Windows, JS injection (`[4]`–`[8]`) uses a passive sniff-and-resend approach — the target may receive both the original and the modified response. Results vary by browser and network configuration.

---

## Usage

Run with administrator / root privileges:

```bash
# Linux
sudo python3 Terminal.py

# Windows (run terminal as Administrator)
python Terminal.py
```

### Suggested Attack Chains

**Passive monitoring (any platform):**
1. `[A]` HTTP Traffic Logger — see every URL and cookie
2. `[2]` Credential Sniffer — capture login forms

**Active credential harvesting (Linux):**
1. `[B]` Captive Portal — DNS redirect + fake login page

**Full HTTP interception (Linux):**
1. `[9]` SSL Stripping — downgrade HTTPS links
2. `[2]` Credential Sniffer — capture now-readable credentials
3. `[4]` JS Keylogger — capture everything typed

**File delivery (Linux):**
1. `[C]` Custom File Replace — swap any download with your file
2. `[0]` Metasploit Delivery — automated reverse shell payload

---

## NFQUEUE Queue Allocation (Linux)

| Queue | Used by |
|---|---|
| 0 | SSL Stripping `[9]` / Metasploit Delivery `[0]` / Custom File Replace `[C]` |
| 1 | JS/HTML Injection `[4]`–`[8]` |

Only one attack per queue can be active at a time. The tool enforces this and shows a clear error if there is a conflict.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
