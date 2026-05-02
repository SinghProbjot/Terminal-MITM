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
    ║       ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║ ╚██╗██║██╔══██║██║     ║
    ║       ██║   ███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗║
    ║       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝║
    ║                                                              ║
    ║                  MITM Network Testing Tool                   ║
    ║                       Educational Use Only                   ║
    ║                         by Singh Probjot                     ║
    ╚══════════════════════════════════════════════════════════════╝
```

**Terminal-MITM** is a comprehensive and interactive command-line framework for performing Man-in-the-Middle (MITM) attacks. It is designed for security professionals and enthusiasts for educational purposes and network security auditing in controlled environments.

---

## Disclaimer

This tool is intended for educational and research purposes only. The author is not responsible for any misuse or damage caused by this program. Using this tool on networks or systems without explicit permission is illegal. Always respect privacy and the law.

---

## Features

This tool provides a wide range of MITM capabilities through an easy-to-use interactive menu.

- **Network Discovery**: Scans the local network to identify all connected devices, displaying their IP address, MAC address, and hostname.
- **Target Dashboard**: A persistent on-screen display showing detailed information about the selected target, including IP, MAC, hostname, OS guess, and hardware vendor.
- **ARP Spoofing**: The core engine that enables traffic interception between the target and the gateway.
- **DNS Spoofing**: Intercepts DNS queries and provides fake responses, redirecting the target to a specified IP address.
- **SSL Stripping**: Downgrades HTTPS connections to HTTP in real-time, allowing other attacks to function on SSL-protected websites.
- **Credential Sniffer**: Captures and displays potential usernames and passwords from HTTP POST requests. All captured credentials are automatically logged to `credentials.log`.
- **Live Code Injection**: A powerful module to inject custom HTML/JavaScript code into the target's web traffic.
  - **JS Keylogger**: Injects a keylogger to capture all keystrokes on web pages, logging them to `keylog.txt`.
  - **Webcam Access**: Attempts to gain access to the target's webcam via the browser.
  - **Live Screen Preview**: Attempts to capture the target's screen via the browser.
  - **Image Replacement**: Replaces all images on web pages with a local image (`replace.jpg`).
  - **Custom Code**: Allows pasting custom HTML/JS code directly or loading it from a local file.
- **Metasploit Payload Injection**: Automates the generation and delivery of Metasploit payloads.
  - **OS-Aware**: Recommends payloads (e.g., `.exe`, `.apk`, `.elf`) based on the target's detected operating system.
  - **Automated Listener**: Automatically generates a Metasploit resource file and launches the listener in a new terminal window.
  - **File Interception**: Replaces legitimate file downloads (`.exe`, `.apk`, etc.) with the generated payload.
- **Packet Capture**: Sniffs all of the target's traffic and saves it to a `.pcap` file for later analysis in tools like Wireshark.

---

## Installation

The tool is primarily designed for Linux-based systems (like Kali Linux) but has partial compatibility with Windows.

### Prerequisites

- Python 3.8+
- `pip` for Python 3
- **Metasploit Framework** (required for the Payload Injection feature)

### Linux (Recommended)

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/Terminal-MITM.git
    cd Terminal-MITM
    ```

2.  **Install system dependencies:**
    Some Python modules require system-level libraries to be installed first.

    ```bash
    # On Debian/Ubuntu/Kali
    sudo apt-get update
    sudo apt-get install python3-dev libnetfilter-queue-dev
    ```

3.  **Install Python packages:**
    If you encounter an "externally-managed-environment" error on newer Linux distributions (like recent Kali Linux updates), append the `--break-system-packages` flag:
    ```bash
    pip install -r requirements.txt --break-system-packages
    ```

### Windows

The core features like ARP Spoofing and DNS Spoofing will work, but features requiring `netfilterqueue` (SSL Stripping, Payload Injection) are **not available on Windows**.

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/Terminal-MITM.git
    cd Terminal-MITM
    ```

2.  **Install Python packages:**
    ```bash
    pip install -r requirements.txt
    ```

---

## Usage

Due to the nature of network packet manipulation, the script must be run with administrative/root privileges.

1.  **Launch the tool:**

    ```bash
    # On Linux
    sudo python3 Terminal.py

    # On Windows (run as Administrator)
    python Terminal.py
    ```

2.  **Select a Target:**
    The tool will automatically scan the network and present a list of devices. Enter the `ID` of the device you wish to target.

3.  **Choose an Attack:**
    Once a target is selected, a persistent dashboard with the target's information will appear above the main attack menu. Simply enter the number corresponding to the attack you wish to start or stop.

### Attack Workflow Example

A common attack chain would be:

1.  Start **ARP Spoofing** (Option 1) to position yourself in the middle.
2.  Start **SSL Stripping** (Option 8) to downgrade HTTPS traffic.
3.  Start the **Credential Sniffer** (Option 6) or the **JS Keylogger** (Option 3 -> 5) to capture sensitive data.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
