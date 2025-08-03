#!/usr/bin/env python3
"""
WiFi Utilities Module
Additional utility functions for the Advanced WiFi Scanner
"""

import os
import re
import time
import subprocess
import json
from typing import List, Dict, Optional, Tuple
import logging

class WiFiInterface:
    """Utility class for managing WiFi interfaces"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_wireless_interfaces(self) -> List[str]:
        """Get all available wireless interfaces"""
        interfaces = []
        
        try:
            # Method 1: Using iwconfig
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, stderr=subprocess.DEVNULL)
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    interface = line.split()[0]
                    interfaces.append(interface)
            
            # Method 2: Using /proc/net/wireless as fallback
            if not interfaces:
                try:
                    with open('/proc/net/wireless', 'r') as f:
                        for line in f.readlines()[2:]:  # Skip header lines
                            interface = line.split(':')[0].strip()
                            if interface:
                                interfaces.append(interface)
                except FileNotFoundError:
                    pass
            
            # Method 3: Using ip link as final fallback
            if not interfaces:
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'wlan' in line or 'wlp' in line:
                        match = re.search(r'\d+:\s+(\w+):', line)
                        if match:
                            interfaces.append(match.group(1))
        
        except Exception as e:
            self.logger.error(f"Error getting wireless interfaces: {e}")
        
        return list(set(interfaces))  # Remove duplicates
    
    def is_interface_up(self, interface: str) -> bool:
        """Check if interface is up"""
        try:
            result = subprocess.run(['ip', 'link', 'show', interface], 
                                  capture_output=True, text=True)
            return 'UP' in result.stdout
        except:
            return False
    
    def bring_interface_up(self, interface: str) -> bool:
        """Bring interface up"""
        try:
            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                          capture_output=True, check=True)
            return True
        except:
            return False
    
    def get_interface_info(self, interface: str) -> Dict:
        """Get detailed interface information"""
        info = {
            'name': interface,
            'up': False,
            'mac': '',
            'driver': '',
            'chipset': '',
            'monitor_capable': False
        }
        
        try:
            # Get basic info
            result = subprocess.run(['ip', 'link', 'show', interface], 
                                  capture_output=True, text=True)
            if 'UP' in result.stdout:
                info['up'] = True
            
            # Extract MAC address
            mac_match = re.search(r'link/ether ([a-f0-9:]{17})', result.stdout)
            if mac_match:
                info['mac'] = mac_match.group(1)
            
            # Get driver info
            try:
                with open(f'/sys/class/net/{interface}/device/uevent', 'r') as f:
                    content = f.read()
                    driver_match = re.search(r'DRIVER=(.+)', content)
                    if driver_match:
                        info['driver'] = driver_match.group(1)
            except:
                pass
            
            # Check monitor mode capability
            result = subprocess.run(['iw', interface, 'info'], 
                                  capture_output=True, text=True)
            if 'monitor' in result.stdout.lower():
                info['monitor_capable'] = True
        
        except Exception as e:
            self.logger.error(f"Error getting interface info: {e}")
        
        return info

class NetworkAnalyzer:
    """Utility class for network analysis"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def analyze_signal_strength(self, power: int) -> str:
        """Analyze signal strength and return description"""
        if power >= -30:
            return "Excellent"
        elif power >= -50:
            return "Very Good"
        elif power >= -60:
            return "Good"
        elif power >= -70:
            return "Fair"
        elif power >= -80:
            return "Weak"
        else:
            return "Very Weak"
    
    def estimate_distance(self, power: int, frequency: float = 2.4) -> float:
        """Estimate distance based on signal strength (rough approximation)"""
        # Free space path loss formula (simplified)
        # Distance in meters
        if power >= -30:
            return 1.0
        elif power >= -40:
            return 3.0
        elif power >= -50:
            return 10.0
        elif power >= -60:
            return 30.0
        elif power >= -70:
            return 100.0
        elif power >= -80:
            return 300.0
        else:
            return 1000.0
    
    def analyze_encryption(self, encryption: str) -> Dict:
        """Analyze encryption type and return security assessment"""
        analysis = {
            'type': encryption,
            'security_level': 'Unknown',
            'vulnerabilities': [],
            'recommendations': []
        }
        
        if 'WPA3' in encryption.upper():
            analysis['security_level'] = 'Very High'
            analysis['recommendations'].append('Current best practice')
        elif 'WPA2' in encryption.upper():
            analysis['security_level'] = 'High'
            analysis['recommendations'].append('Good security, consider WPA3 upgrade')
        elif 'WPA' in encryption.upper() and 'WPA2' not in encryption.upper():
            analysis['security_level'] = 'Medium'
            analysis['vulnerabilities'].append('Older WPA protocol')
            analysis['recommendations'].append('Upgrade to WPA2/WPA3')
        elif 'WEP' in encryption.upper():
            analysis['security_level'] = 'Very Low'
            analysis['vulnerabilities'].append('Easily crackable')
            analysis['vulnerabilities'].append('Deprecated protocol')
            analysis['recommendations'].append('Immediately upgrade to WPA2/WPA3')
        elif 'OPEN' in encryption.upper() or encryption == '':
            analysis['security_level'] = 'None'
            analysis['vulnerabilities'].append('No encryption')
            analysis['recommendations'].append('Enable WPA2/WPA3 encryption')
        
        return analysis
    
    def get_channel_frequency(self, channel: int) -> float:
        """Get frequency for WiFi channel"""
        if 1 <= channel <= 14:
            # 2.4 GHz band
            if channel == 14:
                return 2.484
            else:
                return 2.407 + (channel * 0.005)
        elif 36 <= channel <= 165:
            # 5 GHz band
            return 5.000 + (channel * 0.005)
        else:
            return 0.0
    
    def detect_channel_conflicts(self, networks: List[Dict]) -> Dict:
        """Detect channel conflicts and congestion"""
        channel_usage = {}
        conflicts = {}
        
        for network in networks:
            channel = network.get('channel', 0)
            if channel not in channel_usage:
                channel_usage[channel] = []
            channel_usage[channel].append(network)
        
        # Detect overlapping channels (2.4 GHz)
        for channel, nets in channel_usage.items():
            if 1 <= channel <= 14 and len(nets) > 1:
                # Check for overlapping channels
                overlapping = []
                for other_channel in channel_usage:
                    if other_channel != channel and 1 <= other_channel <= 14:
                        if abs(channel - other_channel) < 5:  # Overlapping
                            overlapping.extend(channel_usage[other_channel])
                
                if overlapping:
                    conflicts[channel] = {
                        'networks': nets,
                        'overlapping_networks': overlapping,
                        'congestion_level': len(nets) + len(overlapping)
                    }
        
        return conflicts

class ReportGenerator:
    """Utility class for generating various report formats"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)
    
    def generate_csv_report(self, networks: List[Dict], filename: str = None) -> str:
        """Generate CSV report"""
        if not filename:
            filename = f"wifi_scan_{int(time.time())}.csv"
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            import csv
            
            with open(filepath, 'w', newline='') as csvfile:
                fieldnames = ['ESSID', 'BSSID', 'Channel', 'Power', 'Encryption', 
                             'WPS', 'Handshake', 'Attempts', 'Last_Seen']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for network in networks:
                    writer.writerow({
                        'ESSID': network.get('essid', ''),
                        'BSSID': network.get('bssid', ''),
                        'Channel': network.get('channel', ''),
                        'Power': network.get('power', ''),
                        'Encryption': network.get('encryption', ''),
                        'WPS': 'Yes' if network.get('wps', False) else 'No',
                        'Handshake': 'Yes' if network.get('handshake_captured', False) else 'No',
                        'Attempts': network.get('attempts', 0),
                        'Last_Seen': network.get('last_seen', '')
                    })
            
            self.logger.info(f"CSV report generated: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Error generating CSV report: {e}")
            return ""
    
    def generate_xml_report(self, networks: List[Dict], filename: str = None) -> str:
        """Generate XML report"""
        if not filename:
            filename = f"wifi_scan_{int(time.time())}.xml"
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            import xml.etree.ElementTree as ET
            
            root = ET.Element("wifi_scan_results")
            root.set("timestamp", str(int(time.time())))
            root.set("count", str(len(networks)))
            
            for network in networks:
                net_elem = ET.SubElement(root, "network")
                
                for key, value in network.items():
                    elem = ET.SubElement(net_elem, key)
                    elem.text = str(value)
            
            tree = ET.ElementTree(root)
            tree.write(filepath, encoding='utf-8', xml_declaration=True)
            
            self.logger.info(f"XML report generated: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Error generating XML report: {e}")
            return ""
    
    def generate_markdown_report(self, networks: List[Dict], filename: str = None) -> str:
        """Generate Markdown report"""
        if not filename:
            filename = f"wifi_scan_{int(time.time())}.md"
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                f.write("# WiFi Scan Report\n\n")
                f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Total Networks:** {len(networks)}\n\n")
                
                # Summary statistics
                wps_count = sum(1 for n in networks if n.get('wps', False))
                handshake_count = sum(1 for n in networks if n.get('handshake_captured', False))
                
                f.write("## Summary\n\n")
                f.write(f"- **WPS Enabled Networks:** {wps_count}\n")
                f.write(f"- **Handshakes Captured:** {handshake_count}\n")
                f.write(f"- **Open Networks:** {sum(1 for n in networks if 'open' in n.get('encryption', '').lower())}\n\n")
                
                # Network table
                f.write("## Networks\n\n")
                f.write("| ESSID | BSSID | Channel | Power | Encryption | WPS | Handshake |\n")
                f.write("|-------|-------|---------|-------|------------|-----|----------|\n")
                
                for network in sorted(networks, key=lambda x: x.get('power', -100), reverse=True):
                    f.write(f"| {network.get('essid', '')} | {network.get('bssid', '')} | "
                           f"{network.get('channel', '')} | {network.get('power', '')} | "
                           f"{network.get('encryption', '')} | "
                           f"{'✓' if network.get('wps', False) else '✗'} | "
                           f"{'✓' if network.get('handshake_captured', False) else '✗'} |\n")
            
            self.logger.info(f"Markdown report generated: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Error generating Markdown report: {e}")
            return ""

class WordlistManager:
    """Utility class for managing wordlists"""
    
    def __init__(self, wordlist_dir: str = "/opt/wifi-scanner/wordlists"):
        self.wordlist_dir = wordlist_dir
        self.logger = logging.getLogger(__name__)
        os.makedirs(wordlist_dir, exist_ok=True)
    
    def get_available_wordlists(self) -> List[str]:
        """Get list of available wordlists"""
        wordlists = []
        
        # Common wordlist locations
        locations = [
            "/usr/share/wordlists",
            "/usr/share/seclists",
            self.wordlist_dir,
            "/opt/wordlists"
        ]
        
        for location in locations:
            if os.path.exists(location):
                for root, dirs, files in os.walk(location):
                    for file in files:
                        if file.endswith(('.txt', '.lst', '.dic')):
                            wordlists.append(os.path.join(root, file))
        
        return wordlists
    
    def create_custom_wordlist(self, essid: str, bssid: str, output_file: str = None) -> str:
        """Create custom wordlist based on network information"""
        if not output_file:
            output_file = os.path.join(self.wordlist_dir, f"custom_{essid}_{int(time.time())}.txt")
        
        try:
            passwords = set()
            
            # Common patterns based on ESSID
            if essid and essid != "Hidden":
                essid_clean = re.sub(r'[^a-zA-Z0-9]', '', essid)
                passwords.add(essid_clean)
                passwords.add(essid_clean.lower())
                passwords.add(essid_clean.upper())
                
                # Add numbers
                for i in range(10):
                    passwords.add(f"{essid_clean}{i}")
                    passwords.add(f"{i}{essid_clean}")
                
                # Add years
                for year in range(2000, 2025):
                    passwords.add(f"{essid_clean}{year}")
                
                # Add common suffixes
                suffixes = ['123', '1234', '12345', '123456', 'admin', 'password', 'wifi']
                for suffix in suffixes:
                    passwords.add(f"{essid_clean}{suffix}")
            
            # Common passwords
            common_passwords = [
                'password', '123456', '12345678', 'qwerty', 'abc123',
                'password123', 'admin', 'letmein', 'welcome', 'monkey',
                'dragon', 'master', 'shadow', 'superman', 'michael',
                'internet', 'computer', 'welcome123', 'admin123'
            ]
            passwords.update(common_passwords)
            
            # Write to file
            with open(output_file, 'w') as f:
                for password in sorted(passwords):
                    if len(password) >= 8:  # WPA minimum length
                        f.write(f"{password}\n")
            
            self.logger.info(f"Custom wordlist created: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Error creating custom wordlist: {e}")
            return ""

def check_root_privileges() -> bool:
    """Check if script is running with root privileges"""
    return os.geteuid() == 0

def kill_interfering_processes():
    """Kill processes that might interfere with monitor mode"""
    processes = [
        'NetworkManager', 'wpa_supplicant', 'dhclient',
        'avahi-daemon', 'wpa_cli', 'dhcpcd'
    ]
    
    for process in processes:
        try:
            subprocess.run(['pkill', '-f', process], capture_output=True)
        except:
            pass

def backup_network_config():
    """Backup current network configuration"""
    backup_dir = "/tmp/wifi_scanner_backup"
    os.makedirs(backup_dir, exist_ok=True)
    
    config_files = [
        '/etc/network/interfaces',
        '/etc/wpa_supplicant/wpa_supplicant.conf',
        '/etc/NetworkManager/NetworkManager.conf'
    ]
    
    for config_file in config_files:
        if os.path.exists(config_file):
            backup_file = os.path.join(backup_dir, os.path.basename(config_file))
            try:
                subprocess.run(['cp', config_file, backup_file], capture_output=True)
            except:
                pass

def restore_network_config():
    """Restore network configuration from backup"""
    backup_dir = "/tmp/wifi_scanner_backup"
    
    if os.path.exists(backup_dir):
        for backup_file in os.listdir(backup_dir):
            original_path = f"/etc/{backup_file}"
            backup_path = os.path.join(backup_dir, backup_file)
            
            try:
                subprocess.run(['cp', backup_path, original_path], capture_output=True)
            except:
                pass

if __name__ == "__main__":
    # Test utilities
    print("Testing WiFi utilities...")
    
    wifi_interface = WiFiInterface()
    interfaces = wifi_interface.get_wireless_interfaces()
    print(f"Found wireless interfaces: {interfaces}")
    
    if interfaces:
        info = wifi_interface.get_interface_info(interfaces[0])
        print(f"Interface info: {info}")
    
    analyzer = NetworkAnalyzer()
    print(f"Signal strength -60 dBm: {analyzer.analyze_signal_strength(-60)}")
    print(f"Estimated distance for -60 dBm: {analyzer.estimate_distance(-60)} meters")