# Advanced WiFi Cracker for Kali Linux

A powerful, automated WiFi scanner that captures nearby networks using multiple tools with intelligent retry logic and comprehensive reporting.

![WiFi Scanner](https://img.shields.io/badge/Platform-Kali%20Linux-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![License](https://img.shields.io/badge/License-Educational-red)

## 🚀 Features

### Core Functionality
- **Multi-Tool Integration**: Uses aircrack-ng, iwlist, nmcli, and wifite
- **Automatic Retry Logic**: 3 attempts per network with intelligent switching
- **Monitor Mode Management**: Automatic monitor mode setup and cleanup
- **WPS Detection & Attack**: Identifies and attacks WPS-enabled networks
- **Handshake Capture**: Automated WPA/WPA2 handshake capture with deauth
- **Comprehensive Logging**: Detailed logs with multiple verbosity levels

### Advanced Features
- **Signal Strength Analysis**: Distance estimation and signal quality assessment
- **Channel Conflict Detection**: Identifies overlapping channels and congestion
- **Custom Wordlist Generation**: Creates targeted wordlists based on network info
- **Multiple Report Formats**: HTML, JSON, CSV, XML, and Markdown reports
- **Real-time Monitoring**: Live network discovery and status updates
- **Parallel Processing**: Concurrent scanning and attack capabilities

### Security Features
- **Encryption Analysis**: Detailed security assessment of each network
- **Vulnerability Detection**: Identifies weak encryption and security flaws
- **Client Tracking**: Monitors connected devices and probe requests
- **Network Fingerprinting**: Detailed device and manufacturer identification

## 📋 Requirements

### System Requirements
- **OS**: Kali Linux, BlackArch, Parrot OS, or Ubuntu with wireless tools
- **Python**: 3.8 or higher
- **Privileges**: Root access required for monitor mode operations
- **Hardware**: WiFi adapter with monitor mode support

### Dependencies
```bash
# Core wireless tools
aircrack-ng airodump-ng airmon-ng aireplay-ng
reaver bully pixiewps wifite kismet mdk3

# Network utilities  
wireless-tools wpasupplicant network-manager
iw iwconfig iwlist rfkill macchanger nmap

# Python packages
subprocess32 psutil python-dateutil colorama
tabulate rich click scapy netaddr pandas
```

## 🛠️ Installation

### Quick Install (Recommended)
```bash
# Clone the repository
git clone https://github.com/your-repo/advanced-wifi-scanner.git
cd advanced-wifi-scanner

# Run the setup script
sudo chmod +x setup.sh
sudo ./setup.sh
```

### Manual Installation
```bash
# Install system dependencies
sudo apt update
sudo apt install aircrack-ng reaver bully wifite wireless-tools python3-pip

# Install Python dependencies
pip3 install -r requirements.txt

# Make script executable
chmod +x advanced_wifi_scanner.py
```

## 🎯 Usage

### Basic Usage
```bash
# Run with default settings
sudo python3 advanced_wifi_scanner.py

# Or if installed system-wide
sudo wifi-scanner
```

### Command Line Options
```bash
# Specify interface
sudo wifi-scanner -i wlan1

# Scan only (no attacks)
sudo wifi-scanner --scan-only

# Custom output directory
sudo wifi-scanner -o /tmp/wifi_results

# Set scan duration
sudo wifi-scanner -d 60

# Limit attempts per network
sudo wifi-scanner -a 5

# Show help
sudo wifi-scanner --help
```

### Advanced Usage
```bash
# Use specific configuration
sudo wifi-scanner --config /path/to/config.json

# Enable verbose logging
sudo wifi-scanner --verbose

# Target specific networks
sudo wifi-scanner --target-bssid AA:BB:CC:DD:EE:FF

# Use custom wordlist
sudo wifi-scanner --wordlist /path/to/wordlist.txt

# Run in background
sudo wifi-scanner --daemon
```

## ⚙️ Configuration

The scanner uses a JSON configuration file (`config.json`) for advanced settings:

```json
{
  "scanner_settings": {
    "default_interface": "wlan0",
    "scan_duration": 30,
    "max_attempts_per_network": 3,
    "retry_delay": 10
  },
  "attack_settings": {
    "enable_wps_attacks": true,
    "enable_handshake_capture": true,
    "min_signal_strength": -80
  },
  "filtering": {
    "exclude_essids": ["Hidden"],
    "min_power_threshold": -90
  }
}
```

## 📊 Output & Reports

### Report Formats
- **HTML Report**: Interactive web-based report with charts
- **JSON Report**: Machine-readable data for further processing
- **CSV Report**: Spreadsheet-compatible format
- **XML Report**: Structured data format
- **Markdown Report**: Human-readable documentation format

### Log Files
```
wifi_scan_results/
├── logs/
│   ├── wifi_scan_20240103_142530.log
│   └── debug_20240103_142530.log
├── captures/
│   ├── handshake_aabbccddeeff-01.cap
│   └── airodump_scan_1704284730-01.csv
└── reports/
    ├── scan_results_20240103_142530.json
    ├── wifi_scan_report_20240103_142530.html
    └── summary_20240103_142530.md
```

## 🔧 Architecture

### Core Components
```
advanced_wifi_scanner.py    # Main scanner engine
├── WiFiNetwork            # Network data structure
├── WiFiScanner           # Core scanning logic
├── NetworkAnalyzer       # Signal and security analysis
├── ReportGenerator       # Multi-format reporting
└── WordlistManager       # Custom wordlist creation

wifi_utils.py              # Utility functions
├── WiFiInterface         # Interface management
├── NetworkAnalyzer       # Network analysis tools
├── ReportGenerator       # Report generation
└── WordlistManager       # Wordlist utilities
```

### Scanning Workflow
1. **Interface Setup**: Detect and configure wireless interfaces
2. **Monitor Mode**: Enable monitor mode with interference handling
3. **Multi-Tool Scan**: Execute parallel scans using different tools
4. **Network Analysis**: Analyze encryption, signal strength, and vulnerabilities
5. **Target Selection**: Prioritize networks based on signal strength and security
6. **Attack Execution**: Perform WPS attacks or handshake capture
7. **Retry Logic**: Implement intelligent retry with exponential backoff
8. **Report Generation**: Create comprehensive reports in multiple formats

## 🛡️ Security & Ethics

### ⚠️ Legal Disclaimer
This tool is designed for **educational purposes** and **authorized security testing** only. Users are responsible for:

- Obtaining proper authorization before testing any networks
- Complying with local laws and regulations
- Using the tool ethically and responsibly
- Not accessing networks without explicit permission

### Ethical Guidelines
- **Only test networks you own or have explicit permission to test**
- **Respect privacy and confidentiality**
- **Report vulnerabilities responsibly**
- **Do not use for malicious purposes**

## 🐛 Troubleshooting

### Common Issues

#### Monitor Mode Problems
```bash
# Kill interfering processes
sudo airmon-ng check kill

# Restart network services
sudo systemctl restart NetworkManager

# Check interface status
iwconfig
```

#### Permission Errors
```bash
# Ensure running as root
sudo -i

# Check file permissions
chmod +x advanced_wifi_scanner.py
```

#### Missing Dependencies
```bash
# Reinstall aircrack-ng suite
sudo apt install --reinstall aircrack-ng

# Update package lists
sudo apt update && sudo apt upgrade
```

### Debug Mode
```bash
# Enable debug logging
sudo wifi-scanner --debug

# Check log files
tail -f wifi_scan_results/logs/debug_*.log
```

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`
3. **Make your changes** with proper documentation
4. **Test thoroughly** on Kali Linux
5. **Submit a pull request** with detailed description

### Development Setup
```bash
# Clone for development
git clone https://github.com/your-repo/advanced-wifi-scanner.git
cd advanced-wifi-scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt
```

## 📝 Changelog

### Version 2.0.0 (Latest)
- ✅ Multi-tool integration (aircrack-ng, iwlist, nmcli, wifite)
- ✅ Intelligent retry logic with automatic network switching
- ✅ Comprehensive reporting in multiple formats
- ✅ Advanced signal analysis and distance estimation
- ✅ Custom wordlist generation
- ✅ WPS vulnerability detection and exploitation
- ✅ Automated handshake capture with deauth attacks
- ✅ Real-time monitoring and logging

### Version 1.0.0
- Basic WiFi scanning functionality
- Simple network detection
- Basic reporting

## 📞 Support

### Getting Help
- **Documentation**: Check this README and inline code comments
- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Join community discussions
- **Wiki**: Check the project wiki for advanced topics

### Contact
- **GitHub**: [Project Repository](https://github.com/your-repo/advanced-wifi-scanner)
- **Email**: security@example.com (for security issues only)

## 📄 License

This project is licensed under the **Educational Use License** - see the [LICENSE](LICENSE) file for details.

### Key Points:
- ✅ Educational and research use
- ✅ Authorized security testing
- ❌ Commercial use without permission
- ❌ Malicious or illegal activities

## 🙏 Acknowledgments

- **Aircrack-ng Team** - For the excellent wireless security tools
- **Kali Linux Team** - For the comprehensive security platform
- **Security Community** - For continuous feedback and improvements
- **Contributors** - Everyone who helped improve this project

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.

**Stay Safe, Stay Legal, Stay Ethical** 🛡️
