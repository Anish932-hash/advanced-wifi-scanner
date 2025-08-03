#!/bin/bash

# Advanced WiFi Scanner Setup Script
# This script installs all required dependencies and tools for Kali Linux

echo "=========================================="
echo "Advanced WiFi Scanner Setup"
echo "=========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

# Update package lists
echo "[+] Updating package lists..."
apt-get update

# Install core wireless tools
echo "[+] Installing core wireless tools..."
apt-get install -y \
    aircrack-ng \
    airodump-ng \
    airmon-ng \
    aireplay-ng \
    airbase-ng \
    airdecap-ng \
    airdecloak-ng \
    packetforge-ng \
    ivstools \
    kstats

# Install additional wireless tools
echo "[+] Installing additional wireless tools..."
apt-get install -y \
    reaver \
    bully \
    pixiewps \
    wifite \
    kismet \
    mdk3 \
    hostapd \
    dnsmasq

# Install network utilities
echo "[+] Installing network utilities..."
apt-get install -y \
    wireless-tools \
    wpasupplicant \
    network-manager \
    iw \
    iwconfig \
    iwlist \
    rfkill \
    macchanger \
    ettercap-text-only \
    nmap \
    masscan

# Install Python and pip
echo "[+] Installing Python dependencies..."
apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-setuptools \
    python3-wheel

# Install Python packages
echo "[+] Installing Python packages..."
pip3 install -r requirements.txt

# Install additional useful tools
echo "[+] Installing additional tools..."
apt-get install -y \
    hashcat \
    john \
    crunch \
    cewl \
    wordlists \
    rockyou \
    seclists

# Extract rockyou wordlist if compressed
if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    echo "[+] Extracting rockyou wordlist..."
    gunzip /usr/share/wordlists/rockyou.txt.gz
fi

# Set up directories
echo "[+] Setting up directories..."
mkdir -p /opt/wifi-scanner
mkdir -p /opt/wifi-scanner/logs
mkdir -p /opt/wifi-scanner/captures
mkdir -p /opt/wifi-scanner/reports
mkdir -p /opt/wifi-scanner/wordlists

# Copy files to /opt directory
echo "[+] Installing scanner files..."
cp advanced_wifi_scanner.py /opt/wifi-scanner/
cp config.json /opt/wifi-scanner/
cp requirements.txt /opt/wifi-scanner/
chmod +x /opt/wifi-scanner/advanced_wifi_scanner.py

# Create symbolic link for easy access
echo "[+] Creating system-wide access..."
ln -sf /opt/wifi-scanner/advanced_wifi_scanner.py /usr/local/bin/wifi-scanner
chmod +x /usr/local/bin/wifi-scanner

# Install additional wordlists
echo "[+] Setting up wordlists..."
if [ ! -d /usr/share/seclists ]; then
    cd /tmp
    git clone https://github.com/danielmiessler/SecLists.git
    mv SecLists /usr/share/seclists
fi

# Create custom wordlist directory
mkdir -p /opt/wifi-scanner/wordlists/custom

# Set proper permissions
echo "[+] Setting permissions..."
chown -R root:root /opt/wifi-scanner
chmod -R 755 /opt/wifi-scanner
chmod +x /opt/wifi-scanner/advanced_wifi_scanner.py

# Install monitor mode drivers (common USB adapters)
echo "[+] Installing common WiFi adapter drivers..."
apt-get install -y \
    firmware-atheros \
    firmware-ralink \
    firmware-realtek \
    rtl8812au-dkms \
    realtek-rtl88xxau-dkms

# Enable monitor mode support
echo "[+] Configuring monitor mode support..."
modprobe mac80211
modprobe cfg80211

# Create desktop shortcut (if desktop environment exists)
if [ -d /home/*/Desktop ]; then
    echo "[+] Creating desktop shortcut..."
    cat > /home/*/Desktop/WiFi-Scanner.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Advanced WiFi Scanner
Comment=Powerful WiFi scanner with automatic capture
Exec=gnome-terminal -- sudo /usr/local/bin/wifi-scanner
Icon=network-wireless
Terminal=true
Categories=Network;Security;
EOF
    chmod +x /home/*/Desktop/WiFi-Scanner.desktop
fi

# Create systemd service (optional)
echo "[+] Creating systemd service..."
cat > /etc/systemd/system/wifi-scanner.service << EOF
[Unit]
Description=Advanced WiFi Scanner Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/wifi-scanner
ExecStart=/usr/local/bin/wifi-scanner --scan-only
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# Final checks
echo "[+] Performing final checks..."

# Check if aircrack-ng is working
if command -v aircrack-ng &> /dev/null; then
    echo "✓ aircrack-ng installed successfully"
else
    echo "✗ aircrack-ng installation failed"
fi

# Check if Python script is accessible
if [ -x /usr/local/bin/wifi-scanner ]; then
    echo "✓ WiFi scanner installed successfully"
else
    echo "✗ WiFi scanner installation failed"
fi

# Check wireless interfaces
echo "[+] Available wireless interfaces:"
iwconfig 2>/dev/null | grep -o "^[a-zA-Z0-9]*" | head -5

echo ""
echo "=========================================="
echo "Setup completed successfully!"
echo "=========================================="
echo ""
echo "Usage:"
echo "  sudo wifi-scanner                    # Run with default settings"
echo "  sudo wifi-scanner --help            # Show help"
echo "  sudo wifi-scanner --scan-only       # Scan only, no attacks"
echo "  sudo wifi-scanner -i wlan1          # Use specific interface"
echo ""
echo "Configuration file: /opt/wifi-scanner/config.json"
echo "Logs directory: /opt/wifi-scanner/logs"
echo "Captures directory: /opt/wifi-scanner/captures"
echo ""
echo "Note: Always ensure you have permission to test networks!"
echo "This tool is for educational and authorized testing only."
echo ""