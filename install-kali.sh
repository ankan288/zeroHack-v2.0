#!/bin/bash
#
# zeroHack v2.0 - Kali Linux Installation Script
# Automated installer for Kali Linux systems
# 
# Usage: sudo ./install-kali.sh
#

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                     ZEROHACK v2.0 INSTALLER                 ║
║                  Kali Linux Automated Setup                 ║
║              7 Immunefi Case Studies - $14M+                ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ This script must be run as root (use sudo)${NC}"
   exit 1
fi

# Check if running on Kali Linux
if ! grep -qi "kali" /etc/os-release 2>/dev/null; then
    echo -e "${YELLOW}⚠️  Warning: This script is optimized for Kali Linux${NC}"
    echo -e "${YELLOW}    It may work on other Debian-based systems but is not guaranteed${NC}"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo -e "${BLUE}🔄 Starting zeroHack v2.0 installation...${NC}"

# Update package lists
echo -e "${BLUE}📦 Updating package lists...${NC}"
apt update -qq

# Install system dependencies
echo -e "${BLUE}🛠️  Installing system dependencies...${NC}"
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    nmap \
    chromium \
    git \
    wget \
    curl \
    build-essential \
    libpcap-dev \
    libssl-dev \
    libffi-dev \
    python3-scapy \
    python3-cryptography \
    python3-requests \
    python3-bs4 \
    python3-dnspython \
    python3-colorama

# Install optional security tools that integrate well with VulnScanner
echo -e "${BLUE}🔧 Installing additional security tools...${NC}"
apt install -y \
    nikto \
    dirb \
    gobuster \
    sqlmap \
    wpscan \
    whatweb \
    httprobe \
    subfinder || echo -e "${YELLOW}⚠️  Some optional tools failed to install (continuing...)${NC}"

# Determine installation directory
INSTALL_DIR="/opt/zerohack"
USER_HOME=$(eval echo ~${SUDO_USER})

echo -e "${BLUE}📂 Creating installation directory: ${INSTALL_DIR}${NC}"
mkdir -p "$INSTALL_DIR"

# Clone or download zeroHack
echo -e "${BLUE}⬇️  Downloading zeroHack v2.0...${NC}"
if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "${YELLOW}   Repository already exists, updating...${NC}"
    cd "$INSTALL_DIR"
    git pull origin main || {
        echo -e "${RED}❌ Failed to update repository${NC}"
        exit 1
    }
else
    git clone https://github.com/ankan288/zeroHack-v2.0.git "$INSTALL_DIR" || {
        echo -e "${YELLOW}⚠️  Git clone failed, trying direct download...${NC}"
        
        # Fallback: Copy from current directory if this script is in zeroHack directory
        if [ -f "./vulnscanner.py" ] && [ -f "./requirements.txt" ]; then
            echo -e "${BLUE}   Copying from current directory...${NC}"
            cp -r . "$INSTALL_DIR/"
        else
            echo -e "${RED}❌ Could not download zeroHack${NC}"
            exit 1
        fi
    }
fi

# Change to installation directory
cd "$INSTALL_DIR"

# Create virtual environment
echo -e "${BLUE}🐍 Creating Python virtual environment...${NC}"
python3 -m venv venv

# Activate virtual environment and install dependencies
echo -e "${BLUE}📦 Installing Python dependencies...${NC}"
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install zeroHack and dependencies
pip install -e . || {
    echo -e "${YELLOW}⚠️  pip install failed, trying requirements.txt...${NC}"
    pip install -r requirements.txt
}

# Create system-wide executable
echo -e "${BLUE}🔗 Creating system-wide executable...${NC}"
cat > /usr/local/bin/zerohack << EOF
#!/bin/bash
cd "$INSTALL_DIR"
source venv/bin/activate
python vulnscanner.py "\$@"
EOF

chmod +x /usr/local/bin/zerohack

# Create alternative command aliases
ln -sf /usr/local/bin/zerohack /usr/local/bin/zhack
ln -sf /usr/local/bin/zerohack /usr/local/bin/zero-hack

# Set proper permissions
echo -e "${BLUE}🔐 Setting permissions...${NC}"
chown -R ${SUDO_USER}:${SUDO_USER} "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/vulnscanner.py"
chmod +x "$INSTALL_DIR/demos/"*.py

# Create desktop shortcut for GUI users
if [ -d "/home/${SUDO_USER}/Desktop" ]; then
    echo -e "${BLUE}🖥️  Creating desktop shortcut...${NC}"
    cat > "/home/${SUDO_USER}/Desktop/VulnScanner.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=zeroHack v2.0
Comment=Comprehensive Vulnerability Assessment Tool
Exec=gnome-terminal -- bash -c 'vulnscanner --help; echo; echo "Press Enter to exit..."; read'
Icon=applications-security
Terminal=true
Categories=Security;Network;
EOF
    chmod +x "/home/${SUDO_USER}/Desktop/VulnScanner.desktop"
    chown ${SUDO_USER}:${SUDO_USER} "/home/${SUDO_USER}/Desktop/VulnScanner.desktop"
fi

# Create menu entry
echo -e "${BLUE}📋 Creating menu entry...${NC}"
mkdir -p /usr/share/applications
cat > /usr/share/applications/vulnscanner.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=zeroHack v2.0
Comment=Comprehensive Vulnerability Assessment Tool with 7 Immunefi Case Studies
Exec=gnome-terminal -- bash -c 'vulnscanner --help; echo; echo "Press Enter to exit..."; read'
Icon=applications-security
Terminal=true
Categories=Security;Network;System;
Keywords=vulnerability;scanner;security;pentest;kali;
EOF

# Test installation
echo -e "${BLUE}🧪 Testing installation...${NC}"
if zerohack --help > /dev/null 2>&1; then
    echo -e "${GREEN}✅ zeroHack command is working!${NC}"
else
    echo -e "${RED}❌ zeroHack command test failed${NC}"
    exit 1
fi

# Create usage examples script
echo -e "${BLUE}📖 Creating usage examples...${NC}"
cat > "$USER_HOME/zerohack-examples.sh" << 'EOF'
#!/bin/bash
# zeroHack v2.0 - Usage Examples

echo "zeroHack v2.0 - Usage Examples"
echo "==============================="
echo
echo "Basic Commands:"
echo "  zerohack -t example.com                       # Basic scan"
echo "  zerohack -t example.com -l moderate           # Moderate intensity"
echo "  zerohack -t example.com -l extreme            # Advanced scan"
echo "  zerohack -t example.com -o results.json       # Save to file"
echo
echo "Smart Contract Testing:"
echo "  zerohack -t defi-protocol.com -l extreme      # DeFi protocol scan"
echo
echo "Educational Demos:"
echo "  python /opt/zerohack/demos/wormhole_proxy_demo.py      # $10M Wormhole demo"
echo "  python /opt/zerohack/demos/port_finance_demo.py        # $630K Port Finance demo"
echo "  python /opt/zerohack/demos/perpetual_protocol_demo.py  # $30K Perpetual demo"
echo
echo "Alternative Commands:"
echo "  zhack -t example.com           # Short alias"
echo "  zero-hack -t example.com       # Alternative alias"
echo
EOF

chmod +x "$USER_HOME/zerohack-examples.sh"
chown ${SUDO_USER}:${SUDO_USER} "$USER_HOME/zerohack-examples.sh"

# Final success message
echo -e "${GREEN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                  🎉 INSTALLATION COMPLETE! 🎉                ║
║                     ZEROHACK v2.0 READY                     ║
║              ALL 7 IMMUNEFI STUDIES INTEGRATED              ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${GREEN}✅ zeroHack v2.0 has been successfully installed!${NC}"
echo
echo -e "${CYAN}📍 Installation Details:${NC}"
echo -e "   • Location: ${INSTALL_DIR}"
echo -e "   • Command: zerohack (system-wide)"
echo -e "   • Aliases: zhack, zero-hack"
echo -e "   • Examples: ~/zerohack-examples.sh"

echo
echo -e "${CYAN}🚀 Quick Start:${NC}"
echo -e "   zerohack -t example.com                       ${GREEN}# Basic scan${NC}"
echo -e "   zerohack -t example.com -l extreme            ${GREEN}# Advanced scan${NC}"
echo -e "   python ${INSTALL_DIR}/demos/wormhole_proxy_demo.py  ${GREEN}# $10M demo${NC}"

echo
echo -e "${CYAN}📚 Educational Demos:${NC}"
echo -e "   • Wormhole $10M Proxy Vulnerability (World Record)"
echo -e "   • Port Finance $630K DeFi Logic Error"
echo -e "   • Perpetual Protocol $30K Bad Debt Attack"

echo
echo -e "${YELLOW}⚠️  IMPORTANT REMINDERS:${NC}"
echo -e "   • Use ONLY on systems you own or have permission to test"
echo -e "   • Follow responsible disclosure for any findings"
echo -e "   • Respect bug bounty program rules and scope"
echo -e "   • This tool is for authorized security testing only"

echo
echo -e "${PURPLE}💰 Total Immunefi Portfolio Coverage: $14,000,000+${NC}"
echo -e "${BLUE}📖 Documentation: https://github.com/ankan288/zeroHack-v2.0${NC}"
echo -e "${GREEN}Ready to discover the next $10 million vulnerability! 🎯${NC}"

# Log installation
echo "$(date): zeroHack v2.0 installed successfully on $(hostname)" >> /var/log/zerohack-install.log

exit 0