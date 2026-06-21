#!/bin/bash

# ======================================
# FireBounty v2 Installer
# ======================================

INSTALLED_TOOLS=()
FAILED_TOOLS=()

echo "======================================"
echo "      FireBounty v2 Installer"
echo "======================================"

# --------------------------------------
# Update System
# --------------------------------------

echo ""
echo "[*] Updating package lists..."

if sudo apt update; then
    echo "[✓] apt update successful"
else
    echo "[!] apt update failed"
    echo "[!] Continuing installation..."
fi

# --------------------------------------
# Base Packages
# --------------------------------------

echo ""
echo "[*] Installing base packages..."

sudo apt install -y \
    python3 \
    git \
    curl \
    wget \
    unzip \
    nmap \
    amass || true

# --------------------------------------
# Verify Python
# --------------------------------------

echo ""
echo "[*] Checking Python..."

if ! command -v python3 >/dev/null 2>&1
then
    echo "[✗] Python3 not found"
    exit 1
fi

echo "[✓] Python Found"

# --------------------------------------
# Ensure Pip
# --------------------------------------

echo ""
echo "[*] Checking pip..."

python3 -m ensurepip --default-pip >/dev/null 2>&1 || true

if python3 -m pip --version >/dev/null 2>&1
then
    echo "[✓] pip available"
else
    echo "[!] pip unavailable"
    echo "[!] Skipping Python package installation"
fi

# --------------------------------------
# Install Python Requirements
# --------------------------------------

if [ -f requirements.txt ]
then

    echo ""
    echo "[*] Installing Python requirements..."

    python3 -m pip install --upgrade pip

    python3 -m pip install -r requirements.txt

fi

# --------------------------------------
# Install Go
# --------------------------------------

echo ""
echo "[*] Checking Go..."

if ! command -v go >/dev/null 2>&1
then

    echo "[*] Installing Go..."

    GO_VERSION="1.24.5"

    wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz

    sudo rm -rf /usr/local/go

    sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

    rm go${GO_VERSION}.linux-amd64.tar.gz

fi

# --------------------------------------
# Configure PATH
# --------------------------------------

mkdir -p "$HOME/go/bin"

if ! grep -q 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' ~/.zshrc 2>/dev/null
then
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.zshrc
fi

if ! grep -q 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' ~/.bashrc 2>/dev/null
then
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
fi

export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

echo ""
echo "[✓] Go Version:"
go version

# --------------------------------------
# Function
# --------------------------------------

install_go_tool() {

    TOOL_NAME=$1
    TOOL_PATH=$2

    echo ""
    echo "[*] Installing $TOOL_NAME"

    if go install "${TOOL_PATH}@latest"
    then

        echo "[✓] $TOOL_NAME installed"

        INSTALLED_TOOLS+=("$TOOL_NAME")

    else

        echo "[✗] $TOOL_NAME failed"

        FAILED_TOOLS+=("$TOOL_NAME")

    fi
}

# --------------------------------------
# Recon Tools
# --------------------------------------

echo ""
echo "[*] Installing FireBounty Recon Tools..."

install_go_tool \
"subfinder" \
"github.com/projectdiscovery/subfinder/v2/cmd/subfinder"

install_go_tool \
"assetfinder" \
"github.com/tomnomnom/assetfinder"

install_go_tool \
"httpx" \
"github.com/projectdiscovery/httpx/cmd/httpx"

install_go_tool \
"dnsx" \
"github.com/projectdiscovery/dnsx/cmd/dnsx"

install_go_tool \
"naabu" \
"github.com/projectdiscovery/naabu/v2/cmd/naabu"

install_go_tool \
"katana" \
"github.com/projectdiscovery/katana/cmd/katana"

install_go_tool \
"gau" \
"github.com/lc/gau/v2/cmd/gau"

install_go_tool \
"waybackurls" \
"github.com/tomnomnom/waybackurls"

# --------------------------------------
# Output Structure
# --------------------------------------

echo ""
echo "[*] Creating FireBounty folders..."

mkdir -p outputs/recon
mkdir -p outputs/endpoints
mkdir -p outputs/findings
mkdir -p outputs/reports

# --------------------------------------
# Verification
# --------------------------------------

echo ""
echo "======================================"
echo " Installed Tools Verification"
echo "======================================"

TOOLS=(
subfinder
assetfinder
httpx
dnsx
naabu
katana
gau
waybackurls
amass
nmap
)

for tool in "${TOOLS[@]}"
do

    if command -v "$tool" >/dev/null 2>&1
    then
        echo "[✓] $tool"
    else
        echo "[✗] $tool"
    fi

done

# --------------------------------------
# Summary
# --------------------------------------

echo ""
echo "======================================"
echo " FireBounty Installation Summary"
echo "======================================"

echo ""
echo "[✓] Installed Tools"

for tool in "${INSTALLED_TOOLS[@]}"
do
    echo "    $tool"
done

echo ""

if [ ${#FAILED_TOOLS[@]} -gt 0 ]
then

    echo "[!] Failed Tools"

    for tool in "${FAILED_TOOLS[@]}"
    do
        echo "    $tool"
    done

else

    echo "[✓] No installation failures"

fi

echo ""
echo "======================================"
echo "[🔥] FireBounty Ready"
echo "======================================"

echo ""
echo "Usage:"
echo "python3 firebounty.py recon example.com"