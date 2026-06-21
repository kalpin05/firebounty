#!/bin/bash

set -e

echo "======================================"
echo "   FireBounty v2 Installer"
echo "======================================"

echo "[*] Updating system..."
sudo apt update

echo "[*] Installing base packages..."
sudo apt install -y \
    python3 \
    python3-pip \
    git \
    curl \
    wget \
    unzip \
    nmap \
    amass

# ----------------------------------
# Install Go
# ----------------------------------

if ! command -v go >/dev/null 2>&1
then

    echo "[*] Go not found. Installing Go..."

    GO_VERSION="1.24.5"

    wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz

    sudo rm -rf /usr/local/go

    sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

    rm go${GO_VERSION}.linux-amd64.tar.gz

fi

# ----------------------------------
# Create GOPATH structure
# ----------------------------------

mkdir -p "$HOME/go/bin"

# ----------------------------------
# Fix PATH automatically
# ----------------------------------

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
echo "[*] Go Version:"
go version

# ----------------------------------
# Python Requirements
# ----------------------------------

if [ -f requirements.txt ]
then
    echo ""
    echo "[*] Installing Python requirements..."
    pip3 install -r requirements.txt
fi

# ----------------------------------
# Install Recon Tools
# ----------------------------------

echo ""
echo "[*] Installing FireBounty recon tools..."

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

go install github.com/tomnomnom/assetfinder@latest

go install github.com/projectdiscovery/httpx/cmd/httpx@latest

go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

go install github.com/projectdiscovery/katana/cmd/katana@latest

go install github.com/lc/gau/v2/cmd/gau@latest

go install github.com/tomnomnom/waybackurls@latest

# ----------------------------------
# Output Structure
# ----------------------------------

mkdir -p outputs/recon
mkdir -p outputs/endpoints
mkdir -p outputs/findings
mkdir -p outputs/reports

# ----------------------------------
# Verification
# ----------------------------------

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

FAILED=0

for tool in "${TOOLS[@]}"
do

    if command -v "$tool" >/dev/null 2>&1
    then
        echo "[✓] $tool"
    else
        echo "[✗] $tool"
        FAILED=1
    fi

done

echo ""

if [ "$FAILED" -eq 1 ]
then
    echo "[!] Some tools failed installation."
    echo "[!] Check install logs above."
    exit 1
fi

echo "======================================"
echo "[🔥] FireBounty Ready"
echo "======================================"

echo ""
echo "Run:"
echo "python3 firebounty.py recon example.com"