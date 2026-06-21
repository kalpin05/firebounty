#!/bin/bash

echo "======================================"
echo " FireBounty v2 Installer"
echo "======================================"

sudo apt update

sudo apt install -y \
python3 \
python3-pip \
git \
curl \
wget \
unzip \
nmap \
amass

# Install Go if missing
if ! command -v go >/dev/null 2>&1
then
    echo "[*] Installing Go..."

    wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz

    sudo rm -rf /usr/local/go

    sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz

    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.zshrc
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
fi

# Python dependencies
if [ -f requirements.txt ]
then
    pip3 install -r requirements.txt
fi

echo ""
echo "[*] Installing FireBounty Recon Tools..."
echo ""

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

go install github.com/tomnomnom/assetfinder@latest

go install github.com/projectdiscovery/httpx/cmd/httpx@latest

go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

go install github.com/projectdiscovery/katana/cmd/katana@latest

go install github.com/lc/gau/v2/cmd/gau@latest

go install github.com/tomnomnom/waybackurls@latest

mkdir -p outputs/recon
mkdir -p outputs/endpoints
mkdir -p outputs/findings
mkdir -p outputs/reports

echo ""
echo "======================================"
echo " Installed Tools"
echo "======================================"

for tool in \
subfinder \
assetfinder \
httpx \
dnsx \
naabu \
katana \
gau \
waybackurls \
amass \
nmap
do

    if command -v $tool >/dev/null 2>&1
    then
        echo "[✓] $tool"
    else
        echo "[✗] $tool"
    fi

done

echo ""
echo "[🔥] FireBounty Installation Complete"