#!/bin/bash

# ======================================
# FireBounty v2 Installer for Kali Linux
# ======================================

set -euo pipefail

echo "======================================"
echo "      FireBounty v2 Installer"
echo "======================================"

# --------------------------------------
# 1. Update System Package Lists
# --------------------------------------
echo ""
echo "[*] Updating package lists..."
if sudo apt update; then
    echo "[✓] Package lists updated."
else
    echo "[!] apt update failed, attempting package install anyway..."
fi

# --------------------------------------
# 2. Install Base & Standard Tools via APT
# --------------------------------------
echo ""
echo "[*] Installing dependencies via apt..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    unzip \
    nmap \
    subfinder \
    amass \
    assetfinder \
    httpx-toolkit \
    dnsx \
    ffuf \
    findomain || true

# --------------------------------------
# 3. Check and Install Python Requirements
# --------------------------------------
echo ""
echo "[*] Checking Python environment..."
if ! command -v python3 >/dev/null 2>&1; then
    echo "[✗] Python3 is not installed. Exiting."
    exit 1
fi

if [ -f requirements.txt ]; then
    echo "[*] Installing Python packages from requirements.txt..."
    python3 -m pip install --break-system-packages -r requirements.txt || \
    python3 -m pip install -r requirements.txt || \
    echo "[!] Non-blocking warning: Python dependencies installation had issues."
fi

# --------------------------------------
# 4. Check and Install Go Environment (Fallback for missing Go binaries)
# --------------------------------------
echo ""
echo "[*] Checking Go..."
GO_PATH_DIR="$HOME/go/bin"
mkdir -p "$GO_PATH_DIR"

if ! command -v go >/dev/null 2>&1; then
    if [ ! -d "/usr/local/go" ]; then
        echo "[*] Installing Go Lang..."
        GO_VERSION="1.21.6"
        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
        rm "go${GO_VERSION}.linux-amd64.tar.gz"
    fi
    export PATH=$PATH:/usr/local/go/bin:$GO_PATH_DIR
else
    echo "[✓] Go is already installed."
fi

# Set PATH variables in shell RC files if not present
for shell_rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    if [ -f "$shell_rc" ]; then
        if ! grep -q 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' "$shell_rc"; then
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$shell_rc"
        fi
    fi
done

# Ensure PATH matches locally for the rest of the script
export PATH=$PATH:/usr/local/go/bin:$GO_PATH_DIR

# --------------------------------------
# 5. Install Additional Tools via Go
# --------------------------------------
echo ""
echo "[*] Installing additional Go utilities..."

install_go_tool() {
    local name=$1
    local path=$2
    if ! command -v "$name" >/dev/null 2>&1 && [ ! -f "$GO_PATH_DIR/$name" ]; then
        echo "[*] Compiling $name..."
        go install "${path}@latest" || echo "[!] Failed to install $name via go install"
    else
        echo "[✓] $name is already installed."
    fi
}

install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls"
install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana"
install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau"

# --------------------------------------
# 6. Verification Report
# --------------------------------------
echo ""
echo "======================================"
echo " Installed Tools Verification"
echo "======================================"

REQUIRED_TOOLS=(
    subfinder
    amass
    assetfinder
    dnsx
    ffuf
    nmap
    findomain
    waybackurls
    katana
    gau
)

for tool in "${REQUIRED_TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1 || [ -f "$GO_PATH_DIR/$tool" ]; then
        echo "[✓] $tool is available."
    else
        echo "[✗] $tool is MISSING."
    fi
done

# Special verification check for httpx (prioritizing httpx-toolkit)
if command -v httpx-toolkit >/dev/null 2>&1 || command -v httpx >/dev/null 2>&1 || [ -f "$GO_PATH_DIR/httpx" ]; then
    echo "[✓] httpx is available."
else
    echo "[✗] httpx is MISSING."
fi

echo ""
echo "======================================"
echo "[🔥] FireBounty Installation Complete!"
echo "======================================"
echo "To start scanning, run:"
echo "  python3 firebounty.py"
echo "======================================"