#!/bin/bash

echo "[*] Installing FireBounty dependencies"

sudo apt update

sudo apt install -y \
    python3 \
    python3-pip \
    nmap

pip3 install -r requirements.txt

echo "[+] Installation complete"