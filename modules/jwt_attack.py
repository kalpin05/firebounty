import base64
import os
import re
import urllib.parse
from colorama import Fore, init
from utils.logger import log

init(autoreset=True)

# Pattern from core/js/regex_patterns.py
JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+")

def decode_jwt(token: str) -> None:
    """
    Decode JWT payload section and display it.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            print("Invalid token format")
            return
        payload = parts[1]
        decoded = base64.urlsafe_b64decode(payload + "==")
        print(Fore.GREEN + "[+] Decoded JWT:")
        print(decoded.decode(errors="ignore"))
    except Exception as e:
        print(f"Invalid token: {e}")

def find_jwt_in_outputs(target: str) -> str:
    """
    Search for JWT tokens in endpoints/recon files.
    """
    if not target:
        return ""
    # Extract domain
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]
        
    search_paths = [
        f"outputs/{domain}/endpoints/all_endpoints.txt",
        f"outputs/{domain}/endpoints/js_files.txt",
        f"outputs/{domain}/endpoints/interesting.txt"
    ]
    
    for path in search_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        match = JWT_PATTERN.search(line)
                        if match:
                            return match.group(0)
            except Exception:
                pass
    return ""

def run(target: str = None, is_pipeline: bool = False) -> None:
    """
    JWT Analysis entrypoint.
    """
    print(Fore.GREEN + "[*] Running JWT analysis")
    
    token = ""
    if target:
        token = find_jwt_in_outputs(target)
        if token:
            print(Fore.GREEN + f"[+] Automatically discovered JWT token: {token[:30]}...")
            
    if not token and is_pipeline:
        print(Fore.YELLOW + "[*] No JWT token discovered. Skipping JWT analysis (non-interactive).")
        return
        
    if not token:
        try:
            token = input("Enter JWT: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Exiting JWT module")
            return
            
    if token:
        decode_jwt(token)
        print(Fore.YELLOW + "[*] Try modifying payload (admin:true)")
    else:
        print("[!] No token provided.")