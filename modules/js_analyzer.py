import os
import urllib.parse
from colorama import Fore, init
from utils.logger import log

init(autoreset=True)

def run(target: str) -> None:
    """
    Scan discovered JS files for interesting endpoints or dependencies.
    """
    print(Fore.GREEN + "[*] Running JS Analyzer (Sprint 4 Initial Implementation)")
    
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]
        
    js_file = f"outputs/{domain}/endpoints/js_files.txt"
    if os.path.exists(js_file):
        try:
            with open(js_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip() for line in f if line.strip()]
            print(Fore.CYAN + f"[+] Found {len(lines)} JS files in endpoint discovery history.")
            # Summarize first 5 files
            if lines:
                print("[*] Sample files discovered:")
                for line in lines[:5]:
                    print(f"  - {line}")
        except Exception as e:
            log(f"[!] Error reading JS files: {e}")
    else:
        print(Fore.YELLOW + "[*] No JS files discovered yet (run recon/endpoint discovery first).")