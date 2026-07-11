import os
import requests
from colorama import Fore, init

init(autoreset=True)

import urllib.parse

def load_params(target: str = None) -> list:
    """
    Load parameter names from target-specific wordlist if available, 
    otherwise fall back to default wordlists/params.txt or hardcoded defaults.
    """
    path = "wordlists/params.txt"
    
    if target:
        try:
            parsed = urllib.parse.urlparse(target)
            domain = parsed.netloc or parsed.path.split('/')[0]
            if ":" in domain:
                domain = domain.split(":")[0]
            
            parts = domain.split(".")
            for i in range(len(parts) - 1):
                parent_domain = ".".join(parts[i:])
                dynamic_path = f"outputs/{parent_domain}/parameters/params_wordlist.txt"
                if os.path.exists(dynamic_path) and os.path.getsize(dynamic_path) > 0:
                    path = dynamic_path
                    break
        except:
            pass
            
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        print(Fore.YELLOW + "[!] Warning: parameter wordlist is missing or empty. Using fallback parameters.")
        return ["id", "user", "admin", "debug", "role", "email", "token", "key", "password"]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(Fore.RED + f"[!] Error loading param wordlist: {e}. Using fallback parameters.")
        return ["id", "user", "admin", "debug", "role", "email", "token", "key", "password"]

def run(target: str) -> None:
    """
    Bruteforce URL parameters to find differences in response size/status.
    """
    print(Fore.GREEN + "[*] Running parameter bruteforce")

    params = load_params(target)

    try:
        base = requests.get(target, timeout=5)
        base_len = len(base.text)
    except Exception as e:
        print(Fore.RED + f"[!] Target not reachable: {e}")
        return

    for p in params:
        url = f"{target}?{p}=test"
        try:
            r = requests.get(url, timeout=5)

            if len(r.text) != base_len:
                print(Fore.RED + f"[🔥 PARAM FOUND] {url}")
            elif r.status_code != base.status_code:
                print(Fore.YELLOW + f"[~] Interesting param status change: {url}")
        except Exception:
            pass