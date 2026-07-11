import requests
from colorama import Fore, init
from utils.detector import find_sensitive
from utils.report_gen import generate
from utils.smart_analyzer import analyze

init(autoreset=True)

import os
import urllib.parse

def load_params(target: str = None) -> list:
    """
    Loads custom parameters for targeting if available.
    """
    # Hardcoded default values
    fallback = ["id", "user", "role", "admin", "debug"]
    
    if not target:
        return fallback
        
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
                with open(dynamic_path, "r", encoding="utf-8", errors="ignore") as f:
                    return [line.strip() for line in f if line.strip()]
    except:
        pass
        
    return fallback

payloads = ["1","0","-1","999","true","false","admin","root"]


def run(target):

    print(Fore.GREEN + "[*] Running parameter mutation")
    
    params = load_params(target)

    for p in params:
        for val in payloads:

            url = f"{target}?{p}={val}"

            try:
                r = requests.get(url, timeout=5)

                risk = analyze(r.status_code, len(r.text))

                print(f"{url} -> {r.status_code} [{risk}]")

                findings = find_sensitive(r.text)

                if findings:
                    print(Fore.RED + f"[🔥 Sensitive data: {findings}")
                    generate("Sensitive Data Exposure", url)

            except:
                pass