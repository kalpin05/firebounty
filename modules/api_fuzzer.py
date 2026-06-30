import os
import urllib.parse
import requests
from colorama import Fore, init

from core.api.profiler import run as run_api_profiler
from utils.logger import log

init(autoreset=True)

endpoints = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/user",
    "/api/admin",
    "/internal",
    "/debug",
    "/private",
    "/test"
]

def run(target: str) -> None:
    """
    Run API profiling pipeline followed by active route endpoint fuzzing tests.
    """
    # 1. Run static and dynamic specs/schema profiling
    run_api_profiler(target)
    
    # 2. Run active endpoint fuzzing
    log(Fore.GREEN + "[*] Running Active API Route Fuzzing")
    
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]
        
    output_path = f"outputs/{domain}/api/fuzz_findings.txt"
    fuzz_findings = []
    
    for ep in endpoints:
        base_url = target.rstrip("/")
        url = base_url + ep
        
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code in [200, 401, 403]:
                alert = f"[~] Discovered Active API Endpoint: {url} -> {r.status_code}"
                print(Fore.YELLOW + alert)
                fuzz_findings.append(alert)
            else:
                print(Fore.WHITE + f"[ ] {url} -> {r.status_code}")
        except Exception:
            pass
            
    # Save active findings list
    if fuzz_findings:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("=== Active API Fuzzing Findings ===\n\n")
            for item in fuzz_findings:
                f.write(item + "\n")
        log(f"[✓] Active fuzzing findings saved to {output_path}")
    else:
        log("[✓] Active route fuzzing completed (no endpoints discovered).")