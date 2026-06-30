import os
import urllib.parse
import requests
from colorama import Fore, init

from core.auth.analyzer import run as run_auth_audit
from utils.logger import log

init(autoreset=True)

payloads = [
    "/admin",
    "/dashboard",
    "/api/admin",
    "/user/profile"
]

headers_list = [
    {"Authorization": "Bearer null"},
    {"Authorization": "Bearer test"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"}
]

def run(target: str) -> None:
    """
    Run Authentication Intelligence static scans and active bypass verification tests.
    """
    # 1. Run static cookie/auth protocol analysis
    run_auth_audit(target)
    
    # 2. Run active auth bypass scanning
    log(Fore.GREEN + "[*] Running Active Authentication Bypass Tests")
    
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]
        
    output_path = f"outputs/{domain}/authentication/bypass_findings.txt"
    findings = []
    
    for p in payloads:
        # Standardize target URL path append
        base_url = target.rstrip("/")
        url = base_url + p
        
        try:
            base_res = requests.get(url, timeout=5, verify=False)
            base_code = base_res.status_code
            
            for h in headers_list:
                r = requests.get(url, headers=h, timeout=5, verify=False)
                
                # Check for bypass indicators (status shifts from 401/403 to 200)
                if base_code in [401, 403] and r.status_code == 200:
                    alert = f"[🔥 BYPASS FOUND] {url} using {h} -> {r.status_code}"
                    print(Fore.RED + alert)
                    findings.append(alert)
                elif r.status_code != base_code:
                    alert = f"[~] Interesting Response: {url} using {h} (Status changed {base_code} -> {r.status_code})"
                    print(Fore.YELLOW + alert)
                    findings.append(alert)
        except Exception as e:
            pass
            
    # Write findings
    if findings:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("=== Active Authentication Bypass Findings ===\n\n")
            for item in findings:
                f.write(item + "\n")
        log(f"[✓] Active bypass findings saved to {output_path}")
    else:
        log("[✓] Active bypass scanning finished (no bypass indicators detected).")