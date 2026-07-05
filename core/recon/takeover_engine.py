"""
FireBounty v2 - Subdomain Takeover Engine
"""

import os
import subprocess
import requests
from core.recon.takeover_signatures import SIGNATURES
from utils.logger import log
from utils.notifier import send_alert
from utils.reporter import save

def resolve_cnames_dnsx(subdomains_file: str) -> dict:
    """
    Resolves CNAME records for subdomains in a file using dnsx.
    Returns a dict mapping subdomain -> CNAME.
    """
    results = {}
    if not os.path.exists(subdomains_file) or os.path.getsize(subdomains_file) == 0:
        return results

    # Try resolving via system dnsx
    try:
        # dnsx -l list.txt -cname -silent
        cmd = ["dnsx", "-l", subdomains_file, "-cname", "-silent"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                # dnsx returns output formatted as: subdomain.domain.com [cname.target.com]
                if " [" in line and line.endswith("]"):
                    parts = line.split(" [")
                    host = parts[0].strip()
                    cname = parts[1][:-1].strip()
                    results[host] = cname
            return results
    except Exception as e:
        log(f"[Takeover] dnsx failed or not available: {e}. Falling back to nslookup.")
    
    # Fallback to nslookup for each subdomain
    try:
        with open(subdomains_file, encoding="utf-8", errors="ignore") as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        for host in subdomains:
            cname = query_cname_nslookup(host)
            if cname:
                results[host] = cname
    except Exception as e:
        log(f"[Takeover] Fallback nslookup resolver failed: {e}")

    return results


def query_cname_nslookup(host: str) -> str:
    """
    Queries CNAME using nslookup utility. Cross-platform.
    """
    try:
        # Runs: nslookup -query=cname host
        cmd = ["nslookup", "-query=cname", host]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            line = line.lower()
            if "canonical name" in line:
                parts = line.split("canonical name =")
                if len(parts) > 1:
                    return parts[1].strip().rstrip(".")
            # Windows output parsing
            elif "aliases:" in line:
                # Aliases: subdomain.domain.com
                pass
    except:
        pass
    return ""


def check_takeover(subdomain: str, cname: str) -> bool:
    """
    Sends requests to a subdomain and checks body content for takeover signatures.
    """
    for service, meta in SIGNATURES.items():
        matched_cname = False
        for sig_cname in meta["cname"]:
            if sig_cname in cname.lower():
                matched_cname = True
                break
        
        if not matched_cname:
            continue
            
        # Target matched a service CNAME signature, let's verify via HTTP response body
        for proto in ["http", "https"]:
            url = f"{proto}://{subdomain}"
            try:
                r = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                body = r.text
                
                for sig_err in meta["response"]:
                    if sig_err.lower() in body.lower():
                        msg = f"[CRITICAL TAKE OVER] {subdomain} (CNAME: {cname}) is pointing to an unclaimed {service.upper()} service!"
                        log(msg)
                        send_alert(msg)
                        save("Subdomain Takeover", url)
                        return True
            except Exception:
                # Request failures are expected for dead targets
                pass
    return False


def run(target: str) -> None:
    """
    Main entry point for subdomain takeover scanning.
    """
    log(f"[*] Running subdomain takeover check on {target}")
    subdomains_file = f"outputs/{target}/recon/all_subdomains.txt"
    
    if not os.path.exists(subdomains_file):
        log(f"[!] Subdomains list outputs/{target}/recon/all_subdomains.txt not found. Skip.")
        return
        
    cnames = resolve_cnames_dnsx(subdomains_file)
    log(f"[*] Resolved {len(cnames)} CNAME records. Scanning signatures...")
    
    takeovers_count = 0
    for subdomain, cname in cnames.items():
        if check_takeover(subdomain, cname):
            takeovers_count += 1
            
    log(f"[✓] Subdomain Takeover scan complete. Found {takeovers_count} vulnerable subdomains.")
