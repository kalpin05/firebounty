"""
FireBounty v2 - Unified Technology Detector
Analyzes headers, cookies, and HTML bodies for fingerprints.
"""

import os
import json
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from colorama import Fore, init

from core.tech.fingerprints import TECH_FINGERPRINTS
from utils.logger import log

init(autoreset=True)

# Disable urllib3 warnings for HTTPS scans
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

class TechDetector:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "FireBounty/2.0 (Technology Detection)"
        })

    def scan_url(self, url: str) -> dict:
        """
        Scan a single URL by fetching headers and HTML content.
        """
        results = {
            "url": url,
            "detected": defaultdict(list),
            "missing_security_headers": []
        }
        try:
            r = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            # Normalize headers keys and values
            headers = {k.lower(): str(v).lower() for k, v in r.headers.items()}
            html = r.text.lower()
            
            # Combine headers into single target matching string
            header_str = "\n".join([f"{k}: {v}" for k, v in r.headers.items()]).lower()
            
            # 1. Match technology signatures
            for category, technologies in TECH_FINGERPRINTS.items():
                for tech, signatures in technologies.items():
                    for signature in signatures:
                        sig_lower = signature.lower()
                        # Evaluate signature against headers, response body, or URL string
                        if sig_lower in header_str or sig_lower in html or sig_lower in url.lower():
                            results["detected"][category].append(tech)
                            break
                            
            # 2. Check Security Headers
            for header in SECURITY_HEADERS:
                if header.lower() not in headers:
                    results["missing_security_headers"].append(header)
                    
        except Exception:
            pass
            
        return results

def save_results(domain: str, results_list: list) -> None:
    """
    Save scanned results into structured categorized outputs.
    """
    output_dir = f"outputs/{domain}/technology"
    os.makedirs(output_dir, exist_ok=True)
    
    summary = {
        "servers": set(),
        "frameworks": set(),
        "javascript": set(),
        "cloud": set(),
        "cms": set(),
        "security": set()
    }
    
    missing_headers_summary = defaultdict(int)
    total_scanned = len(results_list)
    detailed_results = []
    
    for res in results_list:
        url = res["url"]
        detected = res["detected"]
        missing = res["missing_security_headers"]
        
        serialized_detected = {}
        for category, values in detected.items():
            summary[category].update(values)
            serialized_detected[category] = sorted(list(set(values)))
            
        for h in missing:
            missing_headers_summary[h] += 1
            
        detailed_results.append({
            "url": url,
            "detected": serialized_detected,
            "missing_security_headers": missing
        })
        
    # Write categorized text files
    for category in ["servers", "frameworks", "javascript", "cloud", "cms"]:
        path = os.path.join(output_dir, f"{category}.txt")
        with open(path, "w", encoding="utf-8") as f:
            for item in sorted(list(summary[category])):
                f.write(item + "\n")
                
    # Write security headers text file
    sec_path = os.path.join(output_dir, "headers.txt")
    with open(sec_path, "w", encoding="utf-8") as f:
        f.write("=== Security Headers Audit ===\n\n")
        f.write(f"Total Hosts Audited: {total_scanned}\n\n")
        f.write("Missing Security Headers statistics:\n")
        for h, count in sorted(missing_headers_summary.items(), key=lambda x: x[1], reverse=True):
            pct = (count / total_scanned) * 100 if total_scanned > 0 else 0
            f.write(f"  - {h}: Missing on {count}/{total_scanned} hosts ({pct:.1f}%)\n")
            
    # Write unified JSON summary
    json_path = os.path.join(output_dir, "technology.json")
    master_summary = {
        "summary": {cat: sorted(list(vals)) for cat, vals in summary.items()},
        "details": detailed_results
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(master_summary, f, indent=4)
        
    log(f"[✓] Technology profiles saved for {domain} inside technology/")

def run(target: str) -> None:
    """
    Run Technology Detection.
    """
    log("[*] Initializing Technology Detection Engine")
    
    # Parse target domain
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]
        
    # Attempt to read alive hosts
    alive_file = f"outputs/{domain}/recon/alive.txt"
    urls = []
    if os.path.exists(alive_file) and os.path.getsize(alive_file) > 0:
        try:
            with open(alive_file, "r", encoding="utf-8", errors="ignore") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception:
            pass
            
    # Fallback to single URL target
    if not urls:
        urls = [target]
        
    log(f"[*] Scanning {len(urls)} hosts for technologies...")
    
    detector = TechDetector()
    results_list = []
    
    # Run scans concurrently
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(detector.scan_url, url): url for url in urls}
        for future in as_completed(futures):
            res = future.result()
            results_list.append(res)
            # Log immediate findings
            found_techs = []
            for cat, vals in res["detected"].items():
                found_techs.extend(vals)
            if found_techs:
                log(f"[+] {res['url']}: Match found -> {', '.join(set(found_techs))}")
                
    save_results(domain, results_list)
    log("[✓] Technology Detection completed successfully")
