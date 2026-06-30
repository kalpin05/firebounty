"""
FireBounty v2 - Central Vulnerability Scanner
Executes active vulnerability scanning (CORS, Open Redirect, Host Header, SQLi/LFI).
"""

import os
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from colorama import Fore, init

from utils.logger import log

init(autoreset=True)

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Common SQLi/LFI error signatures in responses
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "mysql_fetch",
    "mariadb",
    "postgresql query failed",
    "sqlite3::",
    "driver error",
    "unclosed quotation mark after the character string"
]

LFI_PATTERNS = [
    "root:x:",
    "boot.ini",
    "[boot loader]"
]

class ActiveScanner:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "FireBounty/2.0 (Vulnerability Intelligence)"
        })

    def check_cors(self, url: str) -> dict:
        """
        Check for CORS misconfiguration by reflection.
        """
        headers = {"Origin": "https://evil.com"}
        try:
            r = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)
            allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
            allow_cred = r.headers.get("Access-Control-Allow-Credentials", "")
            
            if allow_origin == "https://evil.com" and allow_cred.lower() == "true":
                return {
                    "vulnerable": True,
                    "detail": "Reflects Origin header dynamically with Credentials enabled."
                }
            elif allow_origin == "*":
                return {
                    "vulnerable": True,
                    "detail": "Wildcard CORS origin configured."
                }
        except Exception:
            pass
        return {"vulnerable": False}

    def check_open_redirect(self, url: str) -> dict:
        """
        Check query parameters for open redirection.
        """
        parsed = urllib.parse.urlparse(url)
        queries = urllib.parse.parse_qs(parsed.query)
        if not queries:
            return {"vulnerable": False}
            
        payloads = ["https://evil.com", "//evil.com"]
        for p in payloads:
            for param in queries.keys():
                # Replace parameter with payload
                new_query = urllib.parse.urlencode({k: (p if k == param else v[0]) for k, v in queries.items()})
                test_url = parsed._replace(query=new_query).geturl()
                try:
                    # Do not follow redirect
                    r = requests.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                    loc = r.headers.get("Location", "")
                    if r.status_code in [301, 302, 303, 307, 308] and (loc.startswith(p) or p in loc):
                        return {
                            "vulnerable": True,
                            "parameter": param,
                            "payload": p,
                            "url": test_url
                        }
                except Exception:
                    pass
        return {"vulnerable": False}

    def check_host_injection(self, url: str) -> dict:
        """
        Check for Host Header injection anomalies.
        """
        headers = {
            "Host": "evil.com",
            "X-Forwarded-Host": "evil.com"
        }
        try:
            r = requests.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=False)
            loc = r.headers.get("Location", "")
            if "evil.com" in loc or "evil.com" in r.text.lower():
                return {
                    "vulnerable": True,
                    "detail": "Host header reflected in response location or body."
                }
        except Exception:
            pass
        return {"vulnerable": False}

    def check_sqli_lfi(self, url: str) -> dict:
        """
        Scan parameters for basic SQL injection or LFI vulnerability errors.
        """
        parsed = urllib.parse.urlparse(url)
        queries = urllib.parse.parse_qs(parsed.query)
        if not queries:
            return {"vulnerable": False}
            
        payloads = ["'", "\"", "../../../../etc/passwd", "..\\..\\..\\..\\win.ini"]
        for p in payloads:
            for param in queries.keys():
                new_query = urllib.parse.urlencode({k: (v[0] + p if k == param else v[0]) for k, v in queries.items()})
                test_url = parsed._replace(query=new_query).geturl()
                try:
                    r = requests.get(test_url, timeout=self.timeout, verify=False)
                    res_body = r.text.lower()
                    
                    # Inspect SQL Errors
                    for err in SQL_ERRORS:
                        if err in res_body:
                            return {
                                "vulnerable": True,
                                "type": "SQLi Error Based",
                                "parameter": param,
                                "payload": p,
                                "signature": err,
                                "url": test_url
                            }
                    # Inspect LFI Errors
                    for pat in LFI_PATTERNS:
                        if pat in r.text:
                            return {
                                "vulnerable": True,
                                "type": "Local File Inclusion",
                                "parameter": param,
                                "payload": p,
                                "signature": pat,
                                "url": test_url
                            }
                except Exception:
                    pass
        return {"vulnerable": False}

    def scan_target(self, url: str) -> dict:
        """
        Perform all active audits on a single URL.
        """
        findings = []
        
        # 1. CORS
        cors_res = self.check_cors(url)
        if cors_res.get("vulnerable"):
            findings.append({
                "type": "CORS Misconfiguration",
                "severity": "Medium",
                "detail": cors_res["detail"]
            })
            
        # 2. Open Redirect
        or_res = self.check_open_redirect(url)
        if or_res.get("vulnerable"):
            findings.append({
                "type": "Open Redirection",
                "severity": "Medium",
                "detail": f"Parameter '{or_res['parameter']}' redirects using payload '{or_res['payload']}'",
                "proof_url": or_res["url"]
            })
            
        # 3. Host Injection
        host_res = self.check_host_injection(url)
        if host_res.get("vulnerable"):
            findings.append({
                "type": "Host Header Injection",
                "severity": "Low",
                "detail": host_res["detail"]
            })
            
        # 4. SQLi/LFI
        vuln_res = self.check_sqli_lfi(url)
        if vuln_res.get("vulnerable"):
            findings.append({
                "type": vuln_res["type"],
                "severity": "High",
                "detail": f"Parameter '{vuln_res['parameter']}' exposes trigger '{vuln_res['signature']}'",
                "proof_url": vuln_res["url"]
            })
            
        return {
            "url": url,
            "findings": findings
        }

def save_vuln_results(domain: str, scan_results: list) -> None:
    """
    Format and save findings reports to disk.
    """
    output_dir = f"outputs/{domain}/findings"
    os.makedirs(output_dir, exist_ok=True)
    
    unique_findings = []
    
    for res in scan_results:
        url = res["url"]
        for f in res["findings"]:
            unique_findings.append({
                "url": url,
                "type": f["type"],
                "severity": f["severity"],
                "detail": f["detail"],
                "proof_url": f.get("proof_url", "")
            })
            
    # 1. Write findings.txt
    txt_path = os.path.join(output_dir, "findings.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=== Vulnerability Scanner Findings ===\n\n")
        if unique_findings:
            for item in unique_findings:
                f.write(f"[{item['severity'].upper()}] {item['type']} on {item['url']}\n")
                f.write(f"  Detail: {item['detail']}\n")
                if item["proof_url"]:
                    f.write(f"  Proof URL: {item['proof_url']}\n")
                f.write("\n")
        else:
            f.write("No active vulnerabilities discovered.\n")
            
    # 2. Write vulnerabilities.json
    json_path = os.path.join(output_dir, "vulnerabilities.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "metrics": {
                "total_vulnerabilities": len(unique_findings),
                "high_severity": len([x for x in unique_findings if x["severity"] == "High"]),
                "medium_severity": len([x for x in unique_findings if x["severity"] == "Medium"]),
                "low_severity": len([x for x in unique_findings if x["severity"] == "Low"])
            },
            "findings": unique_findings
        }, f, indent=4)
        
    log(f"[✓] Saved vulnerability findings for {domain} inside findings/")

def run(target: str) -> list:
    """
    Orchestrate active vulnerability scanning.
    """
    log("[*] Initializing Active Vulnerability Scanner Engine")
    
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]
        
    # Read discovered endpoints
    endpoints_file = f"outputs/{domain}/endpoints/all_endpoints.txt"
    urls = []
    if os.path.exists(endpoints_file) and os.path.getsize(endpoints_file) > 0:
        try:
            with open(endpoints_file, "r", encoding="utf-8", errors="ignore") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception:
            pass
            
    # Fallback to target URL
    if not urls:
        urls = [target]
        
    # Limit fuzzer target list to optimize time (e.g. max 30 routes)
    scan_urls = urls[:30]
    log(f"[*] Scanning {len(scan_urls)} endpoints for vulnerabilities...")
    
    scanner = ActiveScanner()
    scan_results = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scanner.scan_target, url): url for url in scan_urls}
        for future in as_completed(futures):
            res = future.result()
            scan_results.append(res)
            
            # Print immediate findings in console
            for f in res["findings"]:
                severity = f["severity"].upper()
                msg = f"[{severity} VULNERABILITY] {f['type']} on {res['url']}: {f['detail']}"
                if severity == "HIGH":
                    print(Fore.RED + msg)
                else:
                    print(Fore.YELLOW + msg)
                    
    save_vuln_results(domain, scan_results)
    log("[✓] Vulnerability scanning completed successfully")
    return scan_results
