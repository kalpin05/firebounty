"""
FireBounty v2 - Authentication Intelligence Engine
Scans and profiles authentication methods, cookie security, and CSRF mechanisms.
"""

import os
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from colorama import Fore, init

from utils.logger import log

init(autoreset=True)

# Disable urllib3 warnings for HTTPS scans
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

OAUTH_OIDC_KEYWORDS = ["oauth", "oidc", "openid", "authorize", "token", "callback", ".well-known"]
SAML_KEYWORDS = ["saml", "sso", "adfs", "samlrequest", "samlresponse"]
CSRF_KEYWORDS = ["csrf", "xsrf", "_token", "authenticity_token"]

class AuthAnalyzer:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "FireBounty/2.0 (Authentication Intelligence)"
        })

    def analyze_url(self, url: str) -> dict:
        """
        Audit a single URL for auth methods, cookies, and CSRF protection.
        """
        result = {
            "url": url,
            "oauth_oidc_detected": [],
            "saml_detected": [],
            "cookies": [],
            "csrf_protected": False,
            "forms_analyzed": 0
        }
        
        try:
            r = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            html = r.text.lower()
            url_lower = url.lower()
            
            # 1. Detect OAuth/OIDC/SAML routes or page links
            for kw in OAUTH_OIDC_KEYWORDS:
                if kw in url_lower or kw in html:
                    result["oauth_oidc_detected"].append(kw)
            for kw in SAML_KEYWORDS:
                if kw in url_lower or kw in html:
                    result["saml_detected"].append(kw)
                    
            result["oauth_oidc_detected"] = sorted(list(set(result["oauth_oidc_detected"])))
            result["saml_detected"] = sorted(list(set(result["saml_detected"])))
            
            # 2. Inspect session cookies security flags
            cookies_header = r.headers.get("Set-Cookie", "")
            if cookies_header:
                # Set-Cookie could contain multiple cookies separated by commas
                # (but commas can also exist inside dates, so parse carefully)
                raw_cookies = [c.strip() for c in cookies_header.split(",") if "=" in c]
                for raw in raw_cookies:
                    parts = [p.strip().lower() for p in raw.split(";")]
                    cookie_name = raw.split(";")[0].split("=")[0].strip()
                    
                    has_httponly = any("httponly" in p for p in parts)
                    has_secure = any("secure" in p for p in parts)
                    has_samesite = any("samesite" in p for p in parts)
                    
                    result["cookies"].append({
                        "name": cookie_name,
                        "httponly": has_httponly,
                        "secure": has_secure,
                        "samesite": has_samesite
                    })
                    
            # 3. CSRF token detection in HTML forms
            # Simple form inputs parsing via regex
            form_inputs = r.text.split("<input")
            if len(form_inputs) > 1:
                result["forms_analyzed"] = len(form_inputs) - 1
                for input_tag in form_inputs[1:]:
                    input_tag = input_tag.split(">")[0].lower()
                    # Check if it has a CSRF name or value
                    if any(kw in input_tag for kw in CSRF_KEYWORDS):
                        result["csrf_protected"] = True
                        break
        except Exception:
            pass
            
        return result

def save_auth_results(domain: str, results_list: list) -> None:
    """
    Format and save auth intelligence logs to disk.
    """
    output_dir = f"outputs/{domain}/authentication"
    os.makedirs(output_dir, exist_ok=True)
    
    unique_oauth = set()
    unique_saml = set()
    cookie_issues = []
    csrf_details = []
    
    for res in results_list:
        url = res["url"]
        
        for method in res["oauth_oidc_detected"]:
            unique_oauth.add(f"{method.upper()} route indicator matched on {url}")
        for method in res["saml_detected"]:
            unique_saml.add(f"{method.upper()} route indicator matched on {url}")
            
        for c in res["cookies"]:
            issues = []
            if not c["httponly"]:
                issues.append("Missing HttpOnly")
            if not c["secure"]:
                issues.append("Missing Secure")
            if not c["samesite"]:
                issues.append("Missing SameSite")
                
            cookie_issues.append({
                "url": url,
                "cookie": c["name"],
                "issues": issues
            })
            
        csrf_details.append({
            "url": url,
            "forms_count": res["forms_analyzed"],
            "csrf_protected": res["csrf_protected"]
        })
        
    # 1. Save auth_methods.txt
    methods_path = os.path.join(output_dir, "auth_methods.txt")
    with open(methods_path, "w", encoding="utf-8") as f:
        f.write("=== SSO / OAuth / SAML Authentication Methods ===\n\n")
        f.write("OAuth / OIDC Indicators:\n")
        for m in sorted(list(unique_oauth)):
            f.write(f"  - {m}\n")
        f.write("\nSAML / SSO Indicators:\n")
        for m in sorted(list(unique_saml)):
            f.write(f"  - {m}\n")
            
    # 2. Save cookie_security.txt
    cookies_path = os.path.join(output_dir, "cookie_security.txt")
    with open(cookies_path, "w", encoding="utf-8") as f:
        f.write("=== Session Cookie Security Issues ===\n\n")
        if cookie_issues:
            for item in cookie_issues:
                if item["issues"]:
                    f.write(f"URL: {item['url']}\n")
                    f.write(f"  Cookie: {item['cookie']}\n")
                    f.write(f"  Warnings: {', '.join(item['issues'])}\n\n")
        else:
            f.write("No session cookies identified or all flags configured securely.\n")
            
    # 3. Save csrf_status.txt
    csrf_path = os.path.join(output_dir, "csrf_status.txt")
    with open(csrf_path, "w", encoding="utf-8") as f:
        f.write("=== Anti-CSRF Protections Status ===\n\n")
        for item in csrf_details:
            status = "PROTECTED" if item["csrf_protected"] else "NOT DETECTED (Vulnerable?)"
            if item["forms_count"] > 0:
                f.write(f"URL: {item['url']} -> Found {item['forms_count']} form(s) -> {status}\n")
            else:
                f.write(f"URL: {item['url']} -> No forms found\n")
                
    # 4. Save authentication.json summary
    json_path = os.path.join(output_dir, "authentication.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "summary": {
                "oauth_oidc_findings": len(unique_oauth),
                "saml_findings": len(unique_saml),
                "cookie_issues_found": len([i for i in cookie_issues if i["issues"]]),
                "csrf_vulnerable_forms": len([i for i in csrf_details if i["forms_count"] > 0 and not i["csrf_protected"]])
            },
            "details": results_list
        }, f, indent=4)
        
    log(f"[✓] Saved authentication profiles for {domain} inside authentication/")

def run(target: str) -> list:
    """
    Run Authentication static analysis pipeline.
    """
    log("[*] Initializing Authentication Intelligence Engine")
    
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]
        
    alive_file = f"outputs/{domain}/recon/alive.txt"
    urls = []
    if os.path.exists(alive_file) and os.path.getsize(alive_file) > 0:
        try:
            with open(alive_file, "r", encoding="utf-8", errors="ignore") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception:
            pass
            
    if not urls:
        urls = [target]
        
    log(f"[*] Scanning {len(urls)} hosts for Auth indicators and cookie configs...")
    
    analyzer = AuthAnalyzer()
    results_list = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(analyzer.analyze_url, url): url for url in urls}
        for future in as_completed(futures):
            res = future.result()
            results_list.append(res)
            
            # Console warning flags
            detected_methods = res["oauth_oidc_detected"] + res["saml_detected"]
            if detected_methods:
                log(f"[+] {res['url']}: Detected Auth Methods -> {', '.join(detected_methods)}")
            for cookie in res["cookies"]:
                missing = []
                if not cookie["httponly"]: missing.append("HttpOnly")
                if not cookie["secure"]: missing.append("Secure")
                if missing:
                    log(Fore.YELLOW + f"[~] {res['url']}: Cookie '{cookie['name']}' missing {', '.join(missing)}")
                    
    save_auth_results(domain, results_list)
    log("[✓] Authentication analysis completed successfully")
    return results_list
