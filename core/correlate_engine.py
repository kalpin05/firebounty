"""
FireBounty v2 - Threat Correlation Engine
"""

import os
import json
import urllib.parse
from utils.logger import log

def get_subdomain(url: str) -> str:
    """
    Extracts the subdomain from a URL.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc or parsed.path.split('/')[0]
        if ":" in netloc:
            netloc = netloc.split(":")[0]
        return netloc.strip().lower()
    except:
        return ""


def load_lines(filepath: str) -> list:
    """
    Reads a file line by line, returns a list of stripped lines.
    """
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        log(f"[Correlate] Error reading {filepath}: {e}")
        return []


def load_json(filepath: str) -> dict:
    """
    Safely loads a JSON file.
    """
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log(f"[Correlate] Error reading JSON {filepath}: {e}")
        return {}


def run(target: str) -> None:
    """
    Runs the correlation engine on local target scan output logs.
    """
    log(f"[*] Running Exploit Chain Correlation Engine on {target}")
    
    target_dir = f"outputs/{target}"
    if not os.path.exists(target_dir):
        log(f"[!] Target output folder {target_dir} not found. Skipping correlation.")
        return

    # 1. Load data files
    alive_hosts = load_lines(f"{target_dir}/recon/alive.txt")
    interesting_endpoints = load_lines(f"{target_dir}/endpoints/interesting.txt")
    js_secrets = load_json(f"{target_dir}/javascript/secrets_extracted.json")
    
    # Load technologies
    servers = load_lines(f"{target_dir}/technology/servers.txt")
    frameworks = load_lines(f"{target_dir}/technology/frameworks.txt")
    cloud = load_lines(f"{target_dir}/technology/cloud.txt")
    security = load_lines(f"{target_dir}/technology/security.txt")
    
    # 2. Build subdomain profile map
    # profile = { subdomain: { "alive": True/False, "endpoints": [], "secrets": [], "frameworks": [], ... } }
    profiles = {}
    
    # Initialize profiles for alive hosts
    for host in alive_hosts:
        subdomain = get_subdomain(host)
        if subdomain and subdomain not in profiles:
            profiles[subdomain] = {
                "subdomain": subdomain,
                "alive": True,
                "endpoints": [],
                "secrets": [],
                "frameworks": frameworks,  # Currently global in tech scan, but mapping for correlation
                "servers": servers,
                "cloud": cloud,
                "security": security
            }
            
    # Associate interesting endpoints with subdomains
    for url in interesting_endpoints:
        subdomain = get_subdomain(url)
        if subdomain:
            if subdomain not in profiles:
                profiles[subdomain] = {
                    "subdomain": subdomain,
                    "alive": False,
                    "endpoints": [],
                    "secrets": [],
                    "frameworks": frameworks,
                    "servers": servers,
                    "cloud": cloud,
                    "security": security
                }
            profiles[subdomain]["endpoints"].append(url)
            
    # Associate extracted secrets with subdomains
    # js_secrets format: { "filename": [ { "type": "aws", "match": "AKIA...", "entropy": 3.8 } ] }
    # To map filename back to subdomain, we can match filenames or check JS URLs
    js_urls = load_lines(f"{target_dir}/endpoints/js_files.txt")
    
    # Create mapping: filename -> subdomain
    filename_to_subdomain = {}
    for url in js_urls:
        subdomain = get_subdomain(url)
        filename = os.path.basename(url)
        if subdomain and filename:
            filename_to_subdomain[filename] = subdomain
            
    for filename, findings in js_secrets.items():
        subdomain = filename_to_subdomain.get(filename)
        # Fallback: check if the target base domain is the owner if filename is unmapped
        if not subdomain:
            subdomain = target
            
        if subdomain not in profiles:
            profiles[subdomain] = {
                "subdomain": subdomain,
                "alive": False,
                "endpoints": [],
                "secrets": [],
                "frameworks": frameworks,
                "servers": servers,
                "cloud": cloud,
                "security": security
            }
        profiles[subdomain]["secrets"].extend(findings)

    # 3. Apply correlation and scoring logic
    threat_chains = []
    
    for subdomain, prof in profiles.items():
        endpoints = prof["endpoints"]
        secrets = prof["secrets"]
        fws = prof["frameworks"]
        
        score = 0
        severity = "INFO"
        reason = "Subdomain active with no specific vulnerabilities."
        chain = []
        
        # Threat evaluation rules
        has_secrets = len(secrets) > 0
        has_sensitive_endpoints = any(
            any(k in ep.lower() for k in ["/admin", "/debug", "/env", "/config", "/backup"])
            for ep in endpoints
        )
        has_api_endpoints = any(
            any(k in ep.lower() for k in ["/api", "/v1", "/v2", "/graphql", "/swagger"])
            for ep in endpoints
        )
        
        # Rule 1: CRITICAL Chain (Secrets + Sensitive Endpoints)
        if has_secrets and has_sensitive_endpoints:
            severity = "CRITICAL"
            reason = "Subdomain leaks high-entropy secrets and exposes administrative/debug endpoints."
            score = 10
            chain = ["Exposed JS Secrets", "Exposed Admin/Debug Routes"]
            
        # Rule 2: HIGH Chain (Secrets only or Admin routes + Framework stack)
        elif has_secrets:
            severity = "HIGH"
            reason = "Subdomain exposes cryptographic credentials or access tokens in JavaScript files."
            score = 8
            chain = ["Exposed JS Secrets"]
        elif has_sensitive_endpoints and fws:
            severity = "HIGH"
            reason = f"Subdomain exposes admin/debug routes running web framework stack ({', '.join(fws)})."
            score = 7
            chain = ["Web Framework Stack", "Exposed Admin/Debug Routes"]
            
        # Rule 3: MEDIUM Chain (API routes + Framework stack)
        elif has_api_endpoints and fws:
            severity = "MEDIUM"
            reason = f"Active API routes running web framework stack ({', '.join(fws)})."
            score = 5
            chain = ["Web Framework Stack", "Exposed API Endpoints"]
        elif has_api_endpoints:
            severity = "MEDIUM"
            reason = "Exposed REST or GraphQL API endpoints detected."
            score = 4
            chain = ["Exposed API Endpoints"]
            
        # Rule 4: LOW Chain (Generic active endpoint)
        elif len(endpoints) > 0:
            severity = "LOW"
            reason = "Exposed endpoints detected with normal priority."
            score = 2
            chain = ["Exposed Endpoints"]
            
        threat_chains.append({
            "subdomain": subdomain,
            "severity": severity,
            "score": score,
            "reason": reason,
            "chain": chain,
            "endpoints_count": len(endpoints),
            "secrets_count": len(secrets),
            "profile": {
                "frameworks": fws,
                "servers": prof["servers"],
                "cloud": prof["cloud"]
            }
        })
        
    # Sort threat chains by score in descending order
    threat_chains.sort(key=lambda x: x["score"], reverse=True)
    
    # 4. Save results
    output_dir = f"{target_dir}/findings"
    os.makedirs(output_dir, exist_ok=True)
    
    output_file = f"{output_dir}/correlated_threats.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(threat_chains, f, indent=4)
        
    log(f"[SUCCESS] Threat Correlation Engine complete. Synthesized {len(threat_chains)} subdomain profiles. Results saved to findings/correlated_threats.json")
