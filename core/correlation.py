"""
FireBounty v2 - Correlation Engine
Correlates findings (secrets, APIs, configs, vulnerabilities) into prioritized attack chains.
"""

import os
import json
import urllib.parse
from colorama import Fore, init
from utils.logger import log

init(autoreset=True)

class CorrelationEngine:
    def __init__(self, domain: str):
        self.domain = domain
        self.base_path = f"outputs/{domain}"
        
        # Load all artifacts
        self.tech_data = self._load_json("technology/technology.json")
        self.js_data = self._load_json("javascript/javascript.json")
        self.param_data = self._load_json("parameters/parameters.json")
        self.auth_data = self._load_json("authentication/authentication.json")
        self.api_data = self._load_json("api/api.json")
        self.vuln_data = self._load_json("findings/vulnerabilities.json")

    def _load_json(self, relative_path: str) -> dict:
        path = os.path.join(self.base_path, relative_path)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def correlate(self) -> list:
        chains = []

        # Chain 1: JavaScript + Tech Stack + Credentials Leaks
        # React/Vue/Frontend + Leaked AWS/Firebase/Stripe/Slack keys
        js_summary = self.js_data.get("summary", {})
        total_secrets = js_summary.get("total_secrets_found", 0)
        
        if total_secrets > 0:
            frontend_libs = []
            if self.tech_data:
                frontend_libs = self.tech_data.get("summary", {}).get("javascript", [])
                
            libs_str = ", ".join(frontend_libs) if frontend_libs else "Frontend Client Script"
            
            # Find which keys were leaked
            leaked_types = set()
            for file_entry in self.js_data.get("files", []):
                for cat in file_entry.get("findings", {}).keys():
                    if cat not in ["url", "api_path"]:
                        leaked_types.add(cat.upper())
                        
            chains.append({
                "title": "Client-Side Secrets Exposure via Frontend Bundle",
                "severity": "High",
                "reasoning": f"Target uses {libs_str} which embeds hardcoded credentials matching: {', '.join(leaked_types)}.",
                "reproduction": "1. Analyze client-side scripts under outputs/javascript/js_files/\n2. Extract keys specified in outputs/javascript/secrets.txt",
                "impact": "Exposed keys can allow unauthorized access to third-party databases, cloud buckets, or payment gateways."
            })

        # Chain 2: Unauthenticated Admin/Internal APIs
        # Match routes with /admin or /private and auth check failures
        admin_routes = []
        if self.api_data:
            for detail in self.api_data.get("details", []):
                for v in detail.get("versioning_found", []):
                    if "admin" in v.lower() or "private" in v.lower() or "internal" in v.lower():
                        admin_routes.append(detail["url"] + v)
                        
        auth_issues_count = 0
        if self.auth_data:
            auth_issues_count = self.auth_data.get("summary", {}).get("cookie_issues_found", 0)
            
        if admin_routes and auth_issues_count > 0:
            chains.append({
                "title": "Unprotected Administrative Endpoints mapped",
                "severity": "High",
                "reasoning": f"Identified versioned admin/internal routes: {', '.join(admin_routes[:3])} while auditing missing cookie security controls.",
                "reproduction": "1. Access versioned internal API paths.\n2. Attempt access without session authentication headers.",
                "impact": "Exposes administrative backend routes to public scanning, potentially leading to privilege escalation."
            })

        # Chain 3: Permissive CORS + CSRF/Information leakage
        # Wildcard CORS origin reflection + sensitive POST parameters
        cors_vulns = []
        if self.vuln_data:
            cors_vulns = [f for f in self.vuln_data.get("findings", []) if f["type"] == "CORS Misconfiguration"]
            
        sensitive_params = []
        if self.param_data:
            for name, p_data in self.param_data.get("parameters", {}).items():
                if p_data.get("type") == "POST/JSON" and any(k in name.lower() for k in ["email", "user", "pass", "token", "session"]):
                    sensitive_params.append(name)
                    
        if cors_vulns and sensitive_params:
            chains.append({
                "title": "Cross-Origin Data Leakage via Permissive CORS",
                "severity": "Medium",
                "reasoning": f"Target reflects permissive CORS header flags, coupled with endpoints utilizing sensitive parameters ({', '.join(sensitive_params[:4])}).",
                "reproduction": "1. Perform cross-origin request passing Origin: https://evil.com\n2. Verify that Access-Control-Allow-Origin reflects origin with Credentials enabled, enabling read of sensitive POST params.",
                "impact": "Enables malicious scripts on external origins to read authenticated response data containing user emails, sessions, or tokens."
            })

        # Chain 4: GraphQL Introspection + SQLi / Fuzzing vulnerabilities
        # Active GraphQL introspection + SQLi/LFI active triggers
        graphql_introspection = False
        if self.api_data:
            for detail in self.api_data.get("details", []):
                for gql in detail.get("graphql_endpoints", []):
                    if gql.get("introspection"):
                        graphql_introspection = True
                        break
                        
        sqli_vulns = []
        if self.vuln_data:
            sqli_vulns = [f for f in self.vuln_data.get("findings", []) if "SQL" in f["type"] or "LFI" in f["type"]]
            
        if graphql_introspection and sqli_vulns:
            chains.append({
                "title": "GraphQL Introspection coupled with Injection vectors",
                "severity": "High",
                "reasoning": "Identified active GraphQL introspection enabling schema mapping, concurrently with injection vulnerability triggers.",
                "reproduction": "1. Query introspection query schema mapping on GraphQL endpoint.\n2. Leverage SQLi/LFI parameters on versioned API endpoints.",
                "impact": "Full database map disclosure combined with remote SQL injection execution pathways."
            })

        # Default Chain: Low severity fallback correlation if nothing specific is found
        if not chains:
            chains.append({
                "title": "Standard Target Surface Profile Map",
                "severity": "Low",
                "reasoning": "No high-priority security correlation chains mapped. Target exhibits standard perimeter hygiene.",
                "reproduction": "Review individual module logs in outputs/.",
                "impact": "Perimeter validation remains within baseline guidelines."
            })

        return chains

def save_correlations(domain: str, chains: list) -> None:
    output_dir = f"outputs/{domain}/findings"
    os.makedirs(output_dir, exist_ok=True)

    # 1. Write attack_paths.txt
    txt_path = os.path.join(output_dir, "attack_paths.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=== Core Correlation Attack Chains ===\n\n")
        for i, c in enumerate(chains, 1):
            f.write(f"{i}. [{c['severity'].upper()}] {c['title']}\n")
            f.write(f"   Reasoning: {c['reasoning']}\n")
            f.write(f"   Reproduction:\n{c['reproduction']}\n")
            f.write(f"   Impact: {c['impact']}\n\n")

    # 2. Write correlations.json
    json_path = os.path.join(output_dir, "correlations.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "metrics": {
                "high_priority_chains": len([x for x in chains if x["severity"] == "High"]),
                "medium_priority_chains": len([x for x in chains if x["severity"] == "Medium"]),
                "low_priority_chains": len([x for x in chains if x["severity"] == "Low"])
            },
            "chains": chains
        }, f, indent=4)

    log(f"[✓] Saved correlation attack paths for {domain} inside findings/")

def run(target: str) -> list:
    """
    Run correlation engine pipeline.
    """
    log("[*] Initializing Attack Chain Correlation Engine")

    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]

    engine = CorrelationEngine(domain)
    chains = engine.correlate()

    for i, c in enumerate(chains, 1):
        color = Fore.RED if c["severity"] == "High" else Fore.YELLOW
        print(color + f"[🔥 PATH {i}] ({c['severity'].upper()}) {c['title']}")
        print(Fore.WHITE + f"   Reason: {c['reasoning']}")

    save_correlations(domain, chains)
    log("[✓] Correlation analysis completed successfully")
    return chains
