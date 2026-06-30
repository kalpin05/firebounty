"""
FireBounty v2 - API Profiler Engine
Discovers and profiles REST, SOAP, GraphQL, and Swagger/OpenAPI endpoints.
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

SCHEMA_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/api-docs",
    "/api/docs",
    "/swagger-ui.html",
    "/swagger/index.html"
]

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql"
]

SOAP_PATHS = [
    "?wsdl",
    "/service.asmx?wsdl",
    "/soap?wsdl"
]

VERSION_PATTERNS = ["/v1/", "/v2/", "/v3/", "/api/v1/", "/api/v2/"]

class APIProfiler:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "FireBounty/2.0 (API Profiler)",
            "Content-Type": "application/json"
        })

    def check_graphql_introspection(self, url: str) -> bool:
        """
        Send a GraphQL introspection query to verify if introspection is enabled.
        """
        probe_query = {"query": "query { __schema { queryType { name } } }"}
        try:
            r = self.session.post(url, json=probe_query, timeout=self.timeout, verify=False)
            if r.status_code == 200 and "__schema" in r.text:
                return True
        except Exception:
            pass
        return False

    def profile_url(self, url: str) -> dict:
        """
        Audit a single URL for schemas, GraphQL, SOAP, and versioned paths.
        """
        result = {
            "url": url,
            "schemas": [],
            "graphql_endpoints": [],
            "soap_endpoints": [],
            "versioning_found": []
        }
        
        base_url = url.rstrip("/")
        
        # 1. Probing Swagger/OpenAPI Schemas
        for path in SCHEMA_PATHS:
            test_url = base_url + path
            try:
                r = requests.get(test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                if r.status_code == 200 and ("swagger" in r.text.lower() or "openapi" in r.text.lower() or "paths" in r.text.lower()):
                    result["schemas"].append(test_url)
            except Exception:
                pass
                
        # 2. Probing GraphQL Endpoints
        for path in GRAPHQL_PATHS:
            test_url = base_url + path
            try:
                r = requests.get(test_url, timeout=self.timeout, verify=False)
                # GraphQL endpoints often return 400 (Bad Request) or 405 (Method Not Allowed) for GET, but they exist
                if r.status_code in [200, 400, 415, 405] or "graphql" in r.text.lower():
                    introspection_enabled = self.check_graphql_introspection(test_url)
                    result["graphql_endpoints"].append({
                        "url": test_url,
                        "introspection": introspection_enabled
                    })
            except Exception:
                pass
                
        # 3. Probing SOAP/WSDL Endpoints
        for path in SOAP_PATHS:
            test_url = base_url + path
            try:
                r = requests.get(test_url, timeout=self.timeout, verify=False)
                if r.status_code == 200 and ("wsdl" in r.text.lower() or "definitions" in r.text.lower()):
                    result["soap_endpoints"].append(test_url)
            except Exception:
                pass
                
        # 4. Checking versioning signatures in path or standard checks
        for pattern in VERSION_PATTERNS:
            test_url = base_url + pattern
            try:
                r = requests.get(test_url, timeout=self.timeout, verify=False)
                if r.status_code in [200, 401, 403]:
                    result["versioning_found"].append(pattern)
            except Exception:
                pass
                
        return result

def save_api_results(domain: str, results_list: list) -> None:
    """
    Format and save API profiling logs to disk.
    """
    output_dir = f"outputs/{domain}/api"
    os.makedirs(output_dir, exist_ok=True)
    
    unique_schemas = set()
    unique_graphql = set()
    unique_soap = set()
    unique_versions = set()
    
    for res in results_list:
        for schema in res["schemas"]:
            unique_schemas.add(schema)
        for gql in res["graphql_endpoints"]:
            intro = " (Introspection Enabled)" if gql["introspection"] else " (Introspection Disabled)"
            unique_graphql.add(gql["url"] + intro)
        for soap in res["soap_endpoints"]:
            unique_soap.add(soap)
        for v in res["versioning_found"]:
            unique_versions.add(f"{v} mapped on {res['url']}")
            
    # 1. Save spec_schemas.txt
    spec_path = os.path.join(output_dir, "spec_schemas.txt")
    with open(spec_path, "w", encoding="utf-8") as f:
        f.write("=== Discovered API Specifications / Schema Files ===\n\n")
        if unique_schemas:
            for s in sorted(list(unique_schemas)):
                f.write(s + "\n")
        else:
            f.write("No Swagger/OpenAPI schemas discovered.\n")
            
    # 2. Save graphql_status.txt
    graphql_path = os.path.join(output_dir, "graphql_status.txt")
    with open(graphql_path, "w", encoding="utf-8") as f:
        f.write("=== GraphQL Endpoints ===\n\n")
        if unique_graphql:
            for g in sorted(list(unique_graphql)):
                f.write(g + "\n")
        else:
            f.write("No GraphQL endpoints discovered.\n")
            
    # 3. Save api_endpoints.txt
    endpoints_path = os.path.join(output_dir, "api_endpoints.txt")
    with open(endpoints_path, "w", encoding="utf-8") as f:
        f.write("=== Discovered API Version paths / SOAP Endpoints ===\n\n")
        f.write("API Versions Map:\n")
        for v in sorted(list(unique_versions)):
            f.write(f"  - {v}\n")
        f.write("\nSOAP WSDL Endpoints:\n")
        for s in sorted(list(unique_soap)):
            f.write(f"  - {s}\n")
            
    # 4. Save api.json summary map
    json_path = os.path.join(output_dir, "api.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "summary": {
                "schemas_found": len(unique_schemas),
                "graphql_endpoints_found": len(unique_graphql),
                "soap_endpoints_found": len(unique_soap),
                "version_patterns_mapped": len(unique_versions)
            },
            "details": results_list
        }, f, indent=4)
        
    log(f"[✓] Saved API profiles for {domain} inside api/")

def run(target: str) -> list:
    """
    Run API profiling pipeline.
    """
    log("[*] Initializing API Intelligence Engine")
    
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
        
    log(f"[*] Probing {len(urls)} hosts for API specs and schema listings...")
    
    profiler = APIProfiler()
    results_list = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(profiler.profile_url, url): url for url in urls}
        for future in as_completed(futures):
            res = future.result()
            results_list.append(res)
            
            # Immediate logs
            if res["schemas"]:
                log(Fore.GREEN + f"[+] {res['url']}: Found API schema(s) -> {', '.join(res['schemas'])}")
            for gql in res["graphql_endpoints"]:
                alert = f"[+] {gql['url']}: GraphQL Endpoint found"
                if gql["introspection"]:
                    alert += " (INTROSPECTION ENABLED!)"
                    print(Fore.RED + alert)
                else:
                    print(Fore.YELLOW + alert)
                    
    save_api_results(domain, results_list)
    log("[✓] API profiling completed successfully")
    return results_list
