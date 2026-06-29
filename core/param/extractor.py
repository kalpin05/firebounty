"""
FireBounty v2 - Parameter Extraction Engine
Harvests parameters from endpoint URLs, crawling logs, and JS files.
"""

import os
import urllib.parse
from utils.logger import log

def extract_get_params(urls: list) -> dict:
    """
    Parse GET parameters from a list of URLs.
    Returns a dict mapping param names to a set of URLs they were found on.
    """
    param_map = {}
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
            queries = urllib.parse.parse_qs(parsed.query)
            for param in queries.keys():
                param_clean = param.strip()
                if param_clean:
                    if param_clean not in param_map:
                        param_map[param_clean] = set()
                    param_map[param_clean].add(url)
        except Exception:
            pass
    return param_map

def extract_js_params(js_endpoints_path: str) -> list:
    """
    Extract potential parameters from static JS endpoint findings.
    """
    params = []
    if not os.path.exists(js_endpoints_path):
        return params
        
    try:
        with open(js_endpoints_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                # If the line contains query parameters
                if "?" in line:
                    parsed = urllib.parse.urlparse(line)
                    queries = urllib.parse.parse_qs(parsed.query)
                    params.extend(queries.keys())
    except Exception:
        pass
    return list(set(params))

def run_extraction(domain: str) -> dict:
    """
    Run parameter extraction across all discovery files for a domain.
    """
    endpoints_file = f"outputs/{domain}/endpoints/all_endpoints.txt"
    js_endpoints_file = f"outputs/{domain}/javascript/endpoints.txt"
    
    urls = []
    if os.path.exists(endpoints_file):
        try:
            with open(endpoints_file, "r", encoding="utf-8", errors="ignore") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            log(f"[!] Error reading endpoints: {e}")
            
    get_param_map = extract_get_params(urls)
    js_params = extract_js_params(js_endpoints_file)
    
    # Merge JS params into query params map with a placeholder origin if not present
    for p in js_params:
        if p not in get_param_map:
            get_param_map[p] = {"Discovered in JS files"}
            
    return get_param_map
