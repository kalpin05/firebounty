"""
FireBounty v2 - Parameter Discovery & Intelligence
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


def clean_param_name(param: str) -> str:
    """
    Cleans parameter name and returns stripped lowercase.
    """
    return param.strip().lower()


def is_valid_param(param: str) -> bool:
    """
    Filters out tracking parameters and extreme noise.
    """
    if not param:
        return False
        
    # Check length
    if len(param) > 40:
        return False
        
    # Ignore tracking, analytics, and session noise
    ignored_prefixes = ["utm_", "_ga", "_gi", "fbclid", "gclid", "amp_"]
    for prefix in ignored_prefixes:
        if param.startswith(prefix):
            return False
            
    # Check alphanumeric with hyphens/underscores only
    # (Removes junk parameters containing symbols)
    clean = param.replace("_", "").replace("-", "")
    if not clean.isalnum():
        return False
        
    return True


from utils.helpers import sanitize_target

def run(target: str) -> None:
    """
    Reads crawled endpoints for the target and extracts unique query parameters.
    """
    log(f"[*] Running Parameter Intelligence on {target}")
    
    domain, _ = sanitize_target(target)

    target_dir = f"outputs/{domain}"
    endpoints_file = f"{target_dir}/endpoints/all_endpoints.txt"
    
    if not os.path.exists(endpoints_file):
        log(f"[!] Crawl endpoints file {endpoints_file} not found. Skipping parameter extraction.")
        return
        
    try:
        with open(endpoints_file, "r", encoding="utf-8", errors="ignore") as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        log(f"[!] Error reading endpoints file: {e}")
        return
        
    log(f"[*] Parsing {len(urls)} URLs to extract parameters...")
    
    subdomain_params = {}
    all_unique_params = set()
    
    for url in urls:
        subdomain = get_subdomain(url)
        if not subdomain:
            continue
            
        try:
            parsed = urllib.parse.urlparse(url)
            query = parsed.query
            if not query:
                continue
                
            params = urllib.parse.parse_qs(query)
            for raw_key in params.keys():
                key = clean_param_name(raw_key)
                if is_valid_param(key):
                    all_unique_params.add(key)
                    
                    if subdomain not in subdomain_params:
                        subdomain_params[subdomain] = set()
                    subdomain_params[subdomain].add(key)
        except:
            continue
            
    # Convert sets to sorted lists for JSON serialization
    serializable_map = {sub: sorted(list(keys)) for sub, keys in subdomain_params.items()}
    sorted_wordlist = sorted(list(all_unique_params))
    
    # Save files
    output_dir = f"{target_dir}/parameters"
    os.makedirs(output_dir, exist_ok=True)
    
    # Save mapping
    map_file = f"{output_dir}/parameters.json"
    with open(map_file, "w", encoding="utf-8") as f:
        json.dump(serializable_map, f, indent=4)
        
    # Save flat list
    list_file = f"{output_dir}/params_wordlist.txt"
    with open(list_file, "w", encoding="utf-8") as f:
        for param in sorted_wordlist:
            f.write(f"{param}\n")
            
    log(f"[SUCCESS] Parameter Intelligence completed. Extracted {len(sorted_wordlist)} unique parameters.")
    log(f"[*] Map saved to parameters/parameters.json")
    log(f"[*] Wordlist saved to parameters/params_wordlist.txt")
