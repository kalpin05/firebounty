import os
import json
import urllib.parse
import requests
from colorama import Fore, init

from core.param.extractor import run_extraction
from core.param.classifier import classify_param
from utils.logger import log

init(autoreset=True)

def run(target: str) -> None:
    """
    Wrapper to execute Parameter Intelligence analysis.
    """
    log("[*] Starting Parameter Discovery and Classification")
    
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]
        
    output_dir = f"outputs/{domain}/parameters"
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Run parameter extraction from endpoints, JS and history
    extracted_params = run_extraction(domain)
    
    # 2. Classify parameters into GET, POST, GraphQL, Multipart
    classified = {
        "GET": [],
        "POST/JSON": [],
        "GraphQL": [],
        "Multipart": []
    }
    
    json_summary = {}
    for name, urls in extracted_params.items():
        category = classify_param(name)
        classified[category].append(name)
        json_summary[name] = {
            "type": category,
            "origins": sorted(list(urls))
        }
        
    # Write categorized text files
    for cat, items in classified.items():
        cat_file = cat.lower().replace("/", "_")
        path = os.path.join(output_dir, f"params_{cat_file}.txt")
        with open(path, "w", encoding="utf-8") as f:
            for item in sorted(items):
                f.write(item + "\n")
                
    # Write JSON summary map
    json_path = os.path.join(output_dir, "parameters.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "metrics": {
                "total_unique": len(extracted_params),
                "get_count": len(classified["GET"]),
                "post_count": len(classified["POST/JSON"]),
                "graphql_count": len(classified["GraphQL"]),
                "multipart_count": len(classified["Multipart"])
            },
            "parameters": json_summary
        }, f, indent=4)
        
    log(f"[✓] Discovered {len(extracted_params)} unique parameters across endpoints.")
    log(f"[✓] Saved parameters profiles to outputs/{domain}/parameters/")

    # 3. Active validation checks (from the original module implementation)
    active_test_params = list(extracted_params.keys())[:15]
    if not active_test_params:
        active_test_params = [
            "id", "user", "account", "email", "token",
            "debug", "admin", "test", "role", "uid"
        ]
        
    log(f"[*] Running active validation on top {len(active_test_params)} parameters...")
    try:
        base = requests.get(target, timeout=5)
        base_len = len(base.text)
        
        for p in active_test_params:
            url = f"{target}?{p}=1"
            try:
                r = requests.get(url, timeout=5)
                if len(r.text) != base_len:
                    print(Fore.YELLOW + f"[~] Active match: {url} (response length diff)")
                elif r.status_code != base.status_code:
                    print(Fore.RED + f"[🔥] Active match: {url} -> {r.status_code}")
            except Exception:
                pass
    except Exception as e:
        log(f"[!] Active parameter validation skipped: target unreachable ({e})")