"""
FireBounty v2 - JS Findings Reporter
Summarizes and formats findings into normalized logs and JSON summary.
"""

import os
import json
from collections import defaultdict
from utils.logger import log

def save_js_report(domain: str, analysis_results: dict) -> None:
    """
    Format and write all JS analysis findings to secrets.txt, endpoints.txt, and javascript.json.
    
    analysis_results schema:
    {
        url: {
            "local_path": filepath,
            "findings": findings_dict,
            "score": score_int,
            "label": label_str
        }
    }
    """
    output_dir = f"outputs/{domain}/javascript"
    os.makedirs(output_dir, exist_ok=True)
    
    unique_secrets = set()
    unique_endpoints = set()
    
    json_details = []
    
    # Track metrics
    high_count = 0
    medium_count = 0
    low_count = 0
    
    for url, data in analysis_results.items():
        findings = data["findings"]
        score = data["score"]
        label = data["label"]
        
        if label == "HIGH":
            high_count += 1
        elif label == "MEDIUM":
            medium_count += 1
        elif label == "LOW":
            low_count += 1
            
        # Parse endpoints
        endpoints_matches = findings.get("api_path", []) + findings.get("url", [])
        for ep in endpoints_matches:
            unique_endpoints.add(ep)
            
        # Parse secrets
        for cat in ["aws_access_key", "aws_secret", "stripe_live", "github_token", "slack", "jwt", "bearer", "basic_auth", "google_api", "firebase"]:
            for match in findings.get(cat, []):
                unique_secrets.add(f"[{cat.upper()}] {match} (Found in: {url})")
                
        json_details.append({
            "url": url,
            "local_file": os.path.basename(data["local_path"]),
            "risk_score": score,
            "risk_level": label,
            "findings": findings
        })
        
    # 1. Save secrets.txt
    secrets_file = os.path.join(output_dir, "secrets.txt")
    with open(secrets_file, "w", encoding="utf-8") as f:
        f.write("=== Discovered JS Secrets ===\n\n")
        if unique_secrets:
            for secret in sorted(list(unique_secrets)):
                f.write(secret + "\n")
        else:
            f.write("No secrets or tokens discovered.\n")
            
    # 2. Save endpoints.txt
    endpoints_file = os.path.join(output_dir, "endpoints.txt")
    with open(endpoints_file, "w", encoding="utf-8") as f:
        f.write("=== Discovered JS Endpoints ===\n\n")
        if unique_endpoints:
            for ep in sorted(list(unique_endpoints)):
                f.write(ep + "\n")
        else:
            f.write("No endpoints or API paths discovered.\n")
            
    # 3. Save javascript.json summary
    json_summary_file = os.path.join(output_dir, "javascript.json")
    master_summary = {
        "summary": {
            "total_analyzed": len(analysis_results),
            "high_risk_files": high_count,
            "medium_risk_files": medium_count,
            "low_risk_files": low_count,
            "total_secrets_found": len(unique_secrets),
            "total_endpoints_found": len(unique_endpoints)
        },
        "files": json_details
    }
    
    with open(json_summary_file, "w", encoding="utf-8") as f:
        json.dump(master_summary, f, indent=4)
        
    log(f"[✓] JS intelligence reports successfully written to outputs/{domain}/javascript/")
