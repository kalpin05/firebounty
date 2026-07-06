"""
FireBounty v2 - Local JavaScript Secret Extractor
"""

import os
import json
import math
import re
from collections import Counter
from core.js.regex_patterns import PATTERNS
from utils.logger import log

def calculate_shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon Entropy of a string to measure its randomness.
    Higher entropy indicates a higher probability of being a secret.
    """
    if not data:
        return 0.0
    
    frequencies = Counter(data)
    length = len(data)
    
    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
        
    return round(entropy, 2)


def scan_content(content: str) -> list:
    """
    Scans a block of text for potential secrets using regex patterns and Shannon Entropy.
    Returns a list of dictionaries with matching details.
    """
    findings = []
    
    for name, pattern in PATTERNS.items():
        # Skip generic non-secret patterns in this scan to avoid noise (e.g., plain URLs)
        if name in ["url", "api_path", "swagger", "graphql", "firebase"]:
            continue
            
        matches = pattern.findall(content)
        for match in set(matches):
            # If regex match is a tuple (caused by group captures in regex), extract the main part
            match_str = match
            if isinstance(match, tuple):
                # Take the longest non-empty group
                match_str = max(match, key=len)
            
            match_str = match_str.strip(" '\"()[]{}")
            if len(match_str) < 8:
                continue
                
            entropy = calculate_shannon_entropy(match_str)
            
            # Apply an entropy filter (secrets usually have entropy > 3.0)
            if entropy > 3.0:
                findings.append({
                    "type": name,
                    "match": match_str,
                    "entropy": entropy
                })
                
    return findings


def scan_local_file(filepath: str) -> list:
    """
    Reads a local file and scans its content.
    """
    if not os.path.exists(filepath):
        return []
        
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return scan_content(content)
    except Exception as e:
        log(f"[JS Secrets] Error reading {filepath}: {e}")
        return []


def run(target: str) -> None:
    """
    Scans downloaded JavaScript files inside target's directory.
    """
    log(f"[*] Running local JavaScript Secret Hunter on {target}")
    
    # We look for JS files in the outputs directory recursively
    target_dir = f"outputs/{target}"
    if not os.path.exists(target_dir):
        log(f"[!] Target directory {target_dir} does not exist. Skipping.")
        return
        
    js_files = []
    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith((".js", ".mjs")):
                js_files.append(os.path.join(root, file))
                
    if not js_files:
        log(f"[*] No local JS files found in {target_dir} to scan.")
        return
        
    log(f"[*] Found {len(js_files)} JS files. Scanning for secrets...")
    
    results = {}
    total_findings = 0
    
    for filepath in js_files:
        filename = os.path.basename(filepath)
        findings = scan_local_file(filepath)
        if findings:
            results[filename] = findings
            total_findings += len(findings)
            log(f"[+] {filename}: Found {len(findings)} potential secrets")
            
    # Save the output
    output_dir = f"{target_dir}/javascript"
    os.makedirs(output_dir, exist_ok=True)
    
    with open(f"{output_dir}/secrets_extracted.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
        
    log(f"[✓] JS Secret Hunter complete. Extracted {total_findings} secrets saved to javascript/secrets_extracted.json")