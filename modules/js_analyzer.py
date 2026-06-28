import os
import urllib.parse
from colorama import Fore, init

from core.js.downloader import download_all_js
from core.js.analyzer import analyze_js_file
from core.js.scorer import calculate_risk, get_risk_label
from core.js.reporter import save_js_report
from utils.logger import log

init(autoreset=True)

def run(target: str) -> None:
    """
    Run JS Intelligence scanning pipeline.
    """
    log("[*] Starting JS Intelligence analysis")
    
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]
        
    js_urls_file = f"outputs/{domain}/endpoints/js_files.txt"
    if not os.path.exists(js_urls_file) or os.path.getsize(js_urls_file) == 0:
        log(f"[!] Skipping JS Intelligence: {js_urls_file} is empty or missing (run endpoints discovery first).")
        return
        
    try:
        with open(js_urls_file, "r", encoding="utf-8", errors="ignore") as f:
            js_urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        log(f"[!] Error loading discovered JS URLs list: {e}")
        return
        
    # 1. Concurrently download all script files
    downloaded_files = download_all_js(domain, js_urls)
    
    # 2. Analyze script files for secrets and paths
    analysis_results = {}
    
    for url, local_path in downloaded_files.items():
        findings = analyze_js_file(local_path)
        
        # Calculate risk metrics
        score = calculate_risk(findings)
        label = get_risk_label(score)
        
        analysis_results[url] = {
            "local_path": local_path,
            "findings": findings,
            "score": score,
            "label": label
        }
        
        # Immediate console alerts for sensitive findings
        if label in ["HIGH", "MEDIUM"]:
            log(Fore.RED + f"[🔥 ALERT] Found {label} risk script bundle: {url} (Score: {score})")
            for cat, matches in findings.items():
                if cat not in ["url", "api_path"]:
                    log(Fore.YELLOW + f"  - [{cat.upper()}]: Matched {len(matches)} signature(s)")
                    
    # 3. Generate structured outputs (txt and JSON)
    save_js_report(domain, analysis_results)
    log("[✓] JS Intelligence analysis completed successfully")