"""
FireBounty v2 - Broken Link Hijacking Engine
"""

import os
import re
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import log
from utils.notifier import send_alert
from utils.reporter import save

# Regex patterns for identifying outgoing social profiles
SOCIAL_PATTERNS = {
    "twitter": re.compile(r"https?://(?:www\.)?(?:twitter|x)\.com/([A-Za-z0-9_]{1,15})(?![A-Za-z0-9_])", re.IGNORECASE),
    "github": re.compile(r"https?://(?:www\.)?github\.com/([A-Za-z0-9_-]+)(?![A-Za-z0-9_-])", re.IGNORECASE),
    "instagram": re.compile(r"https?://(?:www\.)?instagram\.com/([A-Za-z0-9_.]+)(?![A-Za-z0-9_.])", re.IGNORECASE),
    "youtube": re.compile(r"https?://(?:www\.)?youtube\.com/(?:channel/|user/|c/|@)([A-Za-z0-9_-]+)", re.IGNORECASE),
    "medium": re.compile(r"https?://(?:www\.)?medium\.com/@([A-Za-z0-9_]+)", re.IGNORECASE)
}

# Ignore common static system usernames that aren't claimable
EXCLUDED_USERNAMES = {
    "about", "help", "terms", "privacy", "features", "explore", "blog", "jobs", "support", 
    "contact", "security", "settings", "notifications", "search", "messages", "profile"
}

def extract_social_links(html_content: str) -> list:
    """
    Parses HTML content and extracts social media profile links.
    Returns a list of tuples: (platform, username, profile_url)
    """
    found_profiles = []
    for platform, pattern in SOCIAL_PATTERNS.items():
        matches = pattern.findall(html_content)
        for username in matches:
            username = username.strip().lower()
            if username in EXCLUDED_USERNAMES or len(username) < 3:
                continue
            
            # Construct standard profile URL
            if platform == "twitter":
                url = f"https://x.com/{username}"
            elif platform == "github":
                url = f"https://github.com/{username}"
            elif platform == "instagram":
                url = f"https://instagram.com/{username}"
            elif platform == "youtube":
                url = f"https://youtube.com/@{username}"
            elif platform == "medium":
                url = f"https://medium.com/@{username}"
            
            found_profiles.append((platform, username, url))
            
    return list(set(found_profiles))


def check_profile_status(platform: str, username: str, url: str) -> tuple:
    """
    Checks if a social profile page returns a 404 Not Found, indicating it is claimable.
    Returns (url, is_broken)
    """
    try:
        # Send GET request simulating a browser
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        r = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        
        # Twitter handles return 404 or specific text if user doesn't exist
        # GitHub returns 404
        if r.status_code == 404:
            return url, True
            
        # Optional: Add extra string matching (e.g. "This account doesn’t exist")
        if platform == "twitter" and "account doesn" in r.text.lower():
            return url, True
            
    except Exception:
        pass
    return url, False


def scan_url_for_broken_links(target_url: str) -> list:
    """
    Fetches a URL, extracts outgoing social links, and checks them.
    """
    broken_findings = []
    try:
        r = requests.get(target_url, timeout=10, verify=False)
        if r.status_code != 200:
            return broken_findings
            
        profiles = extract_social_links(r.text)
        if not profiles:
            return broken_findings
            
        for platform, username, profile_url in profiles:
            _, is_broken = check_profile_status(platform, username, profile_url)
            if is_broken:
                msg = f"[🔥 BROKEN LINK HIJACKING] {target_url} references defunct/claimable {platform.upper()} handle: {profile_url}"
                log(msg)
                send_alert(msg)
                save("Broken Link Hijacking", target_url)
                broken_findings.append(profile_url)
    except Exception:
        pass
    return broken_findings


def run(target: str) -> None:
    """
    Main entry point for broken link hijacking checks.
    """
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]
    if not domain:
        domain = target

    endpoints_file = f"outputs/{domain}/endpoints/all_endpoints.txt"
    
    if not os.path.exists(endpoints_file):
        log(f"[!] Endpoints file {endpoints_file} not found. Skipping broken link check.")
        return
        
    try:
        with open(endpoints_file, encoding="utf-8", errors="ignore") as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        log(f"[!] Error loading endpoints: {e}")
        return

    # Select target pages (limit to first 30 URLs to keep execution fast and focused)
    scan_targets = urls[:30]
    log(f"[*] Crawling {len(scan_targets)} pages to check for broken outgoing social links...")
    
    broken_count = 0
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(scan_url_for_broken_links, url): url for url in scan_targets}
        for future in as_completed(futures):
            res = future.result()
            broken_count += len(res)
            
    log(f"[✓] Broken link hijacking scan complete. Found {broken_count} broken profile links.")
