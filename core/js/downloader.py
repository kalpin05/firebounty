"""
FireBounty v2 - Asynchronous JS Downloader
Downloads script bundles concurrently from target list.
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from colorama import Fore, init

from core.js.utils import safe_filename, ensure_directory
from utils.logger import log

init(autoreset=True)

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

MAX_JS_SIZE = 5 * 1024 * 1024  # 5MB size limit

def download_file(url: str, output_dir: str, timeout: int = 15) -> str:
    """
    Download a single JS file and return its local file path if successful.
    """
    filename = safe_filename(url)
    dest_path = os.path.join(output_dir, filename)
    
    # Skip if already downloaded
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 0:
        return dest_path
        
    try:
        # Fetch stream to check size header first
        r = requests.get(url, stream=True, timeout=timeout, verify=False)
        if r.status_code != 200:
            return ""
            
        cl = r.headers.get("Content-Length")
        if cl and int(cl) > MAX_JS_SIZE:
            log(f"[!] Skipping {url} (file exceeds 5MB size limit)")
            return ""
            
        content = []
        downloaded = 0
        for chunk in r.iter_content(chunk_size=1024 * 64):
            downloaded += len(chunk)
            if downloaded > MAX_JS_SIZE:
                return ""
            content.append(chunk)
            
        with open(dest_path, "wb") as f:
            f.write(b"".join(content))
            
        return dest_path
    except Exception:
        return ""

def download_all_js(domain: str, js_urls: list) -> dict:
    """
    Concurrently download a list of JS URLs and map them to their local filenames.
    """
    output_dir = f"outputs/{domain}/javascript/js_files"
    ensure_directory(output_dir)
    
    mapped_files = {}
    
    log(f"[*] Downloading {len(js_urls)} JS files concurrently...")
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(download_file, url, output_dir): url for url in js_urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                dest = future.result()
                if dest:
                    mapped_files[url] = dest
            except Exception:
                pass
                
    log(f"[✓] Downloaded {len(mapped_files)}/{len(js_urls)} JS files.")
    return mapped_files
