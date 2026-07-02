"""
FireBounty v2 - Stable Recon Engine (Sprint 2.6)
Orchestrates passive/active subdomain aggregation and validation.
"""

import os
import json
import shutil
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from utils.logger import log

TIMEOUT = 45

TOOLS = {

    "subfinder": ["subfinder", "-silent", "-d", "{domain}"],
    "assetfinder": ["assetfinder", "--subs-only", "{domain}"],
    "amass": ["amass", "enum", "-passive", "-d", "{domain}"],
    "findomain": ["findomain", "-t", "{domain}", "-q"],
    "chaos": ["chaos", "-d", "{domain}", "-silent"],
    "dnsx": ["dnsx", "-silent", "-l", "{input}", "-o", "{output}"],
    "httpx": ["httpx", "-silent", "-l", "{input}", "-o", "{output}"],
    "naabu": ["naabu", "-silent", "-list", "{input}", "-o", "{output}"]
}

def resolve_tool(name):
    candidates = []
    if name == "httpx":
        toolkit = shutil.which("httpx-toolkit")
        if toolkit:
            candidates.append(toolkit)
            
    candidates.extend([
        os.path.expanduser(f"~/go/bin/{name}"),
        f"/root/go/bin/{name}",
        shutil.which(name)
    ])
    
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return name


def run_cmd(cmd, timeout=TIMEOUT):
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if r.returncode != 0:
            log(f"[!] Command failed (code {r.returncode}): {' '.join(cmd)}")
            if r.stderr:
                log(f"[!] Stderr: {r.stderr.strip()}")
        return r.returncode == 0, r.stdout
    except subprocess.TimeoutExpired:
        log(f"[!] Timeout: {' '.join(cmd)}")
    except Exception as e:
        log(f"[!] Command error: {e}")
    return False, ""


def save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for x in sorted(set(filter(None, map(str.strip, data)))):
            f.write(x + "\n")

# --- Programmatic API Passive Sources ---

def fetch_crtsh(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": "FireBounty/2.0"})
        if r.status_code != 200 or "json" not in r.headers.get("Content-Type", ""):
            return []
        data = r.json()
        out = []
        for row in data:
            for s in row.get("name_value", "").splitlines():
                s = s.strip()
                if s:
                    out.append(s)
        return out
    except Exception:
        return []

def fetch_alienvault(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": "FireBounty/2.0"})
        if r.status_code != 200:
            return []
        data = r.json()
        out = []
        for record in data.get("passive_dns", []):
            hostname = record.get("hostname", "").strip()
            if hostname and domain in hostname:
                out.append(hostname)
        return out
    except Exception:
        return []

def fetch_hackertarget(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": "FireBounty/2.0"})
        if r.status_code != 200:
            return []
        out = []
        for line in r.text.splitlines():
            parts = line.split(",")
            if parts:
                host = parts[0].strip()
                if host and domain in host:
                    out.append(host)
        return out
    except Exception:
        return []

def fetch_rapiddns(domain):
    url = f"https://rapiddns.io/subdomain/{domain}#result"
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": "FireBounty/2.0"})
        if r.status_code != 200:
            return []
        # Match <th scope="row">number</th><td>subdomain.domain.com</td>
        pattern = re.compile(rf'<td>([^<]+\.{re.escape(domain)})</td>')
        return pattern.findall(r.text)
    except Exception:
        return []

def recon_source(tool, domain):
    exe = resolve_tool(tool)
    # Check if CLI tool exists. If not, do not run command.
    if exe == tool and not shutil.which(tool):
        return []
    cmd_template = TOOLS.get(tool)
    if not cmd_template:
        return []
        
    cmd = [x.format(domain=domain) for x in cmd_template]
    if exe != tool:
        cmd = [exe] + cmd[1:]
        
    ok, out = run_cmd(cmd)
    return out.splitlines() if ok else []

def run(domain):
    base = os.path.join("outputs", domain, "recon")
    os.makedirs(base, exist_ok=True)

    futures = {}
    results = {}

    log("[*] Starting Enhanced Subdomain Recon (Sprint 2.6)")

    # Execute passive discovery sources in parallel threads
    with ThreadPoolExecutor(max_workers=6) as ex:
        # CLI tools
        for t in ("subfinder", "assetfinder", "amass", "findomain", "chaos"):
            futures[ex.submit(recon_source, t, domain)] = t
        # Programmatic web APIs
        futures[ex.submit(fetch_crtsh, domain)] = "crtsh"
        futures[ex.submit(fetch_alienvault, domain)] = "alienvault"
        futures[ex.submit(fetch_hackertarget, domain)] = "hackertarget"
        futures[ex.submit(fetch_rapiddns, domain)] = "rapiddns"

        for f in as_completed(futures):
            name = futures[f]
            try:
                res = f.result()
                results[name] = res
                if res:
                    save(os.path.join(base, f"{name}.txt"), res)
                    log(f"[+] {name}: Found {len(res)} subdomains")
            except Exception as e:
                log(f"[!] Passive source {name} error: {e}")
                results[name] = []

    # Merge all subdomains
    subs = set()
    for v in results.values():
        subs.update(v)
    
    # Ensure the root target domain itself is always in the subdomain target set
    subs.add(domain)

    all_file = os.path.join(base, "all_subdomains.txt")
    save(all_file, subs)
    log(f"[+] Total Unique Subdomains gathered: {len(subs)}")


    # Setup file paths
    resolved_file = os.path.join(base, "resolved_subdomains.txt")
    alive_file = os.path.join(base, "alive.txt")
    ports_file = os.path.join(base, "ports.txt")

    # Gate 1: Active DNS Resolution via DNSX
    dnsx = resolve_tool("dnsx")
    if os.path.exists(all_file) and os.path.getsize(all_file) > 0:
        if shutil.which("dnsx") or dnsx != "dnsx":
            log("[*] Actively resolving subdomains via dnsx...")
            run_cmd([dnsx, "-silent", "-l", all_file, "-o", resolved_file], 180)
        else:
            # Fallback to copying all if dnsx is missing
            log("[!] dnsx missing: Skipping active resolution fallback to using all passive domains")
            shutil.copyfile(all_file, resolved_file)

    # Gate 2: Probing alive web hosts via HTTPX
    httpx = resolve_tool("httpx")
    input_resolved = resolved_file if os.path.exists(resolved_file) and os.path.getsize(resolved_file) > 0 else all_file
    
    if os.path.exists(input_resolved) and os.path.getsize(input_resolved) > 0:
        log("[*] Checking for alive HTTP/S hosts via httpx...")
        run_cmd([httpx, "-silent", "-l", input_resolved, "-o", alive_file], 180)

    # Gate 3: Port scanning via Naabu
    naabu = resolve_tool("naabu")
    if os.path.exists(alive_file) and os.path.getsize(alive_file) > 0:
        log("[*] Scanning open ports on alive hosts via naabu...")
        run_cmd([naabu, "-silent", "-list", alive_file, "-o", ports_file], 180)

    # Save summary representation
    summary = {
        "subdomains": sum(1 for _ in open(all_file, encoding="utf-8")) if os.path.exists(all_file) else 0,
        "resolved": sum(1 for _ in open(resolved_file, encoding="utf-8")) if os.path.exists(resolved_file) else 0,
        "alive": sum(1 for _ in open(alive_file, encoding="utf-8")) if os.path.exists(alive_file) else 0,
        "ports": sum(1 for _ in open(ports_file, encoding="utf-8")) if os.path.exists(ports_file) else 0
    }

    with open(os.path.join(base, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    log(f"[+] Summary: Unique Subdomains: {summary['subdomains']} | Resolved: {summary['resolved']} | Alive: {summary['alive']} | Ports: {summary['ports']}")
    log("[✓] Recon Enhancement Completed")
