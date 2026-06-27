
"""
FireBounty v2 - Stable Recon Engine (Sprint 2.5)
Drop-in replacement for core/recon_engine.py
"""

import os
import json
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

TIMEOUT = 120

TOOLS = {
    "subfinder": ["subfinder","-silent","-d","{domain}"],
    "assetfinder": ["assetfinder","--subs-only","{domain}"],
    "amass": ["amass","enum","-passive","-d","{domain}"],
    "httpx": ["httpx","-silent","-l","{input}","-o","{output}"],
    "naabu": ["naabu","-silent","-list","{input}","-o","{output}"]
}


def resolve_tool(name):
    for c in (
        shutil.which(name),
        os.path.expanduser(f"~/go/bin/{name}"),
        f"/root/go/bin/{name}",
    ):
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
        return r.returncode == 0, r.stdout
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout: {' '.join(cmd)}")
    except Exception as e:
        print(f"[!] Command error: {e}")
    return False, ""


def save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for x in sorted(set(filter(None, map(str.strip, data)))):
            f.write(x + "\n")


def fetch_crtsh(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(
            url,
            timeout=20,
            headers={"User-Agent":"FireBounty/2.0"}
        )
        if r.status_code != 200:
            return []
        if "json" not in r.headers.get("Content-Type",""):
            return []
        data = r.json()
        out = []
        for row in data:
            for s in row.get("name_value","").splitlines():
                s = s.strip()
                if s:
                    out.append(s)
        return out
    except Exception:
        return []


def recon_source(tool, domain):
    exe = resolve_tool(tool)
    ok, out = run_cmd(
        [x.format(domain=domain) for x in TOOLS[tool]]
        if exe == tool else
        [exe] + [x.format(domain=domain) for x in TOOLS[tool][1:]]
    )
    return out.splitlines() if ok else []


def run(domain):
    base = os.path.join("outputs", domain, "recon")
    os.makedirs(base, exist_ok=True)

    futures = {}
    results = {}

    print("[*] Starting Recon")

    with ThreadPoolExecutor(max_workers=4) as ex:
        for t in ("subfinder","assetfinder","amass"):
            futures[ex.submit(recon_source,t,domain)] = t
        futures[ex.submit(fetch_crtsh,domain)] = "crtsh"

        for f in as_completed(futures):
            name = futures[f]
            try:
                results[name] = f.result()
                save(os.path.join(base,f"{name}.txt"), results[name])
                print(f"[+] {name}: {len(results[name])}")
            except Exception as e:
                print(f"[!] {name}: {e}")
                results[name] = []

    subs = set()
    for v in results.values():
        subs.update(v)

    save(os.path.join(base,"all_subdomains.txt"), subs)

    all_file = os.path.join(base,"all_subdomains.txt")
    alive = os.path.join(base,"alive.txt")
    ports = os.path.join(base,"ports.txt")

    httpx = resolve_tool("httpx")
    if os.path.exists(all_file):
        run_cmd([httpx,"-silent","-l",all_file,"-o",alive],180)

    naabu = resolve_tool("naabu")
    if os.path.exists(alive) and os.path.getsize(alive):
        run_cmd([naabu,"-silent","-list",alive,"-o",ports],180)

    summary = {
        "subdomains": sum(1 for _ in open(all_file,encoding="utf-8")) if os.path.exists(all_file) else 0,
        "alive": sum(1 for _ in open(alive,encoding="utf-8")) if os.path.exists(alive) else 0,
        "ports": sum(1 for _ in open(ports,encoding="utf-8")) if os.path.exists(ports) else 0
    }

    with open(os.path.join(base,"summary.json"),"w") as f:
        json.dump(summary,f,indent=2)

    print(f"[+] Total Subdomains : {summary['subdomains']}")
    print(f"[+] Alive Hosts      : {summary['alive']}")
    print(f"[+] Open Ports       : {summary['ports']}")
    print("[✓] Recon Finished")
