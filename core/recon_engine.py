import os
import subprocess
import threading
import requests


# ----------------------------------
# Tool Resolver
# ----------------------------------

def get_tool(tool_name):

    candidates = [

        f"{os.path.expanduser('~')}/go/bin/{tool_name}",

        f"/root/go/bin/{tool_name}",

        tool_name

    ]

    for tool in candidates:

        try:

            subprocess.run(
                [tool, "-h"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            return tool

        except:
            pass

    return tool_name


SUBFINDER = get_tool("subfinder")
ASSETFINDER = get_tool("assetfinder")
HTTPX = get_tool("httpx")
NAABU = get_tool("naabu")

# We will temporarily skip Amass if broken
AMASS = get_tool("amass")


# ----------------------------------
# Folder Creation
# ----------------------------------

def create_folders(target):

    base = f"outputs/{target}"

    recon = f"{base}/recon"
    endpoints = f"{base}/endpoints"
    findings = f"{base}/findings"
    reports = f"{base}/reports"

    os.makedirs(recon, exist_ok=True)
    os.makedirs(endpoints, exist_ok=True)
    os.makedirs(findings, exist_ok=True)
    os.makedirs(reports, exist_ok=True)

    return recon


# ----------------------------------
# Save File
# ----------------------------------

def save_file(path, data):

    with open(path, "w") as f:

        for item in sorted(set(data)):

            if item.strip():

                f.write(item.strip() + "\n")


# ----------------------------------
# Subfinder
# ----------------------------------

def run_subfinder(domain, output):

    try:

        result = subprocess.check_output(
            [
                SUBFINDER,
                "-silent",
                "-d",
                domain
            ],
            text=True
        )

        output.extend(result.splitlines())

    except Exception as e:

        print(f"[!] Subfinder error: {e}")


# ----------------------------------
# Amass
# ----------------------------------

def run_amass(domain, output):

    try:

        result = subprocess.check_output(
            [
                AMASS,
                "enum",
                "-passive",
                "-d",
                domain
            ],
            text=True
        )

        output.extend(result.splitlines())

    except Exception:

        print("[!] Amass unavailable - skipping")


# ----------------------------------
# Assetfinder
# ----------------------------------

def run_assetfinder(domain, output):

    try:

        result = subprocess.check_output(
            [
                ASSETFINDER,
                "--subs-only",
                domain
            ],
            text=True
        )

        output.extend(result.splitlines())

    except Exception as e:

        print(f"[!] Assetfinder error: {e}")


# ----------------------------------
# crt.sh
# ----------------------------------

def run_crtsh(domain, output):

    try:

        url = f"https://crt.sh/?q=%.{domain}&output=json"

        r = requests.get(
            url,
            timeout=20
        )

        data = r.json()

        for item in data:

            name = item.get(
                "name_value",
                ""
            )

            for sub in name.split("\n"):

                sub = sub.strip()

                if sub:

                    output.append(sub)

    except Exception as e:

        print(f"[!] crt.sh error: {e}")


# ----------------------------------
# HTTPX
# ----------------------------------

def run_httpx(recon_dir):

    input_file = f"{recon_dir}/all_subdomains.txt"

    output_file = f"{recon_dir}/alive.txt"

    if not os.path.exists(input_file):

        print("[!] all_subdomains.txt missing")

        return

    try:

        subprocess.run(
            [
                HTTPX,
                "-silent",
                "-l",
                input_file,
                "-o",
                output_file
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    except Exception as e:

        print(f"[!] HTTPX error: {e}")


# ----------------------------------
# Naabu
# ----------------------------------

def run_naabu(recon_dir):

    alive_file = f"{recon_dir}/alive.txt"

    output_file = f"{recon_dir}/ports.txt"

    if not os.path.exists(alive_file):

        print("[!] alive.txt missing")

        return

    try:

        subprocess.run(
            [
                NAABU,
                "-silent",
                "-list",
                alive_file,
                "-o",
                output_file
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    except Exception as e:

        print(f"[!] Naabu error: {e}")


# ----------------------------------
# Main
# ----------------------------------

def run(domain):

    print("\n[🔥] FireBounty Recon Engine\n")

    recon_dir = create_folders(domain)

    subfinder_results = []
    amass_results = []
    assetfinder_results = []
    crtsh_results = []

    threads = [

        threading.Thread(
            target=run_subfinder,
            args=(domain, subfinder_results)
        ),

        threading.Thread(
            target=run_amass,
            args=(domain, amass_results)
        ),

        threading.Thread(
            target=run_assetfinder,
            args=(domain, assetfinder_results)
        ),

        threading.Thread(
            target=run_crtsh,
            args=(domain, crtsh_results)
        )

    ]

    print("[*] Starting sources")

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    save_file(
        f"{recon_dir}/subfinder.txt",
        subfinder_results
    )

    save_file(
        f"{recon_dir}/amass.txt",
        amass_results
    )

    save_file(
        f"{recon_dir}/assetfinder.txt",
        assetfinder_results
    )

    save_file(
        f"{recon_dir}/crtsh.txt",
        crtsh_results
    )

    all_subs = set()

    all_subs.update(subfinder_results)
    all_subs.update(amass_results)
    all_subs.update(assetfinder_results)
    all_subs.update(crtsh_results)

    all_subs = {

        x.strip()
        for x in all_subs
        if x.strip()
    }

    save_file(
        f"{recon_dir}/all_subdomains.txt",
        all_subs
    )

    print(f"[+] Unique Subdomains: {len(all_subs)}")

    print("[*] Running HTTPX")

    run_httpx(recon_dir)

    print("[*] Running Naabu")

    run_naabu(recon_dir)

    alive_file = f"{recon_dir}/alive.txt"
    ports_file = f"{recon_dir}/ports.txt"

    alive_count = 0
    ports_count = 0

    if os.path.exists(alive_file):

        with open(alive_file) as f:
            alive_count = len(f.readlines())

    if os.path.exists(ports_file):

        with open(ports_file) as f:
            ports_count = len(f.readlines())

    print(f"[+] Alive Hosts: {alive_count}")
    print(f"[+] Open Ports: {ports_count}")

    print("\n[✓] Recon Complete")
    print(f"[✓] Results -> {recon_dir}")