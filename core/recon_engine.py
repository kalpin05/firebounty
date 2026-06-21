import os
import subprocess
import threading
import requests


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


def save_file(path, data):

    with open(path, "w") as f:

        for item in sorted(set(data)):
            f.write(item + "\n")


# ----------------------------------
# Subfinder
# ----------------------------------

def run_subfinder(domain, output):

    try:

        result = subprocess.check_output(
            [
                "subfinder",
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
                "amass",
                "enum",
                "-passive",
                "-d",
                domain
            ],
            text=True
        )

        output.extend(result.splitlines())

    except Exception as e:

        print(f"[!] Amass error: {e}")


# ----------------------------------
# Assetfinder
# ----------------------------------

def run_assetfinder(domain, output):

    try:

        result = subprocess.check_output(
            [
                "assetfinder",
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

        r = requests.get(url, timeout=30)

        data = r.json()

        for item in data:

            name = item.get("name_value", "")

            for sub in name.split("\n"):

                output.append(sub.strip())

    except Exception as e:

        print(f"[!] crt.sh error: {e}")


# ----------------------------------
# Alive Check
# ----------------------------------

def run_httpx(recon_dir):

    try:

        subprocess.run(
            [
                "httpx",
                "-silent",
                "-l",
                f"{recon_dir}/all_subdomains.txt",
                "-o",
                f"{recon_dir}/alive.txt"
            ]
        )

    except Exception as e:

        print(f"[!] HTTPX error: {e}")


# ----------------------------------
# Port Scan
# ----------------------------------

def run_naabu(recon_dir):

    try:

        subprocess.run(
            [
                "naabu",
                "-silent",
                "-list",
                f"{recon_dir}/alive.txt",
                "-o",
                f"{recon_dir}/ports.txt"
            ]
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

    print(
        f"[+] Unique Subdomains: {len(all_subs)}"
    )

    print("[*] Running HTTPX")

    run_httpx(recon_dir)

    print("[*] Running Naabu")

    run_naabu(recon_dir)

    print("")
    print("[✓] Recon Complete")
    print(f"[✓] Results -> {recon_dir}")