import subprocess
import threading
import requests
import os


OUTPUT_DIR = "outputs/recon"


def save_results(filename, data):

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(f"{OUTPUT_DIR}/{filename}", "w") as f:

        for item in sorted(set(data)):
            f.write(item + "\n")


def run_subfinder(domain, results):

    try:

        output = subprocess.check_output(
            ["subfinder", "-silent", "-d", domain],
            text=True
        )

        results.extend(output.splitlines())

    except Exception as e:

        print(f"[!] Subfinder error: {e}")


def run_amass(domain, results):

    try:

        output = subprocess.check_output(
            ["amass", "enum", "-passive", "-d", domain],
            text=True
        )

        results.extend(output.splitlines())

    except Exception as e:

        print(f"[!] Amass error: {e}")


def run_assetfinder(domain, results):

    try:

        output = subprocess.check_output(
            ["assetfinder", "--subs-only", domain],
            text=True
        )

        results.extend(output.splitlines())

    except Exception as e:

        print(f"[!] Assetfinder error: {e}")


def run_crtsh(domain, results):

    try:

        url = f"https://crt.sh/?q=%.{domain}&output=json"

        r = requests.get(url, timeout=20)

        data = r.json()

        for item in data:

            name = item.get("name_value", "")

            for sub in name.split("\n"):

                results.append(sub.strip())

    except Exception as e:

        print(f"[!] crt.sh error: {e}")


def check_alive():

    try:

        subprocess.run(
            [
                "httpx",
                "-silent",
                "-l",
                f"{OUTPUT_DIR}/all_subdomains.txt",
                "-o",
                f"{OUTPUT_DIR}/alive.txt"
            ]
        )

    except Exception as e:

        print(f"[!] HTTPX error: {e}")


def run(domain):

    print("\n[+] Starting Recon Engine\n")

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

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    save_results(
        "subfinder.txt",
        subfinder_results
    )

    save_results(
        "amass.txt",
        amass_results
    )

    save_results(
        "assetfinder.txt",
        assetfinder_results
    )

    save_results(
        "crtsh.txt",
        crtsh_results
    )

    all_subs = set()

    all_subs.update(subfinder_results)
    all_subs.update(amass_results)
    all_subs.update(assetfinder_results)
    all_subs.update(crtsh_results)

    all_subs = {

        s.strip()
        for s in all_subs
        if s.strip()
    }

    save_results(
        "all_subdomains.txt",
        all_subs
    )

    print(
        f"[+] Total Unique Subdomains: {len(all_subs)}"
    )

    print("[+] Running HTTPX")

    check_alive()

    print(
        "[+] Results saved in outputs/recon/"
    )