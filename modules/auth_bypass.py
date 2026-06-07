import requests
from colorama import Fore, init

init(autoreset=True)

payloads = [
    "/admin",
    "/dashboard",
    "/api/admin",
    "/user/profile"
]

headers_list = [
    {"Authorization": "Bearer null"},
    {"Authorization": "Bearer test"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"}
]


def run(target):

    print(Fore.GREEN + "[*] Running Auth Bypass Tests")

    for p in payloads:

        url = target + p

        try:
            r = requests.get(url, timeout=5)

            base = r.status_code

            for h in headers_list:

                r2 = requests.get(url, headers=h, timeout=5)

                if base in [401, 403] and r2.status_code == 200:
                    print(Fore.RED + f"[🔥 AUTH BYPASS] {url} using {h}")

                elif r2.status_code != base:
                    print(Fore.YELLOW + f"[~] Interesting: {url} {h} -> {r2.status_code}")

        except:
            pass