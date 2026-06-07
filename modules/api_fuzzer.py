import requests
from colorama import Fore, init

init(autoreset=True)

endpoints = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/user",
    "/api/admin",
    "/internal",
    "/debug",
    "/private",
    "/test"
]

def run(target):

    print(Fore.GREEN + "[*] Running API fuzzing")

    for ep in endpoints:

        url = target + ep

        try:
            r = requests.get(url, timeout=5)

            if r.status_code in [200, 401, 403]:
                print(Fore.YELLOW + f"[~] Found endpoint: {url} -> {r.status_code}")

            else:
                print(Fore.WHITE + f"[ ] {url}")

        except:
            pass