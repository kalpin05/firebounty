import requests
from colorama import Fore, init

init(autoreset=True)

params = [
    "id", "user", "account", "email", "token",
    "debug", "admin", "test", "role", "uid"
]

def run(target):

    print(Fore.GREEN + "[*] Running parameter discovery")

    try:
        base = requests.get(target, timeout=5)
        base_len = len(base.text)
    except:
        print(Fore.RED + "[!] Target not reachable")
        return

    for p in params:

        url = f"{target}?{p}=1"

        try:
            r = requests.get(url, timeout=5)

            if len(r.text) != base_len:
                print(Fore.YELLOW + f"[~] Possible param: {url} (length diff)")

            elif r.status_code != base.status_code:
                print(Fore.RED + f"[🔥] Interesting param: {url} -> {r.status_code}")

            else:
                print(Fore.WHITE + f"[ ] {url}")

        except:
            pass