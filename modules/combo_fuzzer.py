import requests
from colorama import Fore, init

init(autoreset=True)

payloads = [
    "?id=1&admin=true",
    "?user=1&role=admin",
    "?id=2&debug=true",
    "?account=1&access=full"
]


def run(target):

    print(Fore.GREEN + "[*] Running combo fuzzing")

    for p in payloads:

        url = target + p

        try:
            r = requests.get(url, timeout=5)

            print(f"{url} -> {r.status_code}")

            if r.status_code == 200:
                print(Fore.RED + f"[🔥 Interesting combo: {url}")

        except:
            pass