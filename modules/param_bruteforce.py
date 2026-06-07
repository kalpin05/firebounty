import requests
from colorama import Fore, init

init(autoreset=True)


def load_params():
    with open("wordlists/params.txt") as f:
        return [line.strip() for line in f]


def run(target):

    print(Fore.GREEN + "[*] Running parameter bruteforce")

    params = load_params()

    try:
        base = requests.get(target)
        base_len = len(base.text)
    except:
        print("Target not reachable")
        return

    for p in params:

        url = f"{target}?{p}=test"

        try:
            r = requests.get(url, timeout=5)

            if len(r.text) != base_len:
                print(Fore.RED + f"[🔥 PARAM FOUND] {url}")

            elif r.status_code != base.status_code:
                print(Fore.YELLOW + f"[~] Interesting: {url}")

        except:
            pass