import os
import requests
from colorama import Fore, init

init(autoreset=True)

def load_params() -> list:
    """
    Load parameter names from wordlists file, falling back to defaults if empty/missing.
    """
    path = "wordlists/params.txt"
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        print(Fore.YELLOW + "[!] Warning: wordlists/params.txt is missing or empty. Using fallback parameters.")
        return ["id", "user", "admin", "debug", "role", "email", "token", "key", "password"]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(Fore.RED + f"[!] Error loading param wordlist: {e}. Using fallback parameters.")
        return ["id", "user", "admin", "debug", "role", "email", "token", "key", "password"]

def run(target: str) -> None:
    """
    Bruteforce URL parameters to find differences in response size/status.
    """
    print(Fore.GREEN + "[*] Running parameter bruteforce")

    params = load_params()

    try:
        base = requests.get(target, timeout=5)
        base_len = len(base.text)
    except Exception as e:
        print(Fore.RED + f"[!] Target not reachable: {e}")
        return

    for p in params:
        url = f"{target}?{p}=test"
        try:
            r = requests.get(url, timeout=5)

            if len(r.text) != base_len:
                print(Fore.RED + f"[🔥 PARAM FOUND] {url}")
            elif r.status_code != base.status_code:
                print(Fore.YELLOW + f"[~] Interesting param status change: {url}")
        except Exception:
            pass