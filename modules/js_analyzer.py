import requests
from colorama import Fore, init
from utils.diff import compare

init(autoreset=True)


def run(target):

    print(Fore.GREEN + "[*] Running IDOR test")

    baseline_text = None

    for i in range(1, 6):

        url = f"{target}?id={i}"

        try:
            r = requests.get(url, timeout=5)

            print(f"{url} -> {len(r.text)}")

            if baseline_text is None:
                baseline_text = r.text
                continue

            similarity = compare(baseline_text, r.text)

            print(Fore.CYAN + f"Similarity: {similarity}")

            if similarity < 0.95:
                print(Fore.RED + f"[🔥] Strong IDOR signal at {url}")

        except:
            pass