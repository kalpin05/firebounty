import requests
from colorama import Fore, init
from utils.detector import find_sensitive
from utils.report_gen import generate
from utils.smart_analyzer import analyze

init(autoreset=True)

params = ["id", "user", "role", "admin", "debug"]

payloads = ["1","0","-1","999","true","false","admin","root"]


def run(target):

    print(Fore.GREEN + "[*] Running parameter mutation")

    for p in params:
        for val in payloads:

            url = f"{target}?{p}={val}"

            try:
                r = requests.get(url, timeout=5)

                risk = analyze(r.status_code, len(r.text))

                print(f"{url} -> {r.status_code} [{risk}]")

                findings = find_sensitive(r.text)

                if findings:
                    print(Fore.RED + f"[🔥 Sensitive data: {findings}")
                    generate("Sensitive Data Exposure", url)

            except:
                pass