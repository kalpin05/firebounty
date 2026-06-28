import os
import shutil
from colorama import Fore, init

init(autoreset=True)

def run(target: str) -> None:
    """
    Perform directory bruteforcing using ffuf.
    """
    print(Fore.GREEN + "[*] Running Directory Bruteforce")
    
    if not shutil.which("ffuf"):
        print(Fore.RED + "[!] Skipping dirfuzz: ffuf is not installed or not in PATH.")
        return

    wordlist = "wordlists/dirs.txt"
    if not os.path.exists(wordlist) or os.path.getsize(wordlist) == 0:
        print(Fore.YELLOW + "[!] Skipping dirfuzz: wordlists/dirs.txt is empty or missing.")
        return

    print(Fore.CYAN + f"[+] Executing ffuf on: {target}")
    os.system(f"ffuf -u {target}/FUZZ -w {wordlist}")