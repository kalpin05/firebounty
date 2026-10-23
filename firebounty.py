import sys
import argparse
from colorama import Fore, init
from core.runner import run_pipeline
from core.output_manager import create_output_dirs

init(autoreset=True)

BANNER = r"""
  ______ _          ____                  _         
 |  ____(_)        |  _ \                | |        
 | |__   _ _ __ ___| |_) | ___  _   _ __ | |_ _   _ 
 |  __| | | '__/ _ \  _ < / _ \| | | '_ \| __| | | |
 | |    | | | |  __/ |_) | (_) | |_| | | | |_| |_| |
 |_|    |_|_|  \___|____/ \___/ \__,_|_| |_|\__|\__, |
                                                 __/ |
                                                |___/ 
                     Bug Bounty Intelligence v2
"""

MENU_OPTIONS = {
    "1": ("Recon & Subdomain Discovery", "recon"),
    "2": ("Technology Detection", "technology"),
    "3": ("JavaScript Intelligence", "js"),
    "4": ("Parameter Discovery", "param"),
    "5": ("Authentication Security Audit", "auth"),
    "6": ("API Specification Profiler", "api"),
    "7": ("Active Vulnerability Scanner", "vuln"),
    "8": ("Attack Path Correlation", "correlate"),
    "9": ("Compile Reports Summary", "report"),
    "10": ("Run Full Scan Pipeline", "full")
}

def run_interactive() -> None:
    """
    Run the interactive menu configuration selector.
    """
    print(Fore.RED + BANNER)
    print(Fore.CYAN + "=== FireBounty v2 Interactive Wizard ===")
    for num, (desc, _) in sorted(MENU_OPTIONS.items(), key=lambda x: int(x[0])):
        print(f"  [{Fore.GREEN}{num}{Fore.RESET}] {desc}")
    print()

    choice = ""
    while choice not in MENU_OPTIONS:
        try:
            choice = input(Fore.YELLOW + "Select a feature (1-10): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Exiting Wizard.")
            return

    desc, mode = MENU_OPTIONS[choice]
    print(Fore.CYAN + f"\n[+] Selected: {desc}")
    
    target = ""
    while not target:
        try:
            target = input(Fore.YELLOW + "Enter target domain or URL: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Exiting Wizard.")
            return

    print(Fore.GREEN + f"\n[*] Launching pipeline mode '{mode}' on target '{target}'...\n")
    run_pipeline(mode, target)

def main() -> None:
    create_output_dirs()

    # If no CLI arguments are supplied, fall back to interactive wizard
    if len(sys.argv) < 3:
        run_interactive()
    else:
        parser = argparse.ArgumentParser(
            description="FireBounty v2 - Bug Bounty & WAF Testing CLI"
        )
        parser.add_argument(
            "mode",
            help="recon | waf | technology | bypass | js | param | api | idor | auth | brute | mutate | combo | jwt | race | correlate | report | full"
        )
        parser.add_argument(
            "target",
            help="target domain or URL"
        )
        args = parser.parse_args()
        run_pipeline(args.mode, args.target)

if __name__ == "__main__":
    main()