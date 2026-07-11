import argparse
from colorama import Fore, init
from modules import takeover
from modules import broken_links
from core.runner import run_pipeline
from core.output_manager import create_output_dirs

init(autoreset=True)

def print_banner():
    try:
        banner = (
            f"{Fore.RED} ______ _          ____                       _         \n"
            f"{Fore.LIGHTRED_EX}|  ____(_)        |  _ \\                     | |        \n"
            f"{Fore.YELLOW}| |__   _ _ __ ___| |_) | ___  _   _ _ __  __| |_ _   _ \n"
            f"{Fore.LIGHTYELLOW_EX}|  __| | | '__/ _ \\  _ < / _ \\| | | | '_ \\/ _` | __| | | |\n"
            f"{Fore.RED}| |    | | | |  __/ |_) | (_) | |_| | | | | (_| | |_| |_| |\n"
            f"{Fore.RED}|_|    |_|_|  \\___|____/ \\___/ \\__,_|_| |_|\\__,_|\\__|\\__, |\n"
            f"                                                       __/ |\n"
            f"                                                      |___/ "
        )
        print(banner)
        print(f"   {Fore.CYAN}* FireBounty v2 - Bug Bounty & WAF Testing CLI Framework *")
        print(f"   {Fore.GREEN}>> Modes: recon | waf | technology | bypass | js | param | api | idor | auth | brute")
        print(f"             mutate | combo | jwt | race | takeover | links | correlate | report | parameters | full")
        print(f"   {Fore.YELLOW}>> Disclaimer: For authorized security testing and research only!")
        print("=" * 86 + "\n")
    except Exception:
        # Fallback to plain ASCII if printing codes fails
        banner = (
            " ______ _          ____                       _         \n"
            "|  ____(_)        |  _ \\                     | |        \n"
            "| |__   _ _ __ ___| |_) | ___  _   _ _ __  __| |_ _   _ \n"
            "|  __| | | '__/ _ \\  _ < / _ \\| | | | '_ \\/ _` | __| | | |\n"
            "| |    | | | |  __/ |_) | (_) | |_| | | | | (_| | |_| |_| |\n"
            "|_|    |_|_|  \\___|____/ \\___/ \\__,_|_| |_|\\__,_|\\__|\\__, |\n"
            "                                                       __/ |\n"
            "                                                      |___/ "
        )
        print(banner)
        print("   * FireBounty v2 - Bug Bounty & WAF Testing CLI Framework *")
        print("   >> Modes: recon | waf | technology | bypass | js | param | api | idor | auth | brute")
        print("             mutate | combo | jwt | race | takeover | links | correlate | report | parameters | full")
        print("   >> Disclaimer: For authorized security testing and research only!")
        print("======================================================================================\n")

def main():
    print_banner()
    create_output_dirs()

    parser = argparse.ArgumentParser(
        description="FireBounty v2 - Bug Bounty & WAF Testing CLI"
    )

    parser.add_argument(
        "mode",
        help="recon | waf | technology | bypass | js | param | api | idor | auth | brute | mutate | combo | jwt | race | takeover | links | correlate | report | parameters | full"
    )

    parser.add_argument(
        "target",
        help="target domain or URL"
    )

    args = parser.parse_args()
    run_pipeline(args.mode, args.target)

if __name__ == "__main__":
    main()