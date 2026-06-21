import argparse
from modules import param_mutator
from modules import combo_fuzzer
from modules import recon
from core.toolcheck import check_tools
from core.output_manager import create_output_dirs
from modules import wafdetect
from modules import waf_bypass
from modules import portscan
from modules import subdomain
from modules import js_analyzer
from modules import param_finder
from modules import api_fuzzer
from modules import idor
from modules import auth_bypass
from modules import param_bruteforce
from modules import jwt_attack
from modules import race

def main():
    create_output_dirs()

    check_tools()
    parser = argparse.ArgumentParser(
        description="FireBounty - Bug Bounty & WAF Testing CLI"
    )

    parser.add_argument(
        "mode",
        help="recon | waf | bypass | js | param | api | idor | full"
    )

    parser.add_argument(
        "target",
        help="target domain (include https://)"
    )

    args = parser.parse_args()

    # 🔹 Individual modes

    if args.mode == "recon":
        recon.run(args.target)

    elif args.mode == "waf":
        wafdetect.run(args.target)

    elif args.mode == "bypass":
        waf_bypass.run(args.target)

    elif args.mode == "js":
        js_analyzer.run(args.target)

    elif args.mode == "param":
        param_finder.run(args.target)

    elif args.mode == "api":
        api_fuzzer.run(args.target)

    elif args.mode == "idor":
        idor.run(args.target)
    elif args.mode == "auth":
        auth_bypass.run(args.target)

    elif args.mode == "brute":
        param_bruteforce.run(args.target)
    elif args.mode == "mutate":
        param_mutator.run(args.target)

    elif args.mode == "combo":
        combo_fuzzer.run(args.target)
    elif args.mode == "jwt":
        jwt_attack.run()

    elif args.mode == "race":
        race.run(args.target)

    # 🔥 FULL PIPELINE

    elif args.mode == "full":

        print("\n[🔥] Starting Full Scan\n")

        subdomain.run(args.target)
        portscan.run(args.target)
        recon.run(args.target)
        auth_bypass.run(args.target)
        param_bruteforce.run(args.target)
        wafdetect.run(args.target)
        waf_bypass.run(args.target)
        param_mutator.run(args.target)
        combo_fuzzer.run(args.target)
        js_analyzer.run(args.target)
        jwt_attack.run()
        race.run(args.target)
        param_finder.run(args.target)
        api_fuzzer.run(args.target)
        idor.run(args.target)

        print("\n[✅] Scan Completed\n")

    else:
        print("Invalid mode")


if __name__ == "__main__":
    main()