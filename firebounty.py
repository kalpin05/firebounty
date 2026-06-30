import argparse
from core.runner import run_pipeline
from core.output_manager import create_output_dirs

def main():
    create_output_dirs()

    parser = argparse.ArgumentParser(
        description="FireBounty v2 - Bug Bounty & WAF Testing CLI"
    )

    parser.add_argument(
        "mode",
        help="recon | waf | technology | bypass | js | param | api | idor | auth | brute | mutate | combo | jwt | race | correlate | full"
    )


    parser.add_argument(
        "target",
        help="target domain or URL"
    )

    args = parser.parse_args()
    run_pipeline(args.mode, args.target)

if __name__ == "__main__":
    main()