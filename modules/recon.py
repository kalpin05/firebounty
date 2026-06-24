from modules import subdomain
from core.endpoint_engine import run as endpoint_run


def run(target):

    print("[*] Running recon")

    try:

        subdomain.run(target)

    except Exception as e:

        print(f"[!] Recon Engine Error: {e}")

        return

    try:

        endpoint_run(target)

    except Exception as e:

        print(f"[!] Endpoint Engine Error: {e}")

    print("[✓] Recon Module Finished")