from modules import subdomain
from core.endpoint_engine import run as endpoint_run


def run(target):

    print("[*] Running recon")

    subdomain.run(target)

    endpoint_run(target)