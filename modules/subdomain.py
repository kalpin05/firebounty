from core.recon_engine import run as recon_run

def run(domain: str) -> None:
    """
    Run Passive Subdomain Enumeration engine.
    """
    recon_run(domain)