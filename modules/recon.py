from core.endpoint_engine import run as endpoint_run
from utils.logger import log

def run(target: str) -> None:
    """
    Run Endpoint Discovery wrapper.
    """
    log("[*] Running Endpoint Discovery Engine")
    try:
        endpoint_run(target)
    except Exception as e:
        log(f"[!] Endpoint Engine Error: {e}")
    log("[✓] Endpoint Discovery Module Finished")