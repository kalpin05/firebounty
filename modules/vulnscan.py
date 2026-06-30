from core.scanner import run as run_scanner

def run(target: str) -> None:
    """
    Wrapper to execute Vulnerability Scanner module.
    """
    run_scanner(target)
