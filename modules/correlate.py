from core.correlation import run as run_correlator

def run(target: str) -> None:
    """
    Wrapper to execute Correlation Engine module.
    """
    run_correlator(target)
