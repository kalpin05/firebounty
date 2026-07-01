from core.report_engine import run as run_report

def run(target: str) -> None:
    """
    Wrapper to execute Report Compilation module.
    """
    run_report(target)
