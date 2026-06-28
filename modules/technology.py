from core.tech.detector import run as detect_run

def run(target: str) -> None:
    """
    Wrapper to execute Technology Detection module.
    """
    detect_run(target)