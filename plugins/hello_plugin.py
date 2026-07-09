"""
FireBounty v2 - Custom Plugin Example
"""

from utils.logger import log

NAME = "Hello Plugin"
MODE = "hello"
DESCRIPTION = "Prints a welcome message to confirm dynamic plugin loading functions properly."

def run(target: str) -> None:
    """
    Executes plugin task logic.
    """
    log(f"[Hello Plugin] Dynamically loaded and run against: {target}")
    print(f"Hello, World! FireBounty Plugin system is active. Targeted: {target}")
