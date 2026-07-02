import shutil
import os

TOOLS = [
    "subfinder",
    "amass",
    "assetfinder",
    "httpx",
    "dnsx",
    "ffuf",
    "nmap"
]

def check_tools() -> dict:
    """
    Check availability of external command-line dependencies.
    """
    print("\n[+] Checking dependencies\n")

    results = {}

    for tool in TOOLS:
        # Check standard PATH
        resolved = shutil.which(tool)
        
        # On Debian/Kali, ProjectDiscovery httpx is packaged as httpx-toolkit
        if tool == "httpx" and not resolved:
            resolved = shutil.which("httpx-toolkit")
            
        # Check Go installation paths
        if not resolved:
            for path in [
                os.path.expanduser(f"~/go/bin/{tool}"),
                f"/root/go/bin/{tool}"
            ]:
                if os.path.exists(path):
                    resolved = path
                    break

        if resolved:
            print(f"[✓] {tool}")
            results[tool] = True
        else:
            print(f"[✗] {tool}")
            results[tool] = False

    return results