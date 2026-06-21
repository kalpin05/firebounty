import shutil

TOOLS = [
    "subfinder",
    "amass",
    "assetfinder",
    "httpx",
    "dnsx",
    "ffuf",
    "nmap"
]

def check_tools():

    print("\n[+] Checking dependencies\n")

    results = {}

    for tool in TOOLS:

        if shutil.which(tool):

            print(f"[✓] {tool}")
            results[tool] = True

        else:

            print(f"[✗] {tool}")
            results[tool] = False

    return results