import os

def run(target):

    print("[*] Running subdomain discovery")

    os.system(f"subfinder -d {target} -silent")