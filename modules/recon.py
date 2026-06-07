import os

def run(target):

    print("[*] Running recon")

    os.system(f"subfinder -d {target}")