import os

def run(target):

    print("[*] Running port scan")

    os.system(f"nmap -T4 -F {target}")