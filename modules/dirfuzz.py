import os

def run(target):

    os.system(
        f"ffuf -u {target}/FUZZ -w wordlists/dirs.txt"
    )