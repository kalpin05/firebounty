import base64
import json
from colorama import Fore, init

init(autoreset=True)


def decode_jwt(token):

    try:
        header, payload, signature = token.split(".")

        decoded = base64.urlsafe_b64decode(payload + "==")

        print(Fore.GREEN + "[+] Decoded JWT:")
        print(decoded.decode())

    except:
        print("Invalid token")


def run():

    token = input("Enter JWT: ")

    decode_jwt(token)

    print(Fore.YELLOW + "[*] Try modifying payload (admin:true)")