import requests

def run(target):

    print("[*] Checking WAF...")

    try:
        r = requests.get(target, timeout=5)

        headers = str(r.headers).lower()

        if "cloudflare" in headers:
            print("[+] Cloudflare WAF detected")

        elif "akamai" in headers:
            print("[+] Akamai WAF detected")

        elif "imperva" in headers:
            print("[+] Imperva WAF detected")

        elif "sucuri" in headers:
            print("[+] Sucuri WAF detected")

        else:
            print("[+] No common WAF detected")

    except:
        print("Request failed")