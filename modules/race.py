import requests
import threading

def hit(url):

    try:
        r = requests.get(url)
        print(url, r.status_code)
    except:
        pass


def run(target):

    print("[*] Running race condition test")

    threads = []

    for i in range(20):

        t = threading.Thread(target=hit, args=(target,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()