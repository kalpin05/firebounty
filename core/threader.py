from concurrent.futures import ThreadPoolExecutor

def run_threads(function, items, threads=10):

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(function, items)