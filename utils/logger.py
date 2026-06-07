from utils.logger import save

save(url)
def save(url):

    with open("reports.txt", "a") as f:
        f.write(url + "\n")