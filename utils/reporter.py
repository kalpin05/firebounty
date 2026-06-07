def save(issue, url):

    with open("report.txt", "a") as f:

        f.write(f"[{issue}] {url}\n")
from utils.reporter import save

save("IDOR", url)