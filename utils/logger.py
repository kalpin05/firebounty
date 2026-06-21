from datetime import datetime

LOGFILE = "outputs/firebounty.log"

def log(message):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    line = f"[{timestamp}] {message}"

    print(line)

    with open(LOGFILE, "a") as f:
        f.write(line + "\n")