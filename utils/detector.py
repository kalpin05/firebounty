import re

def find_sensitive(data):

    findings = []

    patterns = {
        "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "api_key": r"api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{16,}",
        "token": r"token['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{10,}"
    }

    for key, pattern in patterns.items():

        if re.search(pattern, data):
            findings.append(key)

    return findings