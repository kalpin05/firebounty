def score(issue):

    if "idor" in issue:
        return "HIGH"

    elif "param" in issue:
        return "MEDIUM"

    elif "api" in issue:
        return "LOW"

    return "INFO"