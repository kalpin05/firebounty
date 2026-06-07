def analyze(status, length):

    if status == 200 and length > 100000:
        return "HIGH"

    elif status in [401,403]:
        return "AUTH"

    elif length < 500:
        return "LOW"

    return "NORMAL"