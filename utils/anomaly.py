
def is_anomalous(base_len, new_len):

    diff = abs(base_len - new_len)

    if diff > 1000:
        return True

    return False