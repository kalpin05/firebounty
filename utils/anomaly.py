from utils.anomaly import is_anomalous
if is_anomalous(base_len, len(r.text)):
    print("[🔥] Strong anomaly detected!")
def is_anomalous(base_len, new_len):

    diff = abs(base_len - new_len)

    if diff > 1000:
        return True

    return False