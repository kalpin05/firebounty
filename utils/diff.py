import difflib

def compare(a, b):

    diff = difflib.SequenceMatcher(None, a, b)

    return diff.ratio()