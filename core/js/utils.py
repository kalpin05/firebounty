"""
FireBounty JS Utilities
"""

import hashlib
import os


def safe_filename(url: str):

    ext = ".js"

    if ".mjs" in url:
        ext = ".mjs"

    return hashlib.sha256(
        url.encode()
    ).hexdigest()[:20] + ext


def write_list(path, items):

    os.makedirs(
        os.path.dirname(path),
        exist_ok=True
    )

    with open(path, "w", encoding="utf-8") as f:

        for item in sorted(set(items)):

            f.write(item.strip() + "\n")


def append_line(path, text):

    os.makedirs(
        os.path.dirname(path),
        exist_ok=True
    )

    with open(path, "a", encoding="utf-8") as f:

        f.write(text + "\n")


def read_lines(path):

    if not os.path.exists(path):

        return []

    with open(
        path,
        encoding="utf-8",
        errors="ignore"
    ) as f:

        return [

            line.strip()

            for line in f

            if line.strip()

        ]


def file_size(path):

    if not os.path.exists(path):

        return 0

    return os.path.getsize(path)


def ensure_directory(path):

    os.makedirs(
        path,
        exist_ok=True
    )