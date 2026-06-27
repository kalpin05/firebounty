"""
FireBounty v2
HTTP Header Technology Detection
"""

import json
import os
from collections import defaultdict

import requests

from core.tech.fingerprints import TECH_FINGERPRINTS


class HeaderDetector:

    def __init__(self, timeout: int = 10):

        self.timeout = timeout

        self.session = requests.Session()

        self.session.headers.update({

            "User-Agent": (
                "FireBounty/2.0 "
                "(Technology Detection)"
            )

        })

    # -----------------------------

    def fetch_headers(self, url):

        try:

            r = self.session.get(

                url,

                timeout=self.timeout,

                verify=False,

                allow_redirects=True

            )

            return dict(r.headers)

        except Exception:

            return {}

    # -----------------------------

    def normalize(self, headers):

        normalized = {}

        for k, v in headers.items():

            normalized[k.lower()] = str(v).lower()

        return normalized

    # -----------------------------

    def detect(self, headers):

        findings = defaultdict(list)

        merged = "\n".join(

            [

                f"{k}: {v}"

                for k, v in headers.items()

            ]

        )

        merged = merged.lower()

        for category, technologies in TECH_FINGERPRINTS.items():

            for tech, signatures in technologies.items():

                for signature in signatures:

                    if signature.lower() in merged:

                        findings[category].append(tech)

                        break

        return findings

    # -----------------------------

    def scan_target(self, url):

        headers = self.fetch_headers(url)

        headers = self.normalize(headers)

        findings = self.detect(headers)

        return {

            "url": url,

            "headers": headers,

            "findings": findings

        }


# =====================================

def save_results(output_dir, results):

    os.makedirs(output_dir, exist_ok=True)

    categories = [

        "servers",

        "frameworks",

        "cloud",

        "security"

    ]

    for category in categories:

        path = os.path.join(

            output_dir,

            f"{category}.txt"

        )

        with open(path, "w") as f:

            for item in results.get(category, []):

                f.write(item + "\n")

    with open(

        os.path.join(output_dir, "technology.json"),

        "w"

    ) as f:

        json.dump(

            results,

            f,

            indent=4

        )


# =====================================

def run(target):

    alive_file = f"outputs/{target}/recon/alive.txt"

    output_dir = f"outputs/{target}/technology"

    if not os.path.exists(alive_file):

        print("[!] alive.txt not found")

        return

    detector = HeaderDetector()

    summary = defaultdict(set)

    with open(alive_file) as f:

        urls = [

            line.strip()

            for line in f

            if line.strip()

        ]

    print(f"[*] Detecting technology on {len(urls)} hosts")

    for url in urls:

        result = detector.scan_target(url)

        for category, values in result["findings"].items():

            summary[category].update(values)

    final = {}

    for category, values in summary.items():

        final[category] = sorted(values)

    save_results(

        output_dir,

        final

    )

    print("[✓] Technology Detection Complete")