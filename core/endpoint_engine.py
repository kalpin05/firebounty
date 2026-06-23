import os
import subprocess


INTERESTING_PATTERNS = [
    "/api",
    "/v1",
    "/v2",
    "/admin",
    "/internal",
    "/debug",
    "/private",
    "/swagger",
    "/graphql",
    "/auth",
    "/login",
    "/token",
    "/jwt",
    "/oauth",
    "/config",
    "/backup"
]


def save_file(path, data):

    with open(path, "w") as f:

        for item in sorted(set(data)):
            f.write(item + "\n")


def run_gau(target, output_file):

    try:

        with open(output_file, "w") as f:

            subprocess.run(
                ["gau", target],
                stdout=f,
                stderr=subprocess.DEVNULL,
                text=True
            )

    except Exception as e:

        print(f"[!] gau error: {e}")


def run_waybackurls(target, output_file):

    try:

        with open(output_file, "w") as f:

            subprocess.run(
                ["waybackurls"],
                input=target,
                stdout=f,
                stderr=subprocess.DEVNULL,
                text=True
            )

    except Exception as e:

        print(f"[!] waybackurls error: {e}")


def run_katana(alive_file, output_file):

    try:

        subprocess.run(
            [
                "katana",
                "-silent",
                "-list",
                alive_file,
                "-o",
                output_file
            ],
            stderr=subprocess.DEVNULL
        )

    except Exception as e:

        print(f"[!] katana error: {e}")


def load_lines(path):

    if not os.path.exists(path):
        return []

    with open(path, "r", errors="ignore") as f:

        return [line.strip() for line in f if line.strip()]


def extract_js(endpoints):

    js_files = []

    for url in endpoints:

        lower = url.lower()

        if (
            ".js" in lower
            or ".mjs" in lower
            or "bundle.js" in lower
            or "chunk.js" in lower
        ):
            js_files.append(url)

    return js_files


def extract_interesting(endpoints):

    findings = []

    for url in endpoints:

        lower = url.lower()

        for pattern in INTERESTING_PATTERNS:

            if pattern in lower:

                findings.append(url)
                break

    return findings


def run(target):

    print("\n[*] Running Endpoint Engine")

    base = f"outputs/{target}"
    endpoint_dir = f"{base}/endpoints"
    recon_dir = f"{base}/recon"

    os.makedirs(endpoint_dir, exist_ok=True)

    gau_file = f"{endpoint_dir}/gau.txt"
    wayback_file = f"{endpoint_dir}/waybackurls.txt"
    katana_file = f"{endpoint_dir}/katana.txt"

    alive_file = f"{recon_dir}/alive.txt"

    print("[*] Running gau")
    run_gau(target, gau_file)

    print("[*] Running waybackurls")
    run_waybackurls(target, wayback_file)

    print("[*] Running katana")
    run_katana(alive_file, katana_file)

    endpoints = []

    endpoints.extend(load_lines(gau_file))
    endpoints.extend(load_lines(wayback_file))
    endpoints.extend(load_lines(katana_file))

    endpoints = sorted(set(endpoints))

    all_endpoints = f"{endpoint_dir}/all_endpoints.txt"

    save_file(all_endpoints, endpoints)

    js_files = extract_js(endpoints)

    save_file(
        f"{endpoint_dir}/js_files.txt",
        js_files
    )

    interesting = extract_interesting(endpoints)

    save_file(
        f"{endpoint_dir}/interesting.txt",
        interesting
    )

    print(f"[+] Total Endpoints: {len(endpoints)}")
    print(f"[+] JS Files: {len(js_files)}")
    print(f"[+] Interesting Endpoints: {len(interesting)}")

    print("[✓] Endpoint Engine Complete")