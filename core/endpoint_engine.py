import os
import subprocess


# ----------------------------------
# Tool Resolver
# ----------------------------------

def get_tool(tool_name):

    candidates = [

        f"{os.path.expanduser('~')}/go/bin/{tool_name}",

        f"/root/go/bin/{tool_name}",

        tool_name

    ]

    for tool in candidates:

        try:

            subprocess.run(
                [tool, "-h"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            return tool

        except:
            pass

    return tool_name


GAU = get_tool("gau")
WAYBACKURLS = get_tool("waybackurls")
KATANA = get_tool("katana")


# ----------------------------------
# Patterns
# ----------------------------------

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


# ----------------------------------
# Helpers
# ----------------------------------

def save_file(path, data):

    with open(path, "w") as f:

        for item in sorted(set(data)):

            if item.strip():

                f.write(item.strip() + "\n")


def load_lines(path):

    if not os.path.exists(path):

        return []

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        return [

            line.strip()

            for line in f

            if line.strip()
        ]


# ----------------------------------
# gau
# ----------------------------------

def run_gau(target, output_file):

    try:

        with open(output_file, "w") as f:

            subprocess.run(
                [GAU, target],
                stdout=f,
                stderr=subprocess.DEVNULL,
                text=True
            )

    except Exception as e:

        print(f"[!] gau error: {e}")


# ----------------------------------
# waybackurls
# ----------------------------------

def run_waybackurls(target, output_file):

    try:

        with open(output_file, "w") as f:

            subprocess.run(
                [WAYBACKURLS],
                input=target,
                stdout=f,
                stderr=subprocess.DEVNULL,
                text=True
            )

    except Exception as e:

        print(f"[!] waybackurls error: {e}")


# ----------------------------------
# katana
# ----------------------------------

def run_katana(alive_file, output_file):

    if not os.path.exists(alive_file):

        print("[!] alive.txt missing")

        return

    try:

        subprocess.run(
            [
                KATANA,
                "-silent",
                "-list",
                alive_file,
                "-o",
                output_file
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    except Exception as e:

        print(f"[!] katana error: {e}")


# ----------------------------------
# JS Extraction
# ----------------------------------

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


# ----------------------------------
# Interesting URLs
# ----------------------------------

def extract_interesting(endpoints):

    findings = []

    for url in endpoints:

        lower = url.lower()

        for pattern in INTERESTING_PATTERNS:

            if pattern in lower:

                findings.append(url)

                break

    return findings


# ----------------------------------
# Main
# ----------------------------------

from utils.helpers import sanitize_target

def run(target):

    print("\n[*] Running Endpoint Engine")

    domain, _ = sanitize_target(target)

    base = f"outputs/{domain}"

    endpoint_dir = f"{base}/endpoints"

    recon_dir = f"{base}/recon"

    os.makedirs(
        endpoint_dir,
        exist_ok=True
    )

    gau_file = f"{endpoint_dir}/gau.txt"

    wayback_file = f"{endpoint_dir}/waybackurls.txt"

    katana_file = f"{endpoint_dir}/katana.txt"

    alive_file = f"{recon_dir}/alive.txt"

    print("[*] Running gau")

    run_gau(
        target,
        gau_file
    )

    print("[*] Running waybackurls")

    run_waybackurls(
        target,
        wayback_file
    )

    print("[*] Running katana")

    run_katana(
        alive_file,
        katana_file
    )

    endpoints = []

    endpoints.extend(
        load_lines(gau_file)
    )

    endpoints.extend(
        load_lines(wayback_file)
    )

    endpoints.extend(
        load_lines(katana_file)
    )

    endpoints = sorted(
        set(endpoints)
    )

    save_file(
        f"{endpoint_dir}/all_endpoints.txt",
        endpoints
    )

    js_files = extract_js(
        endpoints
    )

    save_file(
        f"{endpoint_dir}/js_files.txt",
        js_files
    )

    interesting = extract_interesting(
        endpoints
    )

    save_file(
        f"{endpoint_dir}/interesting.txt",
        interesting
    )

    print(
        f"[+] Total Endpoints: {len(endpoints)}"
    )

    print(
        f"[+] JS Files: {len(js_files)}"
    )

    print(
        f"[+] Interesting Endpoints: {len(interesting)}"
    )

    print(
        "[✓] Endpoint Engine Complete"
    )