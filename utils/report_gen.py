def generate(issue, url):

    report = f"""
==== BUG REPORT ====

Title: {issue}

Endpoint:
{url}

Steps to Reproduce:
1. Open the URL
2. Observe response

Impact:
Potential sensitive data exposure or access control issue

====================
"""

    with open("bug_report.txt", "a") as f:
        f.write(report + "\n")

    print("[+] Report saved")