"""
FireBounty v2 - Extensible Reporting Engine
"""

import os
import json
import csv
from utils.logger import log

def load_json(filepath: str) -> list:
    """
    Safely loads JSON data from a file, returning a list.
    """
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log(f"[Report] Error reading JSON {filepath}: {e}")
        return []


def generate_csv(threats: list, output_path: str) -> bool:
    """
    Generates a CSV report from findings.
    """
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        headers = ["Subdomain", "Severity", "Score", "Reason", "Threat Chain", "Secrets Count", "Endpoints Count"]
        
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for t in threats:
                writer.writerow([
                    t.get("subdomain"),
                    t.get("severity"),
                    t.get("score"),
                    t.get("reason"),
                    ", ".join(t.get("chain", [])),
                    t.get("secrets_count", 0),
                    t.get("endpoints_count", 0)
                ])
        return True
    except Exception as e:
        log(f"[Report] Error writing CSV report: {e}")
        return False


def generate_markdown(threats: list, target: str, output_path: str) -> bool:
    """
    Generates a Markdown report from findings.
    """
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Calculate stats
        severities = [t.get("severity") for t in threats]
        critical = severities.count("CRITICAL")
        high = severities.count("HIGH")
        medium = severities.count("MEDIUM")
        low = severities.count("LOW")
        
        md = f"""# FireBounty Security Assessment Report

**Target:** {target}  
**Total Priority Targets Analyzed:** {len(threats)}

## 📊 Executive Summary

| Severity | Count |
| :--- | :--- |
| 🔴 **Critical** | {critical} |
| 🟠 **High** | {high} |
| 🟡 **Medium** | {medium} |
| 🔵 **Low** | {low} |

---

## 🔍 Detailed Vulnerability Exposure Findings
"""
        
        for t in threats:
            sub = t.get("subdomain")
            sev = t.get("severity")
            score = t.get("score")
            reason = t.get("reason")
            chain = t.get("chain", [])
            endpoints_cnt = t.get("endpoints_count", 0)
            secrets_cnt = t.get("secrets_count", 0)
            prof = t.get("profile", {})
            
            md += f"""
### 🌐 {sub}
*   **Severity:** {sev} (Score: {score}/10)
*   **Reason:** {reason}
*   **Active Tech:** {', '.join(prof.get('frameworks', [])) or 'None detected'} | {', '.join(prof.get('servers', [])) or 'None detected'}
*   **Exposed Findings:** {secrets_cnt} secrets found, {endpoints_cnt} interesting endpoints mapped.
"""
            if chain:
                md += f"*   **Exposure Path:** `{' -> '.join(chain)}`\n"
                
            md += """
#### Steps to Verify:
1. Open the subdomain in your browser.
2. Inspect network headers/responses to check for path exposure.
3. Verify credential usage (if secrets are flagged) in the local findings.
"""
            md += "\n---\n"
            
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md)
        return True
    except Exception as e:
        log(f"[Report] Error writing Markdown report: {e}")
        return False


def generate_html(threats: list, target: str, output_path: str) -> bool:
    """
    Generates a beautiful HTML report from findings.
    """
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Calculate stats
        severities = [t.get("severity") for t in threats]
        critical = severities.count("CRITICAL")
        high = severities.count("HIGH")
        medium = severities.count("MEDIUM")
        low = severities.count("LOW")
        
        # Build Table rows
        table_rows = ""
        for t in threats:
            sub = t.get("subdomain")
            sev = t.get("severity")
            score = t.get("score")
            reason = t.get("reason")
            chain = t.get("chain", [])
            endpoints_cnt = t.get("endpoints_count", 0)
            secrets_cnt = t.get("secrets_count", 0)
            
            badge_class = f"badge-{sev.lower()}"
            chain_html = " ".join([f"<span class='chain-item'>{c}</span>" for c in chain])
            
            table_rows += f"""
            <tr>
                <td><strong>{sub}</strong></td>
                <td><span class="badge {badge_class}">{sev}</span></td>
                <td>{score}/10</td>
                <td>{reason}</td>
                <td>{chain_html or 'N/A'}</td>
                <td>{secrets_cnt}</td>
                <td>{endpoints_cnt}</td>
            </tr>
            """
            
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FireBounty Report - {target}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #0f172a;
            color: #f1f5f9;
            margin: 0;
            padding: 40px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1, h2 {{
            color: #38bdf8;
        }}
        .header {{
            border-bottom: 2px solid #1e293b;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: #1e293b;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #334155;
        }}
        .stat-card h3 {{
            margin: 0 0 10px 0;
            font-size: 14px;
            color: #94a3b8;
            text-transform: uppercase;
        }}
        .stat-card p {{
            margin: 0;
            font-size: 28px;
            font-weight: bold;
        }}
        .stat-critical {{ border-top: 4px solid #ef4444; }}
        .stat-high {{ border-top: 4px solid #f97316; }}
        .stat-medium {{ border-top: 4px solid #eab308; }}
        .stat-low {{ border-top: 4px solid #3b82f6; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: #1e293b;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #334155;
        }}
        th, td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #334155;
        }}
        th {{
            background-color: #0f172a;
            color: #38bdf8;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #334155;
        }}
        .badge {{
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 11px;
            text-transform: uppercase;
        }}
        .badge-critical {{ background-color: #ef4444; color: #fff; }}
        .badge-high {{ background-color: #f97316; color: #fff; }}
        .badge-medium {{ background-color: #eab308; color: #000; }}
        .badge-low {{ background-color: #3b82f6; color: #fff; }}
        .badge-info {{ background-color: #64748b; color: #fff; }}
        
        .chain-item {{
            display: inline-block;
            background: #0f172a;
            color: #38bdf8;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            margin-right: 5px;
            border: 1px solid #38bdf8;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 FireBounty Security Report</h1>
            <p>Target: <strong>{target}</strong> | Assessment Priority Overview</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card stat-critical">
                <h3>Critical</h3>
                <p>{critical}</p>
            </div>
            <div class="stat-card stat-high">
                <h3>High</h3>
                <p>{high}</p>
            </div>
            <div class="stat-card stat-medium">
                <h3>Medium</h3>
                <p>{medium}</p>
            </div>
            <div class="stat-card stat-low">
                <h3>Low</h3>
                <p>{low}</p>
            </div>
        </div>
        
        <h2>🔍 Prioritized Threat Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>Severity</th>
                    <th>Score</th>
                    <th>Reason</th>
                    <th>Threat Chain</th>
                    <th>Secrets</th>
                    <th>Endpoints</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return True
    except Exception as e:
        log(f"[Report] Error writing HTML report: {e}")
        return False


def run(target: str) -> None:
    """
    Reads local correlated findings JSON and compiles HTML, MD, and CSV reports.
    """
    log(f"[*] Running Reporting Engine on {target}")
    
    findings_file = f"outputs/{target}/findings/correlated_threats.json"
    if not os.path.exists(findings_file):
        log(f"[!] Prioritized findings file {findings_file} not found. Skipping reporting.")
        return
        
    threats = load_json(findings_file)
    if not threats:
        log("[*] No threat profiles found in findings. Skipped reports generation.")
        return
        
    reports_dir = f"outputs/{target}/reports"
    
    csv_ok = generate_csv(threats, f"{reports_dir}/report.csv")
    md_ok = generate_markdown(threats, target, f"{reports_dir}/report.md")
    html_ok = generate_html(threats, target, f"{reports_dir}/report.html")
    
    if csv_ok and md_ok and html_ok:
        log(f"[SUCCESS] Reporting Engine completed. Reports generated inside outputs/{target}/reports/")
    else:
        log("[!] Some reports failed to compile. Check errors above.")
