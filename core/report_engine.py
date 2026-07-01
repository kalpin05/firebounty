"""
FireBounty v2 - Reporting Engine
Aggregates all module results and compiles HTML, Markdown, CSV, and JSON exports.
"""

import os
import json
import csv
import urllib.parse
from utils.logger import log

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>FireBounty Scan Report - {domain}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #ef4444; border-bottom: 2px solid #ef4444; padding-bottom: 10px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .card {{ background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; }}
        .card-title {{ font-size: 14px; color: #94a3b8; text-transform: uppercase; margin-bottom: 10px; }}
        .card-value {{ font-size: 28px; font-weight: bold; color: #38bdf8; }}
        .section {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 30px; margin-bottom: 30px; }}
        .section-title {{ font-size: 20px; color: #f1f5f9; border-bottom: 1px solid #334155; padding-bottom: 10px; margin-top: 0; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-high {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-medium {{ background: #78350f; color: #fde047; }}
        .badge-low {{ background: #1e3a8a; color: #93c5fd; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>FireBounty Intelligence Report</h1>
        <p style="color: #94a3b8;">Target Domain: <strong>{domain}</strong></p>
        
        <div class="grid">
            <div class="card">
                <div class="card-title">Subdomains Discovered</div>
                <div class="card-value">{subdomains}</div>
            </div>
            <div class="card">
                <div class="card-title">Alive Web Hosts</div>
                <div class="card-value">{alive}</div>
            </div>
            <div class="card">
                <div class="card-title">Leaked JS Secrets</div>
                <div class="card-value">{secrets}</div>
            </div>
            <div class="card">
                <div class="card-title">Vulnerabilities Found</div>
                <div class="card-value">{vulnerabilities}</div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">High Priority Attack Paths</div>
            {attack_paths_html}
        </div>

        <div class="section">
            <div class="section-title">Active Vulnerabilities</div>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Target Endpoint</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {vulns_table_rows}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <div class="section-title">Mapped Technologies</div>
            <p><strong>Servers:</strong> {servers_tech}</p>
            <p><strong>Frameworks:</strong> {frameworks_tech}</p>
            <p><strong>Cloud/CDNs:</strong> {cloud_tech}</p>
        </div>
    </div>
</body>
</html>
"""

class ReportEngine:
    def __init__(self, domain: str):
        self.domain = domain
        self.base_path = f"outputs/{domain}"
        self.reports_dir = os.path.join(self.base_path, "reports")
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Load core artifacts data
        self.summary_data = self._load_json("recon/summary.json")
        self.tech_data = self._load_json("technology/technology.json")
        self.js_data = self._load_json("javascript/javascript.json")
        self.vuln_data = self._load_json("findings/vulnerabilities.json")
        self.correlation_data = self._load_json("findings/correlations.json")

    def _load_json(self, relative_path: str) -> dict:
        path = os.path.join(self.base_path, relative_path)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def compile_reports(self) -> None:
        # Load stats
        sub_count = self.summary_data.get("subdomains", 0)
        alive_count = self.summary_data.get("alive", 0)
        secrets_count = self.js_data.get("summary", {}).get("total_secrets_found", 0)
        vuln_count = self.vuln_data.get("metrics", {}).get("total_vulnerabilities", 0)
        
        # Build vulnerabilities tables rows
        vuln_rows = []
        vulns_list = self.vuln_data.get("findings", [])
        if vulns_list:
            for v in vulns_list:
                sev = v["severity"].lower()
                badge_class = f"badge badge-{sev}"
                vuln_rows.append(f"""
                <tr>
                    <td><strong>{v['type']}</strong></td>
                    <td><span class="{badge_class}">{v['severity'].upper()}</span></td>
                    <td><code>{v['url']}</code></td>
                    <td>{v['detail']}</td>
                </tr>
                """)
        else:
            vuln_rows.append("<tr><td colspan='4'>No active vulnerabilities mapped.</td></tr>")
            
        # Build attack paths listings
        path_blocks = []
        paths_list = self.correlation_data.get("chains", [])
        if paths_list:
            for p in paths_list:
                path_blocks.append(f"""
                <div style="background: #0f172a; padding: 15px; border-radius: 6px; border-left: 4px solid #ef4444; margin-bottom: 15px;">
                    <div style="font-weight: bold; color: #f1f5f9; font-size: 16px;">{p['title']} ({p['severity'].upper()})</div>
                    <div style="color: #94a3b8; margin: 8px 0;">{p['reasoning']}</div>
                    <div style="font-size: 13px; color: #38bdf8;">Impact: {p['impact']}</div>
                </div>
                """)
        else:
            path_blocks.append("<p>No prioritized attack chains mapped.</p>")
            
        # Mapped tech lists
        tech_summary = self.tech_data.get("summary", {})
        servers = ", ".join(tech_summary.get("servers", [])) or "None detected"
        frameworks = ", ".join(tech_summary.get("frameworks", [])) or "None detected"
        cloud = ", ".join(tech_summary.get("cloud", [])) or "None detected"
        
        # 1. Compile HTML Dashboard
        html_content = HTML_TEMPLATE.format(
            domain=self.domain,
            subdomains=sub_count,
            alive=alive_count,
            secrets=secrets_count,
            vulnerabilities=vuln_count,
            attack_paths_html="".join(path_blocks),
            vulns_table_rows="".join(vuln_rows),
            servers_tech=servers,
            frameworks_tech=frameworks,
            cloud_tech=cloud
        )
        with open(os.path.join(self.reports_dir, "report.html"), "w", encoding="utf-8") as f:
            f.write(html_content)
            
        # 2. Compile Markdown report
        md_lines = [
            f"# FireBounty Scan Report - {self.domain}\n",
            f"**Subdomains Gathered:** {sub_count}",
            f"**Alive Web Hosts:** {alive_count}",
            f"**Identified Secrets:** {secrets_count}",
            f"**Total Vulnerabilities:** {vuln_count}\n",
            "## Mapped Technologies",
            f"* **Servers:** {servers}",
            f"* **Frameworks:** {frameworks}",
            f"* **Cloud / CDNs:** {cloud}\n",
            "## Prioritized Attack Chains"
        ]
        
        for p in paths_list:
            md_lines.append(f"### [{p['severity'].upper()}] {p['title']}")
            md_lines.append(f"* **Reasoning:** {p['reasoning']}")
            md_lines.append(f"* **Impact:** {p['impact']}\n")
            
        md_lines.append("## Vulnerability Registry Details")
        for v in vulns_list:
            md_lines.append(f"### [{v['severity'].upper()}] {v['type']}")
            md_lines.append(f"* **URL:** {v['url']}")
            md_lines.append(f"* **Detail:** {v['detail']}")
            if v.get("proof_url"):
                md_lines.append(f"* **Proof URL:** {v['proof_url']}")
            md_lines.append("")
            
        with open(os.path.join(self.reports_dir, "report.md"), "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines))
            
        # 3. Compile CSV report
        csv_path = os.path.join(self.reports_dir, "report.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Severity", "Vulnerability Type", "Target URL", "Details", "Proof URL"])
            for v in vulns_list:
                writer.writerow([v["severity"], v["type"], v["url"], v["detail"], v.get("proof_url", "")])
                
        # 4. Compile JSON master db
        json_path = os.path.join(self.reports_dir, "report.json")
        master_db = {
            "target": self.domain,
            "statistics": {
                "subdomains": sub_count,
                "alive": alive_count,
                "secrets": secrets_count,
                "vulnerabilities": vuln_count
            },
            "technologies": tech_summary,
            "attack_paths": paths_list,
            "vulnerabilities": vulns_list
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(master_db, f, indent=4)
            
        log(f"[✓] Compiled HTML, MD, CSV, and JSON exports under outputs/{self.domain}/reports/")

def run(target: str) -> None:
    log("[*] Initializing Report Compilation Engine")
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]
        
    engine = ReportEngine(domain)
    engine.compile_reports()
