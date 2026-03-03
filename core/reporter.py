#!/usr/bin/env python3
# core/reporter.py - Professional Pentest Report Generator

import os
import datetime
import markdown2
from jinja2 import Template
from core.memory import get_host_history

REPORT_DIR = os.path.expanduser("~/pentest-ai/data/reports")
os.makedirs(REPORT_DIR, exist_ok=True)

# ─── HTML Template ────────────────────────────────────────────
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    margin: 0;
    padding: 0;
  }
  .cover {
    background: linear-gradient(135deg, #161b22, #21262d);
    padding: 80px 60px;
    border-bottom: 4px solid #f85149;
  }
  .cover h1 {
    font-size: 42px;
    color: #f85149;
    margin: 0 0 10px 0;
    letter-spacing: 2px;
    text-transform: uppercase;
  }
  .cover h2 {
    font-size: 22px;
    color: #8b949e;
    margin: 0 0 40px 0;
    font-weight: normal;
  }
  .cover .meta {
    display: flex;
    gap: 40px;
    margin-top: 40px;
  }
  .cover .meta-item {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px 24px;
  }
  .cover .meta-item .label {
    font-size: 11px;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  .cover .meta-item .value {
    font-size: 16px;
    color: #c9d1d9;
    margin-top: 4px;
    font-weight: bold;
  }
  .container {
    max-width: 1000px;
    margin: 0 auto;
    padding: 40px 60px;
  }
  h2 {
    color: #f85149;
    font-size: 22px;
    border-bottom: 1px solid #30363d;
    padding-bottom: 8px;
    margin-top: 40px;
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  h3 {
    color: #79c0ff;
    font-size: 16px;
    margin-top: 24px;
  }
  .risk-bar {
    display: flex;
    gap: 16px;
    margin: 24px 0;
    flex-wrap: wrap;
  }
  .risk-badge {
    border-radius: 6px;
    padding: 12px 20px;
    font-weight: bold;
    font-size: 14px;
    text-align: center;
    min-width: 80px;
  }
  .critical { background: #3d1a1a; border: 1px solid #f85149; color: #f85149; }
  .high     { background: #2d2000; border: 1px solid #e3b341; color: #e3b341; }
  .medium   { background: #1a2d40; border: 1px solid #79c0ff; color: #79c0ff; }
  .low      { background: #1a2d1a; border: 1px solid #56d364; color: #56d364; }
  .finding-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-left: 4px solid #f85149;
    border-radius: 8px;
    padding: 20px 24px;
    margin: 16px 0;
  }
  .finding-card.high   { border-left-color: #e3b341; }
  .finding-card.medium { border-left-color: #79c0ff; }
  .finding-card.low    { border-left-color: #56d364; }
  .finding-card h4 {
    margin: 0 0 8px 0;
    color: #c9d1d9;
    font-size: 15px;
  }
  .finding-card p {
    margin: 4px 0;
    color: #8b949e;
    font-size: 13px;
    line-height: 1.6;
  }
  .severity-tag {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
    margin-bottom: 8px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 16px 0;
    font-size: 13px;
  }
  th {
    background: #21262d;
    color: #8b949e;
    padding: 10px 16px;
    text-align: left;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 1px;
  }
  td {
    padding: 10px 16px;
    border-bottom: 1px solid #21262d;
    color: #c9d1d9;
  }
  tr:hover td { background: #161b22; }
  code {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 2px 6px;
    font-family: monospace;
    font-size: 12px;
    color: #79c0ff;
  }
  pre {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px;
    overflow-x: auto;
    font-size: 12px;
    color: #8b949e;
    line-height: 1.6;
  }
  .timeline {
    border-left: 2px solid #30363d;
    padding-left: 24px;
    margin: 16px 0;
  }
  .timeline-item {
    position: relative;
    margin-bottom: 16px;
  }
  .timeline-item::before {
    content: '';
    position: absolute;
    left: -30px;
    top: 6px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #f85149;
    border: 2px solid #0d1117;
  }
  .timeline-item .time {
    font-size: 11px;
    color: #8b949e;
  }
  .timeline-item .desc {
    color: #c9d1d9;
    font-size: 13px;
  }
  .recommendation {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px 20px;
    margin: 12px 0;
    display: flex;
    gap: 16px;
    align-items: flex-start;
  }
  .rec-priority {
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
    min-width: 60px;
    padding-top: 2px;
  }
  .rec-content { flex: 1; }
  .rec-content strong { color: #c9d1d9; font-size: 14px; }
  .rec-content p { color: #8b949e; font-size: 13px; margin: 4px 0 0 0; }
  .footer {
    background: #161b22;
    border-top: 1px solid #30363d;
    padding: 24px 60px;
    margin-top: 60px;
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    color: #8b949e;
  }
  .watermark { color: #f85149; font-weight: bold; }
</style>
</head>
<body>

<div class="cover">
  <h1>⚡ Penetration Test Report</h1>
  <h2>Security Assessment — {{ target }}</h2>
  <div class="meta">
    <div class="meta-item">
      <div class="label">Target</div>
      <div class="value">{{ target }}</div>
    </div>
    <div class="meta-item">
      <div class="label">Date</div>
      <div class="value">{{ date }}</div>
    </div>
    <div class="meta-item">
      <div class="label">Overall Risk</div>
      <div class="value" style="color: {{ risk_color }}">{{ overall_risk }}</div>
    </div>
    <div class="meta-item">
      <div class="label">Total Findings</div>
      <div class="value">{{ total_findings }}</div>
    </div>
  </div>
</div>

<div class="container">

  <h2>Executive Summary</h2>
  <p>{{ executive_summary }}</p>

  <h2>Risk Overview</h2>
  <div class="risk-bar">
    <div class="risk-badge critical">CRITICAL<br>{{ critical_count }}</div>
    <div class="risk-badge high">HIGH<br>{{ high_count }}</div>
    <div class="risk-badge medium">MEDIUM<br>{{ medium_count }}</div>
    <div class="risk-badge low">LOW<br>{{ low_count }}</div>
  </div>

  <h2>Attack Surface</h2>
  <table>
    <tr>
      <th>Port</th><th>Service</th><th>Version</th><th>Risk</th>
    </tr>
    {% for port in open_ports %}
    <tr>
      <td><code>{{ port.port }}</code></td>
      <td>{{ port.service }}</td>
      <td>{{ port.version }}</td>
      <td class="{{ port.risk|lower }}">{{ port.risk }}</td>
    </tr>
    {% endfor %}
  </table>

  <h2>Detailed Findings</h2>
  {% for finding in findings %}
  <div class="finding-card {{ finding.severity|lower }}">
    <span class="severity-tag {{ finding.severity|lower }}">{{ finding.severity }}</span>
    <h4>{{ finding.title }}</h4>
    <p><strong>Description:</strong> {{ finding.description }}</p>
    <p><strong>Impact:</strong> {{ finding.impact }}</p>
    <p><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
    {% if finding.cve %}
    <p><strong>CVE:</strong> <code>{{ finding.cve }}</code></p>
    {% endif %}
  </div>
  {% endfor %}

  <h2>CVE Intelligence</h2>
  {% if cve_findings %}
  <table>
    <tr>
      <th>CVE ID</th><th>Service</th><th>CVSS</th><th>Severity</th>
    </tr>
    {% for cve in cve_findings %}
    <tr>
      <td><code>{{ cve.id }}</code></td>
      <td>{{ cve.service }}</td>
      <td>{{ cve.cvss }}</td>
      <td class="{{ cve.severity|lower }}">{{ cve.severity }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>No CVEs detected for identified services.</p>
  {% endif %}

  <h2>Attack Timeline</h2>
  <div class="timeline">
    {% for event in timeline %}
    <div class="timeline-item">
      <div class="time">{{ event.time }}</div>
      <div class="desc">{{ event.desc }}</div>
    </div>
    {% endfor %}
  </div>

  <h2>Recommendations</h2>
  {% for rec in recommendations %}
  <div class="recommendation">
    <div class="rec-priority {{ rec.priority|lower }}">{{ rec.priority }}</div>
    <div class="rec-content">
      <strong>{{ rec.title }}</strong>
      <p>{{ rec.description }}</p>
    </div>
  </div>
  {% endfor %}

  <h2>Conclusion</h2>
  <p>{{ conclusion }}</p>

</div>

<div class="footer">
  <span>Generated by <span class="watermark">AI Pentest Suite</span></span>
  <span>{{ date }} — CONFIDENTIAL</span>
</div>

</body>
</html>
"""

def generate_report(
    target: str,
    executive_summary: str,
    findings: list,
    open_ports: list,
    cve_findings: list,
    recommendations: list,
    timeline: list,
    conclusion: str,
    overall_risk: str = "HIGH"
) -> str:
    """Generate a professional HTML pentest report."""

    risk_colors = {
        "CRITICAL": "#f85149",
        "HIGH":     "#e3b341",
        "MEDIUM":   "#79c0ff",
        "LOW":      "#56d364"
    }

    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count     = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium_count   = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count      = sum(1 for f in findings if f.get("severity") == "LOW")

    template = Template(HTML_TEMPLATE)
    html = template.render(
        target           = target,
        date             = datetime.datetime.now().strftime("%B %d, %Y %H:%M"),
        overall_risk     = overall_risk,
        risk_color       = risk_colors.get(overall_risk, "#e3b341"),
        total_findings   = len(findings),
        critical_count   = critical_count,
        high_count       = high_count,
        medium_count     = medium_count,
        low_count        = low_count,
        executive_summary = executive_summary,
        findings         = findings,
        open_ports       = open_ports,
        cve_findings     = cve_findings,
        recommendations  = recommendations,
        timeline         = timeline,
        conclusion       = conclusion
    )

    # Save HTML report
    timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORT_DIR, f"report_{target}_{timestamp}.html")
    with open(report_path, "w") as f:
        f.write(html)

    # Try PDF generation
    try:
        from weasyprint import HTML as WP
        pdf_path = report_path.replace(".html", ".pdf")
        WP(string=html).write_pdf(pdf_path)
        print(f"\033[92m[+] PDF report saved: {pdf_path}\033[0m")
    except Exception as e:
        print(f"\033[93m[!] PDF generation skipped: {e}\033[0m")
        print(f"\033[92m[+] HTML report saved: {report_path}\033[0m")

    return report_path

def build_report_from_agent(target: str, agent_summary: str, raw_scan: str = "") -> str:
    """Parse agent output and auto-build report structure."""
    from core.cve_intel import extract_services_from_nmap, search_cves

    # Parse open ports from nmap output
    open_ports = []
    if raw_scan:
        services = extract_services_from_nmap(raw_scan)
        for svc in services:
            open_ports.append({
                "port":    svc["port"],
                "service": svc["service"],
                "version": svc["version"],
                "risk":    "MEDIUM"
            })

    # Parse CVEs
    cve_findings = []
    if raw_scan:
        services = extract_services_from_nmap(raw_scan)
        for svc in services[:5]:
            cves = search_cves(svc["service"], svc["version"], max_results=2)
            for cve in cves:
                if "error" not in cve:
                    cve_findings.append({
                        "id":       cve["id"],
                        "service":  f"{svc['service']} {svc['version']}",
                        "cvss":     cve["cvss_score"],
                        "severity": cve["severity"]
                    })

    # Build findings from agent summary
    findings = []
    lines    = agent_summary.splitlines()
    for line in lines:
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if severity in line.upper():
                findings.append({
                    "title":          line[:80],
                    "severity":       severity,
                    "description":    line,
                    "impact":         "Potential system compromise or data exposure.",
                    "recommendation": "Review and remediate immediately.",
                    "cve":            None
                })
                break

    # Default finding if none parsed
    if not findings:
        findings.append({
            "title":          "Security Assessment Complete",
            "severity":       "MEDIUM",
            "description":    agent_summary[:300],
            "impact":         "See full agent analysis above.",
            "recommendation": "Review all findings and apply patches.",
            "cve":            None
        })

    # Build timeline from memory
    history  = get_host_history(target)
    timeline = []
    for scan in history.get("scans", [])[-5:]:
        timeline.append({
            "time": scan.get("timestamp", "")[:16],
            "desc": f"Scan performed — {len(scan.get('findings', []))} findings"
        })
    if not timeline:
        timeline.append({
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "desc": "Initial security assessment performed"
        })

    recommendations = [
        {
            "priority":    "CRITICAL",
            "title":       "Patch all critical vulnerabilities immediately",
            "description": "Address all CRITICAL and HIGH severity findings within 24-48 hours."
        },
        {
            "priority": "HIGH",
            "title":    "Enable and configure firewall",
            "description": "Ensure only necessary ports are exposed. Block all unused services."
        },
        {
            "priority": "MEDIUM",
            "title":    "Implement regular security scanning",
            "description": "Schedule automated scans weekly to catch new vulnerabilities early."
        },
        {
            "priority": "LOW",
            "title":    "Security awareness and hardening",
            "description": "Follow CIS benchmarks for system hardening and keep all software updated."
        }
    ]

    overall_risk = "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else \
                   "HIGH"     if any(f["severity"] == "HIGH"     for f in findings) else \
                   "MEDIUM"

    return generate_report(
        target            = target,
        executive_summary = f"A comprehensive penetration test was conducted against {target}. "
                            f"The assessment identified {len(findings)} findings across multiple attack vectors. "
                            f"Immediate attention is required for critical and high severity issues.",
        findings          = findings,
        open_ports        = open_ports,
        cve_findings      = cve_findings,
        recommendations   = recommendations,
        timeline          = timeline,
        conclusion        = f"The security posture of {target} requires immediate attention. "
                            f"All critical findings must be remediated before the system is considered secure. "
                            f"A follow-up assessment is recommended after remediation.",
        overall_risk      = overall_risk
    )
