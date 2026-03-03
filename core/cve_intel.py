#!/usr/bin/env python3
# core/cve_intel.py - CVE Live Intelligence Module

import requests
import json
import os
import datetime
from tinydb import TinyDB, Query

MEMORY_DIR = os.path.expanduser("~/pentest-ai/data/memory")
os.makedirs(MEMORY_DIR, exist_ok=True)
cve_db = TinyDB(os.path.join(MEMORY_DIR, "cve_cache.json"))
cve_table = cve_db.table("cves")

def search_cves(service: str, version: str = "", max_results: int = 5) -> list:
    """Search NVD for CVEs matching a service/version."""
    Cve = Query()
    cache_key = f"{service}_{version}"

    # Check cache first (24 hour cache)
    cached = cve_table.search(Cve.cache_key == cache_key)
    if cached:
        cached_time = datetime.datetime.fromisoformat(cached[0]["timestamp"])
        if (datetime.datetime.now() - cached_time).seconds < 86400:
            return cached[0]["results"]

    # Query NVD API
    try:
        query = f"{service} {version}".strip()
        url   = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage={max_results}"
        resp  = requests.get(url, timeout=10)

        if resp.status_code != 200:
            return []

        data        = resp.json()
        cve_items   = data.get("vulnerabilities", [])
        results     = []

        for item in cve_items:
            cve  = item.get("cve", {})
            cvss = 0.0

            # Get CVSS score
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            # Get description
            descs = cve.get("descriptions", [])
            desc  = next((d["value"] for d in descs if d["lang"] == "en"), "No description")

            results.append({
                "id":          cve.get("id", "Unknown"),
                "description": desc[:300],
                "cvss_score":  cvss,
                "severity":    score_to_severity(cvss),
                "published":   cve.get("published", "Unknown"),
                "url":         f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}"
            })

        # Sort by CVSS score
        results.sort(key=lambda x: x["cvss_score"], reverse=True)

        # Cache results
        cve_table.upsert({
            "cache_key": cache_key,
            "results":   results,
            "timestamp": datetime.datetime.now().isoformat()
        }, Cve.cache_key == cache_key)

        return results

    except Exception as e:
        return [{"error": str(e)}]

def score_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0:    return "LOW"
    return "NONE"

def extract_services_from_nmap(nmap_output: str) -> list:
    """Parse nmap output and extract service/version pairs."""
    services = []
    for line in nmap_output.splitlines():
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "open":
                service = parts[2]
                version = " ".join(parts[3:6]) if len(parts) > 3 else ""
                services.append({
                    "port":    parts[0],
                    "service": service,
                    "version": version
                })
    return services

def analyze_nmap_for_cves(nmap_output: str) -> str:
    """Full pipeline: extract services from nmap → search CVEs → return report."""
    services = extract_services_from_nmap(nmap_output)
    if not services:
        return "No services detected in nmap output."

    report = "CVE INTELLIGENCE REPORT\n" + "="*50 + "\n"
    found_any = False

    for svc in services:
        cves = search_cves(svc["service"], svc["version"], max_results=3)
        if not cves or "error" in cves[0]:
            continue

        found_any = True
        report += f"\n[{svc['port']}] {svc['service']} {svc['version']}\n"

        for cve in cves:
            report += f"  ⚠ {cve['id']} | CVSS: {cve['cvss_score']} | {cve['severity']}\n"
            report += f"    {cve['description'][:150]}...\n"
            report += f"    Details: {cve['url']}\n"

    if not found_any:
        report += "No known CVEs found for detected services.\n"

    return report

def get_cve_summary_for_ai(nmap_output: str) -> str:
    """Get a compact CVE summary to inject into AI context."""
    services = extract_services_from_nmap(nmap_output)
    summary  = []

    for svc in services[:5]:
        cves = search_cves(svc["service"], svc["version"], max_results=2)
        if cves and "error" not in cves[0]:
            top = cves[0]
            summary.append(
                f"{svc['service']} {svc['version']} → {top['id']} (CVSS:{top['cvss_score']})"
            )

    return "\n".join(summary) if summary else "No CVEs found."
