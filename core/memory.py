#!/usr/bin/env python3
# core/memory.py - AI Memory & Learning Module

import json
import os
import datetime
from tinydb import TinyDB, Query

MEMORY_DIR = os.path.expanduser("~/pentest-ai/data/memory")
os.makedirs(MEMORY_DIR, exist_ok=True)

db = TinyDB(os.path.join(MEMORY_DIR, "memory.json"))
scans_table     = db.table("scans")
hosts_table     = db.table("hosts")
findings_table  = db.table("findings")
baselines_table = db.table("baselines")

def save_scan(target: str, scan_type: str, output: str, findings: list):
    """Save a completed scan to memory."""
    scans_table.insert({
        "target":    target,
        "scan_type": scan_type,
        "output":    output[:2000],
        "findings":  findings,
        "timestamp": datetime.datetime.now().isoformat()
    })
    update_host(target, findings)

def update_host(target: str, findings: list):
    """Update or create host profile."""
    Host = Query()
    existing = hosts_table.search(Host.target == target)
    now = datetime.datetime.now().isoformat()

    if existing:
        hosts_table.update({
            "last_seen":  now,
            "scan_count": existing[0].get("scan_count", 0) + 1,
            "findings":   findings
        }, Host.target == target)
    else:
        hosts_table.insert({
            "target":     target,
            "first_seen": now,
            "last_seen":  now,
            "scan_count": 1,
            "findings":   findings
        })

def save_finding(target: str, severity: str, finding: str, fixed: bool = False):
    """Save individual finding."""
    findings_table.insert({
        "target":    target,
        "severity":  severity,
        "finding":   finding,
        "fixed":     fixed,
        "timestamp": datetime.datetime.now().isoformat()
    })

def get_host_history(target: str) -> dict:
    """Get full history for a target."""
    Host = Query()
    host  = hosts_table.search(Host.target == target)
    scans = scans_table.search(Host.target == target)
    finds = findings_table.search(Host.target == target)
    return {
        "host":     host[0] if host else None,
        "scans":    scans,
        "findings": finds
    }

def get_all_hosts() -> list:
    """Get all known hosts."""
    return hosts_table.all()

def detect_changes(target: str, new_findings: list) -> list:
    """Compare new findings against last scan — detect changes."""
    Host = Query()
    existing = hosts_table.search(Host.target == target)
    if not existing:
        return []

    old_findings = set(existing[0].get("findings", []))
    new_set      = set(new_findings)
    changes      = []

    new_items     = new_set - old_findings
    resolved      = old_findings - new_set

    for item in new_items:
        changes.append(f"NEW: {item}")
    for item in resolved:
        changes.append(f"RESOLVED: {item}")

    return changes

def save_baseline(target: str, baseline_type: str, data: dict):
    """Save behavior baseline."""
    Base = Query()
    existing = baselines_table.search(
        (Base.target == target) & (Base.baseline_type == baseline_type)
    )
    now = datetime.datetime.now().isoformat()
    if existing:
        baselines_table.update(
            {"data": data, "updated": now},
            (Base.target == target) & (Base.baseline_type == baseline_type)
        )
    else:
        baselines_table.insert({
            "target":        target,
            "baseline_type": baseline_type,
            "data":          data,
            "created":       now,
            "updated":       now
        })

def get_baseline(target: str, baseline_type: str) -> dict:
    """Get saved baseline."""
    Base = Query()
    result = baselines_table.search(
        (Base.target == target) & (Base.baseline_type == baseline_type)
    )
    return result[0]["data"] if result else {}

def build_context_summary(target: str) -> str:
    """Build a context string for the AI about this target."""
    history = get_host_history(target)
    if not history["host"]:
        return f"No previous data on {target}. This is the first scan."

    host      = history["host"]
    scan_count = host.get("scan_count", 0)
    first_seen = host.get("first_seen", "unknown")
    last_seen  = host.get("last_seen", "unknown")
    findings   = history["findings"]

    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high     = [f for f in findings if f.get("severity") == "HIGH"]
    unfixed  = [f for f in findings if not f.get("fixed")]

    summary = f"""MEMORY CONTEXT for {target}:
- First scanned: {first_seen}
- Last scanned:  {last_seen}
- Total scans:   {scan_count}
- Known findings: {len(findings)} total, {len(critical)} critical, {len(high)} high
- Unfixed issues: {len(unfixed)}
"""
    if unfixed:
        summary += "- Unfixed issues:\n"
        for f in unfixed[:5]:
            summary += f"  * [{f.get('severity')}] {f.get('finding')}\n"

    return summary
