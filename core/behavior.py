#!/usr/bin/env python3
import os
import json
import time
import datetime
import subprocess
import hashlib
import threading
from tinydb import TinyDB, Query

MEMORY_DIR = os.path.expanduser("~/pentest-ai/data/memory")
BASELINE_DIR = os.path.expanduser("~/pentest-ai/data/baselines")
os.makedirs(MEMORY_DIR, exist_ok=True)
os.makedirs(BASELINE_DIR, exist_ok=True)

behavior_db    = TinyDB(os.path.join(MEMORY_DIR, "behavior.json"))
baseline_table = behavior_db.table("baselines")
anomaly_table  = behavior_db.table("anomalies")
snapshot_table = behavior_db.table("snapshots")

def get_running_processes():
    try:
        result = subprocess.run("ps aux --no-headers | awk '{print $11}'", shell=True, capture_output=True, text=True)
        return set(result.stdout.strip().splitlines())
    except:
        return set()

def get_open_ports():
    try:
        result = subprocess.run("netstat -tulpn 2>/dev/null | grep LISTEN | awk '{print $4}' | rev | cut -d: -f1 | rev", shell=True, capture_output=True, text=True)
        return set(result.stdout.strip().splitlines())
    except:
        return set()

def get_active_connections():
    try:
        result = subprocess.run("netstat -an 2>/dev/null | grep ESTABLISHED | awk '{print $5}'", shell=True, capture_output=True, text=True)
        return set(result.stdout.strip().splitlines())
    except:
        return set()

def get_logged_in_users():
    try:
        result = subprocess.run("who | awk '{print $1}'", shell=True, capture_output=True, text=True)
        return set(result.stdout.strip().splitlines())
    except:
        return set()

def get_cpu_memory_usage():
    try:
        cpu = subprocess.run("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'", shell=True, capture_output=True, text=True).stdout.strip()
        mem = subprocess.run("free | grep Mem | awk '{print ($3/$2)*100}'", shell=True, capture_output=True, text=True).stdout.strip()
        return {"cpu": float(cpu.replace("%us,","").strip()) if cpu else 0.0, "mem": float(mem) if mem else 0.0}
    except:
        return {"cpu": 0.0, "mem": 0.0}

def get_file_hashes(paths):
    hashes = {}
    for path in paths:
        try:
            with open(path, "rb") as f:
                hashes[path] = hashlib.sha256(f.read()).hexdigest()
        except:
            hashes[path] = None
    return hashes

def take_snapshot():
    critical_files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/hosts", "/etc/crontab"]
    return {
        "timestamp":   datetime.datetime.now().isoformat(),
        "processes":   list(get_running_processes()),
        "ports":       list(get_open_ports()),
        "connections": list(get_active_connections()),
        "users":       list(get_logged_in_users()),
        "resources":   get_cpu_memory_usage(),
        "file_hashes": get_file_hashes(critical_files)
    }

def build_baseline(samples=5, interval=60):
    print(f"\033[94m[*] Building behavioral baseline ({samples} samples, {interval}s apart)...\033[0m")
    print(f"\033[94m[*] This will take {samples * interval / 60:.1f} minutes.\033[0m")
    snapshots = []
    for i in range(samples):
        print(f"\033[94m[*] Taking snapshot {i+1}/{samples}...\033[0m")
        snapshots.append(take_snapshot())
        if i < samples - 1:
            time.sleep(interval)
    all_processes = set()
    all_ports = set()
    cpu_readings = []
    mem_readings = []
    for snap in snapshots:
        all_processes.update(snap["processes"])
        all_ports.update(snap["ports"])
        cpu_readings.append(snap["resources"]["cpu"])
        mem_readings.append(snap["resources"]["mem"])
    baseline = {
        "created":          datetime.datetime.now().isoformat(),
        "normal_processes": list(all_processes),
        "normal_ports":     list(all_ports),
        "normal_users":     list(snapshots[-1]["users"]),
        "file_hashes":      snapshots[-1]["file_hashes"],
        "cpu_avg":          sum(cpu_readings) / len(cpu_readings),
        "cpu_max":          max(cpu_readings) * 1.5,
        "mem_avg":          sum(mem_readings) / len(mem_readings),
        "mem_max":          min(max(mem_readings) * 1.5, 95.0),
        "sample_count":     samples
    }
    Base = Query()
    baseline_table.upsert({"key": "system_baseline", **baseline}, Base.key == "system_baseline")
    with open(os.path.join(BASELINE_DIR, "system_baseline.json"), "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"\033[92m[+] Baseline built! Processes: {len(all_processes)}, Ports: {list(all_ports)}\033[0m")
    return baseline

def load_baseline():
    Base = Query()
    result = baseline_table.search(Base.key == "system_baseline")
    if result:
        return result[0]
    path = os.path.join(BASELINE_DIR, "system_baseline.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}

def baseline_exists():
    return bool(load_baseline())

def detect_anomalies(baseline, current):
    anomalies = []
    now = datetime.datetime.now().isoformat()
    suspicious_keywords = ["nc", "netcat", "ncat", "nmap", "msfconsole", "hydra", "john", "hashcat", "sqlmap", "backdoor", "reverse", "shell", "exploit", "payload"]
    dangerous_ports  = ["4444", "1337", "31337", "6666", "9999", "4545"]
    honeypot_ports   = {"2222", "8888", "2121"}

    # Processes
    normal_procs  = set(baseline.get("normal_processes", []))
    current_procs = set(current.get("processes", []))
    for proc in current_procs - normal_procs:
        if any(kw in proc.lower() for kw in suspicious_keywords):
            anomalies.append({"type": "SUSPICIOUS_PROCESS", "severity": "CRITICAL", "detail": f"Suspicious process: {proc}", "timestamp": now})

    # Ports — skip honeypot ports
    normal_ports  = set(baseline.get("normal_ports", []))
    current_ports = set(current.get("ports", []))
    for port in (current_ports - normal_ports) - honeypot_ports:
        severity = "CRITICAL" if port in dangerous_ports else "HIGH"
        anomalies.append({"type": "NEW_PORT", "severity": severity, "detail": f"New port opened: {port}", "timestamp": now})

    # Users
    normal_users  = set(baseline.get("normal_users", []))
    current_users = set(current.get("users", []))
    for user in current_users - normal_users:
        anomalies.append({"type": "NEW_USER_LOGIN", "severity": "HIGH", "detail": f"New user login: {user}", "timestamp": now})

    # File integrity
    baseline_hashes = baseline.get("file_hashes", {})
    current_hashes  = current.get("file_hashes", {})
    for path, orig_hash in baseline_hashes.items():
        curr_hash = current_hashes.get(path)
        if curr_hash and orig_hash and curr_hash != orig_hash:
            anomalies.append({"type": "FILE_MODIFIED", "severity": "CRITICAL", "detail": f"Critical file modified: {path}", "timestamp": now})
        elif curr_hash is None and orig_hash:
            anomalies.append({"type": "FILE_MISSING", "severity": "CRITICAL", "detail": f"Critical file missing: {path}", "timestamp": now})

    # Resources
    resources = current.get("resources", {})
    if resources.get("cpu", 0) > baseline.get("cpu_max", 90.0):
        anomalies.append({"type": "HIGH_CPU", "severity": "HIGH", "detail": f"CPU {resources['cpu']:.1f}% exceeds baseline", "timestamp": now})
    if resources.get("mem", 0) > baseline.get("mem_max", 90.0):
        anomalies.append({"type": "HIGH_MEMORY", "severity": "HIGH", "detail": f"Memory {resources['mem']:.1f}% exceeds baseline", "timestamp": now})

    for anomaly in anomalies:
        anomaly_table.insert(anomaly)
    return anomalies
     

def get_recent_anomalies(limit=20):
    all_anomalies = anomaly_table.all()
    return sorted(all_anomalies, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]

def get_anomaly_summary():
    anomalies = get_recent_anomalies(10)
    if not anomalies:
        return "No anomalies detected recently."
    critical = [a for a in anomalies if a["severity"] == "CRITICAL"]
    high     = [a for a in anomalies if a["severity"] == "HIGH"]
    medium   = [a for a in anomalies if a["severity"] == "MEDIUM"]
    summary  = f"BEHAVIOR ANOMALIES:\nCritical: {len(critical)} | High: {len(high)} | Medium: {len(medium)}\n\n"
    for a in anomalies[:5]:
        summary += f"[{a['severity']}] {a['type']}: {a['detail']}\n"
    return summary

def start_behavior_monitor(alert_callback=None, interval=30):
    def monitor():
        baseline = load_baseline()
        if not baseline:
            print("\033[93m[!] No baseline found. Type 'baseline' to build one.\033[0m")
            return
        print(f"\033[92m[+] Behavior monitor active. Checking every {interval}s.\033[0m")
        while True:
            try:
                current   = take_snapshot()
                anomalies = detect_anomalies(baseline, current)
                if anomalies:
                    critical = [a for a in anomalies if a["severity"] == "CRITICAL"]
                    high     = [a for a in anomalies if a["severity"] == "HIGH"]
                    if critical or high:
                        print(f"\n\033[91m[BEHAVIOR ALERT] {len(critical)} critical, {len(high)} high!\033[0m")
                        for a in critical + high:
                            print(f"\033[91m  [{a['severity']}] {a['detail']}\033[0m")
                        if alert_callback:
                            alert_callback(get_anomaly_summary())
                time.sleep(interval)
            except Exception as e:
                print(f"\033[91m[!] Monitor error: {e}\033[0m")
                time.sleep(interval)
    t = threading.Thread(target=monitor, daemon=True)
    t.start()
    return t
