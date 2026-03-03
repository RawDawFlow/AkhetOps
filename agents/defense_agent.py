#!/usr/bin/env python3
# defense_agent.py - Cross-Platform AI Cyber Defense Agent
# Supports: Linux, Windows, macOS

import subprocess
import os
import sys
import datetime
import time
import threading
import hashlib
import platform

# Add project root to path BEFORE any core imports
sys.path.insert(0, os.path.expanduser("~/pentest-ai"))

from core.honeypot import deploy_all_honeypots, get_honeypot_status, remove_all_honeypots
from core.behavior import (
    build_baseline, load_baseline, baseline_exists,
    take_snapshot, detect_anomalies, get_anomaly_summary,
    start_behavior_monitor
)
from core.key_manager import key_manager
from groq import Groq

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# ─── OS Detection ────────────────────────────────────────────
OS = platform.system()
OS_VERSION = platform.version()
OS_RELEASE = platform.release()

# ─── Report Setup ────────────────────────────────────────────
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
if OS == "Windows":
    report_dir = os.path.expanduser("~/defense_reports")
else:
    report_dir = os.path.expanduser("~/pentest-ai/defense_reports")

os.makedirs(report_dir, exist_ok=True)
report_file = os.path.join(report_dir, f"defense_{timestamp}.txt")

# ─── Critical Files ──────────────────────────────────────────
CRITICAL_FILES = {
    "Linux": [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/ssh/sshd_config", "/etc/hosts", "/etc/crontab"
    ],
    "Darwin": [
        "/etc/passwd", "/etc/hosts", "/etc/sudoers",
        "/etc/pf.conf"
    ],
    "Windows": [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ]
}

# ─── Tools ───────────────────────────────────────────────────
TOOLS = {
    "Linux": {
        "failed_logins":   "grep 'Failed password' /var/log/auth.log | tail -20",
        "active_users":    "who && w",
        "open_ports":      "netstat -tulpn",
        "processes":       "ps aux --sort=-%cpu | head -20",
        "firewall":        "iptables -L -n -v",
        "rootkit":         "rkhunter --check --skip-keypress",
        "services":        "systemctl list-units --state=running",
        "updates":         "apt list --upgradable 2>/dev/null",
        "suid":            "find / -perm -4000 2>/dev/null",
        "crons":           "crontab -l && cat /etc/crontab",
        "connections":     "netstat -an | grep ESTABLISHED",
        "block_ip":        "sudo iptables -A INPUT -s {ip} -j DROP",
        "kill_process":    "sudo kill -9 {pid}",
        "lock_user":       "sudo passwd -l {user}",
        "harden_ssh":      "sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
        "enable_firewall": "sudo ufw enable && sudo ufw default deny incoming",
        "check_integrity": "sha256sum /etc/passwd /etc/shadow /etc/sudoers",
        "lynis":           "sudo lynis audit system",
        "chkrootkit":      "sudo chkrootkit",
    },
    "Darwin": {
        "failed_logins":   "log show --predicate 'eventMessage contains \"Failed\"' --last 1h",
        "active_users":    "who && w",
        "open_ports":      "netstat -tulpn",
        "processes":       "ps aux | sort -k3 -rn | head -20",
        "firewall":        "pfctl -s rules",
        "rootkit":         "rkhunter --check --skip-keypress",
        "services":        "launchctl list | head -30",
        "updates":         "softwareupdate -l",
        "suid":            "find / -perm -4000 2>/dev/null",
        "crons":           "crontab -l && ls /Library/LaunchDaemons/",
        "connections":     "netstat -an | grep ESTABLISHED",
        "block_ip":        "sudo pfctl -t blocklist -T add {ip}",
        "kill_process":    "sudo kill -9 {pid}",
        "lock_user":       "sudo dscl . -append /Users/{user} AuthenticationAuthority ';DisabledUser;'",
        "harden_ssh":      "sudo sed -i '' 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
        "enable_firewall": "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
        "check_integrity": "sha256sum /etc/passwd /etc/hosts /etc/sudoers",
        "lynis":           "sudo lynis audit system",
        "chkrootkit":      "sudo chkrootkit",
    },
    "Windows": {
        "failed_logins":   'powershell "Get-EventLog -LogName Security -InstanceId 4625 -Newest 20 | Format-List"',
        "active_users":    'powershell "query user"',
        "open_ports":      'powershell "netstat -ano"',
        "processes":       'powershell "Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | Format-Table Name,Id,CPU"',
        "firewall":        'powershell "Get-NetFirewallProfile | Format-Table Name,Enabled"',
        "rootkit":         'powershell "Get-MpComputerStatus | Select-Object AMRunningMode,RealTimeProtectionEnabled"',
        "services":        'powershell "Get-Service | Where-Object {$_.Status -eq \'Running\'} | Format-Table Name,DisplayName"',
        "updates":         'powershell "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10"',
        "suid":            'powershell "Get-ChildItem C:\\Windows\\System32 -Filter *.exe | Get-Acl"',
        "crons":           'powershell "Get-ScheduledTask | Where-Object {$_.State -eq \'Ready\'} | Format-Table TaskName"',
        "connections":     'powershell "netstat -ano | findstr ESTABLISHED"',
        "block_ip":        'powershell "New-NetFirewallRule -DisplayName \'Block {ip}\' -Direction Inbound -RemoteAddress {ip} -Action Block"',
        "kill_process":    'powershell "Stop-Process -Id {pid} -Force"',
        "lock_user":       'powershell "Disable-LocalUser -Name \'{user}\'"',
        "harden_ssh":      'powershell "Set-NetFirewallRule -DisplayName \'SSH\' -Enabled True"',
        "enable_firewall": 'powershell "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"',
        "check_integrity": 'powershell "Get-FileHash C:\\Windows\\System32\\drivers\\etc\\hosts"',
        "lynis":           'echo "Lynis not available on Windows. Use winpeas or PowerSploit."',
        "chkrootkit":      'powershell "Get-MpThreatDetection | Format-List"',
    }
}

def get_tool(name):
    return TOOLS.get(OS, TOOLS["Linux"]).get(name, f"echo '{name} not available on {OS}'")

def get_critical_files():
    return CRITICAL_FILES.get(OS, CRITICAL_FILES["Linux"])

# ─── System Prompt ────────────────────────────────────────────
SYSTEM_PROMPT = f"""You are a professional Cyber Defense AI Agent protecting a {OS} system ({OS_RELEASE}).
You think like a senior SOC analyst and incident responder.

CURRENT SYSTEM: {OS} {OS_RELEASE}

Your job:
1. Analyze security data for {OS}
2. Detect threats, anomalies, vulnerabilities
3. Classify: CRITICAL, HIGH, MEDIUM, LOW
4. Suggest and apply OS-appropriate fixes

FIX POLICY:
- CRITICAL/HIGH: ASK_USER before fixing
- MEDIUM/LOW: AUTO_FIX silently

RESPONSE FORMAT for findings:
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>
FINDING: <what you found>
COMMAND: <exact command for {OS}>
REASON: <why>
ACTION: <AUTO_FIX or ASK_USER>

For conversation just reply naturally.
When done: DONE: <full security report>
Be concise to save tokens. Prioritize critical findings."""

conversation = [{"role": "system", "content": SYSTEM_PROMPT}]
monitoring_active = False
integrity_baseline = {}

# ─── Colors ───────────────────────────────────────────────────
COLORS = {
    "INFO":     "\033[0m",
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[92m",
    "SUCCESS":  "\033[92m",
    "CMD":      "\033[96m",
    "RESET":    "\033[0m"
}

def log(content, level="INFO"):
    color = COLORS.get(level, COLORS["INFO"])
    print(f"{color}[{level}] {content}{COLORS['RESET']}")
    with open(report_file, "a") as f:
        f.write(f"{datetime.datetime.now()} [{level}] {content}\n")

def ask_agent(message: str) -> str:
    conversation.append({"role": "user", "content": message})
    trimmed = [conversation[0]] + conversation[-6:]

    while True:
        try:
            current_client = Groq(api_key=key_manager.get_key())
            response = current_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=trimmed,
                max_tokens=1024
            )
            reply = response.choices[0].message.content or "No response generated."
            # Track token usage
            if hasattr(response, "usage") and response.usage:
                key_manager.track_usage(response.usage.total_tokens)
            conversation.append({"role": "assistant", "content": reply})
            return reply

        except Exception as e:
            error = str(e)
            if "429" in error or "rate_limit" in error.lower():
                wait = 60
                try:
                    if "Please try again in" in error:
                        wait_str = error.split("Please try again in")[1].split(".")[0].strip()
                        mins = float(wait_str.split("m")[0]) if "m" in wait_str else 0
                        secs = float(wait_str.split("m")[-1].replace("s","")) if "s" in wait_str else float(wait_str.replace("s",""))
                        wait = int(mins * 60 + secs) + 5
                except:
                    wait = 60
                key_manager.handle_rate_limit(wait)
            else:
                reply = f"API error: {error}"
                conversation.append({"role": "assistant", "content": reply})
                return reply

def run_command(command, silent=False):
    if not silent:
        log(f"Executing: {command}", "CMD")
    try:
        result = subprocess.run(
            command, shell=True,
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout + result.stderr
        if not silent and output:
            print(output[:1500])
        with open(report_file, "a") as f:
            f.write(f"CMD: {command}\nOUT: {output[:300]}\n")
        return output
    except subprocess.TimeoutExpired:
        return "Command timed out."
    except Exception as e:
        return f"Error: {str(e)}"

def extract_field(response, field):
    for line in response.splitlines():
        if line.startswith(f"{field}:"):
            return line.replace(f"{field}:", "").strip()
    return None


def check_integrity(baseline):
    changed = []
    for path, original_hash in baseline.items():
        try:
            with open(path, "rb") as f:
                current = hashlib.sha256(f.read()).hexdigest()
            if current != original_hash:
                changed.append(path)
        except:
            changed.append(f"{path} (missing)")
    return changed

def handle_finding(response):
    severity = extract_field(response, "SEVERITY") or "LOW"
    finding  = extract_field(response, "FINDING") or ""
    command  = extract_field(response, "COMMAND")
    action   = extract_field(response, "ACTION") or "ASK_USER"

    # Strip backticks if agent wraps command in them
    if command:
        command = command.strip("`")

    if finding:
        log(finding, severity)

    if not command:
        return response

    if action == "AUTO_FIX" and severity in ["LOW", "MEDIUM"]:
        log(f"Auto-fixing: {command}", "SUCCESS")
        output = run_command(command)
        followup = ask_agent(f"Fix output:\n{output[:500]}\nConfirm and continue briefly.")
        return followup
    else:
        log(f"Action required for {severity} finding!", severity)
        print(f"\n\033[91m[!] Proposed fix: {command}\033[0m")
        confirm = input("Apply this fix? (yes/no/skip): ").strip().lower()
        if confirm == "yes":
            output = run_command(command)
            followup = ask_agent(f"Fix output:\n{output[:500]}\nConfirm and continue briefly.")
            log("Fix applied.", "SUCCESS")
            return followup
        else:
            log("Fix skipped.", "INFO")
            return ask_agent("User declined fix. Note briefly and continue.")

def monitor_loop():
    global monitoring_active
    baseline = build_baseline()
    interval = 60
    log(f"24/7 monitoring active on {OS}. Checking every {interval}s.", "SUCCESS")

    while monitoring_active:
        time.sleep(interval)
        log("Running automated check...", "INFO")

        # File integrity
        changed = check_integrity(baseline)
        if changed:
            alert = f"FILE INTEGRITY ALERT: {', '.join(changed)}"
            log(alert, "CRITICAL")
            response = ask_agent(f"ALERT: {alert}\nBrief analysis and fix for {OS}.")
            print(f"\n[Agent]: {response}")
            handle_finding(response)

        # Failed logins
        failed = run_command(get_tool("failed_logins"), silent=True)
        if failed and len(failed.strip()) > 10:
            response = ask_agent(f"Failed logins on {OS}:\n{failed[:500]}\nBrute force? Be brief.")
            if "SEVERITY:" in response:
                print(f"\n[Agent]: {response}")
                handle_finding(response)

        # Processes
        procs = run_command(get_tool("processes"), silent=True)
        response = ask_agent(f"Process check on {OS}:\n{procs[:500]}\nOnly flag if malicious.")
        if "CRITICAL" in response or "HIGH" in response:
            print(f"\n[Agent]: {response}")
            handle_finding(response)

def main():
    monitoring_active = True
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()

    # Start behavior monitor if baseline exists
    if baseline_exists():
        print("\033[92m[+] Behavior fingerprint found — starting anomaly detection.\033[0m")
        def behavior_alert(summary):
            response = ask_agent(f"BEHAVIOR ANOMALY ALERT:\n{summary}\nAnalyze and suggest response.")
            print(f"\n\033[91m[Behavior Agent]: {response}\033[0m")
            handle_finding(response)
        start_behavior_monitor(alert_callback=behavior_alert, interval=30)
    else:
        print("\033[93m[!] No behavior baseline found. Type 'baseline' to build one.\033[0m")

    while True:
        try:
            user_input = input("\n[You]: ").strip()

            if not user_input:
                continue

            if user_input.lower() == "exit":
                monitoring_active = False
                log("Shutting down. Stay safe!", "SUCCESS")
                break

            if user_input.lower() == "stop":
                monitoring_active = False
                log("Monitoring stopped.", "INFO")
                continue

            if user_input.lower() == "keys":
                key_manager.status()
                continue

            if user_input.lower() == "monitor":
                if not monitoring_active:
                    monitoring_active = True
                    t = threading.Thread(target=monitor_loop, daemon=True)
                    t.start()
                    log("Monitoring restarted.", "SUCCESS")
                else:
                    log("Already monitoring.", "INFO")
                continue

            if user_input.lower() == "baseline":
                print("\033[94m[*] Building behavior baseline (5 samples, 1 min apart = 5 mins)...\033[0m")
                build_baseline(samples=5, interval=60)
                print("\033[92m[+] Baseline complete! Anomaly detection now active.\033[0m")
                def behavior_alert(summary):
                    response = ask_agent(f"BEHAVIOR ANOMALY ALERT:\n{summary}\nAnalyze and suggest response.")
                    print(f"\n\033[91m[Behavior Agent]: {response}\033[0m")
                    handle_finding(response)
                start_behavior_monitor(alert_callback=behavior_alert, interval=30)
                continue

            if user_input.lower() == "anomalies":
                summary = get_anomaly_summary()
                print(f"\n{summary}")
                continue

            if user_input.lower() == "honeypot":
                def honeypot_alert(alert):
                    print(f"\n\033[91m[HONEYPOT TRIGGERED] {alert['detail']}\033[0m")
                    response = ask_agent(f"HONEYPOT ALERT:\n{json.dumps(alert)}\nAnalyze and suggest response.")
                    print(f"\n[Agent]: {response}")
                    handle_finding(response)
                deploy_all_honeypots(alert_callback=honeypot_alert)
                continue

            if user_input.lower() == "honeypot status":
                print(get_honeypot_status())
                continue

            if user_input.lower() == "honeypot remove":
                remove_all_honeypots()
                continue

            if user_input.lower() == "scan":
                user_input = f"Full security scan of this {OS} system. Check logs, network, processes, ports, file integrity. Be concise, list findings with severity."

            if user_input.lower() == "report":
                log(f"Report: {report_file}", "INFO")
                response = ask_agent("Generate a concise professional security report of everything analyzed.")
                print(f"\n[Agent]:\n{response}")
                with open(report_file, "a") as f:
                    f.write(f"\n[FINAL REPORT]\n{response}\n")
                continue

            with open(report_file, "a") as f:
                f.write(f"\n[User]: {user_input}\n")

            response = ask_agent(user_input)
            print(f"\n[Agent]: {response}")

            while "COMMAND:" in response or "SEVERITY:" in response:
                response = handle_finding(response)
                if response and ("COMMAND:" in response or "SEVERITY:" in response):
                    print(f"\n[Agent]: {response}")
                else:
                    break

        except KeyboardInterrupt:
            print()
            log("Interrupted. Type 'exit' to quit.", "INFO")

if __name__ == "__main__":
    main()
