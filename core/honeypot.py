#!/usr/bin/env python3
# core/honeypot.py - Honeypot Deployer Module

import os
import socket
import threading
import datetime
import json
import time
from tinydb import TinyDB, Query

MEMORY_DIR = os.path.expanduser("~/pentest-ai/data/memory")
HONEYPOT_DIR = os.path.expanduser("~/pentest-ai/data/honeypots")
os.makedirs(MEMORY_DIR, exist_ok=True)
os.makedirs(HONEYPOT_DIR, exist_ok=True)

honeypot_db    = TinyDB(os.path.join(MEMORY_DIR, "honeypots.json"))
traps_table    = honeypot_db.table("traps")
triggers_table = honeypot_db.table("triggers")

active_honeypots = {}

# ─── Fake File Honeypots ──────────────────────────────────────

FAKE_FILES = {
    "passwords.txt": """admin:admin123
root:toor123
user:password123
backup:backup2024
""",
    "credentials.txt": """Database credentials:
Host: 192.168.1.100
User: dbadmin
Pass: Sup3rS3cr3t!
""",
    "config.bak": """[database]
host=localhost
user=root
password=P@ssw0rd123
db=production
""",
    "id_rsa": """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4Vou7HONEYPOT_TRAP_FILE
DO_NOT_USE_THIS_KEY_IT_IS_A_TRAP
-----END RSA PRIVATE KEY-----
""",
    "backup.sql": """-- Database backup
-- HONEYPOT FILE - DO NOT USE
INSERT INTO users VALUES ('admin','$2y$10$FAKEHASH');
INSERT INTO users VALUES ('root','$2y$10$FAKEHASH2');
""",
    ".env": """APP_KEY=base64:HONEYPOT_TRAP
DB_PASSWORD=FakePassword123!
AWS_SECRET=AKIAIOSFODNN7HONEYPOT
""",
    "secret_keys.txt": """API Keys (HONEYPOT):
stripe_key=sk_live_HONEYPOT123
twilio_key=HONEYPOT_AUTH_TOKEN
""",
}

def deploy_file_honeypots(paths: list = None) -> list:
    """Deploy fake sensitive files as honeypots."""
    if not paths:
        paths = [
            "/tmp",
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
        ]

    deployed = []
    for directory in paths:
        os.makedirs(directory, exist_ok=True)
        for filename, content in FAKE_FILES.items():
            filepath = os.path.join(directory, filename)
            try:
                with open(filepath, "w") as f:
                    f.write(content)

                # Save to DB
                traps_table.insert({
                    "type":      "file",
                    "path":      filepath,
                    "filename":  filename,
                    "deployed":  datetime.datetime.now().isoformat(),
                    "triggered": False
                })
                deployed.append(filepath)
                print(f"\033[92m[+] File honeypot deployed: {filepath}\033[0m")
            except Exception as e:
                print(f"\033[91m[!] Failed to deploy {filepath}: {e}\033[0m")

    return deployed

def monitor_file_honeypots(alert_callback=None):
    """Monitor honeypot files for access."""
    Trap = Query()
    traps = traps_table.search(Trap.type == "file")

    def monitor():
        # Get initial access times
        access_times = {}
        for trap in traps:
            try:
                access_times[trap["path"]] = os.path.getatime(trap["path"])
            except:
                pass

        print(f"\033[92m[+] Monitoring {len(traps)} file honeypots...\033[0m")

        while True:
            for trap in traps:
                path = trap["path"]
                try:
                    current_atime = os.path.getatime(path)
                    if path in access_times and current_atime != access_times[path]:
                        alert = {
                            "type":      "FILE_HONEYPOT_TRIGGERED",
                            "severity":  "CRITICAL",
                            "path":      path,
                            "timestamp": datetime.datetime.now().isoformat(),
                            "detail":    f"Honeypot file accessed: {path}"
                        }
                        triggers_table.insert(alert)
                        access_times[path] = current_atime

                        print(f"\n\033[91m[HONEYPOT TRIGGERED] {path} was accessed!\033[0m")

                        if alert_callback:
                            alert_callback(alert)
                except:
                    pass
            time.sleep(5)

    t = threading.Thread(target=monitor, daemon=True)
    t.start()
    return t

# ─── Fake Service Honeypots ───────────────────────────────────

def create_fake_ssh(port: int = 2222, alert_callback=None):
    """Deploy a fake SSH honeypot."""
    def handle_client(conn, addr):
        alert = {
            "type":      "SSH_HONEYPOT_TRIGGERED",
            "severity":  "CRITICAL",
            "source_ip": addr[0],
            "port":      port,
            "timestamp": datetime.datetime.now().isoformat(),
            "detail":    f"SSH honeypot triggered from {addr[0]}:{addr[1]}"
        }
        triggers_table.insert(alert)
        print(f"\n\033[91m[HONEYPOT] Fake SSH connection from {addr[0]}:{addr[1]}\033[0m")

        try:
            # Send fake SSH banner
            conn.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
            data = conn.recv(1024)

            # Log what they sent
            alert["data"] = data.hex()
            conn.send(b"Permission denied (publickey).\r\n")
            conn.close()
        except:
            pass

        if alert_callback:
            alert_callback(alert)

    def server():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(5)
            active_honeypots[f"ssh_{port}"] = s
            traps_table.insert({
                "type":     "service",
                "service":  "ssh",
                "port":     port,
                "deployed": datetime.datetime.now().isoformat()
            })
            print(f"\033[92m[+] Fake SSH honeypot listening on port {port}\033[0m")
            while True:
                try:
                    conn, addr = s.accept()
                    t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                    t.start()
                except:
                    break
        except Exception as e:
            print(f"\033[91m[!] SSH honeypot error: {e}\033[0m")

    t = threading.Thread(target=server, daemon=True)
    t.start()
    return t

def create_fake_http(port: int = 8888, alert_callback=None):
    """Deploy a fake HTTP honeypot."""
    def handle_client(conn, addr):
        try:
            data    = conn.recv(4096).decode("utf-8", errors="ignore")
            request = data.split("\n")[0] if data else "Unknown"

            alert = {
                "type":      "HTTP_HONEYPOT_TRIGGERED",
                "severity":  "HIGH",
                "source_ip": addr[0],
                "port":      port,
                "request":   request,
                "timestamp": datetime.datetime.now().isoformat(),
                "detail":    f"HTTP honeypot hit from {addr[0]} — {request}"
            }
            triggers_table.insert(alert)
            print(f"\n\033[93m[HONEYPOT] HTTP request from {addr[0]}: {request}\033[0m")

            # Send fake response
            response = """HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n
<html><body>
<h1>Admin Panel</h1>
<form method='post'>
Username: <input name='user'><br>
Password: <input type='password' name='pass'><br>
<input type='submit' value='Login'>
</form>
</body></html>"""
            conn.send(response.encode())
            conn.close()

            if alert_callback:
                alert_callback(alert)
        except:
            pass

    def server():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(5)
            active_honeypots[f"http_{port}"] = s
            traps_table.insert({
                "type":    "service",
                "service": "http",
                "port":    port,
                "deployed": datetime.datetime.now().isoformat()
            })
            print(f"\033[92m[+] Fake HTTP honeypot listening on port {port}\033[0m")
            while True:
                try:
                    conn, addr = s.accept()
                    t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                    t.start()
                except:
                    break
        except Exception as e:
            print(f"\033[91m[!] HTTP honeypot error: {e}\033[0m")

    t = threading.Thread(target=server, daemon=True)
    t.start()
    return t

def create_fake_ftp(port: int = 2121, alert_callback=None):
    """Deploy a fake FTP honeypot."""
    def handle_client(conn, addr):
        try:
            alert = {
                "type":      "FTP_HONEYPOT_TRIGGERED",
                "severity":  "HIGH",
                "source_ip": addr[0],
                "port":      port,
                "timestamp": datetime.datetime.now().isoformat(),
                "detail":    f"FTP honeypot triggered from {addr[0]}"
            }
            triggers_table.insert(alert)
            print(f"\n\033[93m[HONEYPOT] FTP connection from {addr[0]}\033[0m")

            conn.send(b"220 FTP Server Ready\r\n")
            while True:
                data = conn.recv(1024).decode("utf-8", errors="ignore").strip()
                if not data:
                    break
                if data.upper().startswith("USER"):
                    conn.send(b"331 Password required\r\n")
                elif data.upper().startswith("PASS"):
                    alert["credentials"] = data
                    triggers_table.upsert(alert, Query().source_ip == addr[0])
                    conn.send(b"530 Login incorrect\r\n")
                    break
                else:
                    conn.send(b"500 Unknown command\r\n")
            conn.close()

            if alert_callback:
                alert_callback(alert)
        except:
            pass

    def server():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(5)
            active_honeypots[f"ftp_{port}"] = s
            traps_table.insert({
                "type":     "service",
                "service":  "ftp",
                "port":     port,
                "deployed": datetime.datetime.now().isoformat()
            })
            print(f"\033[92m[+] Fake FTP honeypot listening on port {port}\033[0m")
            while True:
                try:
                    conn, addr = s.accept()
                    t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                    t.start()
                except:
                    break
        except Exception as e:
            print(f"\033[91m[!] FTP honeypot error: {e}\033[0m")

    t = threading.Thread(target=server, daemon=True)
    t.start()
    return t

# ─── Deploy All ───────────────────────────────────────────────

def deploy_all_honeypots(alert_callback=None) -> dict:
    """Deploy all honeypots at once."""
    print("\n\033[94m[*] Deploying AkhetOps Honeypot Grid...\033[0m")

    results = {
        "files":    deploy_file_honeypots(),
        "services": []
    }

    # Deploy fake services
    create_fake_ssh(2222, alert_callback)
    results["services"].append("SSH:2222")

    create_fake_http(8888, alert_callback)
    results["services"].append("HTTP:8888")

    create_fake_ftp(2121, alert_callback)
    results["services"].append("FTP:2121")

    # Start file monitor
    monitor_file_honeypots(alert_callback)

    print(f"\n\033[92m[+] Honeypot grid active!\033[0m")
    print(f"\033[92m[+] File traps: {len(results['files'])}\033[0m")
    print(f"\033[92m[+] Service traps: {results['services']}\033[0m")
    print(f"\033[93m[!] Any interaction will trigger a CRITICAL alert.\033[0m")

    return results

def get_honeypot_status() -> str:
    """Get status of all honeypots and triggers."""
    traps    = traps_table.all()
    triggers = triggers_table.all()

    status   = "\n[HONEYPOT STATUS]\n" + "="*40 + "\n"
    status  += f"Active traps: {len(traps)}\n"
    status  += f"Total triggers: {len(triggers)}\n"

    if triggers:
        status += "\nRecent triggers:\n"
        for t in sorted(triggers, key=lambda x: x.get("timestamp",""), reverse=True)[:5]:
            status += f"  [{t['severity']}] {t['detail']}\n"
            status += f"  Time: {t['timestamp']}\n\n"
    else:
        status += "\nNo triggers yet — system is clean.\n"

    return status

def remove_all_honeypots():
    """Remove all deployed honeypot files."""
    Trap = Query()
    file_traps = traps_table.search(Trap.type == "file")
    removed = 0
    for trap in file_traps:
        try:
            os.remove(trap["path"])
            removed += 1
        except:
            pass
    traps_table.truncate()
    print(f"\033[92m[+] Removed {removed} honeypot files.\033[0m")

    # Close sockets
    for name, sock in active_honeypots.items():
        try:
            sock.close()
        except:
            pass
    active_honeypots.clear()
    print(f"\033[92m[+] All honeypot services stopped.\033[0m")
