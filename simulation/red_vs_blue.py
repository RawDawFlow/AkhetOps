#!/usr/bin/env python3
# simulation/red_vs_blue.py - AkhetOps Red vs Blue Simulation

import os
import sys
import json
import time
import datetime
import threading
import subprocess

sys.path.insert(0, os.path.expanduser("~/pentest-ai"))

from groq import Groq
from core.key_manager import key_manager
from core.cve_intel import analyze_nmap_for_cves, get_cve_summary_for_ai
from core.memory import save_scan, save_finding
from core.honeypot import deploy_all_honeypots, get_honeypot_status
from core.behavior import build_baseline, start_behavior_monitor, get_anomaly_summary

REPORT_DIR = os.path.expanduser("~/pentest-ai/data/reports")
os.makedirs(REPORT_DIR, exist_ok=True)

timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
report_file = os.path.join(REPORT_DIR, f"simulation_{timestamp}.txt")

# ─── Colors ───────────────────────────────────────────────────
R = "\033[91m"   # Red
B = "\033[94m"   # Blue
Y = "\033[93m"   # Yellow
G = "\033[92m"   # Green
C = "\033[96m"   # Cyan
W = "\033[0m"    # Reset
BOLD = "\033[1m"

# ─── Simulation State ─────────────────────────────────────────
simulation_state = {
    "round":           0,
    "red_score":       0,
    "blue_score":      0,
    "red_findings":    [],
    "blue_responses":  [],
    "timeline":        [],
    "winner":          None,
    "target":          "",
    "start_time":      None,
    "end_time":        None
}

# ─── AI Agents ────────────────────────────────────────────────
red_conversation  = []
blue_conversation = []

RED_SYSTEM = """You are an aggressive Red Team AI pentester in a simulation.
Your goal is to find and exploit vulnerabilities as fast as possible.
Think like an attacker — be creative, persistent and technical.

Each round you must:
1. Analyze what you know so far
2. Choose the best attack action
3. Respond ONLY in this format:

ACTION: <what you're doing>
COMMAND: <exact command to run>
REASON: <why this will work>
SCORE_ATTEMPT: <what you're trying to achieve, 1-10 difficulty>

Be aggressive and technical. Base actions on real scan data."""

BLUE_SYSTEM = """You are a defensive Blue Team AI security analyst in a simulation.
Your goal is to detect, respond to and neutralize red team attacks.
Think like a defender — be thorough, fast and decisive.

Each round you must:
1. Analyze what the red team did
2. Choose the best defensive response
3. Respond ONLY in this format:

DETECTION: <what you detected>
RESPONSE: <defensive action>
COMMAND: <exact command to run>
MITIGATION: <how you're stopping the attack>
SCORE_DEFENSE: <how well you defended, 1-10>

Be decisive and technical."""

def log(content: str, team: str = "SIM"):
    colors = {"RED": R, "BLUE": B, "SIM": Y, "WIN": G}
    color  = colors.get(team, Y)
    msg    = f"{color}[{team}] {content}{W}"
    print(msg)
    with open(report_file, "a") as f:
        f.write(f"{datetime.datetime.now()} [{team}] {content}\n")

def ask_red(message: str) -> str:
    red_conversation.append({"role": "user", "content": message})
    trimmed = [{"role": "system", "content": RED_SYSTEM}] + red_conversation[-6:]
    try:
        client   = Groq(api_key=key_manager.get_key())
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=trimmed,
            max_tokens=512
        )
        reply = response.choices[0].message.content or ""
        red_conversation.append({"role": "assistant", "content": reply})
        return reply
    except Exception as e:
        if "429" in str(e):
            key_manager.handle_rate_limit(30)
            return ask_red(message)
        return f"Error: {e}"

def ask_blue(message: str) -> str:
    blue_conversation.append({"role": "user", "content": message})
    trimmed = [{"role": "system", "content": BLUE_SYSTEM}] + blue_conversation[-6:]
    try:
        client   = Groq(api_key=key_manager.get_key())
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=trimmed,
            max_tokens=512
        )
        reply = response.choices[0].message.content or ""
        blue_conversation.append({"role": "assistant", "content": reply})
        return reply
    except Exception as e:
        if "429" in str(e):
            key_manager.handle_rate_limit(30)
            return ask_blue(message)
        return f"Error: {e}"

def run_command(command: str, timeout: int = 60) -> str:
    try:
        result = subprocess.run(
            command, shell=True,
            capture_output=True, text=True,
            timeout=timeout
        )
        return (result.stdout + result.stderr)[:1000]
    except subprocess.TimeoutExpired:
        return "Command timed out."
    except Exception as e:
        return f"Error: {str(e)}"

def extract_field(text: str, field: str) -> str:
    for line in text.splitlines():
        if line.startswith(f"{field}:"):
            return line.replace(f"{field}:", "").strip()
    return ""

def calculate_scores(red_response: str, blue_response: str, command_output: str) -> tuple:
    red_score  = 0
    blue_score = 0

    # Red scores points for finding things
    if any(kw in command_output.lower() for kw in ["open", "found", "success", "vulnerable", "running"]):
        red_score += 3
    if any(kw in command_output.lower() for kw in ["password", "credential", "hash", "admin", "root"]):
        red_score += 5
    if "error" in command_output.lower() or "failed" in command_output.lower():
        red_score += 0

    # Blue scores points for detecting/blocking
    detection = extract_field(blue_response, "DETECTION")
    if detection and len(detection) > 10:
        blue_score += 3
    mitigation = extract_field(blue_response, "MITIGATION")
    if mitigation and len(mitigation) > 10:
        blue_score += 2
    blue_cmd = extract_field(blue_response, "COMMAND")
    if blue_cmd and "block" in blue_cmd.lower() or "deny" in blue_cmd.lower():
        blue_score += 2

    return red_score, blue_score

def print_scoreboard():
    red  = simulation_state["red_score"]
    blue = simulation_state["blue_score"]
    rnd  = simulation_state["round"]

    print(f"\n{BOLD}{'='*60}{W}")
    print(f"{BOLD}  AKHETOPS SIMULATION — ROUND {rnd} SCOREBOARD{W}")
    print(f"{BOLD}{'='*60}{W}")
    print(f"  {R}🔴 RED TEAM:  {red:3d} points{W}")
    print(f"  {B}🔵 BLUE TEAM: {blue:3d} points{W}")

    if red > blue:
        print(f"  {R}Red team is winning by {red-blue} points{W}")
    elif blue > red:
        print(f"  {B}Blue team is winning by {blue-red} points{W}")
    else:
        print(f"  {Y}Tied game!{W}")
    print(f"{BOLD}{'='*60}{W}\n")

def generate_final_report() -> str:
    state    = simulation_state
    duration = "Unknown"
    if state["start_time"] and state["end_time"]:
        delta    = state["end_time"] - state["start_time"]
        duration = f"{int(delta.total_seconds() / 60)}m {int(delta.total_seconds() % 60)}s"

    winner = state["winner"] or ("RED" if state["red_score"] > state["blue_score"] else "BLUE" if state["blue_score"] > state["red_score"] else "TIE")

    report = f"""
{'='*60}
  AKHETOPS RED VS BLUE SIMULATION — FINAL REPORT
{'='*60}
Target:   {state['target']}
Duration: {duration}
Rounds:   {state['round']}
Winner:   {'🔴 RED TEAM' if winner == 'RED' else '🔵 BLUE TEAM' if winner == 'BLUE' else '🤝 TIE'}

FINAL SCORES:
  🔴 Red Team:  {state['red_score']} points
  🔵 Blue Team: {state['blue_score']} points

RED TEAM FINDINGS:
"""
    for i, f in enumerate(state["red_findings"], 1):
        report += f"  {i}. {f}\n"

    report += "\nBLUE TEAM RESPONSES:\n"
    for i, r in enumerate(state["blue_responses"], 1):
        report += f"  {i}. {r}\n"

    report += "\nBATTLE TIMELINE:\n"
    for event in state["timeline"]:
        report += f"  {event}\n"

    report += f"\n{'='*60}\n"

    # Save report
    with open(report_file, "a") as f:
        f.write(report)

    return report

def run_simulation(target: str, rounds: int = 5):
    """Run the full Red vs Blue simulation."""
    simulation_state["target"]     = target
    simulation_state["start_time"] = datetime.datetime.now()

    print(f"\n{BOLD}{'='*60}{W}")
    print(f"{BOLD}  ⚔️  AKHETOPS RED VS BLUE SIMULATION{W}")
    print(f"{BOLD}  Target: {target}{W}")
    print(f"{BOLD}  Rounds: {rounds}{W}")
    print(f"{BOLD}{'='*60}{W}")
    print(f"\n{Y}[SIM] Initializing simulation...{W}")

    # Phase 1 — Initial recon
    log(f"Starting initial recon on {target}...", "SIM")
    nmap_output = run_command(f"nmap -sV -T4 --top-ports 100 {target}", timeout=120)
    log(f"Recon complete. Analyzing...", "SIM")

    # Get CVE intel
    cve_summary = get_cve_summary_for_ai(nmap_output)

    initial_context = f"""Target: {target}
Nmap scan results:
{nmap_output[:1500]}

CVE Intelligence:
{cve_summary}

You are starting your attack. What is your first move?"""

    # Phase 2 — Battle rounds
    for round_num in range(1, rounds + 1):
        simulation_state["round"] = round_num

        print(f"\n{BOLD}{Y}{'─'*60}{W}")
        print(f"{BOLD}{Y}  ROUND {round_num}/{rounds}{W}")
        print(f"{BOLD}{Y}{'─'*60}{W}")

        # Red team attacks
        log(f"Red team thinking...", "RED")
        red_input   = initial_context if round_num == 1 else f"Previous command output:\n{prev_output}\n\nContinue your attack."
        red_response = ask_red(red_input)

        print(f"\n{R}[RED TEAM]:{W}")
        print(red_response)

        # Extract and run red team command
        red_command = extract_field(red_response, "COMMAND").strip("`")
        red_action  = extract_field(red_response, "ACTION")
        prev_output = ""

        if red_command and red_command not in ["N/A", "None", ""]:
            log(f"Executing: {red_command}", "RED")
            prev_output = run_command(red_command)
            print(f"{R}[RED OUTPUT]: {prev_output[:300]}{W}")

            # Save finding
            if red_action:
                simulation_state["red_findings"].append(red_action)
                save_finding(target, "HIGH", f"[RED TEAM] {red_action}")

        # Blue team responds
        log(f"Blue team responding...", "BLUE")
        blue_input    = f"""Red team just ran: {red_command}
Red team output: {prev_output[:500]}
Red team action: {red_action}

Detect and respond to this attack."""

        blue_response = ask_blue(blue_input)

        print(f"\n{B}[BLUE TEAM]:{W}")
        print(blue_response)

        # Execute blue team response
        blue_command = extract_field(blue_response, "COMMAND").strip("`")
        if blue_command and blue_command not in ["N/A", "None", ""]:
            log(f"Executing defense: {blue_command}", "BLUE")
            blue_output = run_command(blue_command)
            print(f"{B}[BLUE OUTPUT]: {blue_output[:200]}{W}")

        # Calculate scores
        red_pts, blue_pts = calculate_scores(red_response, blue_response, prev_output)
        simulation_state["red_score"]  += red_pts
        simulation_state["blue_score"] += blue_pts

        # Log timeline
        event = f"Round {round_num}: Red({red_action[:50]}) vs Blue({extract_field(blue_response, 'DETECTION')[:50]})"
        simulation_state["timeline"].append(event)

        # Save blue response
        blue_detection = extract_field(blue_response, "DETECTION")
        if blue_detection:
            simulation_state["blue_responses"].append(blue_detection)

        # Show scoreboard
        print_scoreboard()

        # Small delay between rounds
        time.sleep(2)

    # Phase 3 — Final report
    simulation_state["end_time"] = datetime.datetime.now()

    red  = simulation_state["red_score"]
    blue = simulation_state["blue_score"]
    simulation_state["winner"] = "RED" if red > blue else "BLUE" if blue > red else "TIE"

    print(f"\n{BOLD}{'='*60}{W}")
    print(f"{BOLD}  ⚔️  SIMULATION COMPLETE!{W}")
    print(f"{BOLD}{'='*60}{W}")

    if simulation_state["winner"] == "RED":
        print(f"{R}{BOLD}  🔴 RED TEAM WINS! System compromised.{W}")
        print(f"{R}  Recommendation: Urgent security hardening needed!{W}")
    elif simulation_state["winner"] == "BLUE":
        print(f"{B}{BOLD}  🔵 BLUE TEAM WINS! Attack repelled.{W}")
        print(f"{B}  Recommendation: Good defenses, keep monitoring!{W}")
    else:
        print(f"{Y}{BOLD}  🤝 TIE! Evenly matched.{W}")
        print(f"{Y}  Recommendation: Some improvements needed on both sides.{W}")

    report = generate_final_report()
    print(report)
    print(f"{G}[+] Full report saved: {report_file}{W}")

    return simulation_state

def main():
    print(f"\n{BOLD}{'='*60}{W}")
    print(f"{BOLD}  ⚔️  AKHETOPS RED VS BLUE SIMULATION{W}")
    print(f"{BOLD}{'='*60}{W}")
    print(f"{C}[*] Key manager loading...{W}\n")

    target = input(f"{Y}[SIM] Enter target IP/domain: {W}").strip()
    if not target:
        target = "scanme.nmap.org"

    try:
        rounds = int(input(f"{Y}[SIM] Number of rounds (default 5): {W}").strip() or "5")
    except:
        rounds = 5

    print(f"\n{Y}[SIM] Starting {rounds}-round simulation against {target}{W}")
    print(f"{Y}[SIM] Red team will attack, Blue team will defend{W}")
    print(f"{Y}[SIM] Watch the battle unfold in real time!\n{W}")

    input(f"{BOLD}Press Enter to start...{W}")
    run_simulation(target, rounds)

if __name__ == "__main__":
    main()
