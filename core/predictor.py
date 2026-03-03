#!/usr/bin/env python3
# core/predictor.py - Attack Prediction Engine

import os
import json
import datetime
from groq import Groq
from core.key_manager import key_manager
from core.memory import get_host_history

REPORT_DIR = os.path.expanduser("~/pentest-ai/data/reports")
os.makedirs(REPORT_DIR, exist_ok=True)

def build_attack_tree(target: str, nmap_output: str, cve_data: str = "", extra_context: str = "") -> dict:
    """
    Analyze scan results and build a probability attack tree.
    Returns structured attack paths ranked by success probability.
    """

    client = Groq(api_key=key_manager.get_key())

    # Get memory context
    history      = get_host_history(target)
    memory_ctx   = ""
    if history["findings"]:
        memory_ctx = f"Previous findings on this target:\n"
        for f in history["findings"][:5]:
            memory_ctx += f"- [{f.get('severity')}] {f.get('finding')}\n"

    prompt = f"""You are an expert penetration tester and threat modeler.
Analyze the following scan results and build a detailed attack prediction tree.

TARGET: {target}
{memory_ctx}

SCAN RESULTS:
{nmap_output[:2000]}

CVE INTELLIGENCE:
{cve_data[:500] if cve_data else "Not available"}

{extra_context}

Respond ONLY with a JSON object in this exact format:
{{
    "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
    "compromise_probability": 0.0-1.0,
    "attack_paths": [
        {{
            "path_id": 1,
            "name": "Path name",
            "probability": 0.0-1.0,
            "complexity": "LOW|MEDIUM|HIGH",
            "steps": [
                {{
                    "step": 1,
                    "action": "what to do",
                    "tool": "tool to use",
                    "command": "exact command",
                    "success_rate": 0.0-1.0,
                    "description": "why this works"
                }}
            ],
            "entry_point": "initial access vector",
            "end_goal": "what attacker achieves",
            "mitigations": ["how to stop this path"]
        }}
    ],
    "highest_value_targets": ["list of most valuable targets found"],
    "quick_wins": ["easy low hanging fruit vulnerabilities"],
    "recommended_first_steps": ["top 3 actions to take right now"]
}}

Be specific, technical and realistic. Base everything on the actual scan data provided.
Return ONLY the JSON, no other text."""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2048
        )
        raw = response.choices[0].message.content

        # Clean and parse JSON
        raw = raw.strip()
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0].strip()

        tree = json.loads(raw)
        tree["target"]    = target
        tree["timestamp"] = datetime.datetime.now().isoformat()

        # Save to file
        path = os.path.join(REPORT_DIR, f"attack_tree_{target}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(path, "w") as f:
            json.dump(tree, f, indent=2)

        return tree

    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse attack tree: {e}", "raw": raw}
    except Exception as e:
        return {"error": str(e)}

def format_attack_tree(tree: dict) -> str:
    """Format attack tree for terminal display."""
    if "error" in tree:
        return f"[!] Error: {tree['error']}"

    colors = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[94m",
        "LOW":      "\033[92m",
        "RESET":    "\033[0m",
        "BOLD":     "\033[1m",
        "CYAN":     "\033[96m"
    }

    output = []
    output.append(f"\n{colors['BOLD']}{'='*60}{colors['RESET']}")
    output.append(f"{colors['BOLD']}  AKHETOPS ATTACK PREDICTION ENGINE{colors['RESET']}")
    output.append(f"{colors['BOLD']}{'='*60}{colors['RESET']}")

    risk     = tree.get("overall_risk", "UNKNOWN")
    prob     = tree.get("compromise_probability", 0) * 100
    color    = colors.get(risk, colors["RESET"])

    output.append(f"\n{colors['BOLD']}TARGET:{colors['RESET']} {tree.get('target')}")
    output.append(f"{colors['BOLD']}OVERALL RISK:{colors['RESET']} {color}{risk}{colors['RESET']}")
    output.append(f"{colors['BOLD']}COMPROMISE PROBABILITY:{colors['RESET']} {color}{prob:.1f}%{colors['RESET']}")

    # Quick wins
    quick_wins = tree.get("quick_wins", [])
    if quick_wins:
        output.append(f"\n{colors['CYAN']}[+] QUICK WINS (Low hanging fruit):{colors['RESET']}")
        for qw in quick_wins:
            output.append(f"  → {qw}")

    # Highest value targets
    hvt = tree.get("highest_value_targets", [])
    if hvt:
        output.append(f"\n{colors['CYAN']}[+] HIGHEST VALUE TARGETS:{colors['RESET']}")
        for t in hvt:
            output.append(f"  ★ {t}")

    # Attack paths
    paths = tree.get("attack_paths", [])
    output.append(f"\n{colors['BOLD']}[+] ATTACK PATHS ({len(paths)} identified):{colors['RESET']}")

    for path in sorted(paths, key=lambda x: x.get("probability", 0), reverse=True):
        prob      = path.get("probability", 0) * 100
        complexity = path.get("complexity", "UNKNOWN")
        color     = colors["RESET"]
        if prob >= 70:   color = colors["CRITICAL"]
        elif prob >= 50: color = colors["HIGH"]
        elif prob >= 30: color = colors["MEDIUM"]
        else:            color = colors["LOW"]

        output.append(f"\n{colors['BOLD']}PATH {path.get('path_id')}: {path.get('name')}{colors['RESET']}")
        output.append(f"  Probability: {color}{prob:.1f}%{colors['RESET']} | Complexity: {complexity}")
        output.append(f"  Entry: {path.get('entry_point')}")
        output.append(f"  Goal:  {path.get('end_goal')}")

        steps = path.get("steps", [])
        if steps:
            output.append(f"  {colors['CYAN']}Steps:{colors['RESET']}")
            for step in steps:
                success = step.get("success_rate", 0) * 100
                output.append(f"    {step.get('step')}. {step.get('action')}")
                output.append(f"       Tool: {step.get('tool')} | Success rate: {success:.0f}%")
                output.append(f"       CMD:  {step.get('command')}")

        mitigations = path.get("mitigations", [])
        if mitigations:
            output.append(f"  {colors['LOW']}Mitigations:{colors['RESET']}")
            for m in mitigations:
                output.append(f"    ✓ {m}")

    # Recommended first steps
    rfs = tree.get("recommended_first_steps", [])
    if rfs:
        output.append(f"\n{colors['BOLD']}[+] RECOMMENDED FIRST STEPS:{colors['RESET']}")
        for i, step in enumerate(rfs, 1):
            output.append(f"  {i}. {step}")

    output.append(f"\n{colors['BOLD']}{'='*60}{colors['RESET']}")
    return "\n".join(output)

def predict_from_nmap(target: str, nmap_output: str, cve_data: str = "") -> str:
    """Main function — build and display attack tree from nmap output."""
    print(f"\n\033[93m[*] Building attack prediction tree for {target}...\033[0m")
    tree      = build_attack_tree(target, nmap_output, cve_data)
    formatted = format_attack_tree(tree)
    print(formatted)

    # Save formatted report
    path = os.path.join(REPORT_DIR, f"attack_prediction_{target}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(path, "w") as f:
        f.write(formatted)
    print(f"\n\033[92m[+] Attack tree saved: {path}\033[0m")

    return formatted
