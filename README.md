<p align="center">
  <img src="assets/logo.png" alt="AkhetOps Logo" width="300"/>
</p>

# ⚡ AkhetOps
> Where attack meets defense — The horizon between red and blue.

AkhetOps is a fully autonomous AI-powered cybersecurity platform combining
red team and blue team agents into a single free open source tool.

![AkhetOps](https://img.shields.io/badge/AkhetOps-v1.0-red)
![Python](https://img.shields.io/badge/Python-3.13-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-orange)

---

## ⚠️ Legal Disclaimer
AkhetOps is intended for **authorized penetration testing and security research only**.
Only use against systems you own or have explicit written permission to test.
The authors are not responsible for any misuse or damage caused by this tool.

---

## 🌅 What is AkhetOps?

In Egyptian mythology, **Akhet** is the horizon — the sacred place where
the sun meets the darkness, where day meets night, where light meets shadow.

AkhetOps embodies this duality:
- 🔴 **Red Team Agent** — autonomous attacker
- 🔵 **Blue Team Agent** — autonomous defender
- ⚔️ **Simulation** — watch them fight each other in real time

---

## ✨ Features

### 🔴 Red Team Agent
- Autonomous pentesting with nmap, gobuster, nikto, sqlmap, hydra and more
- Chains tools automatically based on findings
- Live CVE intelligence for every service found
- AI memory — remembers every target across sessions
- Attack prediction engine — probability attack trees
- Professional HTML/PDF report generation

### 🔵 Blue Team Agent
- 24/7 continuous system monitoring
- Behavior fingerprinting — learns YOUR normal system
- Anomaly detection — alerts on anything that deviates
- Auto-fixes LOW/MEDIUM issues silently
- Asks permission for HIGH/CRITICAL fixes
- Honeypot grid — fake files and services that trap attackers
- Cross-platform — Linux, Windows, macOS

### ⚔️ Red vs Blue Simulation
- Both agents fight each other on a target
- Watch the battle unfold in real time
- Full battle report with scores and timeline

### 🧠 Core Intelligence
- AI Memory & Learning
- Live CVE Database Integration (NVD)
- Behavior Fingerprinting
- Attack Prediction Engine
- Professional Report Generator
- 5-Key Auto Rotation (500k free tokens/day)

---

## 🚀 Quick Start

### Requirements
- Kali Linux (recommended) or any Linux distro
- Python 3.10+
- Free Groq API key(s) from console.groq.com

### Installation
```bash
# Clone the repo
git clone https://github.com/yourusername/AkhetOps.git
cd AkhetOps

# Create virtual environment
python3 -m venv pentest-env
source pentest-env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy launcher templates
cp run_pentest.sh.example run_pentest.sh
cp run_defense.sh.example run_defense.sh
cp run_simulation.sh.example run_simulation.sh

# Add your Groq API keys
nano run_pentest.sh
```

### Usage

**Red Team Agent:**
```bash
bash run_pentest.sh
[You]: scan 10.10.10.5 and find all vulnerabilities
[You]: check for web vulnerabilities on port 80
[You]: report
```

**Blue Team Agent:**
```bash
bash run_defense.sh
[You]: scan
[You]: baseline
[You]: honeypot
[You]: anomalies
[You]: report
```

**Red vs Blue Simulation:**
```bash
bash run_simulation.sh
Enter target: 10.10.10.5
Rounds: 5
```

---

## 📁 Project Structure
```
AkhetOps/
├── agents/
│   ├── pentest_agent.py      # Red team agent
│   └── defense_agent.py      # Blue team agent
├── core/
│   ├── memory.py             # AI memory & learning
│   ├── cve_intel.py          # Live CVE intelligence
│   ├── behavior.py           # Behavior fingerprinting
│   ├── predictor.py          # Attack prediction engine
│   ├── reporter.py           # Report generation
│   ├── honeypot.py           # Honeypot deployer
│   └── key_manager.py        # API key rotation
├── simulation/
│   └── red_vs_blue.py        # Red vs Blue simulation
├── run_pentest.sh.example
├── run_defense.sh.example
├── run_simulation.sh.example
├── requirements.txt
└── README.md
```

---

## 🔑 Getting Free API Keys

1. Go to console.groq.com
2. Sign up with your email
3. Create an API key
4. Add it to your launcher script
5. Create multiple accounts for more tokens (100k/day each)

---

## 🛠️ Built With

- Python 3.13
- Groq API (free LLM inference)
- TinyDB (lightweight database)
- Kali Linux tools (nmap, gobuster, nikto, etc.)

---

## 📜 License

MIT License — free to use, modify and distribute.

---

## 🙏 Contributing

Pull requests welcome! If you find bugs or want to add features:
1. Fork the repo
2. Create a feature branch
3. Submit a pull request

---

*Built with ❤️ Perkele — Where the horizon meets security*
