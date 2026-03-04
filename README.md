# Mini IDS using Automata

## Course
Theory of Computation

## Contributors
- [Meijeevan K.T](https://github.com/MEIJEEVAN)
- [Shanmuka Priyan V](https://github.com/ShanmukaPriyan-V2025)
- [Muhilan S R](https://github.com/muhil26)

## Automata Types
- NFA (Nondeterministic Finite Automaton)
- DFA (Deterministic Finite Automaton)
- PDA (Pushdown Automaton)

## Tech Stack
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![HTML](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-F7DF1E?style=for-the-badge&logo=flask&logoColor=black)
![Scapy](https://img.shields.io/badge/Scapy-%23E4405F.svg?&style=for-the-badge&logo=scan&logoColor=white)

## Project Overview
This project implements a Mini Intrusion Detection System (IDS) using various types of automata. It aims to detect abnormal patterns in network traffic and identify potential security threats. The system can classify different types of attacks based on predefined rules and patterns.

## Project Structure
```
Mini_IDS/
├── app.py
├── automata
│   ├── dfa.py
│   ├── __init__.py
│   ├── nfa.py
│   └── pda.py
├── detection
│   ├── bruteforce.py
│   ├── command_injection.py
│   ├── __init__.py
│   ├── login_bypass.py
│   ├── meta_controller.py
│   ├── path_traversal.py
│   ├── port_scan.py
│   ├── session_behavior.py
│   └── supervisor.py
├── detectors
│   ├── dfa_alerts.py
│   ├── __init__.py
│   ├── nfa_alerts.py
│   └── pda_alerts.py
├── docs
├── main.py
├── README.md
├── requirements.txt
└── templates
    └── login.html
```

## Attack Patterns Detected
- Brute Force
- Command Injection
- Login Bypass
- Path Traversal
- Port Scan
- Session Anomaly
- SQL Injection via DFA/NFA/PDA

---

_Last updated: 2026-03-04 07:40:15 UTC_
