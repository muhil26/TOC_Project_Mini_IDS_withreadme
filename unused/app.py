"""
Mini IDS — Flask application entry point.

Pipeline:
    1. DFA  → signature-based pattern matching
    2. NFA  → obfuscated/subsequence pattern matching
    3. PDA  → nested XSS tag detection
    4. LoginBypassDetector → heuristic auth-bypass rules
    5. CommandInjectionDetector → shell operator DFAs
    6. PathTraversalDetector → directory-traversal DFAs
    7. BruteForceDetector → sliding-window rate limiter
    8. SessionBehaviorDetector → request-rate anomaly
    9. MetaController → hierarchical DFA composition → final verdict
"""

import sys
import os

# Make project root importable regardless of working directory
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, render_template, request, jsonify

from detectors.dfa_alerts  import detect_attack, ATTACK_DFAS
from detectors.nfa_alerts  import detect_nfa
from detectors.pda_alerts  import detect_pda
from bruteforce            import BruteForceDetector
from command_injection     import detect_command, CMD_DFAS
from login_bypass          import LoginBypassDetector
from meta_controller       import MetaController
from path_traversal        import detect_path, PATH_DFAS
from session_behavior      import SessionBehaviorDetector

app = Flask(__name__)

# Singleton detectors (stateful)
bf   = BruteForceDetector()
sb   = SessionBehaviorDetector()
lb   = LoginBypassDetector()
meta = MetaController()

_LABEL = {0: "SAFE", 1: "SUSPICIOUS", 2: "INTRUSION"}
_STAGE_LABEL = {
    "dfa":      "DFA Signature Match",
    "nfa":      "NFA Obfuscated Match",
    "pda":      "PDA Nested Tag",
    "login":    "Login Bypass Heuristic",
    "cmd":      "Command Injection",
    "path":     "Path Traversal",
    "bruteforce": "Brute-Force Rate Limit",
    "session":  "Session Anomaly",
}


@app.route("/", methods=["GET", "POST"])
def login():
    analysis = None
    alert    = None
    payload  = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip       = request.remote_addr

        payload  = f"{username}  {password}"
        lowered  = payload.lower()

        signals      = []
        stage_results = []

        # ── 1. DFA signature detection ───────────────────────────────
        dfa_results = detect_attack(lowered, verbose=True)
        dfa_max     = max(v for _, v in dfa_results)
        signals.append(dfa_max)
        stage_results.append({
            "stage":   "dfa",
            "label":   _STAGE_LABEL["dfa"],
            "verdict": dfa_max,
            "details": [
                {"name": name, "verdict": v, "label": _LABEL[v]}
                for name, v in dfa_results
            ],
        })

        # ── 2. NFA obfuscated detection ──────────────────────────────
        nfa_v, nfa_traces = detect_nfa(lowered)
        signals.append(nfa_v)
        stage_results.append({
            "stage":   "nfa",
            "label":   _STAGE_LABEL["nfa"],
            "verdict": nfa_v,
            "details": [{"name": name, "verdict": nfa_v, "label": _LABEL[nfa_v]}
                        for name, _ in nfa_traces],
        })

        # ── 3. PDA nested-tag detection ──────────────────────────────
        pda_v, pda_trace = detect_pda(payload)
        signals.append(pda_v)
        stage_results.append({
            "stage":   "pda",
            "label":   _STAGE_LABEL["pda"],
            "verdict": pda_v,
            "details": [{"name": "PDA – <script> balance", "verdict": pda_v,
                         "label": _LABEL[pda_v]}],
        })

        # ── 4. Login bypass ──────────────────────────────────────────
        lb_v = lb.analyze(username, password)
        signals.append(lb_v)
        stage_results.append({
            "stage":   "login",
            "label":   _STAGE_LABEL["login"],
            "verdict": lb_v,
            "details": [{"name": "Auth bypass patterns", "verdict": lb_v,
                         "label": _LABEL[lb_v]}],
        })

        # ── 5. Command injection ─────────────────────────────────────
        cmd_v = detect_command(lowered)
        signals.append(cmd_v)
        stage_results.append({
            "stage":   "cmd",
            "label":   _STAGE_LABEL["cmd"],
            "verdict": cmd_v,
            "details": [{"name": "Shell operators / subshells", "verdict": cmd_v,
                         "label": _LABEL[cmd_v]}],
        })

        # ── 6. Path traversal ────────────────────────────────────────
        path_v = detect_path(lowered)
        signals.append(path_v)
        stage_results.append({
            "stage":   "path",
            "label":   _STAGE_LABEL["path"],
            "verdict": path_v,
            "details": [{"name": "Directory traversal sequences", "verdict": path_v,
                         "label": _LABEL[path_v]}],
        })

        # ── 7. Brute force ───────────────────────────────────────────
        bf_v = bf.record(ip)
        signals.append(bf_v)
        stage_results.append({
            "stage":   "bruteforce",
            "label":   _STAGE_LABEL["bruteforce"],
            "verdict": bf_v,
            "details": [{"name": f"Attempts from {ip} (last 60s): {bf.count(ip)}",
                         "verdict": bf_v, "label": _LABEL[bf_v]}],
        })

        # ── 8. Session anomaly ───────────────────────────────────────
        sb_v = sb.track(ip)
        signals.append(sb_v)
        stage_results.append({
            "stage":   "session",
            "label":   _STAGE_LABEL["session"],
            "verdict": sb_v,
            "details": [{"name": "Request rate (30s window)", "verdict": sb_v,
                         "label": _LABEL[sb_v]}],
        })

        # ── 9. Meta-controller final decision ────────────────────────
        final = meta.decide(signals)

        if final == 2:
            alert = "INTRUSION DETECTED"
            print("[ALERT] Intrusion detected |", payload)
        elif final == 1:
            alert = "SUSPICIOUS ACTIVITY"
            print("[WARNING] Suspicious behavior |", payload)
        else:
            alert = "CLEAN"
            print("[INFO] Clean input:", payload)

        analysis = {
            "verdict":       final,
            "verdict_label": _LABEL[final],
            "stages":        stage_results,
            "signals":       signals,
            "payload":       payload,
        }

    return render_template("login.html", alert=alert, payload=payload,
                           analysis=analysis)


# Used by main.py packet sniffer
def send_alert(attack, pkt_payload):
    print("[NETWORK ALERT]", attack)
    print("[PAYLOAD]", pkt_payload)


if __name__ == "__main__":
    app.run(debug=True)
