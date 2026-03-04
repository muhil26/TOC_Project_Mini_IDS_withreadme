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

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, render_template, request

from detectors.dfa_alerts        import detect_attack, ATTACK_DFAS
from detectors.nfa_alerts        import detect_nfa
from detectors.pda_alerts        import detect_pda
from detection.bruteforce        import BruteForceDetector
from detection.command_injection import detect_command, CMD_DFAS
from detection.login_bypass      import LoginBypassDetector
from detection.meta_controller   import MetaController
from detection.path_traversal    import detect_path, PATH_DFAS
from detection.session_behavior  import SessionBehaviorDetector

app = Flask(__name__)

bf   = BruteForceDetector()
sb   = SessionBehaviorDetector()
lb   = LoginBypassDetector()
meta = MetaController()

_LABEL = {0: "SAFE", 1: "SUSPICIOUS", 2: "INTRUSION"}
_STAGE_LABEL = {
    "dfa":        "DFA Signature Match",
    "nfa":        "NFA Obfuscated Match",
    "pda":        "PDA Nested Tag",
    "login":      "Login Bypass Heuristic",
    "cmd":        "Command Injection",
    "path":       "Path Traversal",
    "bruteforce": "Brute-Force Rate Limit",
    "session":    "Session Anomaly",
}

SEP = "=" * 62


def _print_nfa_traces(nfa_traces, nfa_v):
    print(f"\n{SEP}")
    print("  NFA -- OBFUSCATED PATTERN DETECTION")
    print(SEP)
    for nfa_name, trace in nfa_traces:
        max_s = max((max(s["states"]) for s in trace), default=0) if trace else 0
        print(f"\n  NFA Name : {nfa_name}")
        print(f"  Q = {{q0 .. q{max_s}}}  |  Non-deterministic state tracking")
        shown   = trace[-15:] if len(trace) > 15 else trace
        skipped = len(trace) - len(shown)
        if skipped:
            print(f"  ... ({skipped} earlier steps not shown) ...")
        for step in shown:
            states_str = "{" + ", ".join(f"q{s}" for s in sorted(step["states"])) + "}"
            print(f"    read[{step['input']!r}]  -->  active states {states_str}")
        print(f"  Verdict : {_LABEL[nfa_v]}")


def _print_pda_trace(payload, pda_trace, pda_v):
    print(f"\n{SEP}")
    print("  PDA -- NESTED <script> TAG DETECTION")
    print(SEP)
    print(f"  Input  : {payload[:72]}")
    print(f"  Stack alphabet G = {{S}}  where S marks an open <script>")
    print(f"  Stack operations (tag events only):")
    tag_ops = [(a, t, s) for a, t, s in pda_trace if a != "READ"]
    if not tag_ops:
        print("    (no <script> tags in input -- nothing pushed or popped)")
    else:
        for action, token, stack in tag_ops:
            stack_str = "[" + ", ".join(stack) + "]" if stack else "[ empty ]"
            if action == "PUSH":
                print(f"    PUSH     {repr(token):<36} stack -> {stack_str}")
            elif action == "POP":
                print(f"    POP      {repr(token):<36} stack -> {stack_str}")
            elif action == "POP_FAIL":
                print(f"    FAIL POP {repr(token):<36} stack was EMPTY -> ALERT")
            elif action == "UNCLOSED":
                print(f"    UNCLOSED {token:<36} stack -> {stack_str} -> ALERT")
    if pda_v == 2:
        print(f"  End state : stack non-empty or unmatched pop  -> ALERT")
    else:
        print(f"  End state : stack empty, all tags balanced    -> SAFE")
    print(f"  Verdict   : {_LABEL[pda_v]}")


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

        signals       = []
        stage_results = []

        # 1. DFA
        dfa_results = detect_attack(lowered, verbose=True)
        dfa_max     = max(v for _, v in dfa_results)
        signals.append(dfa_max)
        stage_results.append({
            "stage":   "dfa",
            "label":   _STAGE_LABEL["dfa"],
            "verdict": dfa_max,
            "details": [{"name": n, "verdict": v, "label": _LABEL[v]}
                        for n, v in dfa_results],
        })

        # 2. NFA
        nfa_v, nfa_traces = detect_nfa(lowered)
        signals.append(nfa_v)
        stage_results.append({
            "stage":   "nfa",
            "label":   _STAGE_LABEL["nfa"],
            "verdict": nfa_v,
            "details": [{"name": name, "verdict": nfa_v, "label": _LABEL[nfa_v]}
                        for name, _ in nfa_traces],
        })
        _print_nfa_traces(nfa_traces, nfa_v)

        # 3. PDA
        pda_v, pda_trace = detect_pda(payload)
        signals.append(pda_v)
        stage_results.append({
            "stage":   "pda",
            "label":   _STAGE_LABEL["pda"],
            "verdict": pda_v,
            "details": [{"name": "PDA -- <script> balance",
                         "verdict": pda_v, "label": _LABEL[pda_v]}],
        })
        _print_pda_trace(payload, pda_trace, pda_v)

        # 4. Login bypass
        lb_v = lb.analyze(username, password)
        signals.append(lb_v)
        stage_results.append({
            "stage":   "login",
            "label":   _STAGE_LABEL["login"],
            "verdict": lb_v,
            "details": [{"name": "Auth bypass patterns",
                         "verdict": lb_v, "label": _LABEL[lb_v]}],
        })

        # 5. Command injection
        cmd_v = detect_command(lowered)
        signals.append(cmd_v)
        stage_results.append({
            "stage":   "cmd",
            "label":   _STAGE_LABEL["cmd"],
            "verdict": cmd_v,
            "details": [{"name": "Shell operators / subshells",
                         "verdict": cmd_v, "label": _LABEL[cmd_v]}],
        })

        # 6. Path traversal
        path_v = detect_path(lowered)
        signals.append(path_v)
        stage_results.append({
            "stage":   "path",
            "label":   _STAGE_LABEL["path"],
            "verdict": path_v,
            "details": [{"name": "Directory traversal sequences",
                         "verdict": path_v, "label": _LABEL[path_v]}],
        })

        # 7. Brute force
        bf_v = bf.record(ip)
        signals.append(bf_v)
        stage_results.append({
            "stage":   "bruteforce",
            "label":   _STAGE_LABEL["bruteforce"],
            "verdict": bf_v,
            "details": [{"name": f"Attempts from {ip} in last 60s: {bf.count(ip)}",
                         "verdict": bf_v, "label": _LABEL[bf_v]}],
        })

        # 8. Session anomaly
        sb_v = sb.track(ip)
        signals.append(sb_v)
        stage_results.append({
            "stage":   "session",
            "label":   _STAGE_LABEL["session"],
            "verdict": sb_v,
            "details": [{"name": "Request rate (30s window)",
                         "verdict": sb_v, "label": _LABEL[sb_v]}],
        })

        # 9. Meta-controller
        final = meta.decide(signals)

        print(f"\n{SEP}")
        print("  META-CONTROLLER -- HIERARCHICAL DFA COMPOSITION")
        print(SEP)
        print(f"  Signal vector  : {signals}")
        state = 0
        path  = ["SAFE"]
        for s in signals:
            if s == 2:
                state = 2
            elif s == 1 and state == 0:
                state = 1
            path.append("ALERT" if state == 2 else "WARN" if state == 1 else "SAFE")
        print(f"  State path     : {' -> '.join(path)}")
        print(f"  Final verdict  : {_LABEL[final]}")
        print(SEP)

        if final == 2:
            alert = "INTRUSION DETECTED"
        elif final == 1:
            alert = "SUSPICIOUS ACTIVITY"
        else:
            alert = "CLEAN"

        analysis = {
            "verdict":       final,
            "verdict_label": _LABEL[final],
            "stages":        stage_results,
            "signals":       signals,
            "payload":       payload,
        }

    return render_template("login.html", alert=alert, payload=payload,
                           analysis=analysis)


def send_alert(attack, pkt_payload):
    print("[NETWORK ALERT]", attack)
    print("[PAYLOAD]", pkt_payload)


if __name__ == "__main__":
    app.run(debug=True)
