"""
DFA-based attack signature detector.

Each attack pattern is compiled into a DFA at import time.
detect_attack() returns a list of (attack_name, verdict) pairs
and optionally prints a detailed trace for academic review.
"""

from automata.dfa import DFA

# -----------------------------------------------------------------------
# Attack signatures → DFA instances
# -----------------------------------------------------------------------
ATTACK_DFAS: dict[str, DFA] = {
    "SQL Injection – UNION":   DFA("union select",  "SQLi-UNION"),
    "SQL Injection – OR 1=1":  DFA(" or 1=1",       "SQLi-OR"),
    "SQL Injection – AND 1=1": DFA(" and 1=1",       "SQLi-AND"),
    "SQL Injection – LIKE":    DFA(" like ",         "SQLi-LIKE"),
    "SQL Injection – comment": DFA(" -- ",           "SQLi-COMMENT"),
    "XSS – script tag":        DFA("<script",        "XSS-SCRIPT"),
    "Directory Traversal":     DFA("../",            "DIR-TRAVERSAL"),
}

_VERDICT_LABEL = {0: "SAFE", 1: "SUSPICIOUS", 2: "INTRUSION"}


def detect_attack(payload: str, verbose: bool = False) -> list[tuple[str, int]]:
    """
    Run every DFA over *payload* (lowercased internally).

    Returns
    -------
    List of (attack_name: str, verdict: int) tuples.
    """
    lowered = payload.lower()
    results = []

    for name, dfa in ATTACK_DFAS.items():
        verdict, trace, final_state = dfa.analyze(lowered)

        if verbose:
            fd = dfa.formal_definition()
            print(f"\n{'─'*60}")
            print(f"  DFA : {dfa.name}")
            print(f"  Pattern : {dfa.pattern!r}")
            print(f"  Q = {fd['Q']}")
            print(f"  Σ = {fd['Sigma']}")
            print(f"  q0 = {fd['q0']}   F = {fd['F']}")
            # Show only the last 10 steps to keep output manageable
            shown = trace[-10:] if len(trace) > 10 else trace
            print(f"  Trace (last {len(shown)} of {len(trace)} steps):")
            for step in shown:
                print(f"    q{step['from']} --[{step['input']!r}]--> q{step['to']}")
            print(f"  Final state : q{final_state}")
            print(f"  Verdict     : {_VERDICT_LABEL[verdict]}")

        results.append((name, verdict))

    return results
