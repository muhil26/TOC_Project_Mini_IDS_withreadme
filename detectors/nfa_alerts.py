"""
NFA-based detector for obfuscated (subsequence-style) attack patterns.
"""

from automata.nfa import NFA

NFAS: list[NFA] = [
    NFA("unionselect",   "SQLi-Obfuscated-UNION"),
    NFA("script",        "XSS-Obfuscated"),
    NFA("or11",          "SQLi-Boolean-Obfuscated"),
    NFA("cmdexec",       "CMD-Obfuscated"),
    NFA("../",           "PATH-Obfuscated"),
]


def detect_nfa(payload: str) -> tuple[int, list]:
    """
    Returns
    -------
    verdict : max verdict across all NFAs  (0 | 2)
    traces  : list of (nfa_name, trace) pairs
    """
    verdicts = []
    traces   = []

    for nfa in NFAS:
        v, t = nfa.analyze(payload.lower())
        verdicts.append(v)
        traces.append((nfa.name, t))

    return max(verdicts), traces
