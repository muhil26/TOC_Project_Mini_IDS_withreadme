"""
Path-traversal detector backed by DFAs.
"""

from automata.dfa import DFA

PATH_DFAS: list[DFA] = [
    DFA("../",         "UNIX-TRAVERSAL"),
    DFA("..\\",        "WIN-TRAVERSAL"),
    DFA("%2e%2e%2f",   "URL-ENCODED-TRAVERSAL"),
    DFA("%2e%2e/",     "MIXED-ENCODED-TRAVERSAL"),
    DFA("/etc/passwd", "UNIX-PASSWD"),
    DFA("/etc/shadow", "UNIX-SHADOW"),
]


def detect_path(payload: str) -> int:
    """Return the maximum verdict across all path-traversal DFAs."""
    return max(dfa.analyze(payload.lower())[0] for dfa in PATH_DFAS)
