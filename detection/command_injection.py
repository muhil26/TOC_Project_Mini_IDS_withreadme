"""
Command-injection detector backed by DFAs.

Each pattern represents a shell operator or sub-command construct.
"""

from automata.dfa import DFA

CMD_DFAS: list[DFA] = [
    DFA("; ls",   "CMD-SEMICOLON-LS"),
    DFA("; cat",  "CMD-SEMICOLON-CAT"),
    DFA("; rm",   "CMD-SEMICOLON-RM"),
    DFA("&&",     "CMD-AND"),
    DFA("||",     "CMD-OR"),
    DFA(" | ",    "CMD-PIPE"),
    DFA("$(", "CMD-SUBSHELL"),
    DFA("`",      "CMD-BACKTICK"),
    DFA("/bin/",  "CMD-BIN-PATH"),
]


def detect_command(payload: str) -> int:
    """Return the maximum verdict (0|1|2) across all command-injection DFAs."""
    verdicts = []
    for dfa in CMD_DFAS:
        v, _, _ = dfa.analyze(payload)
        verdicts.append(v)
    return max(verdicts)
