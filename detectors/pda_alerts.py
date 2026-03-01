"""
PDA-based detector for nested XSS tags.
"""

from automata.pda import PDA

_pda = PDA()


def detect_pda(payload: str) -> tuple[int, list]:
    """
    Returns
    -------
    verdict : 0 (SAFE) | 2 (ALERT)
    trace   : PDA execution trace
    """
    return _pda.analyze(payload)
