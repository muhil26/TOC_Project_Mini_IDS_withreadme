"""
MetaController — hierarchical DFA composition.

Treats outputs of all sub-detectors as an alphabet {0, 1, 2} and
transitions through a top-level DFA to produce a single final verdict.

Formal definition:
    M_meta = (Q, Σ, δ, q0, F)

    Q  = {SAFE=0, WARNING=1, ALERT=2}
    Σ  = {0, 1, 2}   (sub-detector verdicts)
    q0 = SAFE
    F  = {ALERT}

Transition function δ:
    δ(any,    2) = ALERT    — any INTRUSION signal → ALERT immediately
    δ(SAFE,   1) = WARNING  — first SUSPICIOUS signal → WARNING
    δ(WARNING,1) = WARNING  — stay in WARNING
    δ(ALERT,  1) = ALERT    — already alerted, no downgrade
    δ(any,    0) = state    — SAFE signal never downgrades state
"""


class MetaController:
    SAFE    = 0
    WARNING = 1
    ALERT   = 2

    def __init__(self):
        self.state = self.SAFE

    # δ : Q × Σ → Q
    def _transition(self, signal: int) -> None:
        if signal == self.ALERT:
            self.state = self.ALERT
        elif signal == self.WARNING and self.state == self.SAFE:
            self.state = self.WARNING
        # signal == SAFE → no state change

    def decide(self, signals: list[int]) -> int:
        """
        Reset to q0 and process the full signal list.
        Returns the final state (verdict).
        """
        self.state = self.SAFE
        for s in signals:
            self._transition(s)
        return self.state
