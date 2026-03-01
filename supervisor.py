"""
SupervisorDFA — Legacy prototype controller.

DEPRECATED: Replaced by MetaController, which models proper hierarchical
DFA composition over the full sub-detector output alphabet.

Retained here for project history and comparison with MetaController.

Differences from MetaController:
  - Uses a vote-based approach (count of suspicious signals ≥ 2 → WARNING)
    rather than a proper DFA transition function.
  - Does not model stateful transitions correctly:
    δ(WARNING, 1) should stay at WARNING, but this implementation
    resets and re-counts on every call.
  - MetaController formalises δ: Q × {0,1,2} → Q properly.
"""


class SupervisorDFA:
    SAFE    = 0
    WARNING = 1
    ALERT   = 2

    def __init__(self):
        self.state = self.SAFE

    def process(self, verdicts: list[int]) -> int:
        """
        verdicts : list of ints from sub-detectors {0, 1, 2}
        Returns  : SAFE | WARNING | ALERT
        """
        if 2 in verdicts:
            self.state = self.ALERT
            return self.ALERT

        if verdicts.count(1) >= 2:
            self.state = self.WARNING
            return self.WARNING

        self.state = self.SAFE
        return self.SAFE
