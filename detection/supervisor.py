"""
SupervisorDFA — Legacy prototype controller.

DEPRECATED: Replaced by MetaController.
Retained for project history and academic comparison.

Key differences from MetaController:
  - Vote-based approach rather than proper DFA transition function.
  - Does not correctly model δ(WARNING, 1) → stay at WARNING;
    instead it resets and re-counts on every call.
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
