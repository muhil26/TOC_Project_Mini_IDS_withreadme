class DFA:
    """
    Deterministic Finite Automaton for pattern detection.

    Formal definition:
        M = (Q, Σ, δ, q0, F)

        Q  = {0, 1, 2, ..., m}        — finite set of states
        Σ  = characters in pattern     — input alphabet
        δ  = transition function       — δ: Q × Σ → Q
        q0 = 0                         — start state
        F  = {m}                       — set of accepting states

    Verdicts:
        0 → SAFE       (no match)
        1 → SUSPICIOUS (partial match, within 2 chars of accepting)
        2 → INTRUSION  (full pattern matched / accepting state reached)
    """

    SAFE       = 0
    SUSPICIOUS = 1
    INTRUSION  = 2

    def __init__(self, pattern: str, name: str = ""):
        self.name    = name
        self.pattern = pattern
        self.m       = len(pattern)

        self.alphabet = set(pattern)
        self.delta    = self._build_dfa()

        # Semantic threshold: within 2 states of acceptance → SUSPICIOUS
        self.suspicious_threshold = max(self.m - 2, 1)
        self.accepting_state      = self.m

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def formal_definition(self) -> dict:
        """Return the formal 5-tuple components."""
        return {
            "Q":     list(range(self.m + 1)),
            "Sigma": sorted(self.alphabet),
            "delta": "see transition table",
            "q0":    0,
            "F":     [self.accepting_state],
        }

    def transition_table(self) -> list[dict]:
        """Human-readable transition table for display."""
        rows = []
        chars = sorted(self.alphabet)
        for state in range(self.m + 1):
            row = {"state": state}
            for ch in chars:
                row[ch] = self.delta[state].get(ch, 0)
            rows.append(row)
        return rows

    # ------------------------------------------------------------------
    # Core analysis — always returns (verdict: int, trace: list, final_state: int)
    # ------------------------------------------------------------------

    def analyze(self, text: str) -> tuple[int, list, int]:
        """
        Process *text* through the DFA.

        Returns
        -------
        verdict    : 0 (SAFE) | 1 (SUSPICIOUS) | 2 (INTRUSION)
        trace      : list of step dicts  {from, input, to}
        final_state: integer state after processing all input
        """
        state = 0
        trace = []

        for char in text:
            prev  = state
            state = self.delta[state].get(char, 0)
            trace.append({"from": prev, "input": char, "to": state})

            if state == self.accepting_state:
                return self.INTRUSION, trace, state

        if state >= self.suspicious_threshold and self.m > 2:
            return self.SUSPICIOUS, trace, state

        return self.SAFE, trace, state

    # ------------------------------------------------------------------
    # Internal: KMP-based DFA construction
    # ------------------------------------------------------------------

    def _build_dfa(self) -> list[dict]:
        """
        Build transition table using the KMP failure-function approach.
        δ(q, c) = length of longest proper suffix of (pattern[:q] + c)
                  that is also a prefix of pattern.
        """
        table = [{} for _ in range(self.m + 1)]

        for state in range(self.m + 1):
            for char in self.alphabet:
                # Candidate: extend current match
                k = min(self.m, state + 1)
                while k > 0:
                    if self.pattern[:k] == (self.pattern[:state] + char)[-k:]:
                        break
                    k -= 1
                table[state][char] = k

        return table
