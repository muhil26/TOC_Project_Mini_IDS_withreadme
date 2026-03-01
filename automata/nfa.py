class NFA:
    """
    ε-NFA for obfuscated / subsequence attack pattern detection.

    Unlike the DFA, the NFA maintains a *set* of active states and uses
    ε-moves (staying in the current state) to model skip-character matching.
    This lets it detect patterns even when characters are interleaved.

    Formal definition:
        M = (Q, Σ, Δ, q0, F)

        Q  = {0, 1, ..., |pattern|}
        Σ  = all printable characters
        Δ  = non-deterministic transition relation
        q0 = 0
        F  = {|pattern|}
    """

    SAFE  = 0
    ALERT = 2

    def __init__(self, pattern: str, name: str = ""):
        self.name    = name
        self.pattern = pattern.replace("*", "")   # strip any wildcards
        self.final   = len(self.pattern)

    def analyze(self, text: str) -> tuple[int, list]:
        """
        Returns
        -------
        verdict : 0 (SAFE) | 2 (ALERT)
        trace   : list of {input, states} dicts
        """
        current = {0}
        trace   = []

        for char in text:
            nxt = set()
            for state in current:
                nxt.add(state)                                    # ε-move
                if state < self.final and char == self.pattern[state]:
                    nxt.add(state + 1)                            # symbol move

            trace.append({"input": char, "states": sorted(nxt)})
            current = nxt

            if self.final in current:
                return self.ALERT, trace

        return self.SAFE, trace
