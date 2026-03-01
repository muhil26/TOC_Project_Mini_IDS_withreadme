class PDA:
    """
    Pushdown Automaton for nested / balanced-tag XSS detection.

    The PDA uses a stack to track opening <script> tags and expects
    a matching </script> for each one.  An unclosed or unmatched tag
    triggers an ALERT.

    Formal definition:
        M = (Q, Σ, Γ, δ, q0, Z0, F)

        Q  = {scan, accept, reject}
        Σ  = all printable characters
        Γ  = {'S'}    — stack alphabet (S = script tag marker)
        q0 = scan
        Z0 = ε        — empty initial stack
        F  = {accept}
    """

    SAFE  = 0
    ALERT = 2

    def analyze(self, text: str) -> tuple[int, list]:
        """
        Returns
        -------
        verdict : 0 (SAFE) | 2 (ALERT)
        trace   : list of (action, token, stack_snapshot) tuples
        """
        stack = []
        trace = []
        i     = 0

        while i < len(text):
            if text[i:].startswith("<script"):
                # accept <script> or <script ...>
                end = text.find(">", i)
                tag = text[i : end + 1] if end != -1 else "<script>"
                stack.append("S")
                trace.append(("PUSH", tag, list(stack)))
                i = end + 1 if end != -1 else i + 7

            elif text[i:].startswith("</script>"):
                if not stack:
                    trace.append(("POP_FAIL", "</script>", list(stack)))
                    return self.ALERT, trace
                stack.pop()
                trace.append(("POP", "</script>", list(stack)))
                i += 9

            else:
                trace.append(("READ", text[i], list(stack)))
                i += 1

        if stack:
            trace.append(("UNCLOSED", f"{len(stack)} tag(s)", list(stack)))
            return self.ALERT, trace

        return self.SAFE, trace
