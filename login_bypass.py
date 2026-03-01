"""
LoginBypassDetector — rule-based heuristic detector.

Checks for common authentication-bypass patterns that signature DFAs
might miss due to spacing or quoting variants.
"""


class LoginBypassDetector:
    SAFE        = 0
    SUSPICIOUS  = 1
    ALERT       = 2

    # Known verbatim bypass strings
    BYPASS_PATTERNS = [
        "' or 1=1",
        '" or "1"="1',
        "' or '1'='1",
        "admin'--",
        "admin' --",
        "admin admin",
        "admin ''",
        "' or ''='",
        "1' or '1'='1",
        "' or true--",
    ]

    def analyze(self, username: str, password: str) -> int:
        # Empty password is always suspicious
        if not password.strip():
            return self.ALERT

        # Identical credentials
        if username.strip() and username == password:
            return self.SUSPICIOUS

        payload = f"{username} {password}".lower()

        for pattern in self.BYPASS_PATTERNS:
            if pattern in payload:
                return self.ALERT

        # Heuristic: SQL meta-characters in username
        sql_meta = ["'", '"', "--", ";", "/*", "*/"]
        if any(m in username for m in sql_meta):
            return self.SUSPICIOUS

        return self.SAFE
