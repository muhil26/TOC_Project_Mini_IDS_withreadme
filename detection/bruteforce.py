"""
BruteForceDetector — sliding-window rate limiter.

Models a temporal DFA where states represent the number of login
attempts from a single IP within a rolling time window.

States:  0 (SAFE) → 1 (WARNING) → 2 (ALERT)
Threshold configuration is class-level for easy tuning.
"""

import time


class BruteForceDetector:
    WARNING_THRESHOLD = 3   # attempts before WARNING
    ALERT_THRESHOLD   = 5   # attempts before ALERT
    WINDOW            = 60  # seconds

    SAFE    = 0
    WARNING = 1
    ALERT   = 2

    def __init__(self):
        self.attempts: dict[str, list[float]] = {}

    def record(self, key: str) -> int:
        """Record one attempt from *key* (IP address) and return the verdict."""
        now = time.time()
        bucket = self.attempts.setdefault(key, [])
        bucket.append(now)
        self.attempts[key] = [t for t in bucket if now - t <= self.WINDOW]
        count = len(self.attempts[key])
        if count >= self.ALERT_THRESHOLD:
            return self.ALERT
        if count >= self.WARNING_THRESHOLD:
            return self.WARNING
        return self.SAFE

    def count(self, key: str) -> int:
        """Return current attempt count for *key* (for display)."""
        return len(self.attempts.get(key, []))
