"""
SessionBehaviorDetector — detects abnormally high request rates
from a single session/IP within a sliding time window.
"""

import time


class SessionBehaviorDetector:
    WARNING_LIMIT = 8
    ALERT_LIMIT   = 15
    WINDOW        = 30  # seconds

    SAFE    = 0
    WARNING = 1
    ALERT   = 2

    def __init__(self):
        self.sessions: dict[str, list[float]] = {}

    def track(self, session_id: str) -> int:
        now    = time.time()
        bucket = self.sessions.setdefault(session_id, [])
        bucket.append(now)

        self.sessions[session_id] = [t for t in bucket if now - t <= self.WINDOW]

        count = len(self.sessions[session_id])
        if count > self.ALERT_LIMIT:
            return self.ALERT
        if count > self.WARNING_LIMIT:
            return self.WARNING
        return self.SAFE
