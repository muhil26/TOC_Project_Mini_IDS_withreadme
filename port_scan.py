"""
PortScanDetector — temporal DFA extension.

Models a time-windowed DFA where states represent the number of unique
ports accessed by a single IP within a sliding time window.

This extends the classical string DFA to a temporal domain:
  Q  = {0, 1, ..., PORT_LIMIT}
  Σ  = port numbers (integers)
  δ  = add new unique port → increment state; prune old → decrement
  q0 = 0
  F  = {PORT_LIMIT}
"""

import time


class PortScanDetector:
    WINDOW     = 10   # seconds
    PORT_LIMIT = 8    # unique ports before ALERT
    WARN_LIMIT = 5    # unique ports before WARNING

    SAFE    = 0
    WARNING = 1
    ALERT   = 2

    def __init__(self):
        self.ip_ports: dict[str, list[tuple[int, float]]] = {}

    def analyze(self, ip: str, port: int) -> int:
        now = time.time()
        bucket = self.ip_ports.setdefault(ip, [])
        bucket.append((port, now))

        # Slide the window
        self.ip_ports[ip] = [(p, t) for p, t in bucket if now - t <= self.WINDOW]

        unique = {p for p, _ in self.ip_ports[ip]}
        count  = len(unique)

        if count >= self.PORT_LIMIT:
            return self.ALERT
        if count >= self.WARN_LIMIT:
            return self.WARNING
        return self.SAFE
