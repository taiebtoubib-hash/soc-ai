"""
agents/02_analysis/correlator.py
----------------------------------
Tracks recent alerts in memory using a sliding time window.
Detects behavioral patterns like port scans and brute force.
"""

import time

from shared.models import NormalizedAlert
from shared.logger import get_logger

log = get_logger("correlator")


class AlertCorrelator:
    """
    In-memory sliding-window correlator (default window = 5 minutes).

    Appends every seen alert as (timestamp, NormalizedAlert) and
    automatically evicts entries older than ``window`` seconds whenever
    a new alert is added.
    """

    def __init__(self):
        self.events: list[tuple[float, NormalizedAlert]] = []
        self.window: int = 300   # 5 minutes in seconds

    # ── Ingestion ─────────────────────────────────────────────────

    def add(self, alert: NormalizedAlert) -> None:
        """Append alert and prune stale events."""
        self.events.append((time.time(), alert))
        self._cleanup()

    # ── Correlation queries ───────────────────────────────────────

    def count_same_src(self, src_ip: str) -> int:
        """
        Count how many alerts in the last ``window`` seconds share the
        given source IP.  Useful for detecting scan / flood activity.
        """
        return sum(1 for _, a in self.events if a.src_ip == src_ip)

    def unique_dst_ports(self, src_ip: str) -> int:
        """
        Count the number of *distinct* destination ports contacted by
        ``src_ip`` over the last ``window`` seconds.

        High value → likely port scan.
        """
        ports = {a.dst_port for _, a in self.events if a.src_ip == src_ip}
        return len(ports)

    def failed_auth_count(self, src_ip: str) -> int:
        """
        Approximate number of failed authentication attempts from
        ``src_ip`` in the last ``window`` seconds.

        Heuristic: alert.severity >= 10 (Wazuh authentication failure
        rules fire at level 10+).
        """
        return sum(
            1
            for _, a in self.events
            if a.src_ip == src_ip and a.severity >= 10
        )

    # ── Maintenance ───────────────────────────────────────────────

    def _cleanup(self) -> None:
        """
        Remove events older than the sliding window.
        Keeps at most 10 minutes of history (600 seconds) as an upper
        bound so memory never grows unbounded.
        """
        cutoff = time.time() - self.window
        self.events = [
            (ts, a)
            for ts, a in self.events
            if ts >= cutoff
        ]
