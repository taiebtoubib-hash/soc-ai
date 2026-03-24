"""
agents/02_analysis/ip_enricher.py
----------------------------------
IP reputation checker using AbuseIPDB API.
Caches results for 1 hour to avoid repeated API calls.
Falls back gracefully if API key missing or API is down.
"""

import time
import ipaddress

import requests

from shared.logger import get_logger

log = get_logger("ip_enricher")


# ── Private IP Ranges ─────────────────────────────────────────────
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.1/32"),
]

# ── Known bad / high-risk ports ───────────────────────────────────
KNOWN_BAD_PORTS = {22, 23, 3389, 445, 135, 4444, 1337, 6666, 31337, 8080, 9090}


class IPEnricher:
    """
    Queries AbuseIPDB for IP reputation data.

    Returns a score in [0.0, 1.0]:
      0.0 = clean / internal / unknown
      1.0 = maximally malicious

    Results are cached for ``cache_ttl`` seconds (default 3600 = 1 hour)
    to avoid hammering the API on repeated alerts from the same source.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.cache: dict[str, dict] = {}   # {ip: {"data": {...}, "ts": float}}
        self.cache_ttl: int = 3600          # 1 hour

    # ── Public API ────────────────────────────────────────────────

    def get_reputation(self, ip: str) -> dict:
        """
        Returns a reputation dict::

            {
                "score": float,        # 0.0 = clean, 1.0 = malicious
                "country": str,        # e.g. "TN", "RU", "US", "internal"
                "is_whitelisted": bool
            }

        Never raises — always returns a safe default on failure.
        """
        # 1. Private / internal address → no lookup needed
        if self.is_internal(ip):
            return {"score": 0.0, "country": "internal", "is_whitelisted": False}

        # 2. Cache hit?
        cached = self._get_cache(ip)
        if cached is not None:
            return cached

        # 3. No API key → development mode, skip lookup
        if not self.api_key:
            result = {"score": 0.0, "country": "unknown", "is_whitelisted": False}
            self._set_cache(ip, result)
            return result

        # 4. Call AbuseIPDB
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

            # 5. Normalise score 0–100 → 0.0–1.0
            score = data.get("abuseConfidenceScore", 0) / 100.0
            result = {
                "score": score,
                "country": data.get("countryCode", "unknown"),
                "is_whitelisted": bool(data.get("isWhitelisted", False)),
            }

            # 6. Cache
            self._set_cache(ip, result)
            log.debug(f"AbuseIPDB | {ip} → score={score:.2f} country={result['country']}")
            return result

        except Exception as exc:
            log.warning(f"AbuseIPDB lookup failed for {ip}: {exc}")
            return {"score": 0.0, "country": "unknown", "is_whitelisted": False}

    def is_internal(self, ip: str) -> bool:
        """Returns True if IP is in RFC-1918 / loopback ranges."""
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in PRIVATE_RANGES)
        except ValueError:
            return False

    def is_bad_port(self, port: int) -> bool:
        """Returns True if the port is in the known-bad list."""
        return port in KNOWN_BAD_PORTS

    # ── Cache helpers ─────────────────────────────────────────────

    def _get_cache(self, ip: str):
        """Returns cached data if still valid, else None."""
        entry = self.cache.get(ip)
        if entry and (time.time() - entry["ts"]) < self.cache_ttl:
            return entry["data"]
        return None

    def _set_cache(self, ip: str, data: dict) -> None:
        self.cache[ip] = {"data": data, "ts": time.time()}
