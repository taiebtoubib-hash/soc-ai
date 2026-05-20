"""
agents/01_collector/wazuh_collector.py
---------------------------------------
Standalone Wazuh Collector module.

Responsibilities:
  - Authenticate against the Wazuh REST API using JWT (auto-refresh)
  - Poll the /alerts endpoint for recent alerts (configurable window)
  - Normalize every raw Wazuh alert dict → NormalizedAlert (shared model)

Usage (standalone smoke-test):
    python wazuh_collector.py

Usage (from agent.py):
    from agents.01_collector.wazuh_collector import WazuhCollector
    wc = WazuhCollector()
    if wc.authenticate():
        for raw in wc.fetch_alerts(last_n_minutes=1):
            alert = wc.normalize(raw)
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

import requests
import urllib3

# Disable SSL warnings for Wazuh self-signed certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Allow running as a standalone script
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.logger import get_logger
from shared.models import NormalizedAlert
from shared.config import settings

logger = get_logger("wazuh_collector")


class WazuhCollector:
    """
    Connects to the Wazuh REST API and fetches security alerts.

    Authentication:
      - Uses HTTP Basic Auth to obtain a short-lived JWT token
        (valid ~15 min by default on Wazuh).
      - Token is cached and refreshed automatically before expiry.

    Wazuh API reference:
      POST /security/user/authenticate  → returns {"data": {"token": "<jwt>"}}
      GET  /alerts                      → returns paginated alert list
    """

    def __init__(self):
        self.base_url = f"https://{settings.WAZUH_HOST}:{settings.WAZUH_PORT}"
        self.token: str | None = None
        self.token_expiry: datetime | None = None

    # ── Authentication ────────────────────────────────────────────────

    def authenticate(self) -> bool:
        """
        Obtain a JWT token from Wazuh using Basic Auth credentials.

        Returns:
            True  — token obtained and stored in self.token
            False — authentication failed (check credentials / connectivity)
        """
        try:
            response = requests.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(settings.WAZUH_USER, settings.WAZUH_PASSWORD),
                verify=False,   # Wazuh uses a self-signed cert by default
                timeout=10,
            )
            if response.status_code == 200:
                self.token = response.json()["data"]["token"]
                # Refresh 1 minute before the 15-minute expiry
                self.token_expiry = datetime.now() + timedelta(minutes=14)
                logger.info("Wazuh authentication successful")
                return True
            else:
                logger.error(
                    f"Wazuh auth failed | status={response.status_code} "
                    f"| body={response.text[:200]}"
                )
                return False
        except requests.exceptions.ConnectionError:
            logger.error(
                f"Cannot reach Wazuh at {self.base_url} — is the server running?"
            )
            return False
        except Exception as e:
            logger.error(f"Unexpected error during Wazuh auth: {e}")
            return False

    def _ensure_token(self):
        """Re-authenticate if the token is missing or about to expire."""
        if not self.token or datetime.now() >= self.token_expiry:
            logger.debug("JWT token expired — re-authenticating with Wazuh")
            self.authenticate()

    # ── Alert fetching ────────────────────────────────────────────────

    def fetch_alerts(self, last_n_minutes: int = 1) -> list[dict]:
        """
        Fetch all alerts generated in the last N minutes from Wazuh.

        Args:
            last_n_minutes: Time window to query (default: 1 minute).

        Returns:
            List of raw alert dicts as returned by the Wazuh API.
            Returns [] on error or if no alerts were found.
        """
        self._ensure_token()
        if not self.token:
            logger.error("Cannot fetch alerts — no valid Wazuh token")
            return []

        try:
            since = (
                datetime.now(timezone.utc) - timedelta(minutes=last_n_minutes)
            ).isoformat()

            response = requests.get(
                f"{self.base_url}/alerts",
                headers={"Authorization": f"Bearer {self.token}"},
                params={
                    "limit":  500,
                    "sort":   "-timestamp",       # newest first
                    "q":      f"timestamp>{since}",
                },
                verify=False,
                timeout=15,
            )

            if response.status_code == 200:
                alerts = response.json()["data"]["affected_items"]
                logger.info(f"Fetched {len(alerts)} Wazuh alert(s)")
                return alerts
            elif response.status_code == 401:
                # Token was rejected — force a re-auth on next call
                self.token = None
                logger.warning("Wazuh returned 401 — token invalidated, will re-auth")
                return []
            else:
                logger.warning(
                    f"Wazuh /alerts returned {response.status_code}: {response.text[:200]}"
                )
                return []

        except Exception as e:
            logger.error(f"Failed to fetch Wazuh alerts: {e}")
            return []

    # ── Normalization ─────────────────────────────────────────────────

    def normalize(self, raw: dict) -> NormalizedAlert:
        """
        Convert a raw Wazuh alert dict into the shared NormalizedAlert format.

        Wazuh alert structure (simplified):
        {
            "id": "1234567890",
            "timestamp": "2024-01-01T00:00:00.000Z",
            "rule": { "id": "5710", "description": "SSH brute force", "level": 10 },
            "data": { "srcip": "1.2.3.4", "dstip": "10.0.0.1",
                      "srcport": "54321", "dstport": "22", "protocol": "tcp" }
        }

        Missing fields are replaced with safe defaults so the pipeline never
        crashes on incomplete alerts from older Wazuh versions.
        """
        data = raw.get("data", {})
        rule = raw.get("rule", {})

        return NormalizedAlert(
            id=str(raw.get("id", "")),
            timestamp=raw.get("timestamp", datetime.now().isoformat()),
            source="wazuh",
            src_ip=data.get("srcip", "0.0.0.0"),
            dst_ip=data.get("dstip", "0.0.0.0"),
            src_port=int(data.get("srcport", 0) or 0),
            dst_port=int(data.get("dstport", 0) or 0),
            protocol=data.get("protocol", "unknown").lower(),
            rule_id=str(rule.get("id", "")),
            rule_description=rule.get("description", ""),
            severity=int(rule.get("level", 0)),
            raw=raw,
        )


# ── Standalone smoke-test ─────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("=== WazuhCollector smoke-test ===")
    logger.info(f"Target: {settings.WAZUH_HOST}:{settings.WAZUH_PORT}")

    collector = WazuhCollector()

    # Step 1 — authenticate
    ok = collector.authenticate()
    if not ok:
        logger.error("Authentication failed. Check WAZUH_HOST / WAZUH_USER / WAZUH_PASSWORD in .env")
        sys.exit(1)

    # Step 2 — fetch last 5 minutes of alerts
    raw_alerts = collector.fetch_alerts(last_n_minutes=5)
    logger.info(f"Raw alerts received: {len(raw_alerts)}")

    # Step 3 — normalize each one
    for raw in raw_alerts[:5]:   # show first 5 only
        try:
            alert = collector.normalize(raw)
            logger.info(
                f"  → [{alert.severity}] {alert.src_ip}:{alert.src_port} "
                f"→ {alert.dst_ip}:{alert.dst_port} | {alert.rule_description}"
            )
        except Exception as e:
            logger.error(f"Normalization error: {e} | raw={raw}")

    logger.info("=== Smoke-test complete ===")
