"""
agents/01_collector/agent.py
-----------------------------
Collector Agent — first agent in the pipeline.

Responsibilities:
  - Fetch raw alerts from Wazuh API (polling every 60s)
  - Stream raw alerts from Suricata eve.json (real-time)
  - Simulate fake alerts locally (development mode)
  - Normalize all sources into NormalizedAlert format
  - Push to raw_alerts_queue → consumed by Analysis Agent

COLLECTOR_MODE (set in .env):
  "simulate" → fake alerts   (local development, no server needed)
  "wazuh"    → Wazuh API only
  "suricata" → Suricata only
  "both"     → Wazuh + Suricata (production)
"""

import sys
import time
import json
import threading
from pathlib import Path
from datetime import datetime, timedelta, timezone

import requests
import urllib3

# Disable SSL warnings for Wazuh self-signed cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Local imports ──────────────────────────────────────────────────
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.models import NormalizedAlert
from shared.config import settings
from shared.logger import get_logger
from shared.queue_bus import raw_alerts_queue
from scripts.simulate_alerts import stream_to_queue, get_single_alert

log = get_logger("collector")


# ── Wazuh Collector ────────────────────────────────────────────────

class WazuhCollector:
    """
    Connects to Wazuh REST API and fetches security alerts.
    Authenticates with JWT token, refreshes when expired.
    """

    def __init__(self):
        self.base_url = f"https://{settings.WAZUH_HOST}:{settings.WAZUH_PORT}"
        self.token = None
        self.token_expiry = None

    def authenticate(self) -> bool:
        """Get JWT token from Wazuh API."""
        try:
            response = requests.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(settings.WAZUH_USER, settings.WAZUH_PASSWORD),
                verify=False,
                timeout=10
            )
            if response.status_code == 200:
                self.token = response.json()["data"]["token"]
                self.token_expiry = datetime.now() + timedelta(minutes=14)
                log.info("Wazuh authentication successful")
                return True
            else:
                log.error(f"Wazuh auth failed: {response.status_code}")
                return False
        except Exception as e:
            log.error(f"Wazuh connection error: {e}")
            return False

    def _ensure_token(self):
        """Re-authenticate if token is expired."""
        if not self.token or datetime.now() >= self.token_expiry:
            self.authenticate()

    def fetch_alerts(self, last_n_minutes: int = 1) -> list:
        """Fetch alerts from last N minutes via Wazuh API."""
        self._ensure_token()
        if not self.token:
            return []

        try:
            since = (
                datetime.now(timezone.utc) - timedelta(minutes=last_n_minutes)
            ).isoformat()

            response = requests.get(
                f"{self.base_url}/alerts",
                headers={"Authorization": f"Bearer {self.token}"},
                params={
                    "limit": 500,
                    "sort": "-timestamp",
                    "q": f"timestamp>{since}"
                },
                verify=False,
                timeout=15
            )

            if response.status_code == 200:
                alerts = response.json()["data"]["affected_items"]
                log.info(f"Fetched {len(alerts)} alerts from Wazuh")
                return alerts
            else:
                log.warning(f"Wazuh fetch returned {response.status_code}")
                return []

        except Exception as e:
            log.error(f"Failed to fetch Wazuh alerts: {e}")
            return []

    def normalize(self, raw: dict) -> NormalizedAlert:
        """Convert raw Wazuh alert into NormalizedAlert."""
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
            protocol=data.get("protocol", "unknown"),
            rule_id=str(rule.get("id", "")),
            rule_description=rule.get("description", ""),
            severity=int(rule.get("level", 0)),
            raw=raw
        )


# ── Suricata Collector ─────────────────────────────────────────────

class SuricataCollector:
    """
    Reads Suricata EVE JSON log file in real-time (tail -f style).
    Only processes events of type "alert".
    """

    def __init__(self):
        self.log_path = Path(settings.SURICATA_LOG_PATH)

    def follow(self):
        """Generator that yields new alert lines as they appear."""
        if not self.log_path.exists():
            log.error(f"Suricata log not found: {self.log_path}")
            return

        log.info(f"Following Suricata log: {self.log_path}")
        with open(self.log_path, "r") as f:
            f.seek(0, 2)  # jump to end of file
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        yield event
                except json.JSONDecodeError:
                    continue

    def normalize(self, raw: dict) -> NormalizedAlert:
        """Convert raw Suricata alert into NormalizedAlert."""
        alert = raw.get("alert", {})

        return NormalizedAlert(
            id=str(raw.get("flow_id", "")),
            timestamp=raw.get("timestamp", datetime.now().isoformat()),
            source="suricata",
            src_ip=raw.get("src_ip", "0.0.0.0"),
            dst_ip=raw.get("dest_ip", "0.0.0.0"),
            src_port=int(raw.get("src_port", 0)),
            dst_port=int(raw.get("dest_port", 0)),
            protocol=raw.get("proto", "unknown").lower(),
            rule_id=str(alert.get("signature_id", "")),
            rule_description=alert.get("signature", ""),
            severity=int(alert.get("severity", 0)),
            raw=raw
        )


# ── Simulate Collector ─────────────────────────────────────────────

class SimulateCollector:
    """
    Used in development mode.
    Generates fake alerts without needing a real Wazuh/Suricata server.
    """

    def normalize(self, raw: dict) -> NormalizedAlert:
        """Convert fake alert dict into NormalizedAlert."""
        return NormalizedAlert(
            id=str(raw.get("id", "")),
            timestamp=raw.get("timestamp", datetime.now().isoformat()),
            source=raw.get("source", "simulate"),
            src_ip=raw.get("src_ip", "0.0.0.0"),
            dst_ip=raw.get("dst_ip", "0.0.0.0"),
            src_port=int(raw.get("src_port", 0)),
            dst_port=int(raw.get("dst_port", 0)),
            protocol=raw.get("protocol", "tcp"),
            rule_id=raw.get("rule_id", "0"),
            rule_description=raw.get("rule_description", ""),
            severity=int(raw.get("severity", 1)),
            raw=raw
        )


# ── Collector Agent ────────────────────────────────────────────────

class CollectorAgent:
    """
    Master collector — manages all sub-collectors.
    Reads COLLECTOR_MODE from config to decide which source to use.
    Pushes NormalizedAlert objects to raw_alerts_queue.
    """

    def __init__(self):
        self.mode = settings.COLLECTOR_MODE
        self.output_queue = raw_alerts_queue
        log.info(f"CollectorAgent initialized | mode={self.mode} | USE_KAFKA={settings.USE_KAFKA}")
        
        if settings.USE_KAFKA:
            from shared.kafka_bus import KafkaBus
            self.bus = KafkaBus(settings.KAFKA_BOOTSTRAP_SERVERS)

    def _push(self, raw: dict, normalizer):
        """Normalize a raw alert and push to queue/Kafka."""
        try:
            normalized = normalizer(raw)
            if settings.USE_KAFKA:
                self.bus.publish("soc.raw", normalized, key=normalized.id)
            else:
                self.output_queue.put(normalized)
                
            log.debug(
                f"Alert queued | "
                f"src={normalized.src_ip} → "
                f"dst={normalized.dst_ip}:{normalized.dst_port} | "
                f"severity={normalized.severity}"
            )
        except Exception as e:
            log.error(f"Failed to normalize alert: {e} | raw={raw}")

    # ── Simulate mode ────────────────────────────────────────────

    def run_simulate(self):
        """Development mode — fake alerts."""
        log.info("Starting SIMULATE collector")
        sim = SimulateCollector()

        import random
        from scripts.simulate_alerts import ATTACK_TEMPLATES, NORMAL_TRAFFIC

        pool = (NORMAL_TRAFFIC * 3) + ATTACK_TEMPLATES
        count = 0

        while True:
            template = random.choice(pool)
            raw = {
                "id": str(random.randint(100000, 999999)),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **template
            }
            self._push(raw, sim.normalize)
            count += 1
            log.info(f"Simulated alert #{count} | {template.get('label', 'normal')}")
            time.sleep(2)

    # ── Wazuh mode ───────────────────────────────────────────────

    def run_wazuh(self):
        """Production mode — poll Wazuh API every 60s."""
        log.info("Starting WAZUH collector")
        wazuh = WazuhCollector()

        if not wazuh.authenticate():
            log.error("Cannot start Wazuh collector — auth failed")
            return

        while True:
            alerts = wazuh.fetch_alerts(last_n_minutes=1)
            for raw in alerts:
                self._push(raw, wazuh.normalize)
            time.sleep(settings.WAZUH_POLL_INTERVAL)

    # ── Suricata mode ────────────────────────────────────────────

    def run_suricata(self):
        """Production mode — real-time Suricata stream."""
        log.info("Starting SURICATA collector")
        suricata = SuricataCollector()

        for raw in suricata.follow():
            self._push(raw, suricata.normalize)

    # ── Both mode (production) ───────────────────────────────────

    def run_both(self):
        """Production mode — Wazuh + Suricata simultaneously."""
        log.info("Starting BOTH collectors (Wazuh + Suricata)")

        wazuh_thread = threading.Thread(
            target=self.run_wazuh,
            name="wazuh-collector",
            daemon=True
        )
        suricata_thread = threading.Thread(
            target=self.run_suricata,
            name="suricata-collector",
            daemon=True
        )

        wazuh_thread.start()
        suricata_thread.start()

        wazuh_thread.join()
        suricata_thread.join()

    # ── Main entry point ─────────────────────────────────────────

    def run(self):
        """Start the collector in the configured mode."""
        modes = {
            "simulate": self.run_simulate,
            "wazuh":    self.run_wazuh,
            "suricata": self.run_suricata,
            "both":     self.run_both,
        }

        runner = modes.get(self.mode)
        if not runner:
            log.error(f"Unknown COLLECTOR_MODE: {self.mode}")
            return

        try:
            runner()
        except KeyboardInterrupt:
            log.info("Collector stopped by user")
        except Exception as e:
            log.error(f"Collector crashed: {e}")
            raise


# ── Standalone test ────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("Starting Collector Agent standalone test")
    agent = CollectorAgent()
    agent.run()
