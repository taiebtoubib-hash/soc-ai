"""
Suricata Collector: Follows Suricata EVE JSON log and normalizes alerts.
"""
from shared.logger import get_logger
from shared.models import NormalizedAlert

logger = get_logger("suricata_collector")

class SuricataCollector:
    def __init__(self, log_path: str = "/var/log/suricata/eve.json"):
        self.log_path = log_path

    def follow(self):
        """Generator that yields new alerts from the log file."""
        logger.info(f"Following Suricata logs at {self.log_path}")
        # TODO: Implement tail -f logic on eve.json
        yield {}

    def normalize(self, raw_alert: dict) -> NormalizedAlert:
        """Normalize Suricata alert to internal format."""
        # TODO: Implement normalization
        pass
