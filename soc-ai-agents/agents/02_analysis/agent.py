"""
agents/02_analysis/agent.py
-----------------------------
Analysis Agent — second agent in the SOC AI pipeline.

Responsibilities:
  - Receives NormalizedAlert objects from raw_alerts_queue
  - Enriches them with IP reputation (AbuseIPDB) and behavioral data
  - Builds a 41-feature vector ready for ML models
  - Pushes EnrichedAlert objects to enriched_alerts_queue

NO ML — NO LLM — pure Python enrichment.
Speed target: < 1 second per alert.
"""

import sys
import os
from pathlib import Path

# ── Project root on sys.path (same pattern as 01_collector) ──────
_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_ROOT))

from shared.models import NormalizedAlert, EnrichedAlert
from shared.config import settings
from shared.logger import get_logger
from shared.queue_bus import raw_alerts_queue, enriched_alerts_queue

# ── Local imports (same directory as this file) ──────────────────
_DIR = Path(__file__).parent
sys.path.insert(0, str(_DIR))

from ip_enricher import IPEnricher
from correlator import AlertCorrelator
from feature_builder import build_features

log = get_logger("analysis")


class AnalysisAgent:
    """
    Pulls NormalizedAlert objects from raw_alerts_queue,
    enriches each one with IP reputation and behavioral context,
    then pushes EnrichedAlert objects to enriched_alerts_queue.
    """

    def __init__(self):
        self.queue_in   = raw_alerts_queue
        self.queue_out  = enriched_alerts_queue
        self.enricher   = IPEnricher(api_key=settings.ABUSEIPDB_KEY)
        self.correlator = AlertCorrelator()
        log.info("AnalysisAgent initialized")

    # ── Core enrichment logic ─────────────────────────────────────

    def enrich(self, alert: NormalizedAlert) -> EnrichedAlert:
        """
        Full enrichment pipeline for a single alert.

        Steps:
          1. Register alert with the correlator (sliding window).
          2. Fetch IP reputation for the source IP.
          3. Build EnrichedAlert with all enrichment fields populated.
          4. Compute the 41-feature vector and attach it.

        Returns:
            EnrichedAlert ready for the detection agent.
        """
        try:
            # 1. Track in sliding window
            self.correlator.add(alert)

            # 2. IP reputation
            reputation = self.enricher.get_reputation(alert.src_ip)

            # 3. Build enriched object
            enriched = EnrichedAlert(
                alert=alert,
                src_reputation_score=reputation["score"],
                src_geo_country=reputation["country"],
                is_src_internal=self.enricher.is_internal(alert.src_ip),
                is_dst_internal=self.enricher.is_internal(alert.dst_ip),
                is_known_bad_port=self.enricher.is_bad_port(alert.dst_port),
                same_src_ip_count_last_5min=self.correlator.count_same_src(alert.src_ip),
                unique_dst_ports_last_5min=self.correlator.unique_dst_ports(alert.src_ip),
                failed_auth_count_last_5min=self.correlator.failed_auth_count(alert.src_ip),
            )

            # 4. 41-feature vector
            enriched.features = build_features(enriched)

            return enriched

        except Exception as exc:
            log.warning(
                f"Enrichment error for alert {alert.id}: {exc} "
                "— returning minimal EnrichedAlert"
            )
            # Always return a valid object; never crash the pipeline
            return EnrichedAlert(alert=alert)

    # ── Main loop ─────────────────────────────────────────────────

    def _process_alert_and_forward(self, alert: NormalizedAlert):
        """Processes a single alert and forwards it to the next stage."""
        try:
            enriched = self.enrich(alert)
            
            if settings.USE_KAFKA:
                self.bus.publish("soc.enriched", enriched, key=enriched.alert.id)
            else:
                self.queue_out.put(enriched)

            log.info(
                f"Enriched | src={alert.src_ip} | "
                f"reputation={enriched.src_reputation_score:.2f} | "
                f"internal={enriched.is_src_internal} | "
                f"bad_port={enriched.is_known_bad_port} | "
                f"same_src_count={enriched.same_src_ip_count_last_5min}"
            )
            log.info(
                f"✅ Vecteur ML généré : {len(enriched.features)} features -> "
                f"{list(enriched.features.values())[:8]} ..."
            )
        except Exception as exc:
            log.error(f"Unexpected error in AnalysisAgent processing: {exc}")

    def run(self):
        """
        Blocking main loop. Reads from raw alerts queue or Kafka topic,
        enriches each alert, and writes to enriched output.
        """
        log.info(f"AnalysisAgent running — USE_KAFKA={settings.USE_KAFKA}")

        if settings.USE_KAFKA:
            from shared.kafka_bus import KafkaBus
            self.bus = KafkaBus(settings.KAFKA_BOOTSTRAP_SERVERS)
            log.info("AnalysisAgent waiting for alerts via Kafka topic: soc.raw...")
            # This is a blocking call that runs forever
            self.bus.consume(
                topic="soc.raw",
                group_id="analysis-group",
                model_class=NormalizedAlert,
                callback=self._process_alert_and_forward
            )
        else:
            log.info("AnalysisAgent waiting for alerts via in-memory queue...")
            while True:
                try:
                    alert: NormalizedAlert = self.queue_in.get()
                    self._process_alert_and_forward(alert)
                except Exception as exc:
                    log.error(f"Error in Analysis queue loop: {exc}")


# ── Entrypoint ────────────────────────────────────────────────────

if __name__ == "__main__":
    agent = AnalysisAgent()
    agent.run()
