"""
agents/03_detection/agent.py
----------------------------
Rule-based detection agent for the SOC AI pipeline.

Consumes : soc.enriched  (EnrichedAlert)
Publishes: soc.analyzed  (DetectionResult)

Applies a priority-ordered rule chain to each enriched alert,
tags it with a detection verdict, and forwards the result
downstream for optional ML classification.
"""

import logging
from shared.models import EnrichedAlert, DetectionResult
from shared.kafka_bus import KafkaBus
from shared.config import settings
from shared.llm_client import llm

log = logging.getLogger("detection")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
)

# Module-level bus — initialized in main()
bus: KafkaBus = None


def apply_rules(alert: EnrichedAlert) -> DetectionResult:
    """
    Evaluate an EnrichedAlert against a fixed priority chain of
    detection rules and return a DetectionResult.

    Priority order (first match wins):
      1. PORT_SCAN        — unique_dst_ports_last_5min > 10
      2. BRUTE_FORCE      — failed_auth_count_last_5min > 5
      3. C2_COMMUNICATION — is_known_bad_port AND src_reputation_score > 0.7
      4. DATA_EXFILTRATION— dst_port in {21,25,53} AND is_src_internal
      5. NONE             — no rule matched
    """

    # ── Priority 1: PRIVILEGE_ESCALATION ─────────────────
    raw = alert.alert.raw or {}
    raw_data = raw.get("data", raw)

    def check_flag(field):
        val = raw_data.get(field)
        if val is None:
            return False
        try:
            return int(val) == 1
        except (ValueError, TypeError):
            return False

    if check_flag("root_shell") or check_flag("su_attempted"):
        return DetectionResult(
            enriched=alert,
            rule_triggered=True,
            rule_name="PRIVILEGE_ESCALATION",
            confidence=0.90,
            needs_ml=True,
        )

    # ── Priority 2: C2_COMMUNICATION ─────────────────────
    if alert.is_src_internal and alert.is_known_bad_port:
        return DetectionResult(
            enriched=alert,
            rule_triggered=True,
            rule_name="C2_COMMUNICATION",
            confidence=0.85,
            needs_ml=True,
        )

    # ── Priority 3: PORT_SCAN ────────────────────────────
    if alert.unique_dst_ports_last_5min > 10:
        return DetectionResult(
            enriched=alert,
            rule_triggered=True,
            rule_name="PORT_SCAN",
            confidence=min(alert.unique_dst_ports_last_5min / 50.0, 1.0),
            needs_ml=True,
        )

    # ── Priority 4: BRUTE_FORCE ──────────────────────────
    if alert.failed_auth_count_last_5min > 5:
        return DetectionResult(
            enriched=alert,
            rule_triggered=True,
            rule_name="BRUTE_FORCE",
            confidence=min(alert.failed_auth_count_last_5min / 20.0, 1.0),
            needs_ml=True,
        )

    # ── Priority 5: DOS_FLOOD ────────────────────────────
    if alert.same_src_ip_count_last_5min > 20 or alert.alert.severity >= 14:
        return DetectionResult(
            enriched=alert,
            rule_triggered=True,
            rule_name="DOS_FLOOD",
            confidence=min(alert.same_src_ip_count_last_5min / 50.0, 1.0),
            needs_ml=True,
        )

    # ── Priority 6: DATA_EXFILTRATION ────────────────────
    if alert.alert.dst_port in {21, 25, 53} and alert.is_src_internal:
        return DetectionResult(
            enriched=alert,
            rule_triggered=True,
            rule_name="DATA_EXFILTRATION",
            confidence=0.6,
            needs_ml=False,
        )

    # ── Default: NONE ────────────────────────────────────
    return DetectionResult(
        enriched=alert,
        rule_triggered=False,
        rule_name="NONE",
        confidence=0.0,
        needs_ml=False,
    )


def handle_enriched_alert(alert: EnrichedAlert) -> None:
    """Callback invoked for every message on soc.enriched."""
    result = apply_rules(alert)

    # LLM enrichment — non-blocking, advisory only
    if result.rule_triggered and settings.LLM_ENABLED:
        alert_summary = {
            "src_ip":            alert.alert.src_ip,
            "dst_port":          alert.alert.dst_port,
            "protocol":          alert.alert.protocol,
            "rule_description":  alert.alert.rule_description,
            "severity":          alert.alert.severity,
            "rule_name":         result.rule_name,
            "confidence":        result.confidence,
            "src_reputation":    alert.src_reputation_score,
            "src_country":       alert.src_geo_country,
            "failed_auth_count": alert.failed_auth_count_last_5min,
            "unique_ports":      alert.unique_dst_ports_last_5min,
        }
        result.llm_analysis = llm.analyze_threat(alert_summary)

    log.info(
        "[DETECTION] %s → rule=%s confidence=%.2f needs_ml=%s llm=%s",
        alert.alert.src_ip, result.rule_name, result.confidence,
        result.needs_ml, "OK" if result.llm_analysis else "skipped",
    )
    bus.publish("soc.analyzed", result, key=alert.alert.id)


def main() -> None:
    """Entry point — validate config, wire up Kafka, block on consume loop."""
    global bus

    settings.validate()
    log.info("Detection agent starting (USE_KAFKA=%s)", settings.USE_KAFKA)

    bus = KafkaBus(bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS)

    bus.consume(
        topic="soc.enriched",
        group_id="detection-group",
        model_class=EnrichedAlert,
        callback=handle_enriched_alert,
    )


if __name__ == "__main__":
    main()
