"""
training/consume_feedback.py
-----------------------------
Kafka Analyst Feedback Consumer

Listens to the 'soc.feedback' Kafka topic for live feedback submitted by
analysts from the React dashboard. Converts the dashboard data structure
and appends each record to the monthly MLOps feedback CSV:
  training/datasets/feedback/feedback_YYYY-MM.csv

Usage:
  python training/consume_feedback.py
"""

import json
import os
import sys
from typing import Dict, Any

from kafka import KafkaConsumer
from kafka.errors import KafkaError

# Allow running from project root OR training/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from training.training_utils import get_logger, setup_dirs
from training.collect_feedback import append_feedback_row

log = get_logger("consume_feedback")

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092")
TOPIC_NAME = "soc.feedback"


def map_verdict_to_label(verdict: str) -> str:
    """Map dashboard verdict strings to training feedback labels (tp, fp, fn)."""
    mapping = {
        "confirmed_tp": "tp",       # True Positive
        "false_positive": "fp",     # False Positive
        "escalated": "tp",          # Treated as True Positive requiring tier-2 attention
    }
    return mapping.get(verdict, "tp")


def process_message(msg_value: Dict[str, Any]) -> None:
    try:
        # Extract fields from dashboard feedback payload
        incident_id = msg_value.get("incidentId")
        verdict = msg_value.get("verdict", "")
        note = msg_value.get("note", "")
        original_score = msg_value.get("originalScore")
        
        if not incident_id:
            log.warning("Received feedback message without incidentId: %s", msg_value)
            return

        label = map_verdict_to_label(verdict)
        confidence = float(original_score) if original_score is not None else None
        
        # Save to the monthly feedback CSV
        path = append_feedback_row(
            alert_id=incident_id,
            label=label,
            confidence=confidence,
            analyst="dashboard_user",
            notes=note,
            source="dashboard",
        )
        
        log.info("Saved feedback from dashboard:")
        log.info("    Incident ID: %s", incident_id)
        log.info("    Verdict    : %s (mapped to label: %s)", verdict, label)
        log.info("    Notes      : %s", note)
        log.info("    CSV Path   : %s", os.path.basename(path))
        log.info("-" * 40)

    except Exception as e:
        log.error("Failed to process feedback message: %s", e, exc_info=True)


def main() -> None:
    setup_dirs()
    log.info("Starting Analyst Feedback Consumer...")
    log.info("Connecting to Kafka broker at: %s", KAFKA_BOOTSTRAP_SERVERS)
    log.info("Subscribed to topic: %s", TOPIC_NAME)

    try:
        consumer = KafkaConsumer(
            TOPIC_NAME,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            group_id="mlops-feedback-consumer",
            auto_offset_reset="earliest",
            enable_auto_commit=True,
            value_deserializer=lambda m: json.loads(m.decode("utf-8"))
        )
    except Exception as e:
        log.critical("Failed to connect to Kafka at %s: %s", KAFKA_BOOTSTRAP_SERVERS, e)
        sys.exit(1)

    try:
        for msg in consumer:
            log.info("Received feedback message from Kafka.")
            process_message(msg.value)
    except KeyboardInterrupt:
        log.info("Shutting down consumer loop.")
    finally:
        consumer.close()
        log.info("Feedback consumer closed.")


if __name__ == "__main__":
    main()
