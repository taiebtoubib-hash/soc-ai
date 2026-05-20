#!/bin/bash
# infra/kafka/init-topics.sh
# --------------------------
# Creates all SOC AI Kafka topics at cluster startup.
# Run once via the kafka-init service in docker-compose.yml
#
# Topics use:
#   --partitions 3          → parallelism across agent instances
#   --replication-factor 1  → single broker (dev/staging)
#   retention.ms=86400000   → 24h message retention

set -e

KAFKA_BROKER="kafka:9092"
RETENTION_MS="86400000"   # 24 hours
PARTITIONS=3
REPLICATION=1

echo "========================================"
echo " SOC AI — Kafka Topic Initialization"
echo "========================================"
echo " Broker  : $KAFKA_BROKER"
echo " Retention: 24h"
echo " Partitions: $PARTITIONS"
echo ""

# Wait for Kafka to be fully ready
echo "⏳ Waiting for Kafka broker to be ready..."
cub kafka-ready -b $KAFKA_BROKER 1 60
echo "✅ Kafka broker is ready."
echo ""

# Helper function
create_topic() {
  local TOPIC=$1
  local DESC=$2
  echo "📌 Creating topic: $TOPIC ($DESC)"
  kafka-topics --bootstrap-server $KAFKA_BROKER \
    --create \
    --if-not-exists \
    --topic "$TOPIC" \
    --partitions $PARTITIONS \
    --replication-factor $REPLICATION \
    --config retention.ms=$RETENTION_MS \
    --config cleanup.policy=delete
  echo "   ✅ $TOPIC"
}

# ── Pipeline Topics ─────────────────────────────────────────────────
create_topic "soc.raw"             "Collector → Analysis (NormalizedAlert)"
create_topic "soc.enriched"        "Analysis → Detection (EnrichedAlert)"
create_topic "soc.analyzed"        "Detection → ML Classifier (DetectionResult)"
create_topic "soc.classified"      "ML Classifier → FP Detector (ClassificationResult)"
create_topic "soc.true_positives"  "FP Detector → Orchestrator (confirmed threats)"
create_topic "soc.false_positives" "FP Detector → MLOps (false positives for retraining)"
create_topic "soc.orchestrated"    "Orchestrator → Response (IncidentReport + playbook)"
create_topic "soc.frontend"        "Response → Dashboard/SSE (final IncidentReport)"

# ── Feedback / MLOps Topic ──────────────────────────────────────────
create_topic "soc.feedback"        "Analyst feedback → MLOps retraining pipeline"

echo ""
echo "========================================"
echo " ✅ All topics created successfully!"
echo "========================================"
echo ""

# List all created topics
echo "📋 Topic list:"
kafka-topics --bootstrap-server $KAFKA_BROKER --list | grep "^soc\." | sort
echo ""
