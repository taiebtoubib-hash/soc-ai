"""
infra/kafka/healthcheck.py
--------------------------
Verifies Kafka is ready AND all required SOC topics exist.
Run this before starting agents locally (non-Docker mode).

Usage:
    python infra/kafka/healthcheck.py
    python infra/kafka/healthcheck.py --broker localhost:29092
"""

import sys
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

REQUIRED_TOPICS = [
    "soc.raw",
    "soc.enriched",
    "soc.detection",
    "soc.classified",
    "soc.true_positives",
    "soc.false_positives",
    "soc.orchestrated",
    "soc.frontend",
    "soc.feedback",
]

def check_kafka(broker: str) -> bool:
    try:
        from kafka import KafkaAdminClient, KafkaConsumer
        from kafka.errors import NoBrokersAvailable
    except ImportError:
        print("❌ kafka-python not installed. Run: pip install kafka-python")
        return False

    print(f"\n🔍 SOC AI — Kafka Health Check")
    print(f"   Broker: {broker}")
    print("=" * 50)

    # 1. Check connectivity
    try:
        client = KafkaAdminClient(
            bootstrap_servers=broker,
            client_id="soc-healthcheck",
            request_timeout_ms=5000,
        )
        print("✅ Kafka broker reachable")
    except NoBrokersAvailable:
        print(f"❌ Cannot connect to Kafka at {broker}")
        print("   → Is Docker running? Try: docker-compose up kafka -d")
        return False
    except Exception as e:
        print(f"❌ Kafka connection error: {e}")
        return False

    # 2. Check topics
    existing_topics = set(client.list_topics())
    print(f"\n📋 Checking {len(REQUIRED_TOPICS)} required topics:")

    all_ok = True
    for topic in REQUIRED_TOPICS:
        if topic in existing_topics:
            print(f"   ✅  {topic}")
        else:
            print(f"   ❌  {topic}  ← MISSING")
            all_ok = False

    client.close()

    # Summary
    print("\n" + "=" * 50)
    if all_ok:
        print("✅ Kafka is healthy — all topics present")
        print("   Ready to start SOC AI agents with USE_KAFKA=true")
    else:
        print("⚠️  Some topics are missing.")
        print("   Run: docker exec soc-kafka bash /init-topics.sh")
    print()
    return all_ok


def main():
    parser = argparse.ArgumentParser(description="SOC AI Kafka Health Check")
    parser.add_argument(
        "--broker",
        default="localhost:29092",
        help="Kafka bootstrap server (default: localhost:29092)"
    )
    args = parser.parse_args()
    ok = check_kafka(args.broker)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
