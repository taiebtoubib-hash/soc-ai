"""
scripts/simulate_alerts.py
--------------------------
Generates realistic fake Wazuh and Suricata alerts for local testing.
Use this when ENV=development (no real Wazuh/Suricata server needed).

Simulates these attack types:
  - Neptune DoS (SYN flood)
  - Port scan (nmap style)
  - SSH brute force
  - Normal traffic
  - C2 communication
  - Privilege escalation attempt

Usage:
    python scripts/simulate_alerts.py
    → writes fake alerts to shared queue every few seconds
"""

import random
import time
import json
from datetime import datetime, timezone


# ── Fake Alert Templates ───────────────────────────────────────────

NORMAL_TRAFFIC = [
    {
        "source": "wazuh",
        "src_ip": "192.168.1.{}".format(random.randint(1, 50)),
        "dst_ip": "10.0.0.1",
        "src_port": random.randint(1024, 65535),
        "dst_port": 80,
        "protocol": "tcp",
        "rule_id": "1002",
        "rule_description": "Normal HTTP traffic",
        "severity": 2,
        "flag": "SF",
        "serror_rate": 0.0,
        "src_bytes": random.randint(100, 5000),
        "dst_bytes": random.randint(500, 10000),
        "logged_in": 1,
        "count": random.randint(1, 10),
        "same_srv_rate": 1.0,
    },
]

ATTACK_TEMPLATES = [
    # ── Neptune DoS (SYN flood) ──────────────────────────────────
    {
        "label": "neptune",
        "source": "suricata",
        "src_ip": "185.220.101.{}".format(random.randint(1, 255)),
        "dst_ip": "10.0.0.1",
        "src_port": random.randint(1024, 65535),
        "dst_port": 80,
        "protocol": "tcp",
        "rule_id": "2100498",
        "rule_description": "GPL ATTACK_RESPONSE id check returned root",
        "severity": 14,
        "flag": "S0",           # SYN sent, no response → SYN flood
        "serror_rate": 1.0,     # 100% SYN errors
        "src_bytes": 0,
        "dst_bytes": 0,
        "logged_in": 0,
        "count": 511,
        "same_srv_rate": 1.0,
    },

    # ── Port Scan (nmap) ─────────────────────────────────────────
    {
        "label": "portsweep",
        "source": "suricata",
        "src_ip": "203.0.113.{}".format(random.randint(1, 255)),
        "dst_ip": "10.0.0.5",
        "src_port": random.randint(1024, 65535),
        "dst_port": random.randint(1, 1024),
        "protocol": "tcp",
        "rule_id": "2010935",
        "rule_description": "ET SCAN Potential SSH Scan",
        "severity": 10,
        "flag": "REJ",
        "serror_rate": 0.0,
        "rerror_rate": 1.0,     # all connections rejected → scanning
        "src_bytes": 0,
        "dst_bytes": 0,
        "logged_in": 0,
        "count": 1,
        "diff_srv_rate": 1.0,   # hitting many different services
        "same_srv_rate": 0.06,
    },

    # ── SSH Brute Force ──────────────────────────────────────────
    {
        "label": "brute_force",
        "source": "wazuh",
        "src_ip": "91.121.{}. {}".format(
            random.randint(1, 255), random.randint(1, 255)
        ),
        "dst_ip": "192.168.1.10",
        "src_port": random.randint(1024, 65535),
        "dst_port": 22,
        "protocol": "tcp",
        "rule_id": "5763",
        "rule_description": "SSHD brute force trying to get access to the system",
        "severity": 12,
        "flag": "SF",
        "serror_rate": 0.0,
        "src_bytes": 200,
        "dst_bytes": 100,
        "logged_in": 0,
        "num_failed_logins": random.randint(5, 20),
        "count": random.randint(20, 100),
        "same_srv_rate": 1.0,
    },

    # ── C2 Communication ─────────────────────────────────────────
    {
        "label": "c2",
        "source": "suricata",
        "src_ip": "10.0.0.55",           # internal host compromised
        "dst_ip": "185.234.219.{}".format(random.randint(1, 255)),
        "src_port": random.randint(1024, 65535),
        "dst_port": 4444,                # classic C2 port
        "protocol": "tcp",
        "rule_id": "2013028",
        "rule_description": "ET TROJAN Possible C2 Beacon",
        "severity": 13,
        "flag": "SF",
        "serror_rate": 0.0,
        "src_bytes": random.randint(100, 500),
        "dst_bytes": random.randint(100, 500),
        "logged_in": 1,
        "count": 1,
        "same_srv_rate": 1.0,
        "duration": 3600,               # 1 hour connection
    },

    # ── Privilege Escalation ─────────────────────────────────────
    {
        "label": "buffer_overflow",
        "source": "wazuh",
        "src_ip": "10.0.0.22",
        "dst_ip": "10.0.0.1",
        "src_port": random.randint(1024, 65535),
        "dst_port": 80,
        "protocol": "tcp",
        "rule_id": "5501",
        "rule_description": "User missed the password more than one time",
        "severity": 15,
        "flag": "SF",
        "serror_rate": 0.0,
        "src_bytes": random.randint(5000, 50000),
        "dst_bytes": random.randint(100, 500),
        "root_shell": 1,                # root shell obtained
        "su_attempted": 1,
        "num_root": random.randint(1, 5),
        "logged_in": 1,
        "count": 1,
    },
]


def make_alert(template: dict) -> dict:
    """Builds a complete fake alert from a template."""
    return {
        "id": str(random.randint(100000, 999999)),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": template.get("source", "wazuh"),
        "src_ip": template.get("src_ip", "0.0.0.0"),
        "dst_ip": template.get("dst_ip", "0.0.0.0"),
        "src_port": template.get("src_port", 0),
        "dst_port": template.get("dst_port", 0),
        "protocol": template.get("protocol", "tcp"),
        "rule_id": template.get("rule_id", "0"),
        "rule_description": template.get("rule_description", ""),
        "severity": template.get("severity", 1),
        "raw": template,
        "label": template.get("label", "normal"),  # for testing only
    }


def stream_to_queue(queue, speed: str = "normal"):
    """
    Streams fake alerts into the collector queue.
    Used when COLLECTOR_MODE=simulate in config.

    Args:
        queue:  raw_alerts_queue from queue_bus
        speed:  "slow" (5s), "normal" (2s), "fast" (0.5s)
    """
    delays = {"slow": 5.0, "normal": 2.0, "fast": 0.5}
    delay = delays.get(speed, 2.0)

    # Mix: 60% normal, 40% attacks (realistic ratio)
    pool = (NORMAL_TRAFFIC * 3) + ATTACK_TEMPLATES

    print(f"🚀 Simulator started — sending alerts every {delay}s")
    print(f"   Pool: {len(pool)} alert templates")
    print(f"   Press Ctrl+C to stop\n")

    count = 0
    while True:
        template = random.choice(pool)
        alert = make_alert(template)
        queue.put(alert)
        count += 1

        label = alert.get("label", "normal")
        emoji = "🔴" if label != "normal" else "🟢"
        print(
            f"{emoji} Alert #{count:04d} | "
            f"{label:15s} | "
            f"{alert['src_ip']:20s} → "
            f"{alert['dst_ip']:15s} "
            f"port {alert['dst_port']}"
        )
        time.sleep(delay)


def get_single_alert(label: str = None) -> dict:
    """
    Returns one fake alert for unit testing.

    Args:
        label: "neptune" | "brute_force" | "c2" | "normal" | None (random)

    Example:
        alert = get_single_alert("neptune")
        alert = get_single_alert()  # random
    """
    if label:
        template = next(
            (t for t in ATTACK_TEMPLATES if t.get("label") == label),
            NORMAL_TRAFFIC[0]
        )
    else:
        pool = (NORMAL_TRAFFIC * 3) + ATTACK_TEMPLATES
        template = random.choice(pool)

    return make_alert(template)


# ── Run standalone for manual testing ─────────────────────────────
if __name__ == "__main__":
    import sys
    from pathlib import Path
    _ROOT = Path(__file__).parent.parent
    sys.path.insert(0, str(_ROOT))

    from shared.config import settings

    if settings.USE_KAFKA:
        from shared.kafka_bus import KafkaBus
        from shared.models import NormalizedAlert
        print(f"📡 Using Kafka Bus at {settings.KAFKA_BOOTSTRAP_SERVERS}")
        bus = KafkaBus(settings.KAFKA_BOOTSTRAP_SERVERS)
        
        # We wrap the proxy in a fake queue interface for compatibility with stream_to_queue
        class KafkaQueueProxy:
            def put(self, item):
                model_item = NormalizedAlert(**item)
                bus.publish("soc.raw", model_item, key=model_item.id)
            def qsize(self):
                return 0
                
        target_queue = KafkaQueueProxy()
    else:
        import queue as q
        target_queue = q.Queue()

    try:
        stream_to_queue(target_queue, speed="normal")
    except KeyboardInterrupt:
        if not settings.USE_KAFKA:
            print(f"\n⏹  Simulator stopped. {target_queue.qsize()} alerts in queue.")
        else:
            print(f"\n⏹  Simulator stopped.")
