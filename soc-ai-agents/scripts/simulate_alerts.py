"""
scripts/simulate_alerts.py
--------------------------
Generates realistic fake Wazuh and Suricata alerts for local testing.
Use this when ENV=development (no real Wazuh/Suricata server needed).

⚠️  RUN FROM HOST MACHINE ONLY
    python scripts/simulate_alerts.py
    Kafka is reachable at localhost:29092 (external port mapped in docker-compose).
    DO NOT run this inside a container — use kafka:9092 from inside the soc-net network.

Simulates these attack types:
  - Neptune DoS (SYN flood)
  - Port scan (nmap style)
  - SSH brute force
  - Normal traffic
  - C2 communication
  - Privilege escalation attempt

Usage:
    python scripts/simulate_alerts.py
    → writes fake alerts to Kafka or shared queue every few seconds
"""

import random
import time
from datetime import datetime, timezone


# ── Fake Alert Generators ───────────────────────────────────────────

def generate_wazuh_alert(label, rule_id, rule_description, severity, src_ip, dst_ip, src_port, dst_port, protocol="tcp", **extra_data):
    """Generates a realistic Wazuh alert JSON structure."""
    return {
        "id": str(random.randint(1000000000, 9999999999)) + "." + str(random.randint(100000, 999999)),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "wazuh",
        "label": label,
        "rule": {
            "level": severity,
            "description": rule_description,
            "id": str(rule_id)
        },
        "agent": {
            "id": "001",
            "name": "simulated-agent"
        },
        "manager": {
            "name": "wazuh-manager"
        },
        "decoder": {
            "name": "simulated-decoder"
        },
        "data": {
            "srcip": src_ip,
            "srcport": str(src_port),
            "dstip": dst_ip,
            "dstport": str(dst_port),
            "protocol": protocol,
            **extra_data
        },
        "location": "/var/log/messages"
    }

def generate_suricata_alert(label, signature_id, signature, severity, src_ip, dst_ip, src_port, dst_port, protocol="TCP"):
    """Generates a realistic Suricata alert JSON structure."""
    return {
        "flow_id": random.randint(100000000000000, 999999999999999),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "suricata",
        "label": label,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "proto": protocol,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": signature_id,
            "rev": 1,
            "signature": signature,
            "category": "Simulated Alert",
            "severity": severity
        }
    }

def generate_normal_traffic():
    return generate_wazuh_alert(
        label="normal",
        rule_id="1002",
        rule_description="Normal HTTP traffic",
        severity=2,
        src_ip=f"192.168.1.{random.randint(1, 50)}",
        dst_ip="10.0.0.1",
        src_port=random.randint(1024, 65535),
        dst_port=80,
        protocol="tcp",
        flag="SF",
        serror_rate=0.0,
        src_bytes=random.randint(100, 5000),
        dst_bytes=random.randint(500, 10000),
        logged_in=1,
        count=random.randint(1, 10),
        same_srv_rate=1.0
    )

def generate_neptune_dos():
    return generate_suricata_alert(
        label="neptune",
        signature_id=2100498,
        signature="GPL ATTACK_RESPONSE id check returned root",
        severity=14,
        src_ip=f"185.220.101.{random.randint(1, 255)}",
        dst_ip="10.0.0.1",
        src_port=random.randint(1024, 65535),
        dst_port=80,
        protocol="TCP"
    )

def generate_port_scan():
    # Use a small pool so the correlator sees multiple ports from the same src
    src_ip = random.choice(["203.0.113.10", "203.0.113.20", "203.0.113.30"])
    return generate_suricata_alert(
        label="portsweep",
        signature_id=2010935,
        signature="ET SCAN Potential SSH Scan",
        severity=10,
        src_ip=src_ip,
        dst_ip="10.0.0.5",
        src_port=random.randint(1024, 65535),
        dst_port=random.randint(1, 1024),
        protocol="TCP"
    )

def generate_ssh_brute_force():
    return generate_wazuh_alert(
        label="brute_force",
        rule_id="5763",
        rule_description="SSHD brute force trying to get access to the system",
        severity=12,
        src_ip=f"91.121.{random.randint(1, 255)}.{random.randint(1, 255)}",
        dst_ip="192.168.1.10",
        src_port=random.randint(1024, 65535),
        dst_port=22,
        protocol="tcp",
        flag="SF",
        serror_rate=0.0,
        src_bytes=200,
        dst_bytes=100,
        logged_in=0,
        num_failed_logins=random.randint(5, 20),
        count=random.randint(20, 100),
        same_srv_rate=1.0
    )

def generate_c2_communication():
    return generate_suricata_alert(
        label="c2",
        signature_id=2013028,
        signature="ET TROJAN Possible C2 Beacon",
        severity=13,
        src_ip="10.0.0.55",
        dst_ip=f"185.234.219.{random.randint(1, 255)}",
        src_port=random.randint(1024, 65535),
        dst_port=4444,
        protocol="TCP"
    )

def generate_privilege_escalation():
    return generate_wazuh_alert(
        label="buffer_overflow",
        rule_id="5501",
        rule_description="User missed the password more than one time",
        severity=15,
        src_ip="10.0.0.22",
        dst_ip="10.0.0.1",
        src_port=random.randint(1024, 65535),
        dst_port=80,
        protocol="tcp",
        flag="SF",
        serror_rate=0.0,
        src_bytes=random.randint(5000, 50000),
        dst_bytes=random.randint(100, 500),
        root_shell=1,
        su_attempted=1,
        num_root=random.randint(1, 5),
        logged_in=1,
        count=1
    )


def get_single_alert(label: str = None) -> dict:
    """
    Returns one fake alert for unit testing.

    Args:
        label: "neptune" | "brute_force" | "c2" | "normal" | None (random)
    """
    generators = {
        "normal": generate_normal_traffic,
        "neptune": generate_neptune_dos,
        "portsweep": generate_port_scan,
        "brute_force": generate_ssh_brute_force,
        "c2": generate_c2_communication,
        "buffer_overflow": generate_privilege_escalation
    }
    
    if label and label in generators:
        return generators[label]()
    else:
        # Mix: 60% normal, 40% attacks
        choices = ["normal"] * 6 + ["neptune", "portsweep", "brute_force", "c2", "buffer_overflow"]
        selected_label = random.choice(choices)
        return generators[selected_label]()


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

    print(f"Simulator started — sending alerts every {delay}s")
    print(f"   Press Ctrl+C to stop\n")

    count = 0
    while True:
        alert = get_single_alert()
        queue.put(alert)
        count += 1

        label = alert.get("label", "normal")
        status = "[ATTACK]" if label != "normal" else "[NORMAL]"
        
        # Extract IP and port regardless of source format
        if alert.get("source") == "wazuh":
            src_ip = alert.get("data", {}).get("srcip", "0.0.0.0")
            dst_ip = alert.get("data", {}).get("dstip", "0.0.0.0")
            dst_port = alert.get("data", {}).get("dstport", 0)
        else:
            src_ip = alert.get("src_ip", "0.0.0.0")
            dst_ip = alert.get("dest_ip", "0.0.0.0")
            dst_port = alert.get("dest_port", 0)

        print(
            f"{status} Alert #{count:04d} | "
            f"{label:15s} | "
            f"{src_ip:20s} → "
            f"{dst_ip:15s} "
            f"port {dst_port}"
        )
        time.sleep(delay)


# ── Run standalone for manual testing ─────────────────────────────
if __name__ == "__main__":
    import os
    import sys
    from pathlib import Path
    _ROOT = Path(__file__).parent.parent
    sys.path.insert(0, str(_ROOT))

    from shared.config import settings

    kafka_ok = False
    if settings.USE_KAFKA:
        try:
            from shared.kafka_bus import KafkaBus
            from shared.models import NormalizedAlert
            import importlib
            collector_module = importlib.import_module("agents.01_collector.agent")
            WazuhCollector = collector_module.WazuhCollector
            SuricataCollector = collector_module.SuricataCollector

            bootstrap_servers = settings.KAFKA_BOOTSTRAP_SERVERS
            if bootstrap_servers == "kafka:9092":
                bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS_HOST", "localhost:29092")

            print(f"Connecting to Kafka at {bootstrap_servers}...")
            bus = KafkaBus(bootstrap_servers)
            # Force early connection to detect if Kafka is down
            bus._get_producer()

            wazuh_norm = WazuhCollector().normalize
            suri_norm = SuricataCollector().normalize

            class KafkaQueueProxy:
                def put(self, item):
                    if item.get("source") == "wazuh":
                        model_item = wazuh_norm(item)
                    else:
                        model_item = suri_norm(item)
                    bus.publish("soc.raw", model_item, key=model_item.id)
                def qsize(self):
                    return 0

            target_queue = KafkaQueueProxy()
            kafka_ok = True
            print("Kafka connected.")
        except Exception as e:
            print(f"WARNING: Kafka unavailable ({e}). Falling back to in-memory queue.")

    if not kafka_ok:
        import queue as q
        target_queue = q.Queue()

    try:
        stream_to_queue(target_queue, speed="normal")
    except KeyboardInterrupt:
        if not kafka_ok:
            print(f"\nSimulator stopped. {target_queue.qsize()} alerts in queue.")
        else:
            print(f"\nSimulator stopped.")

