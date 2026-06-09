"""
tests/test_collector.py
-----------------------
Unit tests for Wazuh and Suricata alert normalization.
"""

import sys
import importlib.util
from pathlib import Path

# Resolve project root
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# ── Load agents/01_collector module via importlib ─────────────────
# Since the folder starts with a digit, we must load it dynamically.
AGENT_DIR = ROOT / "agents" / "01_collector"

def _load(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        module_name, AGENT_DIR / filename
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod

collector_mod = _load("agent01", "agent.py")
WazuhCollector = collector_mod.WazuhCollector
SuricataCollector = collector_mod.SuricataCollector

from scripts.simulate_alerts import generate_wazuh_alert, generate_suricata_alert

def test_wazuh_normalization():
    # Generate a sample raw Wazuh alert
    raw_alert = generate_wazuh_alert(
        label="brute_force",
        rule_id=5763,
        rule_description="SSHD brute force attempt",
        severity=12,
        src_ip="192.168.1.15",
        dst_ip="10.0.0.5",
        src_port=52345,
        dst_port=22,
        protocol="tcp"
    )
    
    collector = WazuhCollector()
    normalized = collector.normalize(raw_alert)
    
    assert normalized.source == "wazuh"
    assert normalized.src_ip == "192.168.1.15"
    assert normalized.dst_ip == "10.0.0.5"
    assert normalized.src_port == 52345
    assert normalized.dst_port == 22
    assert normalized.protocol == "tcp"
    assert normalized.rule_id == "5763"
    assert normalized.rule_description == "SSHD brute force attempt"
    assert normalized.severity == 12
    assert normalized.raw == raw_alert
    print("✅ Wazuh normalization test passed successfully.")

def test_suricata_normalization():
    # Generate a sample raw Suricata alert
    raw_alert = generate_suricata_alert(
        label="neptune",
        signature_id=2100498,
        signature="GPL ATTACK_RESPONSE id check returned root",
        severity=14,
        src_ip="185.220.101.5",
        dst_ip="10.0.0.1",
        src_port=61234,
        dst_port=80,
        protocol="TCP"
    )
    
    collector = SuricataCollector()
    normalized = collector.normalize(raw_alert)
    
    assert normalized.source == "suricata"
    assert normalized.src_ip == "185.220.101.5"
    assert normalized.dst_ip == "10.0.0.1"
    assert normalized.src_port == 61234
    assert normalized.dst_port == 80
    assert normalized.protocol == "tcp"  # Normalized to lowercase
    assert normalized.rule_id == "2100498"
    assert normalized.rule_description == "GPL ATTACK_RESPONSE id check returned root"
    assert normalized.severity == 14
    assert normalized.raw == raw_alert
    print("✅ Suricata normalization test passed successfully.")

if __name__ == "__main__":
    test_wazuh_normalization()
    test_suricata_normalization()
    print("🎉 All collector normalization tests passed!")
