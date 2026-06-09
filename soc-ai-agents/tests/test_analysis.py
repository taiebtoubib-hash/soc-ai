"""
tests/test_analysis.py
-----------------------
Standalone smoke-test for Agent 02 (Analysis).

Creates a fake NormalizedAlert, runs AnalysisAgent.enrich(),
and verifies the EnrichedAlert structure and 41-feature vector.

Usage (from project root):
    python tests/test_analysis.py

Expected output:
  ✅ EnrichedAlert created
  ✅ Features count: 41
  ✅ All feature names correct
  ✅ Agent 02 Analysis working
"""

import sys
import importlib.util
from pathlib import Path
from datetime import datetime, timezone

# ── Resolve project root ──────────────────────────────────────────
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# ── shared imports ────────────────────────────────────────────────
from shared.models import NormalizedAlert  # noqa: E402
from scripts.simulate_alerts import get_single_alert  # noqa: E402

# ── Load agents/02_analysis modules via importlib ─────────────────
# The folder name starts with a digit so it cannot be imported with
# normal `import agents.02_analysis` syntax.  We use importlib
# instead, exactly like the agents themselves do (sys.path + filename).

AGENT_DIR = ROOT / "agents" / "02_analysis"


def _load(module_name: str, filename: str):
    """Load a .py file from AGENT_DIR as a top-level module."""
    spec = importlib.util.spec_from_file_location(
        module_name, AGENT_DIR / filename
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


feature_builder_mod = _load("feature_builder", "feature_builder.py")
ip_enricher_mod     = _load("ip_enricher",     "ip_enricher.py")
correlator_mod      = _load("correlator",       "correlator.py")
agent_mod           = _load("agent02",          "agent.py")

FEATURE_ORDER = feature_builder_mod.FEATURE_ORDER
AnalysisAgent = agent_mod.AnalysisAgent


# ── Helper: simulate_alerts → NormalizedAlert ─────────────────────

collector_mod = _load("agent01", "../01_collector/agent.py")
WazuhCollector = collector_mod.WazuhCollector
SuricataCollector = collector_mod.SuricataCollector

def make_normalized_alert(raw: dict) -> NormalizedAlert:
    """Convert the native raw alert dict into a NormalizedAlert."""
    if raw.get("source") == "wazuh":
        return WazuhCollector().normalize(raw)
    else:
        return SuricataCollector().normalize(raw)


# ── Test runner ───────────────────────────────────────────────────

def run_tests():
    print("\n── Agent 02 Analysis — smoke tests ──────────────────────\n")

    # 1. Fake alert
    raw = get_single_alert()
    alert = make_normalized_alert(raw)
    print(
        f"  Alert  : src={alert.src_ip}  dst={alert.dst_ip}  "
        f"port={alert.dst_port}  sev={alert.severity}  "
        f"label={raw.get('label', 'normal')}"
    )

    # 2. Run enrich()
    agent = AnalysisAgent()
    enriched = agent.enrich(alert)
    print("✅  EnrichedAlert created")

    # 3. Feature count
    feature_count = len(enriched.features)
    assert feature_count == 41, f"Expected 41 features, got {feature_count}"
    print(f"✅  Features count: {feature_count}")

    # 4. Feature names
    missing = [k for k in FEATURE_ORDER if k not in enriched.features]
    extra   = [k for k in enriched.features if k not in FEATURE_ORDER]
    assert not missing, f"Missing features: {missing}"
    assert not extra,   f"Unexpected features: {extra}"
    print("✅  All feature names correct")

    # 5. Sanity checks
    assert isinstance(enriched.src_reputation_score, float)
    assert 0.0 <= enriched.src_reputation_score <= 1.0
    assert isinstance(enriched.is_src_internal, bool)
    assert isinstance(enriched.is_known_bad_port, bool)
    assert enriched.same_src_ip_count_last_5min >= 1

    print("✅  Agent 02 Analysis working\n")

    # ── Summary ───────────────────────────────────────────────────
    print("── Enrichment details ────────────────────────────────────")
    print(f"   reputation_score : {enriched.src_reputation_score:.2f}")
    print(f"   country          : {enriched.src_geo_country}")
    print(f"   is_src_internal  : {enriched.is_src_internal}")
    print(f"   is_dst_internal  : {enriched.is_dst_internal}")
    print(f"   is_known_bad_port: {enriched.is_known_bad_port}")
    print(f"   same_src_count   : {enriched.same_src_ip_count_last_5min}")
    print(f"   unique_dst_ports : {enriched.unique_dst_ports_last_5min}")
    print(f"   failed_auth_count: {enriched.failed_auth_count_last_5min}")
    print()
    print("── Feature vector (first 10) ─────────────────────────────")
    for name in FEATURE_ORDER[:10]:
        print(f"   {name:35s} = {enriched.features[name]}")
    print("   ...")


if __name__ == "__main__":
    run_tests()
