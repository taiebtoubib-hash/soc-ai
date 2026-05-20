"""
tests/test_llm_integration.py
------------------------------
Integration and robustness test for local Ollama LLM integration.

Validates that:
  1. The Ollama singleton loads correctly from shared/llm_client.py.
  2. Model schemas in shared/models.py correctly include llm_analysis and llm_narrative fields.
  3. LLM client operates defensively—never raising exceptions even when the Ollama server is offline.
  4. Safe fallback structures are correctly returned in offline or disabled configurations.
"""

import sys
from pathlib import Path

# Resolve project root
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from shared.models import EnrichedAlert, DetectionResult, IncidentReport
from shared.llm_client import llm
from shared.config import settings


def run_llm_tests():
    print("\n── testing Ollama LLM Client & Models ──────────────────\n")

    # 1. Verify schema defaults are present and initialized to ""
    print("🤖 Testing Pydantic Models for LLM fields...")
    
    # Fake source alert
    alert = EnrichedAlert(
        alert={
            "id": "9999",
            "timestamp": "2026-05-20T12:00:00Z",
            "source": "simulate",
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.1",
            "src_port": 1234,
            "dst_port": 80,
            "protocol": "tcp",
            "rule_id": "1002",
            "rule_description": "Normal traffic",
            "severity": 2,
            "raw": {}
        }
    )

    det_res = DetectionResult(
        enriched=alert,
        rule_triggered=True,
        rule_name="BRUTE_FORCE",
        confidence=0.85,
        needs_ml=True
    )
    
    # Check llm_analysis field in DetectionResult
    assert hasattr(det_res, "llm_analysis"), "DetectionResult is missing the llm_analysis field!"
    assert det_res.llm_analysis == "", f"Expected default llm_analysis to be empty string, got: {repr(det_res.llm_analysis)}"
    print("✅ DetectionResult contains 'llm_analysis' default empty field.")

    from shared.models import ClassificationResult
    classification = ClassificationResult(
        detection=det_res,
        ml_score=0.92,
        final_score=0.88,
        ml_label="malicious",
        attack_type="r2l",
        explanation="Detected via ML classifier"
    )

    inc_rep = IncidentReport(
        id="inc_9999",
        classification=classification,
        actions_taken=[],
        resolved=False,
        analyst_approved=False,
        notes=""
    )
    
    # Check llm_narrative field in IncidentReport
    assert hasattr(inc_rep, "llm_narrative"), "IncidentReport is missing the llm_narrative field!"
    assert inc_rep.llm_narrative == "", f"Expected default llm_narrative to be empty string, got: {repr(inc_rep.llm_narrative)}"
    print("✅ IncidentReport contains 'llm_narrative' default empty field.")

    print("\n🤖 Testing LLM Client Defensive Calls...")
    print(f"   LLM settings: ENABLED={settings.LLM_ENABLED} | MODEL={settings.OLLAMA_MODEL} | URL={settings.OLLAMA_BASE_URL}")

    # 2. Test analyze_threat() fallback / direct response
    print("\n   [1/3] Testing: analyze_threat()...")
    threat_info = {
        "src_ip": "192.168.1.100",
        "rule_name": "PORT_SCAN",
        "confidence": 0.9,
    }
    analysis = llm.analyze_threat(threat_info)
    print(f"   Result: {repr(analysis)}")
    assert len(analysis) > 0, "analyze_threat returned an empty string"
    if not settings.LLM_ENABLED:
        assert "Rule: PORT_SCAN" in analysis, "Safe fallback for analyze_threat failed to match expected template"
    print("   ✅ analyze_threat completed safely.")

    # 3. Test suggest_playbook() fallback / direct response
    print("\n   [2/3] Testing: suggest_playbook()...")
    playbook_info = {
        "id": "inc_123",
        "rule": "BRUTE_FORCE",
    }
    suggestion = llm.suggest_playbook(playbook_info)
    print(f"   Result: {repr(suggestion)}")
    assert len(suggestion) > 0, "suggest_playbook returned an empty string"
    if not settings.LLM_ENABLED:
        assert "Investigate source IP" in suggestion or "•" in suggestion, "Safe fallback for suggest_playbook failed to match expected template"
    print("   ✅ suggest_playbook completed safely.")

    # 4. Test explain_incident() fallback / direct response
    print("\n   [3/3] Testing: explain_incident()...")
    report_info = {
        "id": "inc_555",
        "src_ip": "10.0.0.99",
        "rule": "C2_COMMUNICATION",
    }
    explanation = llm.explain_incident(report_info)
    print(f"   Result: {repr(explanation)}")
    assert len(explanation) > 0, "explain_incident returned an empty string"
    if not settings.LLM_ENABLED:
        assert "inc_555" in explanation, "Safe fallback for explain_incident failed to match expected template"
    print("   ✅ explain_incident completed safely.")

    print("\n🎉 All LLM integration tests completed successfully!\n")


if __name__ == "__main__":
    run_llm_tests()
