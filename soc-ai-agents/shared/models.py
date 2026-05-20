"""
shared/models.py
----------------
Shared Pydantic models for data normalization and inter-agent communication.
All agents import from here — never define data structures anywhere else.
"""

from pydantic import BaseModel, Field
from typing import Dict, Any, Optional


class NormalizedAlert(BaseModel):
    """
    Output of 01_collector.
    Every alert from Wazuh or Suricata gets normalized into this format.
    """
    id: str
    timestamp: str
    source: str               # "wazuh" | "suricata"
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str             # "tcp" | "udp" | "icmp"
    rule_id: str
    rule_description: str
    severity: int             # 0-15 (wazuh scale)
    raw: Dict[str, Any]       # original payload kept for reference


class EnrichedAlert(BaseModel):
    """
    Output of 02_analysis.
    NormalizedAlert + enrichment data + ML feature vector.
    The 'features' dict is what gets fed directly into the ML models.
    """
    alert: NormalizedAlert

    # IP reputation (from AbuseIPDB)
    src_reputation_score: float = 0.0    # 0.0 = clean, 1.0 = malicious
    src_geo_country: str = ""

    # Network context
    is_src_internal: bool = False
    is_dst_internal: bool = False
    is_known_bad_port: bool = False

    # Behavioral correlation (last 5 minutes)
    same_src_ip_count_last_5min: int = 0
    unique_dst_ports_last_5min: int = 0
    failed_auth_count_last_5min: int = 0

    # ML feature vector — built by feature_builder.py
    # Must match EXACTLY the columns used during training
    features: Dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    """
    Output of 03_detection.
    Result of rule-based evaluation — decides if ML is needed.
    """
    enriched: EnrichedAlert
    rule_triggered: bool
    rule_name: str            # "PORT_SCAN" | "BRUTE_FORCE" | "NONE" etc.
    confidence: float         # 0.0 to 1.0
    needs_ml: bool            # True → send to ML classifier
    llm_analysis: str = ""


class ClassificationResult(BaseModel):
    """
    Output of 04_ml_classifier.
    Final verdict on the alert — used by orchestrator to pick a playbook.
    """
    detection: DetectionResult
    ml_score: float           # raw ML probability (0.0 to 1.0)
    final_score: float        # combined rule + ML score
    ml_label: str             # "benign" | "suspicious" | "malicious"

    # Must match training labels: "normal" | "dos" | "probe" | "r2l" | "u2r"
    attack_type: str

    # Human-readable explanation for dashboard
    explanation: str = ""


class PlaybookAction(BaseModel):
    """
    Single action inside a playbook.
    Used by 06_response agent to execute mitigation.
    """
    action_type: str          # "block_ip" | "isolate_host" | "notify" | "log"
    target: str               # IP, hostname, or channel
    reason: str               # explanation for audit log
    executed: bool = False
    result: str = ""


class IncidentReport(BaseModel):
    """
    Final incident record — saved to DB after response.
    Used for retraining and dashboard display.
    """
    id: str
    classification: ClassificationResult
    actions_taken: list[PlaybookAction] = []
    resolved: bool = False
    analyst_approved: bool = False
    notes: str = ""
    llm_narrative: str = ""
