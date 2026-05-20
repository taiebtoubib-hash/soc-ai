"""
agents/05_orchestrator/agent.py
--------------------------------
Orchestrator Agent — fifth agent in the SOC AI pipeline.

Consumes : Kafka topic `soc.true_positives` → model: ClassificationResult
Publishes: Kafka topic `soc.orchestrated`   → model: IncidentReport

Responsibilities:
  - Load all YAML playbooks from /app/playbooks/ at startup
  - For each confirmed true positive, select the matching playbook
    based on rule_name (primary) or attack_type (fallback)
  - Build an IncidentReport with the resolved PlaybookActions
  - Publish to soc.orchestrated for the Response agent to execute
"""

import sys
import uuid
import logging
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional

from shared.models import ClassificationResult, IncidentReport, PlaybookAction
from shared.kafka_bus import KafkaBus
from shared.config import settings
from shared.llm_client import llm

# ── Logger ─────────────────────────────────────────────────────────────
log = logging.getLogger("orchestrator")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
)

# ── Playbook directory (mounted via Docker volume) ──────────────────────
PLAYBOOKS_DIR = Path("/app/playbooks")

# ── Rule name → playbook file stem mapping ──────────────────────────────
RULE_TO_PLAYBOOK: Dict[str, str] = {
    "PORT_SCAN":         "port_scan",
    "BRUTE_FORCE":       "brute_force",
    "C2_COMMUNICATION":  "c2_communication",
    "DATA_EXFILTRATION": "data_exfiltration",
}

# ── Module-level state — set once in main() ────────────────────────────
PLAYBOOKS: Dict[str, Dict[str, Any]] = {}
bus: KafkaBus = None


# ── Playbook Loading ───────────────────────────────────────────────────

def load_playbooks(playbooks_dir: Path) -> Dict[str, Dict[str, Any]]:
    """
    Load all *.yaml files from the playbooks directory into memory.
    Each file is keyed by its stem (filename without extension).
    Logs each loaded playbook. Exits with code 1 if the directory
    does not exist or no playbooks are found.

    Args:
        playbooks_dir: Path to the directory containing YAML playbooks.

    Returns:
        dict mapping playbook name → parsed YAML content
    """
    if not playbooks_dir.exists():
        log.critical(
            "[PLAYBOOKS] Directory not found: %s — "
            "ensure /app/playbooks is mounted correctly.",
            playbooks_dir,
        )
        sys.exit(1)

    loaded: Dict[str, Dict[str, Any]] = {}

    for yaml_file in sorted(playbooks_dir.glob("*.yaml")):
        try:
            with open(yaml_file, "r") as f:
                data = yaml.safe_load(f)
            stem = yaml_file.stem
            loaded[stem] = data
            actions = len(data.get("actions", []))
            log.info(
                "[PLAYBOOKS] Loaded %-25s  (%d actions) ✓", stem, actions
            )
        except Exception as exc:
            log.error("[PLAYBOOKS] Failed to load %s: %s", yaml_file, exc)

    if not loaded:
        log.critical(
            "[PLAYBOOKS] No playbooks loaded from %s — cannot orchestrate.",
            playbooks_dir,
        )
        sys.exit(1)

    log.info("[PLAYBOOKS] %d playbooks ready.", len(loaded))
    return loaded


# ── Playbook Selection ─────────────────────────────────────────────────

def select_playbook(result: ClassificationResult) -> Optional[Dict[str, Any]]:
    """
    Select the most appropriate playbook for a ClassificationResult.

    Selection priority:
      1. Match rule_name exactly via RULE_TO_PLAYBOOK mapping
      2. Fallback: scan all playbooks for a matching attack_type field
      3. Return None if nothing matches (caller will log a warning)

    Args:
        result: ClassificationResult from 04_ml_classifier

    Returns:
        Parsed playbook dict, or None if no match found.
    """
    rule_name   = result.detection.rule_name
    attack_type = result.attack_type

    # Priority 1 — rule_name direct lookup
    stem = RULE_TO_PLAYBOOK.get(rule_name)
    if stem and stem in PLAYBOOKS:
        log.debug("[ORCH] Playbook selected by rule_name: %s → %s", rule_name, stem)
        return PLAYBOOKS[stem]

    # Priority 2 — attack_type fallback
    for name, playbook in PLAYBOOKS.items():
        if playbook.get("attack_type") == attack_type:
            log.debug(
                "[ORCH] Playbook selected by attack_type: %s → %s",
                attack_type, name,
            )
            return playbook

    return None


# ── Incident Report Builder ────────────────────────────────────────────

def build_incident(
    result: ClassificationResult,
    playbook: Optional[Dict[str, Any]],
) -> IncidentReport:
    """
    Construct an IncidentReport from a ClassificationResult and playbook.

    If no matching playbook is found, a default LOG-only action is created
    so the pipeline never stalls waiting for a playbook.

    Args:
        result:   ClassificationResult from 04_ml_classifier
        playbook: Parsed YAML playbook dict, or None

    Returns:
        IncidentReport ready to publish to soc.orchestrated
    """
    src_ip     = result.detection.enriched.alert.src_ip
    rule_name  = result.detection.rule_name
    final_score = result.final_score

    if playbook:
        raw_actions: List[Dict[str, Any]] = playbook.get("actions", [])
        actions = [
            PlaybookAction(
                action_type=a["type"],
                target=src_ip,
                reason=(
                    f"[{rule_name}] {a.get('description', '')} "
                    f"(score={final_score:.2f})"
                ),
            )
            for a in raw_actions
        ]
        playbook_name = playbook.get("name", "unknown")
    else:
        # No matching playbook — create a safe default
        log.warning(
            "[ORCH] No playbook for rule=%s attack_type=%s — defaulting to log",
            rule_name, result.attack_type,
        )
        actions = [
            PlaybookAction(
                action_type="log",
                target=src_ip,
                reason=(
                    f"No playbook matched rule={rule_name} "
                    f"attack_type={result.attack_type} "
                    f"(score={final_score:.2f})"
                ),
            )
        ]
        playbook_name = "default_log"

    log.info(
        "[ORCH] %s → playbook=%s rule=%s label=%s score=%.2f actions=%d",
        src_ip,
        playbook_name,
        rule_name,
        result.ml_label,
        final_score,
        len(actions),
    )

    return IncidentReport(
        id=str(uuid.uuid4()),
        classification=result,
        actions_taken=actions,
        resolved=False,
        analyst_approved=False,
        notes=(
            f"Playbook: {playbook_name} | "
            f"Rule: {rule_name} | "
            f"Score: {final_score:.2f} | "
            f"Label: {result.ml_label}"
        ),
    )


# ── Kafka Callback ─────────────────────────────────────────────────────

def handle_true_positive(result: ClassificationResult) -> None:
    """Kafka callback — selects playbook, adds LLM narrative, publishes report."""
    playbook = select_playbook(result)
    report   = build_incident(result, playbook)

    # LLM narrative — non-blocking, advisory only
    if settings.LLM_ENABLED:
        summary = {
            "src_ip":       result.detection.enriched.alert.src_ip,
            "rule_name":    result.detection.rule_name,
            "attack_type":  result.attack_type,
            "ml_label":     result.ml_label,
            "final_score":  result.final_score,
            "explanation":  result.explanation,
            "llm_analysis": result.detection.llm_analysis,
        }
        if not playbook:
            narrative = llm.suggest_playbook(summary)
        else:
            narrative = llm.explain_incident({
                **summary,
                "actions": [a.action_type for a in report.actions_taken],
            })
        report = IncidentReport(
            id=report.id,
            classification=report.classification,
            actions_taken=report.actions_taken,
            resolved=report.resolved,
            analyst_approved=report.analyst_approved,
            notes=report.notes,
            llm_narrative=narrative,
        )
        log.info("[ORCH][LLM] Narrative added for incident %s", report.id)

    bus.publish("soc.orchestrated", report, key=report.id)


# ── Entry Point ────────────────────────────────────────────────────────

def main() -> None:
    """Validate config, load playbooks, start Kafka consume loop."""
    global PLAYBOOKS, bus

    settings.validate()
    log.info("Orchestrator agent starting")

    PLAYBOOKS = load_playbooks(PLAYBOOKS_DIR)

    bus = KafkaBus(bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS)

    bus.consume(
        topic="soc.true_positives",
        group_id="orchestrator-group",
        model_class=ClassificationResult,
        callback=handle_true_positive,
    )


if __name__ == "__main__":
    main()
