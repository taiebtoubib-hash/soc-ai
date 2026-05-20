"""
agents/06_response/agent.py
-----------------------------
Response Agent — sixth and final agent in the SOC AI pipeline.

Consumes : Kafka topic `soc.orchestrated` → model: IncidentReport
Publishes: Kafka topic `soc.frontend`     → model: IncidentReport (after execution)

Responsibilities:
  - Execute each PlaybookAction in the IncidentReport
  - Simulate or dispatch real mitigations (block_ip, isolate_host, notify, log)
  - Mark each action as executed=True with a result message
  - Mark the report as resolved=True
  - Publish the completed report to soc.frontend (dashboard / SSE feed)
  - Send Slack notification for malicious or suspicious alerts

Execution mode:
  ENV=development → simulate all actions (log only, no real API calls)
  ENV=production  → dispatch real integrations (Shuffle SOAR, Slack webhook)
"""

import json
import logging
import requests
from datetime import datetime, timezone
from typing import List

from shared.models import IncidentReport, PlaybookAction
from shared.kafka_bus import KafkaBus
from shared.config import settings
from shared.llm_client import llm

# ── Logger ─────────────────────────────────────────────────────────────
log = logging.getLogger("response")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
)

# ── Module-level state — set once in main() ────────────────────────────
bus: KafkaBus = None


# ── Action Executors ───────────────────────────────────────────────────

def _simulate_action(action: PlaybookAction) -> str:
    """Return a simulated result string without making any real API calls."""
    return f"[SIMULATE] {action.action_type} on {action.target} — OK"


def _execute_block_ip(action: PlaybookAction) -> str:
    """Dispatch block_ip via Shuffle SOAR webhook (production only)."""
    if not settings.SHUFFLE_ENABLED or not settings.SHUFFLE_WEBHOOK_URL:
        return _simulate_action(action)

    payload = {
        "action": "block_ip",
        "target": action.target,
        "reason": action.reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        resp = requests.post(
            settings.SHUFFLE_WEBHOOK_URL,
            json=payload,
            timeout=10,
        )
        return f"block_ip dispatched to Shuffle — HTTP {resp.status_code}"
    except Exception as exc:
        return f"block_ip FAILED — {exc}"


def _execute_isolate_host(action: PlaybookAction) -> str:
    """Dispatch isolate_host via Shuffle SOAR webhook (production only)."""
    if not settings.SHUFFLE_ENABLED or not settings.SHUFFLE_WEBHOOK_URL:
        return _simulate_action(action)

    payload = {
        "action": "isolate_host",
        "target": action.target,
        "reason": action.reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        resp = requests.post(
            settings.SHUFFLE_WEBHOOK_URL,
            json=payload,
            timeout=10,
        )
        return f"isolate_host dispatched to Shuffle — HTTP {resp.status_code}"
    except Exception as exc:
        return f"isolate_host FAILED — {exc}"


def _execute_notify(action: PlaybookAction, report: IncidentReport) -> str:
    """Send Slack notification with LLM summary (production only)."""
    if not settings.SLACK_WEBHOOK_URL:
        return _simulate_action(action)

    label  = report.classification.ml_label
    score  = report.classification.final_score
    rule   = report.classification.detection.rule_name
    attack = report.classification.attack_type
    src_ip = action.target

    # LLM analyst summary
    llm_section = ""
    if settings.LLM_ENABLED:
        narrative = report.llm_narrative
        if not narrative:
            narrative = llm.explain_incident({
                "id": report.id, "src_ip": src_ip, "rule": rule,
                "attack_type": attack, "ml_label": label,
                "final_score": score,
                "actions": [a.action_type for a in report.actions_taken],
            })
        if narrative:
            llm_section = f"\n\n*AI Summary:*\n{narrative}"

    emoji = "🚨" if label == "malicious" else "⚠️"
    text = (
        f"{emoji} *SOC AI Alert* — `{label.upper()}`\n"
        f"*Rule:* {rule}  |  *Attack:* {attack}  |  *Score:* {score:.2f}\n"
        f"*Source IP:* `{src_ip}`\n"
        f"*Reason:* {action.reason}\n"
        f"*Incident ID:* `{report.id}`"
        f"{llm_section}"
    )

    try:
        resp = requests.post(settings.SLACK_WEBHOOK_URL, json={"text": text}, timeout=10)
        return f"Slack notification sent — HTTP {resp.status_code}"
    except Exception as exc:
        return f"Slack notify FAILED — {exc}"


def _execute_log(action: PlaybookAction, report: IncidentReport) -> str:
    """Persist incident to local log file."""
    log_entry = {
        "incident_id":  report.id,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "src_ip":       action.target,
        "rule":         report.classification.detection.rule_name,
        "attack_type":  report.classification.attack_type,
        "ml_label":     report.classification.ml_label,
        "final_score":  report.classification.final_score,
        "reason":       action.reason,
    }
    log.info("[RESPONSE][LOG] %s", json.dumps(log_entry))
    return "incident logged ✓"


# ── Action Dispatcher ──────────────────────────────────────────────────

def execute_action(action: PlaybookAction, report: IncidentReport) -> str:
    """
    Dispatch a single PlaybookAction to the correct executor.

    In development mode (ENV != "production") all actions are simulated —
    no external API calls are made.

    Args:
        action: the PlaybookAction to execute
        report: the parent IncidentReport (needed for context in notify/log)

    Returns:
        Human-readable result string stored in action.result
    """
    if settings.ENV != "production":
        return _simulate_action(action)

    dispatcher = {
        "block_ip":      lambda: _execute_block_ip(action),
        "isolate_host":  lambda: _execute_isolate_host(action),
        "notify":        lambda: _execute_notify(action, report),
        "log":           lambda: _execute_log(action, report),
    }

    executor = dispatcher.get(action.action_type)
    if executor:
        return executor()
    else:
        log.warning("[RESPONSE] Unknown action_type: %s", action.action_type)
        return f"unknown action_type={action.action_type} — skipped"


# ── Core Response Logic ────────────────────────────────────────────────

def execute_report(report: IncidentReport) -> IncidentReport:
    """
    Execute all PlaybookActions in the report and return a completed copy.

    Each action is marked executed=True with its result string.
    The report itself is marked resolved=True.
    Always executes all actions even if one fails — never aborts early.

    Args:
        report: IncidentReport from 05_orchestrator

    Returns:
        Updated IncidentReport with all actions executed and resolved=True
    """
    src_ip = report.classification.detection.enriched.alert.src_ip
    label  = report.classification.ml_label
    rule   = report.classification.detection.rule_name

    log.info(
        "[RESPONSE] Executing incident %s | src=%s rule=%s label=%s actions=%d",
        report.id, src_ip, rule, label, len(report.actions_taken),
    )

    executed_actions: List[PlaybookAction] = []
    for action in report.actions_taken:
        result = execute_action(action, report)
        executed_actions.append(
            PlaybookAction(
                action_type=action.action_type,
                target=action.target,
                reason=action.reason,
                executed=True,
                result=result,
            )
        )
        log.info(
            "[RESPONSE]   ↳ %-15s on %-16s → %s",
            action.action_type, action.target, result,
        )

    # Return a new model instance with updated fields
    return IncidentReport(
        id=report.id,
        classification=report.classification,
        actions_taken=executed_actions,
        resolved=True,
        analyst_approved=report.analyst_approved,
        notes=report.notes,
        llm_narrative=report.llm_narrative,
    )


# ── Kafka Callback ─────────────────────────────────────────────────────

def handle_incident_report(report: IncidentReport) -> None:
    """
    Kafka consumer callback — invoked for every message on soc.orchestrated.
    Executes all actions, marks report resolved, publishes to soc.frontend.
    """
    completed = execute_report(report)
    bus.publish("soc.frontend", completed, key=completed.id)
    log.info(
        "[RESPONSE] Incident %s resolved ✓ → published to soc.frontend",
        completed.id,
    )


# ── Entry Point ────────────────────────────────────────────────────────

def main() -> None:
    """Validate config, wire up Kafka, start consume loop."""
    global bus

    settings.validate()
    log.info(
        "Response agent starting (ENV=%s, SHUFFLE_ENABLED=%s)",
        settings.ENV,
        settings.SHUFFLE_ENABLED,
    )

    bus = KafkaBus(bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS)

    bus.consume(
        topic="soc.orchestrated",
        group_id="response-group",
        model_class=IncidentReport,
        callback=handle_incident_report,
    )


if __name__ == "__main__":
    main()
