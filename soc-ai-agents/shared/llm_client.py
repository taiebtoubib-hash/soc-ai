"""
shared/llm_client.py
Wraps Ollama local LLM. Import the singleton `llm` from here.
Never raises — all failures return a safe fallback string.
"""

import json
import logging
import requests
from typing import Optional
from shared.config import settings

log = logging.getLogger("llm_client")


class LLMClient:

    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL
        self.model    = settings.OLLAMA_MODEL
        self.enabled  = settings.LLM_ENABLED
        self.timeout  = settings.LLM_TIMEOUT

    def _chat(self, system: str, user: str) -> Optional[str]:
        if not self.enabled:
            return None
        payload = {
            "model": self.model, "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "options": {"temperature": 0.1, "num_predict": 350},
        }
        try:
            resp = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()["message"]["content"].strip()
        except requests.exceptions.Timeout:
            log.warning("[LLM] Timeout (model=%s)", self.model)
            return None
        except Exception as exc:
            log.warning("[LLM] Call failed: %s", exc)
            return None

    def analyze_threat(self, alert_data: dict) -> str:
        system = (
            "You are a cybersecurity analyst in a SOC. Analyze the security alert "
            "and give a SHORT 3-5 sentence assessment. Focus on: attack intent, "
            "risk level, recommended immediate action. Be concise. Do not repeat raw data."
        )
        user = f"Security alert:\n{json.dumps(alert_data, indent=2, default=str)}\n\nYour assessment:"
        result = self._chat(system, user)
        if result:
            log.info("[LLM] analyze_threat OK (%d chars)", len(result))
            return result
        return (
            f"[LLM unavailable] Rule: {alert_data.get('rule_name','UNKNOWN')} | "
            f"Score: {alert_data.get('confidence', 0):.2f} | "
            f"IP: {alert_data.get('src_ip','?')}"
        )

    def suggest_playbook(self, classification_data: dict) -> str:
        system = (
            "You are a senior SOC analyst. No pre-defined playbook matched this incident. "
            "Recommend a SHORT actionable response plan (3-5 bullet points). "
            "Name specific tools, actions, priorities. Bullet points only, no preamble."
        )
        user = f"Incident:\n{json.dumps(classification_data, indent=2, default=str)}\n\nRecommended response:"
        result = self._chat(system, user)
        if result:
            log.info("[LLM] suggest_playbook OK (%d chars)", len(result))
            return result
        return (
            "• Investigate source IP in threat intel feeds\n"
            "• Review firewall logs for related traffic\n"
            "• Notify tier-2 analyst for manual review\n"
            "• Consider temporary block of source IP"
        )

    def explain_incident(self, report_data: dict) -> str:
        system = (
            "Write an incident summary for an on-call security engineer. "
            "2-3 sentences max. Cover: what happened, what was done automatically, "
            "what needs human attention. Tone: direct and factual."
        )
        user = f"Incident report:\n{json.dumps(report_data, indent=2, default=str)}\n\nAnalyst summary:"
        result = self._chat(system, user)
        if result:
            log.info("[LLM] explain_incident OK (%d chars)", len(result))
            return result
        return (
            f"Automated response executed for incident {report_data.get('id','?')}. "
            f"Source: {report_data.get('src_ip','?')} | Rule: {report_data.get('rule','?')}. "
            "Manual analyst review recommended."
        )


llm = LLMClient()
