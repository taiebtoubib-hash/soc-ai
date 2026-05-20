"""
shared/config.py
----------------
Configuration management using python-dotenv.
All agents import 'settings' from here — never use os.getenv() directly in agents.

Usage:
    from shared.config import settings
    print(settings.WAZUH_HOST)
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=env_path)


class Config:

    # ── General ───────────────────────────────────────────
    ENV = os.getenv("ENV", "development")   # "development" | "production"

    # ── Kafka Infrastructure ────────────────────────────────
    KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092")
    USE_KAFKA               = os.getenv("USE_KAFKA", "false").lower() == "true"

    # ── Wazuh ─────────────────────────────────────────────
    WAZUH_HOST     = os.getenv("WAZUH_HOST", "localhost")
    WAZUH_PORT     = int(os.getenv("WAZUH_PORT", 55000))
    WAZUH_USER     = os.getenv("WAZUH_USER")
    WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")

    # ── Suricata ───────────────────────────────────────────
    SURICATA_LOG_PATH = os.getenv(
        "SURICATA_LOG_PATH", "/var/log/suricata/eve.json"
    )

    # ── Enrichment ────────────────────────────────────────
    ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

    # ── Notifications ─────────────────────────────────────
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

    # ── Shuffle SOAR ──────────────────────────────────────
    SHUFFLE_WEBHOOK_URL = os.getenv("SHUFFLE_WEBHOOK_URL", "")
    SHUFFLE_ENABLED     = os.getenv("SHUFFLE_ENABLED", "false").lower() == "true"

    # ── Vector DB (Chroma) ────────────────────────────────
    CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
    CHROMA_PORT = int(os.getenv("CHROMA_PORT", 8000))

    # ── ML Model Paths ────────────────────────────────────
    ML_THREAT_MODEL_PATH  = os.getenv(
        "ML_THREAT_MODEL_PATH",  "ml_models/threat_model.pkl"
    )
    ML_ATTACK_MODEL_PATH  = os.getenv(
        "ML_ATTACK_MODEL_PATH",  "ml_models/attack_type_model.pkl"
    )
    ML_ANOMALY_MODEL_PATH = os.getenv(
        "ML_ANOMALY_MODEL_PATH", "ml_models/anomaly_model.pkl"
    )
    ML_PREPROCESSOR_PATH  = os.getenv(
        "ML_PREPROCESSOR_PATH",  "ml_models/preprocessor.pkl"
    )
    ML_ENCODERS_PATH      = os.getenv(
        "ML_ENCODERS_PATH",      "ml_models/encoders.pkl"
    )

    ML_FP_MODEL_PATH      = os.getenv(
        "ML_FP_MODEL_PATH",
        "../soc-ai-training/ml_models/production/fp_model.pkl"
    )
    ML_FP_CLASSIFIER_PATH = os.getenv(
        "ML_FP_CLASSIFIER_PATH",
        "../soc-ai-training/ml_models/production/fp_classifier.pkl"
    )

    # ── Collector settings ────────────────────────────────
    WAZUH_POLL_INTERVAL = int(os.getenv("WAZUH_POLL_INTERVAL", 60))
    COLLECTOR_MODE      = os.getenv("COLLECTOR_MODE", "simulate")
    # "simulate" → fake alerts locally (no server needed)
    # "wazuh"    → real Wazuh API only
    # "suricata" → real Suricata eve.json only
    # "both"     → Wazuh + Suricata (production)

    # ── Detection thresholds ──────────────────────────────
    ML_THREAT_THRESHOLD  = float(os.getenv("ML_THREAT_THRESHOLD",  0.75))
    ML_SUSPECT_THRESHOLD = float(os.getenv("ML_SUSPECT_THRESHOLD", 0.45))
    # final_score >= ML_THREAT_THRESHOLD  → "malicious" → auto respond
    # final_score >= ML_SUSPECT_THRESHOLD → "suspicious" → notify analyst
    # final_score <  ML_SUSPECT_THRESHOLD → "benign"    → log only

    # ── Ollama / LLM ──────────────────────────────────────────────────
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
    OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL",    "mistral:7b")
    LLM_ENABLED     = os.getenv("LLM_ENABLED",     "true").lower() == "true"
    LLM_TIMEOUT     = int(os.getenv("LLM_TIMEOUT", 30))

    # ── False Positive thresholds ─────────────────────────
    FP_SCORE_THRESHOLD = float(os.getenv("FP_SCORE_THRESHOLD", 0.60))
    # fp_score >= FP_SCORE_THRESHOLD → confirmed false positive → skip response
    # fp_score <  FP_SCORE_THRESHOLD → confirmed true positive  → send to orchestrator

    @classmethod
    def validate(cls):
        """
        Call this at startup to catch missing critical config early.
        Only checks production — development runs without real credentials.
        """
        if cls.ENV == "production":
            missing = []
            if not cls.WAZUH_HOST:          missing.append("WAZUH_HOST")
            if not cls.WAZUH_USER:          missing.append("WAZUH_USER")
            if not cls.WAZUH_PASSWORD:      missing.append("WAZUH_PASSWORD")
            if not cls.ABUSEIPDB_KEY:       missing.append("ABUSEIPDB_KEY")
            if not cls.SHUFFLE_WEBHOOK_URL: missing.append("SHUFFLE_WEBHOOK_URL")

            if cls.USE_KAFKA and not cls.KAFKA_BOOTSTRAP_SERVERS:
                missing.append("KAFKA_BOOTSTRAP_SERVERS")

            if missing:
                raise ValueError(
                    f"Missing required environment variables: {missing}\n"
                    f"Check your .env file."
                )
        return True


# Singleton — import this everywhere
settings = Config()
