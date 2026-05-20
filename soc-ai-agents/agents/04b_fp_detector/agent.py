"""
agents/04b_fp_detector/agent.py
--------------------------------
False Positive Detector Agent — fourth-b agent in the SOC AI pipeline.

Consumes : Kafka topic `soc.classified`    → model: ClassificationResult
Publishes:
  - Kafka topic `soc.true_positives`  → confirmed real threats (ClassificationResult)
  - Kafka topic `soc.false_positives` → confirmed false alarms  (ClassificationResult)

Decision boundary:
  fp_score >= FP_SCORE_THRESHOLD  → false positive → soc.false_positives
  fp_score <  FP_SCORE_THRESHOLD  → true positive  → soc.true_positives

FP models are loaded ONCE at startup — never reloaded per message.
If any model file is missing → log CRITICAL and exit(1).
"""

import sys
import pickle
import logging
import pandas as pd
from typing import Any, Dict

from shared.models import ClassificationResult
from shared.kafka_bus import KafkaBus
from shared.config import settings

# ── Logger ─────────────────────────────────────────────────────────────
log = logging.getLogger("fp_detector")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
)

# ── Module-level state — set once in main() ────────────────────────────
FP_MODELS: Dict[str, Any] = {}
bus: KafkaBus = None


# ── Model Loading ──────────────────────────────────────────────────────

def load_fp_models() -> Dict[str, Any]:
    """
    Load both FP model artifacts from paths defined in settings.
    Logs each successful load. Calls sys.exit(1) if any file is missing.

    Returns:
        dict with keys:
          "fp_model"      → sklearn model: predict_proba → P(false_positive)
          "fp_classifier" → sklearn model: predict       → binary label
    """
    paths = {
        "fp_model":      settings.ML_FP_MODEL_PATH,
        "fp_classifier": settings.ML_FP_CLASSIFIER_PATH,
    }

    loaded: Dict[str, Any] = {}

    for key, path in paths.items():
        try:
            with open(path, "rb") as f:
                loaded[key] = pickle.load(f)
            log.info("[FP_MODELS] Loaded %-15s from %s ✓", key, path)
        except FileNotFoundError:
            log.critical(
                "[FP_MODELS] CRITICAL — model file not found: %s (key=%s)",
                path, key,
            )
            sys.exit(1)
        except Exception as exc:
            log.critical(
                "[FP_MODELS] CRITICAL — failed to load %s from %s: %s",
                key, path, exc,
            )
            sys.exit(1)

    return loaded


# ── Core FP Scoring Logic ──────────────────────────────────────────────

def score_fp(
    result: ClassificationResult,
    models: Dict[str, Any],
) -> tuple[float, bool]:
    """
    Compute the false-positive probability score for a ClassificationResult.

    Strategy:
      - Benign alerts (ml_label == "benign") are fast-pathed as false positives
        without running the FP models (saves compute, avoids loading features
        for trivially low-confidence alerts).
      - All others are scored by fp_model.predict_proba using the same
        41-feature vector that was built by 02_analysis.

    Args:
        result: ClassificationResult from 04_ml_classifier
        models: dict with keys "fp_model" and "fp_classifier"

    Returns:
        (fp_score: float, is_false_positive: bool)
          fp_score         — probability that this alert is a false positive
          is_false_positive — True if fp_score >= FP_SCORE_THRESHOLD
    """
    # Fast path: if the ML classifier already called it "benign", treat as FP
    if result.ml_label == "benign" and not result.detection.rule_triggered:
        fp_score = 1.0
        is_fp    = True
        return fp_score, is_fp

    # Full FP scoring using the feature vector
    features = result.detection.enriched.features
    df = pd.DataFrame([features])

    fp_score: float = float(models["fp_model"].predict_proba(df)[0][1])
    is_fp: bool     = fp_score >= settings.FP_SCORE_THRESHOLD

    return fp_score, is_fp


# ── Kafka Callback ─────────────────────────────────────────────────────

def handle_classification_result(result: ClassificationResult) -> None:
    """
    Kafka consumer callback — invoked for every message on soc.classified.

    Routes the result to one of two downstream topics:
      - soc.true_positives  → if fp_score < FP_SCORE_THRESHOLD
      - soc.false_positives → if fp_score >= FP_SCORE_THRESHOLD
    """
    src_ip = result.detection.enriched.alert.src_ip
    alert_id = result.detection.enriched.alert.id

    fp_score, is_fp = score_fp(result, FP_MODELS)

    if is_fp:
        destination = "soc.false_positives"
        verdict     = "FALSE_POSITIVE"
    else:
        destination = "soc.true_positives"
        verdict     = "TRUE_POSITIVE"

    log.info(
        "[FP] %s → fp_score=%.2f threshold=%.2f verdict=%s → %s",
        src_ip,
        fp_score,
        settings.FP_SCORE_THRESHOLD,
        verdict,
        destination,
    )

    bus.publish(destination, result, key=alert_id)


# ── Entry Point ────────────────────────────────────────────────────────

def main() -> None:
    """Validate config, load FP models once, start Kafka consume loop."""
    global FP_MODELS, bus

    settings.validate()
    log.info("FP Detector agent starting (threshold=%.2f)", settings.FP_SCORE_THRESHOLD)

    FP_MODELS = load_fp_models()
    log.info("[FP_MODELS] All FP models loaded — ready to score.")

    bus = KafkaBus(bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS)

    bus.consume(
        topic="soc.classified",
        group_id="fp-detector-group",
        model_class=ClassificationResult,
        callback=handle_classification_result,
    )


if __name__ == "__main__":
    main()
