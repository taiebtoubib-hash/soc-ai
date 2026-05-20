"""
agents/04_ml_classifier/agent.py
---------------------------------
ML Classifier Agent — fourth agent in the SOC AI pipeline.

Consumes : Kafka topic `soc.analyzed`   → model: DetectionResult
Publishes: Kafka topic `soc.classified` → model: ClassificationResult

Loads all ML models once at startup (never per message).
Applies a two-model classification pipeline:
  1. threat_model   → binary threat probability (0.0 to 1.0)
  2. attack_model   → multi-class attack type label
Skips both models entirely when detection.needs_ml is False.
"""

import sys
import pickle
import logging
import pandas as pd
from typing import Any, Dict

from shared.models import DetectionResult, ClassificationResult
from shared.kafka_bus import KafkaBus
from shared.config import settings

# ── Logger ────────────────────────────────────────────────────────────
log = logging.getLogger("ml_classifier")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
)

# ── Module-level state — set once in main() ───────────────────────────
MODELS: Dict[str, Any] = {}
bus: KafkaBus = None


# ── Model Loading ─────────────────────────────────────────────────────

def load_models() -> Dict[str, Any]:
    """
    Load all four ML model artifacts from paths defined in settings.
    Logs each successful load. Calls sys.exit(1) if any file is missing.

    Returns:
        dict with keys: "threat", "attack", "preprocessor", "encoders"
    """
    paths = {
        "threat":       settings.ML_THREAT_MODEL_PATH,
        "attack":       settings.ML_ATTACK_MODEL_PATH,
        "preprocessor": settings.ML_PREPROCESSOR_PATH,
        "encoders":     settings.ML_ENCODERS_PATH,
    }

    labels = {
        "threat":       "threat_model",
        "attack":       "attack_model",
        "preprocessor": "preprocessor ",
        "encoders":     "encoders      ",
    }

    loaded: Dict[str, Any] = {}

    for key, path in paths.items():
        try:
            with open(path, "rb") as f:
                loaded[key] = pickle.load(f)
            log.info("[MODELS] Loaded %s from %s ✓", labels[key], path)
        except FileNotFoundError:
            log.critical(
                "[MODELS] CRITICAL — model file not found: %s (key=%s)",
                path, key,
            )
            sys.exit(1)
        except Exception as exc:
            log.critical(
                "[MODELS] CRITICAL — failed to load %s from %s: %s",
                key, path, exc,
            )
            sys.exit(1)

    return loaded


# ── Core Classification Logic ─────────────────────────────────────────

def classify(
    detection: DetectionResult,
    models: Dict[str, Any],
) -> ClassificationResult:
    """
    Produce a ClassificationResult for a DetectionResult.

    Case 1 — needs_ml is False:
        The rule chain already has high confidence. Skip both ML models.
        ml_score   = 0.0
        final_score = detection.confidence
        attack_type = "normal"
        ml_label   = "benign" if confidence < ML_SUSPECT_THRESHOLD else "suspicious"
        explanation = rule-fired notice

    Case 2 — needs_ml is True:
        Step 1: Run threat_model.predict_proba → ml_score
        Step 2: final_score = ml_score * 0.7 + rule_confidence * 0.3
        Step 3: Assign ml_label using configured thresholds
        Step 4: Run attack_model.predict only when label != "benign"
        Step 5: Build human-readable explanation string

    Args:
        detection: upstream DetectionResult from 03_detection
        models:    dict of loaded sklearn model objects

    Returns:
        ClassificationResult ready to publish to soc.classified
    """
    src_ip   = detection.enriched.alert.src_ip
    rule     = detection.rule_name
    conf     = detection.confidence

    # ── Case 1: skip ML ───────────────────────────────────────────────
    if not detection.needs_ml:
        ml_score    = 0.0
        final_score = conf
        attack_type = "normal"
        ml_label    = (
            "benign"
            if conf < settings.ML_SUSPECT_THRESHOLD
            else "suspicious"
        )
        explanation = f"Rule {rule} fired. ML skipped."

        log.info(
            "[ML] %s → ml_score=%.2f final=%.2f label=%s attack=%s needs_ml=False",
            src_ip, ml_score, final_score, ml_label, attack_type,
        )

        return ClassificationResult(
            detection=detection,
            ml_score=ml_score,
            final_score=final_score,
            ml_label=ml_label,
            attack_type=attack_type,
            explanation=explanation,
        )

    # ── Case 2: run ML models ─────────────────────────────────────────
    # Build feature matrix from the pre-built 41-feature vector
    df = pd.DataFrame([detection.enriched.features])
    X  = models["preprocessor"].transform(df)

    # Step 1 — threat probability
    ml_score: float = float(models["threat"].predict_proba(X)[0][1])

    # Step 2 — combined score
    final_score: float = (ml_score * 0.7) + (conf * 0.3)

    # Step 3 — label
    if final_score >= settings.ML_THREAT_THRESHOLD:
        ml_label = "malicious"
    elif final_score >= settings.ML_SUSPECT_THRESHOLD:
        ml_label = "suspicious"
    else:
        ml_label = "benign"

    # Step 4 — attack type (skip for benign to save compute)
    if ml_label != "benign":
        attack_type = str(models["attack"].predict(X)[0])
    else:
        attack_type = "normal"

    # Step 5 — explanation
    explanation = (
        f"ML score: {ml_score:.2f} | "
        f"Rule: {rule} ({conf:.2f}) | "
        f"Final: {final_score:.2f} → {ml_label} | "
        f"Attack type: {attack_type}"
    )

    log.info(
        "[ML] %s → ml_score=%.2f final=%.2f label=%s attack=%s needs_ml=True",
        src_ip, ml_score, final_score, ml_label, attack_type,
    )

    return ClassificationResult(
        detection=detection,
        ml_score=ml_score,
        final_score=final_score,
        ml_label=ml_label,
        attack_type=attack_type,
        explanation=explanation,
    )


# ── Kafka Callback ────────────────────────────────────────────────────

def handle_detection_result(detection: DetectionResult) -> None:
    """
    Kafka consumer callback — invoked for every message on soc.analyzed.
    Calls classify(), logs the result, publishes to soc.classified.
    """
    result = classify(detection, MODELS)
    bus.publish("soc.classified", result, key=detection.enriched.alert.id)


# ── Entry Point ───────────────────────────────────────────────────────

def main() -> None:
    """Validate config, load models once, start Kafka consume loop."""
    global MODELS, bus

    settings.validate()
    log.info("ML Classifier agent starting")

    MODELS = load_models()
    log.info("[MODELS] All models loaded — ready to classify.")

    bus = KafkaBus(bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS)

    bus.consume(
        topic="soc.analyzed",
        group_id="ml-classifier-group",
        model_class=DetectionResult,
        callback=handle_detection_result,
    )


if __name__ == "__main__":
    main()
