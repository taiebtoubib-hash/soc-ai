"""
training/04_evaluate.py
-----------------------
PIPELINE STEP 4 — Model Evaluation

Loads BOTH production and candidate models, runs them on the same
held-out test set, compares metrics, and writes an evaluation report.

Outputs:
  ml_models/candidate/evaluation_report.json

Exit codes:
  0 — candidate is better (or no production baseline exists yet)
  2 — production is better (pipeline will skip promotion)

Run:
  python training/04_evaluate.py
  python training/04_evaluate.py --metric f1_macro
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from training.training_utils import (
    DATASET_PATHS,
    EVAL_REPORT_PATH,
    get_logger,
    load_model,
    production_model_exists,
    setup_dirs,
)

log = get_logger("04_evaluate")

# Models to compare (must exist in both candidate/ and production/ after first promote)
MODELS_TO_EVAL = [
    ("threat_model.pkl",      "binary"),
    ("attack_type_model.pkl", "multiclass"),
    ("fp_model.pkl",          "anomaly"),
    ("fp_classifier.pkl",     "binary"),
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Pipeline Step 4 — Evaluate candidate vs production.")
    p.add_argument("--features", default=DATASET_PATHS["processed"],
                   help="Pickled features file from Step 2.")
    p.add_argument("--metric",   default="f1_macro",
                   choices=["f1_macro", "roc_auc", "accuracy"],
                   help="Primary metric for promotion decision.")
    return p.parse_args()


def load_test_set(path: str):
    if not os.path.isfile(path):
        log.error("Processed features not found: '%s'\nDid you run 02_prepare.py?", path)
        sys.exit(1)
    df = pd.read_pickle(path)
    test = df[df["split"] == "test"]
    feat_cols = [c for c in df.columns if c.startswith("feat_")]
    X  = test[feat_cols].values
    yt = test["y_threat"].values
    ya = test["y_attack"].values
    log.info("  Test set: %s rows | %d features", f"{len(X):,}", len(feat_cols))
    return X, yt, ya


def evaluate_model(model, X: np.ndarray, y: np.ndarray, kind: str) -> Dict[str, float]:
    """Compute a standard metric set for a single model."""
    metrics: Dict[str, float] = {}

    if kind == "anomaly":
        # Isolation Forest predict returns 1 for inliers and -1 for anomalies.
        # Assuming anomalies are attacks (y=1) and inliers are normal (y=0).
        preds = model.predict(X)
        y_pred = np.where(preds == -1, 1, 0)

        metrics["accuracy"]  = float(accuracy_score(y, y_pred))
        metrics["precision"] = float(precision_score(y, y_pred, average="binary", zero_division=0))
        metrics["recall"]    = float(recall_score(y, y_pred, average="binary", zero_division=0))
        metrics["f1_macro"]  = float(f1_score(y, y_pred, average="macro", zero_division=0))
        metrics["f1_weighted"] = float(f1_score(y, y_pred, average="weighted", zero_division=0))

        if hasattr(model, "decision_function"):
            try:
                # Lower decision score is more anomalous. We negate it to align with ROC AUC (higher = more pos).
                probs = -model.decision_function(X)
                metrics["roc_auc"] = float(roc_auc_score(y, probs))
            except Exception:
                metrics["roc_auc"] = 0.0

        return metrics

    y_pred = model.predict(X)

    avg = "binary" if kind == "binary" else "macro"
    metrics["accuracy"]  = float(accuracy_score(y, y_pred))
    metrics["precision"] = float(precision_score(y, y_pred, average=avg, zero_division=0))
    metrics["recall"]    = float(recall_score(y, y_pred, average=avg, zero_division=0))
    metrics["f1_macro"]  = float(f1_score(y, y_pred, average="macro", zero_division=0))
    metrics["f1_weighted"] = float(f1_score(y, y_pred, average="weighted", zero_division=0))

    if kind == "binary" and hasattr(model, "predict_proba"):
        try:
            metrics["roc_auc"] = float(roc_auc_score(y, model.predict_proba(X)[:, 1]))
        except Exception:
            metrics["roc_auc"] = 0.0

    return metrics


def compare_models(
    candidate_scores: Dict[str, float],
    production_scores: Dict[str, float],
    primary_metric: str,
) -> bool:
    """Return True if candidate >= production on the primary metric."""
    c = candidate_scores.get(primary_metric, 0.0)
    p = production_scores.get(primary_metric, 0.0)
    return c >= p


def main() -> None:
    print("=" * 60)
    print("  STEP 04 — EVALUATE MODELS")
    print("=" * 60)

    setup_dirs()
    args = parse_args()
    X, yt, ya = load_test_set(args.features)

    ground_truths = {
        "threat_model.pkl":      (X, yt, "binary"),
        "attack_type_model.pkl": (X, ya, "multiclass"),
        "fp_model.pkl":          (X, yt, "anomaly"),
        "fp_classifier.pkl":     (X, yt, "binary"),
    }

    report: Dict = {
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "primary_metric": args.metric,
        "models":         {},
        "promotion_decision": {},
    }

    overall_candidate_wins = True

    for model_name, kind in MODELS_TO_EVAL:
        log.info("─" * 60)
        log.info("Evaluating: %s", model_name)
        Xi, yi, k = ground_truths[model_name]

        # ── Candidate ────────────────────────────────────────────────────
        candidate = load_model(model_name, "candidate")
        cand_scores = evaluate_model(candidate, Xi, yi, k)
        log.info("  Candidate scores: %s", {m: f"{v:.4f}" for m, v in cand_scores.items()})

        # ── Production  ───────────────────────────────────────────────────
        if production_model_exists(model_name):
            prod = load_model(model_name, "production")
            prod_scores = evaluate_model(prod, Xi, yi, k)
            log.info("  Production scores:%s", {m: f"{v:.4f}" for m, v in prod_scores.items()})
            wins = compare_models(cand_scores, prod_scores, args.metric)
        else:
            prod_scores = {}
            wins = True   # No baseline → always promote
            log.info("  No production baseline — candidate will be promoted automatically.")

        diff = {m: round(cand_scores.get(m, 0) - prod_scores.get(m, 0), 6)
                for m in cand_scores}
        verdict = "✅ CANDIDATE WINS" if wins else "⚠️  PRODUCTION BETTER"
        log.info("  Delta:   %s", {m: f"{v:+.4f}" for m, v in diff.items()})
        log.info("  Verdict: %s", verdict)

        report["models"][model_name] = {
            "candidate":  cand_scores,
            "production": prod_scores,
            "delta":      diff,
            "candidate_wins": wins,
        }
        overall_candidate_wins = overall_candidate_wins and wins

    # ── Overall decision ─────────────────────────────────────────────────
    report["promotion_decision"] = {
        "promote":        overall_candidate_wins,
        "primary_metric": args.metric,
        "reason": (
            "Candidate matches or exceeds production on all evaluated models."
            if overall_candidate_wins else
            "One or more candidate models under-performed production."
        ),
    }

    # ── Write report ──────────────────────────────────────────────────────
    with open(EVAL_REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    log.info("\n  Evaluation report → %s", EVAL_REPORT_PATH)

    log.info("\n%s", "=" * 60)
    if overall_candidate_wins:
        log.info("  ✅  CANDIDATE IS BETTER — ready for promotion (run 05_promote.py)")
        log.info("=" * 60)
        sys.exit(0)
    else:
        log.info("  ⚠️  PRODUCTION IS BETTER — skipping promotion.")
        log.info("=" * 60)
        sys.exit(2)


if __name__ == "__main__":
    main()
