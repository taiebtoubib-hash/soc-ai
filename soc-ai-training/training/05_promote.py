"""
training/05_promote.py
----------------------
PIPELINE STEP 5 — Promote Candidate to Production

Reads ml_models/candidate/evaluation_report.json.
If the report says promote=true:
  - Backs up each current production model to ml_models/versions/ (timestamped)
  - Copies candidate/* → production/*

If the report says promote=false:
  - Keeps production as-is
  - Logs the reason and exits with code 2

Run:
  python training/05_promote.py
  python training/05_promote.py --force    # promotes regardless of evaluation
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from training.training_utils import (
    EVAL_REPORT_PATH,
    get_logger,
    promote_candidate,
    setup_dirs,
)

log = get_logger("05_promote")

MODELS_TO_PROMOTE = [
    "threat_model.pkl",
    "attack_type_model.pkl",
    "fp_model.pkl",
    "fp_classifier.pkl",
    "preprocessor.pkl",
    "encoders.pkl",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Pipeline Step 5 — Promote candidate models.")
    p.add_argument("--force", action="store_true",
                   help="Skip evaluation check and force-promote candidate.")
    return p.parse_args()


def load_report() -> dict:
    if not os.path.isfile(EVAL_REPORT_PATH):
        log.error(
            "Evaluation report not found: '%s'\n"
            "Did you run 04_evaluate.py?", EVAL_REPORT_PATH
        )
        sys.exit(1)
    with open(EVAL_REPORT_PATH) as f:
        return json.load(f)


def do_promote() -> None:
    log.info("Promoting candidate models to production …")
    promoted, skipped = [], []

    for name in MODELS_TO_PROMOTE:
        from training.training_utils import model_path
        src = model_path(name, "candidate")
        if not os.path.isfile(src):
            log.warning("  %-35s not found in candidate/ — skipping.", name)
            skipped.append(name)
            continue
        promote_candidate(name)
        promoted.append(name)

    log.info("\n  ✅  Promoted %d model(s): %s", len(promoted), promoted)
    if skipped:
        log.warning("  ⚠️  Skipped %d model(s): %s", len(skipped), skipped)


def main() -> None:
    print("=" * 60)
    print("  STEP 05 — PROMOTE MODELS")
    print("=" * 60)

    setup_dirs()
    args = parse_args()

    if args.force:
        log.warning("--force flag detected: skipping evaluation check.")
        do_promote()
        log.info("✅  Step 05 complete (forced). Production updated.\n")
        sys.exit(0)

    report = load_report()
    decision = report.get("promotion_decision", {})
    should_promote = decision.get("promote", False)
    reason         = decision.get("reason", "No reason provided.")
    metric         = decision.get("primary_metric", "f1_macro")

    log.info("Evaluation report loaded (primary metric: %s)", metric)
    log.info("Report generated at: %s", report.get("generated_at", "unknown"))

    # ── Print per-model deltas ────────────────────────────────────────────
    log.info("\n  Model comparison summary:")
    for model_name, info in report.get("models", {}).items():
        wins = info.get("candidate_wins", False)
        delta = info.get("delta", {}).get(metric, 0.0)
        tag = "✅" if wins else "⚠️ "
        log.info("  %s %-35s Δ%s = %+.4f", tag, model_name, metric, delta)

    if not should_promote:
        log.info("\n  ⚠️  Decision: KEEP PRODUCTION  —  %s", reason)
        log.info("  To override run: python training/05_promote.py --force")
        log.info("=" * 60)
        sys.exit(2)

    log.info("\n  ✅  Decision: PROMOTE  —  %s", reason)
    do_promote()
    log.info("✅  Step 05 complete. Production updated.\n")


if __name__ == "__main__":
    main()
