"""
training/06_monitor.py
----------------------
PIPELINE STEP 6 — Production Drift Monitor

Reads analyst feedback from the last N days and:
  - Computes False Positive rate (analyst marked 'fp')
  - Computes False Negative rate (analyst marked 'fn')
  - Checks model confidence distribution from feedback
  - Alerts if drift thresholds are breached
  - Recommends (or forces) retraining

Exit codes:
  0 — production looks healthy
  1 — critical drift detected (should trigger retraining)

Run:
  python training/06_monitor.py
  python training/06_monitor.py --days 14 --fp-threshold 0.25
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from training.training_utils import (
    EVAL_REPORT_PATH,
    STAGE_DIRS,
    all_feedback_csvs,
    get_logger,
    setup_dirs,
)

log = get_logger("06_monitor")

# ── Default drift thresholds ──────────────────────────────────────────────────
DEFAULT_FP_THRESHOLD = 0.20   # >20% FP rate → alert
DEFAULT_FN_THRESHOLD = 0.10   # >10% FN rate → alert
DEFAULT_DAYS         = 7


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Pipeline Step 6 — Monitor production drift.")
    p.add_argument("--days",         type=int,   default=DEFAULT_DAYS,
                   help="Number of past days to analyse.")
    p.add_argument("--fp-threshold", type=float, default=DEFAULT_FP_THRESHOLD,
                   dest="fp_threshold", help="FP rate above which drift is flagged.")
    p.add_argument("--fn-threshold", type=float, default=DEFAULT_FN_THRESHOLD,
                   dest="fn_threshold", help="FN rate above which drift is flagged.")
    return p.parse_args()


# ── Read feedback CSVs ────────────────────────────────────────────────────────
def load_recent_feedback(days: int) -> pd.DataFrame:
    files = all_feedback_csvs()
    if not files:
        log.info("No feedback files found — nothing to monitor.")
        return pd.DataFrame()

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    frames: List[pd.DataFrame] = []

    for fpath in files:
        try:
            df = pd.read_csv(fpath, parse_dates=["timestamp"])
        except Exception as exc:
            log.warning("  Could not read '%s': %s", os.path.basename(fpath), exc)
            continue

        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
            recent = df[df["timestamp"] >= cutoff]
        else:
            recent = df  # No timestamp column — include all rows

        if not recent.empty:
            frames.append(recent)

    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


# ── Compute metrics ───────────────────────────────────────────────────────────
def compute_rates(df: pd.DataFrame) -> Dict[str, float]:
    if df.empty or "label" not in df.columns:
        return {}

    total = len(df)
    counts = df["label"].value_counts().to_dict()
    tp = counts.get("tp", 0)
    fp = counts.get("fp", 0)
    fn = counts.get("fn", 0)

    fp_rate = fp / total if total > 0 else 0.0
    fn_rate = fn / total if total > 0 else 0.0
    tp_rate = tp / total if total > 0 else 0.0

    return {
        "total":   total,
        "tp":      tp, "fp":      fp, "fn":      fn,
        "tp_rate": tp_rate,
        "fp_rate": fp_rate,
        "fn_rate": fn_rate,
    }


def check_confidence_drift(df: pd.DataFrame) -> Optional[str]:
    """Return warning message if average model confidence is unusually low."""
    if "confidence" not in df.columns:
        return None
    avg_conf = pd.to_numeric(df["confidence"], errors="coerce").mean()
    if pd.isna(avg_conf):
        return None
    if avg_conf < 0.65:
        return f"⚠️  Average model confidence is LOW: {avg_conf:.2f} (threshold: 0.65)"
    return None


def load_last_evaluation_scores() -> Optional[Dict]:
    """Load the last evaluation report for reference."""
    if not os.path.isfile(EVAL_REPORT_PATH):
        return None
    with open(EVAL_REPORT_PATH) as f:
        return json.load(f)


# ── Production model inventory ────────────────────────────────────────────────
def check_production_inventory() -> List[str]:
    prod_dir = STAGE_DIRS["production"]
    expected = [
        "threat_model.pkl", "attack_type_model.pkl",
        "fp_model.pkl", "fp_classifier.pkl",
        "preprocessor.pkl", "encoders.pkl",
    ]
    missing = [f for f in expected if not os.path.isfile(os.path.join(prod_dir, f))]
    return missing


def main() -> None:
    print("=" * 60)
    print("  STEP 06 — MONITOR PRODUCTION")
    print("=" * 60)

    setup_dirs()
    args = parse_args()
    critical_drift = False

    # ── 1. Production model inventory ────────────────────────────────────
    log.info("Checking production model inventory …")
    missing = check_production_inventory()
    if missing:
        log.error("  ✗ Missing production models: %s", missing)
        log.error("  Run 03_train.py + 05_promote.py to populate production/.")
        critical_drift = True
    else:
        log.info("  ✔ All production models present.")

    # ── 2. Feedback analysis ──────────────────────────────────────────────
    log.info("\nAnalysing analyst feedback (last %d days) …", args.days)
    df = load_recent_feedback(args.days)

    if df.empty:
        log.info("  No recent feedback data — cannot compute FP/FN rates.")
        log.info("  Use collect_feedback.py to record analyst decisions.")
    else:
        rates = compute_rates(df)
        log.info("  Total feedback records : %d", rates.get("total", 0))
        log.info("  TP: %d (%.1f%%)  FP: %d (%.1f%%)  FN: %d (%.1f%%)",
                 rates["tp"], rates["tp_rate"] * 100,
                 rates["fp"], rates["fp_rate"] * 100,
                 rates["fn"], rates["fn_rate"] * 100)

        if rates["fp_rate"] > args.fp_threshold:
            log.warning("  ⚠️  HIGH FP RATE: %.1f%% (threshold: %.1f%%)",
                        rates["fp_rate"] * 100, args.fp_threshold * 100)
            critical_drift = True
        else:
            log.info("  ✔ FP rate OK: %.1f%%", rates["fp_rate"] * 100)

        if rates["fn_rate"] > args.fn_threshold:
            log.warning("  ⚠️  HIGH FN RATE: %.1f%% (threshold: %.1f%%)",
                        rates["fn_rate"] * 100, args.fn_threshold * 100)
            critical_drift = True
        else:
            log.info("  ✔ FN rate OK: %.1f%%", rates["fn_rate"] * 100)

        # Confidence drift
        conf_warning = check_confidence_drift(df)
        if conf_warning:
            log.warning("  %s", conf_warning)
            critical_drift = True

    # ── 3. Last evaluation report ─────────────────────────────────────────
    eval_report = load_last_evaluation_scores()
    if eval_report:
        generated = eval_report.get("generated_at", "unknown")
        log.info("\nLast evaluation report: %s", generated)
        for model_name, info in eval_report.get("models", {}).items():
            prod_f1 = info.get("production", {}).get("f1_macro", "N/A")
            cand_f1 = info.get("candidate",  {}).get("f1_macro", "N/A")
            log.info("  %-35s prod_f1=%.4f  cand_f1=%.4f", model_name,
                     prod_f1 if isinstance(prod_f1, float) else 0,
                     cand_f1 if isinstance(cand_f1, float) else 0)
    else:
        log.info("\nNo evaluation report found. Run 04_evaluate.py.")

    # ── 4. Summary ────────────────────────────────────────────────────────
    log.info("\n%s", "=" * 60)
    if critical_drift:
        log.warning("  ⚠️  DRIFT DETECTED — retraining recommended.")
        log.warning("  Run:  python training/pipeline.py")
        log.info("=" * 60)
        sys.exit(1)
    else:
        log.info("  ✅  Production models are HEALTHY.")
        log.info("=" * 60)
        sys.exit(0)


if __name__ == "__main__":
    main()
