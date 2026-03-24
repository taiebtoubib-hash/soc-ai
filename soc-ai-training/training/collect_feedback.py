"""
training/collect_feedback.py
----------------------------
Analyst Feedback CLI

Allows SOC analysts to record their decisions on specific alerts.
Each decision is appended to the monthly feedback CSV:
  training/datasets/feedback/feedback_YYYY-MM.csv

Feedback labels:
  tp  — True Positive  (model was correct, this IS an attack)
  fp  — False Positive (model was wrong, this is NOT an attack)
  fn  — False Negative (model missed a real attack)

Usage:
  # Interactive mode
  python training/collect_feedback.py

  # Direct mode (all flags provided)
  python training/collect_feedback.py \\
      --alert-id "alert-2026031601" \\
      --label tp \\
      --confidence 0.95 \\
      --notes "Confirmed C2 beacon traffic"
"""

import argparse
import csv
import os
import sys
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from training.training_utils import feedback_csv_path, get_logger, setup_dirs

log = get_logger("collect_feedback")

VALID_LABELS = ("tp", "fp", "fn")
CSV_FIELDNAMES = [
    "timestamp", "alert_id", "label", "confidence",
    "analyst", "notes", "source",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Record analyst feedback for a specific alert.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Labels:
  tp  — True Positive  (model correctly flagged an attack)
  fp  — False Positive (model raised a false alarm)
  fn  — False Negative (model missed a real attack, analyst caught it)
        """,
    )
    p.add_argument("--alert-id",   dest="alert_id",   default=None,
                   help="Unique alert identifier.")
    p.add_argument("--label",      choices=VALID_LABELS, default=None,
                   help="Analyst verdict: tp, fp, or fn.")
    p.add_argument("--confidence", type=float, default=None,
                   help="Analyst confidence (0.0–1.0). Optional.")
    p.add_argument("--analyst",    default=None,
                   help="Analyst name or ID. Optional.")
    p.add_argument("--notes",      default="",
                   help="Free-text notes about the alert.")
    p.add_argument("--source",     default="analyst",
                   help="Source of the feedback (default: analyst).")
    return p.parse_args()


def prompt_if_missing(value: Optional[str], prompt: str, valid=None) -> str:
    """Prompt the analyst interactively if a value is not provided."""
    while not value:
        value = input(prompt).strip()
        if not value:
            print("  ⚠️  This field is required.")
        elif valid and value not in valid:
            print(f"  ⚠️  Invalid value. Must be one of: {valid}")
            value = None
    return value


def append_feedback_row(
    alert_id: str,
    label: str,
    confidence: Optional[float],
    analyst: Optional[str],
    notes: str,
    source: str,
) -> str:
    """Write one feedback row to the current month's CSV. Returns the file path."""
    now  = datetime.now(timezone.utc)
    path = feedback_csv_path(now.year, now.month)

    row = {
        "timestamp":  now.isoformat(),
        "alert_id":   alert_id,
        "label":      label,
        "confidence": "" if confidence is None else f"{confidence:.4f}",
        "analyst":    analyst or "",
        "notes":      notes,
        "source":     source,
    }

    # Create the file with header if it doesn't exist yet
    write_header = not os.path.isfile(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        if write_header:
            writer.writeheader()
        writer.writerow(row)

    return path


def validate_confidence(value: Optional[float]) -> Optional[float]:
    if value is not None and not (0.0 <= value <= 1.0):
        log.error("Confidence must be between 0.0 and 1.0 (got %s).", value)
        sys.exit(1)
    return value


def main() -> None:
    setup_dirs()
    args = parse_args()

    # ── Interactive prompts for any missing required fields ────────────────
    is_interactive = sys.stdin.isatty() and (not args.alert_id or not args.label)
    if is_interactive:
        print("=" * 60)
        print("  SOC AI — Analyst Feedback Collector")
        print("=" * 60)
        print("  Fields marked * are required. Press Ctrl+C to cancel.\n")

    try:
        alert_id = prompt_if_missing(
            args.alert_id,
            "  Alert ID *: ",
        ) if not args.alert_id else args.alert_id

        label = prompt_if_missing(
            args.label,
            f"  Label * ({'/'.join(VALID_LABELS)}): ",
            valid=list(VALID_LABELS),
        ) if not args.label else args.label

        confidence = validate_confidence(args.confidence)
        if confidence is None and is_interactive:
            raw = input("  Confidence (0.0–1.0, or blank to skip): ").strip()
            if raw:
                try:
                    confidence = validate_confidence(float(raw))
                except ValueError:
                    log.warning("  Invalid confidence value — skipping.")

        analyst = args.analyst
        if not analyst and is_interactive:
            analyst = input("  Analyst name (or blank): ").strip() or None

        notes = args.notes
        if not notes and is_interactive:
            notes = input("  Notes (optional): ").strip()

    except KeyboardInterrupt:
        print("\n  Cancelled.")
        sys.exit(0)

    # ── Validate ──────────────────────────────────────────────────────────
    if label not in VALID_LABELS:
        log.error("Invalid label '%s'. Must be one of %s.", label, VALID_LABELS)
        sys.exit(1)

    # ── Write ────────────────────────────────────────────────────────────
    path = append_feedback_row(alert_id, label, confidence, analyst, notes, args.source)

    log.info("✅  Feedback recorded:")
    log.info("    Alert  : %s", alert_id)
    log.info("    Label  : %s", label)
    log.info("    File   : %s", path)
    if confidence is not None:
        log.info("    Confidence: %.2f", confidence)
    if notes:
        log.info("    Notes  : %s", notes)


if __name__ == "__main__":
    main()
