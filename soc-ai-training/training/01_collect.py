"""
training/01_collect.py
----------------------
PIPELINE STEP 1 — Data Collection & Merging

Responsibilities:
  - Load the raw NSL-KDD CSV (kdd_train.csv)
  - Load all analyst-feedback CSVs from datasets/feedback/
  - Merge everything into one raw dataset
  - Save to datasets/raw/merged.csv

Run:
  python training/01_collect.py
  python training/01_collect.py --raw-dataset path/to/other.csv
"""

import argparse
import os
import sys

import pandas as pd

# Allow running from project root OR from training/ directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from training.training_utils import (
    DATASET_PATHS,
    all_feedback_csvs,
    get_logger,
    setup_dirs,
)

log = get_logger("01_collect")

# ── Mandatory columns in kdd_train.csv ────────────────────────────────────────
REQUIRED_RAW_COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "labels",
]

# ── Columns expected in feedback CSVs ─────────────────────────────────────────
FEEDBACK_REQUIRED_COLS = {"alert_id", "label", "source"}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Pipeline Step 1 — Collect & merge data.")
    p.add_argument("--raw-dataset", default=DATASET_PATHS["raw"],
                   help="Path to the primary NSL-KDD CSV.")
    p.add_argument("--out", default=DATASET_PATHS["merged"],
                   help="Destination path for merged CSV.")
    return p.parse_args()


def load_raw(path: str) -> pd.DataFrame:
    log.info("Loading raw dataset: %s", path)
    if not os.path.isfile(path):
        log.error("Raw dataset not found: '%s'", path)
        sys.exit(1)
    if os.path.getsize(path) == 0:
        log.error("Raw dataset is empty: '%s'", path)
        sys.exit(1)

    df = pd.read_csv(path)
    log.info("  → %s rows × %s columns loaded", f"{len(df):,}", df.shape[1])

    # Schema check
    missing = [c for c in REQUIRED_RAW_COLUMNS if c not in df.columns]
    if missing:
        log.error("Missing required columns in raw dataset: %s", missing)
        sys.exit(1)

    df["source"] = "kdd"
    return df[REQUIRED_RAW_COLUMNS + ["source"]]


def load_feedback() -> pd.DataFrame:
    """Load all monthly feedback CSVs and return a combined DataFrame."""
    files = all_feedback_csvs()
    if not files:
        log.info("No feedback CSV files found — skipping feedback merge.")
        return pd.DataFrame()

    frames = []
    for fpath in files:
        log.info("  Loading feedback: %s", os.path.basename(fpath))
        try:
            fb = pd.read_csv(fpath)
        except Exception as exc:
            log.warning("  Could not read '%s': %s — skipping.", fpath, exc)
            continue

        missing_fb = FEEDBACK_REQUIRED_COLS - set(fb.columns)
        if missing_fb:
            log.warning("  Feedback file missing columns %s — skipping.", missing_fb)
            continue

        # Only incorporate analyst-confirmed true-positives as training signal
        confirmed_tp = fb[fb["label"] == "tp"]
        if confirmed_tp.empty:
            log.info("  No confirmed TPs in %s.", os.path.basename(fpath))
            continue

        log.info("  → %d confirmed TPs.", len(confirmed_tp))
        frames.append(confirmed_tp)

    if not frames:
        return pd.DataFrame()

    combined = pd.concat(frames, ignore_index=True)
    log.info("Total feedback rows incorporated: %d", len(combined))
    return combined


def merge_and_save(raw: pd.DataFrame, feedback: pd.DataFrame, out_path: str) -> None:
    if not feedback.empty:
        # Align columns — feedback rows only need the shared features + label
        shared_cols = list(set(raw.columns) & set(feedback.columns))
        combined = pd.concat([raw, feedback[shared_cols]], ignore_index=True)
        log.info("Merged dataset: %s rows (raw + feedback)", f"{len(combined):,}")
    else:
        combined = raw
        log.info("No feedback data merged. Using raw only: %s rows", f"{len(combined):,}")

    # Remove duplicates introduced during merge
    before = len(combined)
    combined = combined.drop_duplicates()
    if before - len(combined):
        log.info("  Removed %d duplicate rows after merge.", before - len(combined))

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    combined.to_csv(out_path, index=False)
    size_kb = os.path.getsize(out_path) / 1024
    log.info("Saved merged dataset → %s  (%.1f KB)", out_path, size_kb)


def main() -> None:
    print("=" * 60)
    print("  STEP 01 — COLLECT & MERGE DATA")
    print("=" * 60)

    setup_dirs()
    args = parse_args()

    raw      = load_raw(args.raw_dataset)
    feedback = load_feedback()
    merge_and_save(raw, feedback, args.out)

    log.info("✅  Step 01 complete.\n")


if __name__ == "__main__":
    main()
