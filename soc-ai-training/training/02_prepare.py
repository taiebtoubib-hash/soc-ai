"""
training/02_prepare.py
----------------------
PIPELINE STEP 2 — Data Preparation

Responsibilities:
  - Load merged.csv from Step 1
  - Clean: drop nulls, duplicates
  - Encode: protocol_type, service, flag  (LabelEncoder)
  - Scale: all numerical features  (StandardScaler)
  - Balance: oversample rare classes (U2R/R2L) with SMOTE
  - Split: 80% train / 20% test
  - Save: datasets/processed/features.parquet
           ml_models/candidate/preprocessor.pkl
           ml_models/candidate/encoders.pkl

Run:
  python training/02_prepare.py
  python training/02_prepare.py --no-smote --test-size 0.25
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from training.training_utils import (
    DATASET_PATHS,
    get_logger,
    save_model,
    setup_dirs,
)

log = get_logger("02_prepare")

# ── Feature / label constants ─────────────────────────────────────────────────
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

FEATURE_COLS = [
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
]

ATTACK_CATEGORY = {
    "neptune":"dos","smurf":"dos","back":"dos","teardrop":"dos","pod":"dos","land":"dos",
    "satan":"probe","ipsweep":"probe","portsweep":"probe","nmap":"probe",
    "warezclient":"r2l","guess_passwd":"r2l","warezmaster":"r2l","imap":"r2l",
    "ftp_write":"r2l","multihop":"r2l","phf":"r2l","spy":"r2l",
    "buffer_overflow":"u2r","rootkit":"u2r","loadmodule":"u2r","perl":"u2r",
    "normal":"normal",
}
CATEGORY_TO_INT = {"normal":0,"dos":1,"probe":2,"r2l":3,"u2r":4}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Pipeline Step 2 — Prepare features.")
    p.add_argument("--input",     default=DATASET_PATHS["merged"],
                   help="Merged CSV from Step 1.")
    p.add_argument("--out", default=DATASET_PATHS["processed"],
                   help="Destination path for processed features (.pkl).")
    p.add_argument("--test-size", type=float, default=0.20, dest="test_size")
    p.add_argument("--no-smote",  action="store_true", dest="no_smote",
                   help="Disable SMOTE oversampling (use class_weight instead).")
    p.add_argument("--random-state", type=int, default=42, dest="random_state")
    return p.parse_args()


# ── Load ──────────────────────────────────────────────────────────────────────
def load_merged(path: str) -> pd.DataFrame:
    if not os.path.isfile(path):
        log.error("Merged dataset not found: '%s'\nDid you run 01_collect.py?", path)
        sys.exit(1)
    df = pd.read_csv(path)
    log.info("Loaded merged dataset: %s rows", f"{len(df):,}")
    return df


# ── Clean ─────────────────────────────────────────────────────────────────────
def clean(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)
    df = df.dropna(subset=FEATURE_COLS + ["labels"])
    df = df.drop_duplicates()
    removed = before - len(df)
    if removed:
        log.info("  Removed %d null/duplicate rows.", removed)
    log.info("  Clean rows: %s", f"{len(df):,}")
    return df.copy()


# ── Encode ────────────────────────────────────────────────────────────────────
def encode_categoricals(df: pd.DataFrame):
    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le
        log.info("  Encoded '%-15s' → %d classes", col, len(le.classes_))
    return df, encoders


# ── Label engineering ─────────────────────────────────────────────────────────
def build_labels(df: pd.DataFrame):
    df["is_threat"] = (df["labels"] != "normal").astype(int)
    df["attack_category"] = df["labels"].map(ATTACK_CATEGORY).fillna("normal")
    df["attack_int"] = df["attack_category"].map(CATEGORY_TO_INT).fillna(0).astype(int)
    return df


# ── Scale ─────────────────────────────────────────────────────────────────────
def scale_features(X: np.ndarray):
    scaler = StandardScaler()
    return scaler.fit_transform(X), scaler


# ── Balance via SMOTE ────────────────────────────────────────────────────────
def apply_smote(X: np.ndarray, y: np.ndarray, label: str, random_state: int):
    try:
        from imblearn.over_sampling import SMOTE
    except ImportError:
        log.warning("  imbalanced-learn not installed — skipping SMOTE for %s.", label)
        return X, y

    counts = {c: (y == c).sum() for c in np.unique(y)}
    log.info("  Class distribution before SMOTE (%s): %s", label, counts)
    smote = SMOTE(random_state=random_state, k_neighbors=min(5, min(counts.values()) - 1))
    try:
        X_res, y_res = smote.fit_resample(X, y)
        after = {c: (y_res == c).sum() for c in np.unique(y_res)}
        log.info("  Class distribution after  SMOTE (%s): %s", label, after)
        return X_res, y_res
    except Exception as exc:
        log.warning("  SMOTE failed (%s) — using original distribution. Reason: %s", label, exc)
        return X, y


# ── Save processed features ───────────────────────────────────────────────────
def save_features(
    X_train, X_test,
    yt_train, yt_test,
    ya_train, ya_test,
    out_path: str,
) -> None:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    df = pd.DataFrame({
        **{f"feat_{i}": X_train[:, i] for i in range(X_train.shape[1])},
        "y_threat":  yt_train,
        "y_attack":  ya_train,
        "split":     "train",
    })
    test_df = pd.DataFrame({
        **{f"feat_{i}": X_test[:, i] for i in range(X_test.shape[1])},
        "y_threat":  yt_test,
        "y_attack":  ya_test,
        "split":     "test",
    })
    combined = pd.concat([df, test_df], ignore_index=True)
    combined.to_pickle(out_path)
    size_kb = os.path.getsize(out_path) / 1024
    log.info("Saved processed features → %s  (%.1f KB)", out_path, size_kb)
    log.info("  Train rows: %s  |  Test rows: %s", f"{len(df):,}", f"{len(test_df):,}")


def main() -> None:
    print("=" * 60)
    print("  STEP 02 — PREPARE FEATURES")
    print("=" * 60)

    setup_dirs()
    args = parse_args()

    # 1. Load
    df = load_merged(args.input)

    # 2. Clean
    df = clean(df)

    # 3. Encode
    df, encoders = encode_categoricals(df)

    # 4. Labels
    df = build_labels(df)
    log.info("  Threat label: normal=%s | attack=%s",
             f"{(df.is_threat==0).sum():,}", f"{(df.is_threat==1).sum():,}")

    # 5. Raw feature matrix
    X = df[FEATURE_COLS].values
    y_threat = df["is_threat"].values
    y_attack  = df["attack_int"].values

    # 6. Scale
    X_scaled, scaler = scale_features(X)
    log.info("  Feature matrix: %s", X_scaled.shape)

    # 7. Train/test split (stratified on binary threat label)
    X_train, X_test, yt_train, yt_test, ya_train, ya_test = train_test_split(
        X_scaled, y_threat, y_attack,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y_threat,
    )
    log.info("  Split: %s train | %s test", f"{len(X_train):,}", f"{len(X_test):,}")

    # 8. SMOTE on attack-type labels (training set only)
    if not args.no_smote:
        log.info("Applying SMOTE to balance rare attack categories …")
        X_train, ya_train_bal = apply_smote(X_train, ya_train, "attack", args.random_state)
        # Re-derive binary threat label after oversampling
        yt_train = (ya_train_bal > 0).astype(int)
        ya_train = ya_train_bal
        log.info("  Post-SMOTE train rows: %s", f"{len(X_train):,}")
    else:
        log.info("SMOTE disabled — using natural class distribution.")

    # 9. Save processed dataset
    save_features(X_train, X_test, yt_train, yt_test, ya_train, ya_test, args.out)

    # 10. Save preprocessor artefacts to candidate/
    save_model(scaler,   "preprocessor.pkl", "candidate")
    save_model(encoders, "encoders.pkl",      "candidate")

    log.info("✅  Step 02 complete.\n")


if __name__ == "__main__":
    main()
