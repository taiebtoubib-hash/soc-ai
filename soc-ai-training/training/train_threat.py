"""
training/train_threat.py
------------------------
Trains TWO models on the NSL-KDD dataset:

  MODEL 1 — Threat Detector   (XGBoost, binary)
             normal → 0  |  any attack → 1

  MODEL 2 — Attack Classifier (Random Forest, multiclass)
             normal → 0  |  dos → 1  |  probe → 2  |  r2l → 3  |  u2r → 4

Outputs
-------
  ml_models/threat_model.pkl
  ml_models/attack_type_model.pkl
  ml_models/preprocessor.pkl
  ml_models/encoders.pkl

Usage
-----
  python training/train_threat.py
  python training/train_threat.py --dataset path/to/kdd_train.csv --models-dir ml_models --test-size 0.2
"""

import argparse
import logging
import os
import sys
import time
from typing import Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("train_threat")


# ─────────────────────────────────────────────────────────────────────────────
# STATIC CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_COLUMNS: list[str] = [
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
    "labels",   # ground-truth label column
]

CATEGORICAL_COLS: list[str] = ["protocol_type", "service", "flag"]

FEATURE_COLS: list[str] = [c for c in REQUIRED_COLUMNS if c != "labels"]

# NSL-KDD attack-category mapping
ATTACK_CATEGORY: Dict[str, str] = {
    # DoS
    "neptune": "dos", "smurf": "dos", "back": "dos",
    "teardrop": "dos", "pod": "dos", "land": "dos",
    # Probe
    "satan": "probe", "ipsweep": "probe", "portsweep": "probe", "nmap": "probe",
    # R2L
    "warezclient": "r2l", "guess_passwd": "r2l", "warezmaster": "r2l",
    "imap": "r2l", "ftp_write": "r2l", "multihop": "r2l",
    "phf": "r2l", "spy": "r2l",
    # U2R
    "buffer_overflow": "u2r", "rootkit": "u2r",
    "loadmodule": "u2r", "perl": "u2r",
    # Normal
    "normal": "normal",
}

CATEGORY_TO_INT: Dict[str, int] = {
    "normal": 0, "dos": 1, "probe": 2, "r2l": 3, "u2r": 4,
}

INT_TO_CATEGORY: Dict[int, str] = {v: k for k, v in CATEGORY_TO_INT.items()}
THREAT_NAMES: Dict[int, str] = {0: "normal", 1: "attack"}


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """Parse and return CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Train SOC AI threat-detection and attack-classification models."
    )
    parser.add_argument(
        "--dataset",
        default="training/datasets/raw/kdd_train.csv",
        help="Path to the NSL-KDD CSV training file.",
    )
    parser.add_argument(
        "--models-dir",
        default="ml_models",
        dest="models_dir",
        help="Directory where trained models will be saved.",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        dest="test_size",
        help="Fraction of data to hold out for testing (default: 0.20).",
    )
    parser.add_argument(
        "--cv-folds",
        type=int,
        default=5,
        dest="cv_folds",
        help="Number of cross-validation folds (default: 5). Set to 0 to skip CV.",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        dest="random_state",
        help="Random seed for reproducibility (default: 42).",
    )
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — PRE-FLIGHT CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def preflight_checks(dataset_path: str, models_dir: str, test_size: float, cv_folds: int) -> None:
    """
    Validate all inputs before any expensive work begins.
    Raises SystemExit on the first fatal issue found.
    """
    log.info("Running pre-flight checks …")
    errors: list[str] = []

    # — Dataset file exists and is readable
    if not os.path.isfile(dataset_path):
        errors.append(f"Dataset not found: '{dataset_path}'")
    else:
        if os.path.getsize(dataset_path) == 0:
            errors.append(f"Dataset file is empty: '{dataset_path}'")

    # — models_dir is not a file (it can be missing; we'll create it)
    if os.path.isfile(models_dir):
        errors.append(f"--models-dir '{models_dir}' is a file, not a directory.")

    # — test_size is sane
    if not (0.05 <= test_size <= 0.50):
        errors.append(f"--test-size must be between 0.05 and 0.50 (got {test_size}).")

    # — cv_folds is sane
    if cv_folds < 0 or cv_folds == 1:
        errors.append(f"--cv-folds must be 0 (disabled) or ≥ 2 (got {cv_folds}).")

    if errors:
        log.error("Pre-flight checks FAILED:")
        for e in errors:
            log.error("  ✗ %s", e)
        sys.exit(1)

    log.info("  ✔ Dataset path   : %s", dataset_path)
    log.info("  ✔ Models dir     : %s", models_dir)
    log.info("  ✔ Test split     : %.0f%%", test_size * 100)
    log.info("  ✔ CV folds       : %s", cv_folds if cv_folds > 0 else "disabled")
    log.info("Pre-flight checks passed.\n")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — LOAD DATA
# ─────────────────────────────────────────────────────────────────────────────

def load_data(path: str) -> pd.DataFrame:
    """
    Load the NSL-KDD CSV, validate schema, and return a clean DataFrame.
    Exits on missing columns or unexpected data issues.
    """
    log.info("Loading dataset …")
    try:
        df = pd.read_csv(path)
    except Exception as exc:
        log.error("Failed to read CSV: %s", exc)
        sys.exit(1)

    log.info("  Loaded %s rows × %s columns.", f"{len(df):,}", df.shape[1])

    # ── Schema check ──────────────────────────────────────────────────────
    missing_cols = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing_cols:
        log.error(
            "Dataset is missing %d required column(s): %s",
            len(missing_cols), missing_cols,
        )
        sys.exit(1)

    # ── Null check ────────────────────────────────────────────────────────
    null_counts = df[REQUIRED_COLUMNS].isnull().sum()
    null_cols = null_counts[null_counts > 0]
    if not null_cols.empty:
        log.warning("Null values detected — will drop affected rows:")
        for col, cnt in null_cols.items():
            log.warning("  %-35s → %d nulls", col, cnt)
        before = len(df)
        df = df.dropna(subset=REQUIRED_COLUMNS)
        log.warning("  Dropped %d rows (%.1f%% of data).", before - len(df), (before - len(df)) / before * 100)

    # ── Label distribution ────────────────────────────────────────────────
    label_counts = df["labels"].value_counts()
    log.info("  Label distribution (top 10):\n%s", label_counts.head(10).to_string())

    # ── Duplicate check ───────────────────────────────────────────────────
    dup_count = df.duplicated().sum()
    if dup_count > 0:
        log.warning("  %d duplicate rows found and removed.", dup_count)
        df = df.drop_duplicates()

    log.info("  Final usable rows: %s\n", f"{len(df):,}")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — PREPROCESS
# ─────────────────────────────────────────────────────────────────────────────

def preprocess(
    df: pd.DataFrame,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, StandardScaler, Dict[str, LabelEncoder]]:
    """
    Encode categoricals, build binary threat label, build multiclass attack
    category label, scale features, and return everything needed for training.
    """
    log.info("Preprocessing features …")

    # ── Encode categorical columns ─────────────────────────────────────────
    encoders: Dict[str, LabelEncoder] = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le
        log.info("  Encoded '%-15s' → %d unique classes", col, len(le.classes_))

    # ── Binary threat label ────────────────────────────────────────────────
    df["is_threat"] = (df["labels"] != "normal").astype(int)

    # ── Multiclass attack-category label ──────────────────────────────────
    df["attack_category"] = df["labels"].map(ATTACK_CATEGORY).fillna("normal")
    unknown = df[~df["labels"].isin(ATTACK_CATEGORY)]["labels"].unique()
    if len(unknown):
        log.warning("  Unknown labels mapped to 'normal': %s", list(unknown))
    df["attack_category_int"] = df["attack_category"].map(CATEGORY_TO_INT).fillna(0).astype(int)

    # ── Feature matrix ─────────────────────────────────────────────────────
    X = df[FEATURE_COLS].values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    y_threat = df["is_threat"].values
    y_attack  = df["attack_category_int"].values

    log.info("  Feature matrix shape : %s", X_scaled.shape)
    log.info("  Threat label balance : normal=%s  attack=%s",
             f"{(y_threat == 0).sum():,}", f"{(y_threat == 1).sum():,}")
    log.info("  Attack-category distribution:")
    for cat, idx in CATEGORY_TO_INT.items():
        log.info("    %-10s (%d) → %s samples", cat, idx, f"{(y_attack == idx).sum():,}")
    log.info("")
    return X_scaled, y_threat, y_attack, scaler, encoders


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _print_confusion_matrix(cm: np.ndarray, class_names: list[str]) -> None:
    """Pretty-print a confusion matrix with class labels."""
    header = "Actual \\ Pred  " + "  ".join(f"{n:>8}" for n in class_names)
    log.info("  %s", header)
    log.info("  %s", "-" * len(header))
    for i, row in enumerate(cm):
        row_str = "  ".join(f"{v:>8,}" for v in row)
        log.info("  %-15s %s", class_names[i], row_str)


def _run_cross_validation(
    model,
    X: np.ndarray,
    y: np.ndarray,
    cv_folds: int,
    scoring: str,
    random_state: int,
    label: str,
) -> None:
    """Run stratified K-fold CV and log mean ± std score."""
    log.info("  Running %d-fold cross-validation (%s) …", cv_folds, scoring)
    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
    scores = cross_val_score(model, X, y, cv=cv, scoring=scoring, n_jobs=-1)
    log.info(
        "  %s CV %s : %.4f  ±  %.4f  (min=%.4f  max=%.4f)",
        label, scoring, scores.mean(), scores.std(), scores.min(), scores.max(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — TRAIN THREAT MODEL  (XGBoost binary)
# ─────────────────────────────────────────────────────────────────────────────

def train_threat_model(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    cv_folds: int,
    random_state: int,
) -> XGBClassifier:
    """
    Train an XGBoost binary classifier to detect whether a network event is
    an attack (1) or normal (0).  Evaluates on the hold-out test set and
    optionally runs stratified cross-validation.

    Returns
    -------
    Trained XGBClassifier instance.
    """
    log.info("─" * 60)
    log.info("Training Threat Detector (XGBoost binary) …")
    t0 = time.perf_counter()

    # ── Scale-pos-weight handles class imbalance automatically ────────────
    neg, pos = (y_train == 0).sum(), (y_train == 1).sum()
    spw = neg / pos if pos > 0 else 1.0
    log.info("  Class weight (neg/pos): %.2f", spw)

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=spw,
        eval_metric="logloss",
        early_stopping_rounds=15,
        random_state=random_state,
        n_jobs=-1,
        verbosity=0,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    elapsed = time.perf_counter() - t0
    best_iter = model.best_iteration
    log.info("  Training done in %.1fs  |  Best iteration: %d", elapsed, best_iter)

    # ── Hold-out evaluation ───────────────────────────────────────────────
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    auc     = roc_auc_score(y_test, y_proba)

    log.info("\n  ── Threat Model — Hold-out Metrics ──")
    log.info("  ROC-AUC : %.4f", auc)
    log.info("\n%s", classification_report(
        y_test, y_pred,
        target_names=["normal", "attack"],
        digits=4,
    ))

    cm = confusion_matrix(y_test, y_pred)
    log.info("  Confusion Matrix:")
    _print_confusion_matrix(cm, ["normal", "attack"])

    # ── Cross-validation (optional) ───────────────────────────────────────
    if cv_folds >= 2:
        cv_model = XGBClassifier(
            n_estimators=best_iter or 200,
            max_depth=6, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8,
            scale_pos_weight=spw,
            eval_metric="logloss",
            random_state=random_state,
            n_jobs=-1, verbosity=0,
        )
        _run_cross_validation(
            cv_model,
            np.vstack([X_train, X_test]),
            np.hstack([y_train, y_test]),
            cv_folds, "roc_auc", random_state, "Threat",
        )

    log.info("")
    return model


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — TRAIN ATTACK TYPE MODEL  (Random Forest multiclass)
# ─────────────────────────────────────────────────────────────────────────────

def train_attack_type_model(
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    cv_folds: int,
    random_state: int,
) -> RandomForestClassifier:
    """
    Train a Random Forest multiclass classifier to identify the category of
    attack (normal/dos/probe/r2l/u2r).

    Returns
    -------
    Trained RandomForestClassifier instance.
    """
    log.info("─" * 60)
    log.info("Training Attack Type Classifier (Random Forest multiclass) …")
    t0 = time.perf_counter()

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=25,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    elapsed = time.perf_counter() - t0
    log.info("  Training done in %.1fs", elapsed)

    # ── Hold-out evaluation ───────────────────────────────────────────────
    target_names = [INT_TO_CATEGORY[i] for i in range(len(CATEGORY_TO_INT))]
    y_pred = model.predict(X_test)

    log.info("\n  ── Attack Type Model — Hold-out Metrics ──")
    log.info("\n%s", classification_report(
        y_test, y_pred,
        target_names=target_names,
        digits=4,
    ))

    cm = confusion_matrix(y_test, y_pred)
    log.info("  Confusion Matrix:")
    _print_confusion_matrix(cm, target_names)

    # ── Feature importance (top 10) ────────────────────────────────────────
    importances = pd.Series(model.feature_importances_, index=FEATURE_COLS)
    top10 = importances.nlargest(10)
    log.info("\n  Top-10 Feature Importances:")
    for feat, score in top10.items():
        bar = "█" * int(score * 50)
        log.info("    %-35s %.4f  %s", feat, score, bar)

    # ── Cross-validation (optional) ───────────────────────────────────────
    if cv_folds >= 2:
        cv_model = RandomForestClassifier(
            n_estimators=200, max_depth=25, min_samples_leaf=2,
            class_weight="balanced",
            random_state=random_state, n_jobs=-1,
        )
        _run_cross_validation(
            cv_model,
            np.vstack([X_train, X_test]),
            np.hstack([y_train, y_test]),
            cv_folds, "f1_macro", random_state, "AttackType",
        )

    log.info("")
    return model


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — SAVE MODELS
# ─────────────────────────────────────────────────────────────────────────────

def save_models(
    threat_model: XGBClassifier,
    attack_model: RandomForestClassifier,
    scaler: StandardScaler,
    encoders: Dict[str, LabelEncoder],
    models_dir: str,
) -> None:
    """Serialise all artefacts to *models_dir* using joblib."""
    log.info("─" * 60)
    log.info("Saving models to '%s' …", models_dir)
    os.makedirs(models_dir, exist_ok=True)

    artefacts = {
        "threat_model.pkl":      threat_model,
        "attack_type_model.pkl": attack_model,
        "preprocessor.pkl":      scaler,
        "encoders.pkl":          encoders,
    }

    for filename, obj in artefacts.items():
        path = os.path.join(models_dir, filename)
        joblib.dump(obj, path)
        size_kb = os.path.getsize(path) / 1024
        log.info("  ✔ %-28s  (%.1f KB)", filename, size_kb)

    log.info("")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — SMOKE TEST
# ─────────────────────────────────────────────────────────────────────────────

def smoke_test(
    threat_model: XGBClassifier,
    attack_model: RandomForestClassifier,
    X_test: np.ndarray,
    y_threat_test: np.ndarray,
    y_attack_test: np.ndarray,
    n_samples: int = 8,
) -> None:
    """
    Run a quick predictions check on *n_samples* rows from the test set and
    verify that the saved models produce valid output shapes and types.
    """
    log.info("─" * 60)
    log.info("Smoke test — %d sample predictions:", n_samples)

    samples        = X_test[:n_samples]
    threat_preds   = threat_model.predict(samples)
    threat_probas  = threat_model.predict_proba(samples)[:, 1]
    attack_preds   = attack_model.predict(samples)

    # Validation assertions
    assert len(threat_preds) == n_samples,  "Threat model output length mismatch"
    assert len(attack_preds) == n_samples,  "Attack model output length mismatch"
    assert all(p in (0, 1) for p in threat_preds), "Threat model produced invalid class"
    assert all(p in CATEGORY_TO_INT.values() for p in attack_preds), "Attack model produced invalid class"
    assert all(0.0 <= p <= 1.0 for p in threat_probas), "Threat probabilities out of range"

    header = f"  {'#':>3}  {'Threat':>8}  {'Score':>6}  {'Attack Type':>12}  {'Act.Threat':>10}  {'Act.Attack':>12}  {'OK?':>4}"
    log.info(header)
    log.info("  %s", "-" * (len(header) - 2))
    for i in range(n_samples):
        threat_ok  = threat_preds[i] == y_threat_test[i]
        attack_ok  = attack_preds[i] == y_attack_test[i]
        status     = "✔" if threat_ok and attack_ok else "✗"
        log.info(
            "  %3d  %8s  %6.2f  %12s  %10s  %12s  %4s",
            i + 1,
            THREAT_NAMES[threat_preds[i]],
            threat_probas[i],
            INT_TO_CATEGORY[attack_preds[i]],
            THREAT_NAMES[y_threat_test[i]],
            INT_TO_CATEGORY[y_attack_test[i]],
            status,
        )

    correct_threat = sum(threat_preds[i] == y_threat_test[i] for i in range(n_samples))
    correct_attack = sum(attack_preds[i] == y_attack_test[i] for i in range(n_samples))
    log.info(
        "\n  Threat accuracy on sample  : %d/%d  |  Attack accuracy on sample : %d/%d",
        correct_threat, n_samples, correct_attack, n_samples,
    )
    log.info("")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    print("=" * 60)
    print("  SOC AI — ML MODEL TRAINING PIPELINE")
    print("=" * 60)

    # 0. Pre-flight checks
    preflight_checks(args.dataset, args.models_dir, args.test_size, args.cv_folds)

    # 1. Load
    df = load_data(args.dataset)

    # 2. Preprocess
    X, y_threat, y_attack, scaler, encoders = preprocess(df)

    # 3. Split  (stratify on binary threat label for balanced folds)
    X_train, X_test, yt_train, yt_test, ya_train, ya_test = train_test_split(
        X, y_threat, y_attack,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y_threat,
    )
    log.info(
        "Train / test split: %s train rows | %s test rows\n",
        f"{len(X_train):,}", f"{len(X_test):,}",
    )

    # 4. Train
    threat_model = train_threat_model(
        X_train, X_test, yt_train, yt_test,
        cv_folds=args.cv_folds,
        random_state=args.random_state,
    )
    attack_model = train_attack_type_model(
        X_train, X_test, ya_train, ya_test,
        cv_folds=args.cv_folds,
        random_state=args.random_state,
    )

    # 5. Save artefacts
    save_models(threat_model, attack_model, scaler, encoders, args.models_dir)

    # 6. Smoke test
    smoke_test(threat_model, attack_model, X_test, yt_test, ya_test)

    print("=" * 60)
    log.info("✅  Training complete. Models are ready in '%s/'", args.models_dir)
    print("=" * 60)


if __name__ == "__main__":
    main()