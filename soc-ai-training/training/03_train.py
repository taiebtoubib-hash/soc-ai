"""
training/03_train.py
--------------------
PIPELINE STEP 3 — Model Training

Trains 4 models on the processed features from Step 2 and saves them
to ml_models/candidate/:

  1. XGBoost          → threat_model.pkl       (binary: normal vs attack)
  2. Random Forest    → attack_type_model.pkl  (multiclass: normal/dos/probe/r2l/u2r)
  3. Isolation Forest → fp_model.pkl           (anomaly scoring for FP detection)
  4. Logistic Regress → fp_classifier.pkl      (FP vs TP binary classifier)

Run:
  python training/03_train.py
  python training/03_train.py --skip-cv --random-state 0
"""

import argparse
import os
import sys
import time
from typing import Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from xgboost import XGBClassifier

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from training.training_utils import (
    DATASET_PATHS,
    get_logger,
    save_model,
    setup_dirs,
)

log = get_logger("03_train")

CATEGORY_NAMES = {0: "normal", 1: "dos", 2: "probe", 3: "r2l", 4: "u2r"}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Pipeline Step 3 — Train models.")
    p.add_argument("--features",     default=DATASET_PATHS["processed"],
                   help="Pickled features file from Step 2.")
    p.add_argument("--skip-cv",      action="store_true", dest="skip_cv",
                   help="Skip cross-validation (faster runs).")
    p.add_argument("--cv-folds",     type=int, default=5, dest="cv_folds")
    p.add_argument("--random-state", type=int, default=42, dest="random_state")
    return p.parse_args()


# ── Load processed features ───────────────────────────────────────────────────
def load_features(path: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray,
                                      np.ndarray, np.ndarray, np.ndarray]:
    if not os.path.isfile(path):
        log.error("Processed features not found: '%s'\nDid you run 02_prepare.py?", path)
        sys.exit(1)

    df = pd.read_pickle(path)
    feat_cols = [c for c in df.columns if c.startswith("feat_")]

    train = df[df["split"] == "train"]
    test  = df[df["split"] == "test"]

    X_train  = train[feat_cols].values
    X_test   = test[feat_cols].values
    yt_train = train["y_threat"].values
    yt_test  = test["y_threat"].values
    ya_train = train["y_attack"].values
    ya_test  = test["y_attack"].values

    log.info("  Train: %s rows | Test: %s rows | Features: %d",
             f"{len(X_train):,}", f"{len(X_test):,}", len(feat_cols))
    return X_train, X_test, yt_train, yt_test, ya_train, ya_test


# ── Cross-validation helper ───────────────────────────────────────────────────
def run_cv(model, X: np.ndarray, y: np.ndarray, scoring: str,
           cv_folds: int, random_state: int, label: str) -> None:
    log.info("  Running %d-fold CV (%s) …", cv_folds, scoring)
    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
    scores = cross_val_score(model, X, y, cv=cv, scoring=scoring, n_jobs=-1)
    log.info("  %s CV %s: %.4f ± %.4f  (min=%.4f  max=%.4f)",
             label, scoring, scores.mean(), scores.std(), scores.min(), scores.max())


def _print_confusion_matrix(cm: np.ndarray, names: list) -> None:
    header = "  Actual \\ Pred  " + "  ".join(f"{n:>8}" for n in names)
    log.info(header)
    log.info("  %s", "-" * (len(header) - 2))
    for i, row in enumerate(cm):
        log.info("  %-15s %s", names[i], "  ".join(f"{v:>8,}" for v in row))


# ── MODEL 1: XGBoost Threat Detector ─────────────────────────────────────────
def train_threat_model(X_train, X_test, y_train, y_test,
                       cv_folds, random_state, skip_cv) -> XGBClassifier:
    log.info("─" * 60)
    log.info("Training MODEL 1 — Threat Detector (XGBoost binary) …")
    t0 = time.perf_counter()

    neg, pos = (y_train == 0).sum(), (y_train == 1).sum()
    spw = neg / pos if pos > 0 else 1.0

    model = XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8,
        scale_pos_weight=spw,
        eval_metric="logloss", early_stopping_rounds=15,
        random_state=random_state, n_jobs=-1, verbosity=0,
    )
    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)
    log.info("  Done in %.1fs | Best iter: %d | SPW: %.2f",
             time.perf_counter() - t0, model.best_iteration, spw)

    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    auc     = roc_auc_score(y_test, y_proba)
    log.info("\n  ROC-AUC: %.4f\n%s", auc,
             classification_report(y_test, y_pred, target_names=["normal","attack"], digits=4))
    _print_confusion_matrix(confusion_matrix(y_test, y_pred), ["normal","attack"])

    if not skip_cv and cv_folds >= 2:
        cv_model = XGBClassifier(
            n_estimators=model.best_iteration or 200, max_depth=6,
            learning_rate=0.1, subsample=0.8, colsample_bytree=0.8,
            scale_pos_weight=spw, eval_metric="logloss",
            random_state=random_state, n_jobs=-1, verbosity=0,
        )
        run_cv(cv_model, np.vstack([X_train, X_test]), np.hstack([y_train, y_test]),
               "roc_auc", cv_folds, random_state, "Threat")
    return model


# ── MODEL 2: Random Forest Attack Classifier ──────────────────────────────────
def train_attack_type_model(X_train, X_test, y_train, y_test,
                             cv_folds, random_state, skip_cv) -> RandomForestClassifier:
    log.info("─" * 60)
    log.info("Training MODEL 2 — Attack Type Classifier (Random Forest multiclass) …")
    t0 = time.perf_counter()

    model = RandomForestClassifier(
        n_estimators=200, max_depth=25, min_samples_leaf=2,
        class_weight="balanced", random_state=random_state, n_jobs=-1,
    )
    model.fit(X_train, y_train)
    log.info("  Done in %.1fs", time.perf_counter() - t0)

    target_names = [CATEGORY_NAMES[i] for i in range(len(CATEGORY_NAMES))]
    y_pred = model.predict(X_test)
    log.info("\n%s", classification_report(y_test, y_pred, target_names=target_names, digits=4))
    _print_confusion_matrix(confusion_matrix(y_test, y_pred), target_names)

    # Feature importance
    feat_names = [f"feat_{i}" for i in range(X_train.shape[1])]
    importances = pd.Series(model.feature_importances_, index=feat_names).nlargest(10)
    log.info("\n  Top-10 Feature Importances:")
    for feat, score in importances.items():
        log.info("    %-30s %.4f  %s", feat, score, "█" * int(score * 50))

    if not skip_cv and cv_folds >= 2:
        run_cv(
            RandomForestClassifier(n_estimators=200, max_depth=25,
                                   min_samples_leaf=2, class_weight="balanced",
                                   random_state=random_state, n_jobs=-1),
            np.vstack([X_train, X_test]), np.hstack([y_train, y_test]),
            "f1_macro", cv_folds, random_state, "AttackType",
        )
    return model


# ── MODEL 3: Isolation Forest FP Detector ────────────────────────────────────
def train_fp_model(X_train, random_state) -> IsolationForest:
    log.info("─" * 60)
    log.info("Training MODEL 3 — FP Anomaly Detector (Isolation Forest) …")
    t0 = time.perf_counter()

    model = IsolationForest(
        n_estimators=150, max_samples="auto",
        contamination=0.05,   # ~5% expected anomalies
        random_state=random_state, n_jobs=-1,
    )
    model.fit(X_train)
    log.info("  Done in %.1fs", time.perf_counter() - t0)
    return model


# ── MODEL 4: Logistic Regression FP Classifier ───────────────────────────────
def train_fp_classifier(X_train, X_test, y_train, y_test, random_state) -> LogisticRegression:
    log.info("─" * 60)
    log.info("Training MODEL 4 — FP Classifier (Logistic Regression binary) …")
    t0 = time.perf_counter()

    model = LogisticRegression(
        max_iter=1000, class_weight="balanced",
        random_state=random_state, n_jobs=-1,
    )
    model.fit(X_train, y_train)
    log.info("  Done in %.1fs", time.perf_counter() - t0)

    y_pred = model.predict(X_test)
    auc = roc_auc_score(y_test, model.predict_proba(X_test)[:, 1])
    log.info("\n  ROC-AUC: %.4f\n%s", auc,
             classification_report(y_test, y_pred, target_names=["normal","attack"], digits=4))
    return model


def main() -> None:
    print("=" * 60)
    print("  STEP 03 — TRAIN MODELS")
    print("=" * 60)

    setup_dirs()
    args = parse_args()

    X_train, X_test, yt_train, yt_test, ya_train, ya_test = load_features(args.features)

    # Train all 4 models
    threat_model  = train_threat_model(X_train, X_test, yt_train, yt_test,
                                       args.cv_folds, args.random_state, args.skip_cv)
    attack_model  = train_attack_type_model(X_train, X_test, ya_train, ya_test,
                                            args.cv_folds, args.random_state, args.skip_cv)
    fp_model      = train_fp_model(X_train, args.random_state)
    fp_classifier = train_fp_classifier(X_train, X_test, yt_train, yt_test, args.random_state)

    # Save all to candidate/
    log.info("─" * 60)
    log.info("Saving candidate models …")
    save_model(threat_model,  "threat_model.pkl",      "candidate")
    save_model(attack_model,  "attack_type_model.pkl", "candidate")
    save_model(fp_model,      "fp_model.pkl",           "candidate")
    save_model(fp_classifier, "fp_classifier.pkl",      "candidate")

    log.info("✅  Step 03 complete.\n")


if __name__ == "__main__":
    main()
