"""
training/training_utils.py
--------------------------
Shared helpers used by every pipeline step:
  - Directory resolution & creation
  - Model save / load wrappers
  - Timestamped production backups
  - Structured logging factory
"""

import glob
import logging
import os
import re
import shutil
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

import joblib


# ─────────────────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR     = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODELS_ROOT  = os.path.join(BASE_DIR, "ml_models")
DATASETS_DIR = os.path.join(BASE_DIR, "training", "datasets")

STAGE_DIRS = {
    "production": os.path.join(MODELS_ROOT, "production"),
    "candidate":  os.path.join(MODELS_ROOT, "candidate"),
    "versions":   os.path.join(MODELS_ROOT, "versions"),
}

DATASET_PATHS = {
    "raw":      os.path.join(DATASETS_DIR, "raw",       "kdd_train.csv"),
    "merged":   os.path.join(DATASETS_DIR, "raw",       "merged.csv"),
    "processed":os.path.join(DATASETS_DIR, "processed", "features.pkl"),
    "feedback": os.path.join(DATASETS_DIR, "feedback"),
}

EVAL_REPORT_PATH = os.path.join(STAGE_DIRS["candidate"], "evaluation_report.json")


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Return a consistently formatted logger for pipeline steps."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s — %(message)s",
                              datefmt="%H:%M:%S")
        )
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


_log = get_logger("training_utils")


# ─────────────────────────────────────────────────────────────────────────────
# DIRECTORY MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

def setup_dirs() -> None:
    """Create all required pipeline directories if they don't exist."""
    all_dirs = list(STAGE_DIRS.values()) + [
        os.path.join(DATASETS_DIR, "raw"),
        os.path.join(DATASETS_DIR, "processed"),
        DATASET_PATHS["feedback"],
    ]
    for d in all_dirs:
        os.makedirs(d, exist_ok=True)
    _log.debug("All pipeline directories verified.")


def get_stage_dir(stage: str) -> str:
    """Resolve path for 'production', 'candidate', or 'versions'."""
    if stage not in STAGE_DIRS:
        raise ValueError(f"Unknown stage '{stage}'. Must be one of {list(STAGE_DIRS)}")
    return STAGE_DIRS[stage]


def model_path(name: str, stage: str) -> str:
    """Return the full path for a model file in the given stage."""
    return os.path.join(get_stage_dir(stage), name)


# ─────────────────────────────────────────────────────────────────────────────
# MODEL I/O
# ─────────────────────────────────────────────────────────────────────────────

def save_model(obj: Any, name: str, stage: str) -> str:
    """
    Serialise *obj* to ml_models/<stage>/<name> using joblib.
    Returns the full path.
    """
    setup_dirs()
    path = model_path(name, stage)
    joblib.dump(obj, path)
    size_kb = os.path.getsize(path) / 1024
    _log.info("  Saved %-30s → %s  (%.1f KB)", name, stage, size_kb)
    return path


def load_model(name: str, stage: str) -> Any:
    """
    Load a model from ml_models/<stage>/<name>.
    Raises FileNotFoundError with a clear message if missing.
    """
    path = model_path(name, stage)
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Model not found: '{path}'\n"
            f"Have you run the previous pipeline step?"
        )
    obj = joblib.load(path)
    _log.debug("  Loaded %s from %s", name, stage)
    return obj


def production_model_exists(name: str) -> bool:
    """Return True if the named model exists in production."""
    return os.path.isfile(model_path(name, "production"))


# ─────────────────────────────────────────────────────────────────────────────
# VERSIONING  (production → versions)
# ─────────────────────────────────────────────────────────────────────────────

def backup_production(name: str) -> Optional[str]:
    """
    Copy ml_models/production/<name> → ml_models/versions/<stem>_<timestamp>.<ext>
    Returns the destination path, or None if production copy doesn't exist.
    """
    src = model_path(name, "production")
    if not os.path.isfile(src):
        _log.debug("  No production copy of '%s' to backup.", name)
        return None

    stem, ext = os.path.splitext(name)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(STAGE_DIRS["versions"], f"{stem}_{ts}{ext}")
    shutil.copy2(src, dest)
    _log.info("  Backed up %-30s → versions/%s", name, os.path.basename(dest))
    return dest


def list_versions(name: str) -> List[str]:
    """Return sorted list of versioned backups for *name* (oldest first)."""
    stem = os.path.splitext(name)[0]
    pattern = os.path.join(STAGE_DIRS["versions"], f"{stem}_*.pkl")
    return sorted(glob.glob(pattern))


def promote_candidate(name: str) -> str:
    """
    Backup production → versions, then copy candidate → production.
    Returns the new production path.
    """
    backup_production(name)
    src  = model_path(name, "candidate")
    dest = model_path(name, "production")
    shutil.copy2(src, dest)
    _log.info("  Promoted %-28s candidate → production", name)
    return dest


# ─────────────────────────────────────────────────────────────────────────────
# MISC HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def next_version_number(name: str) -> int:
    """Count existing backups to derive the next integer version number."""
    return len(list_versions(name)) + 1


def feedback_csv_path(year: int, month: int) -> str:
    """Return path for the monthly feedback CSV (creates dir if needed)."""
    setup_dirs()
    return os.path.join(DATASET_PATHS["feedback"], f"feedback_{year:04d}-{month:02d}.csv")


def all_feedback_csvs() -> List[str]:
    """Glob all feedback CSV files, sorted chronologically."""
    pattern = os.path.join(DATASET_PATHS["feedback"], "feedback_*.csv")
    return sorted(glob.glob(pattern))
