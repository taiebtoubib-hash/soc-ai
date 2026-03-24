# SOC AI Training Pipeline

Machine Learning Operations (MLOps) pipeline for the SOC AI system.
This repository handles the end-to-end training, evaluation, and promotion
of models used by the `soc-ai-agents` repository to detect and classify network threats.

## 🔗 Repository Split & Linkage

The SOC AI system is split into two specialized repositories:
1. **`soc-ai-training`** (This repo): MLOps pipeline (data prep, training, evaluation, promotion).
2. **`soc-ai-agents`**: Software engineering pipeline (Suricata/Wazuh ingestion, Agent orchestration, SOAR responses).

**How they are linked:**
In a local environment, place both repositories in the same parent directory. The `soc-ai-agents` environment is configured to read `.pkl` models directly from this repository's `ml_models/production/` folder.
Whenever this pipeline promotes a new model, the live agents automatically hot-reload the updated intelligence without any manual copying.

## 🧠 Models Trained

| Model | Algorithm | Purpose |
|---|---|---|
| `threat_model` | Random Forest | Binary classifier (Benign vs Malicious) |
| `attack_type_model` | Random Forest | Multi-class categorizer (DoS, Probe, U2R, R2L) |
| `anomaly_model` | Isolation Forest | Zero-day / Unknown behavior detection |
| `fp_model` / `fp_classifier` | Scikit-Learn | False positive/negative tuning filter |

## ⚙️ MLOps Pipeline Steps

The pipeline is fully automated and broken down into 6 modular steps located in `training/`:

1. **`01_collect.py`**: Fetches raw CSV datasets into `datasets/raw/`.
2. **`02_prepare.py`**: Cleans data, applies `.pkl` Encoders/Preprocessors, outputs to `datasets/processed/`.
3. **`03_train.py`**: Trains the core Threat, Attack, and Anomaly models. Saves them to `ml_models/candidate/`.
4. **`04_evaluate.py`**: Runs scoring metrics (F1, Precision, Recall) on candidates vs current production models.
5. **`05_promote.py`**: Promotes candidates to `ml_models/production/` if metrics pass thresholds. Archives old models to `ml_models/versions/`.
6. **`06_monitor.py`**: Evaluates data drift and retraining requirements based on `datasets/feedback/`.

## 🚀 Quick Start

### 1. Requirements
Ensure you use **Python 3.11+**.
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install scikit-learn xgboost pandas numpy joblib loguru
```

### 2. Run the Full Pipeline

**Windows (PowerShell):**
```powershell
.\run_pipeline.ps1
```

**Manual Execution:**
```bash
python training/01_collect.py
python training/02_prepare.py
python training/03_train.py --skip-cv
python training/04_evaluate.py
python training/05_promote.py --force
```

## 📁 Directory Structure
```
soc-ai-training/
├── training/
│   ├── datasets/
│   │   ├── raw/           # Ignored in git
│   │   ├── processed/     # Ignored in git
│   │   └── feedback/      # Ignored in git
│   ├── 01_collect.py
│   ├── 02_prepare.py
│   ├── 03_train.py
│   ├── ...
├── ml_models/
│   ├── production/        # Read by soc-ai-agents
│   ├── candidate/
│   └── versions/
├── run_pipeline.ps1       # Automated wrapper script
├── pipeline_output.log    # Pipeline run logs
├── README.md
└── .gitignore             # Ignores .pkl and large CSVs
```
