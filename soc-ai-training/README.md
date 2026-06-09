# 🧠 SOC AI Training & MLOps Pipeline

Machine Learning Operations (MLOps) pipeline for the SOC AI system. This repository handles end-to-end training, evaluation, drift monitoring, and promotion of the models used by the `soc-ai-agents` pipeline.

---

## 🔗 Repository Split & Linkage

The SOC AI system is structured as two companion repositories:

1. **`soc-ai-training`** *(this repo)*: MLOps pipeline — data preparation, training, evaluation, model promotion, and drift checks.
2. **`soc-ai-agents`**: Software engineering pipeline — Kafka event backbone, agent microservices, playbook orchestration, and React dashboard.

### How They Share Intelligence

* **Local Mode:** Live agents are configured to import `.pkl` models directly from this repository's `ml_models/production/` folder. When a model is promoted here, agents hot-reload instantly without restarting.
* **Docker/Production Mode:** Prior to building or updating the Docker stack, copy the promoted models into `soc-ai-agents/ml_models/`:

  ```bash
  # Linux/macOS:
  cp ./ml_models/production/*.pkl ../soc-ai-agents/ml_models/

  # Windows (PowerShell):
  Copy-Item -Path ".\ml_models\production\*.pkl" -Destination "..\soc-ai-agents\ml_models\" -Force
  ```

---

## 🧠 Models Trained

| Artifact | Algorithm | Purpose | Output |
|---|---|---|---|
| `threat_model.pkl` | **XGBoost** (binary) | Classifies network events as *normal* (0) or *attack* (1) with calibrated probability | `ml_models/production/` |
| `attack_type_model.pkl` | **Random Forest** (multiclass) | Categorizes attacks: `normal / dos / probe / r2l / u2r` | `ml_models/production/` |
| `anomaly_model.pkl` | **Isolation Forest** | Zero-day anomaly detection (used by `04b_fp_detector`) | `ml_models/production/` |
| `fp_model.pkl` | **Isolation Forest** | False-positive pre-filter — flags anomalous events (score = -1) | `ml_models/production/` |
| `fp_classifier.pkl` | **Logistic Regression** | FP probability scorer — second-tier check for events that pass IsolationForest | `ml_models/production/` |
| `preprocessor.pkl` | **StandardScaler** | Normalizes the 41-feature input vector | `ml_models/production/` |
| `encoders.pkl` | **LabelEncoder × 3** | Encodes categorical columns: `protocol_type`, `service`, `flag` | `ml_models/production/` |

### NSL-KDD Dataset

All models are trained on the **NSL-KDD** dataset. The 41-feature vector includes:

- Network statistics: `duration`, `src_bytes`, `dst_bytes`, `count`, `srv_count`, …
- Connection flags: `protocol_type`, `service`, `flag`, `land`, `wrong_fragment`, …
- Host-level rates: `dst_host_count`, `dst_host_same_srv_rate`, `dst_host_serror_rate`, …

> [!NOTE]
> Training uses stratified 80/20 train-test splits with optional 5-fold cross-validation. XGBoost uses `scale_pos_weight` to handle class imbalance automatically.

---

## ⚙️ Pipeline Lifecycle & Scripts

The MLOps lifecycle is modular. All scripts live under `training/`:

```text
  [ Analyst Feedback / CLI ] ──► (datasets/feedback/)
                                       │
                                       ▼
  Step 01: Ingest Data ────────► 01_collect.py        (Fetches raw CSVs & merges feedback)
                                       │
                                       ▼
  Step 02: Prepare Data ───────► 02_prepare.py        (Applies preprocessing & encoders)
                                       │
                                       ▼
  Step 03: Train Candidates ───► 03_train.py          (Trains threat, attack, anomaly models)
                                       │
                                       ▼
  Step 04: Evaluate ───────────► 04_evaluate.py       (Compares candidates vs production)
                                       │
                                       ▼
  Step 05: Promote Model ──────► 05_promote.py        (Moves candidate to prod if F1 passes)
                                       │
                                       ▼
  Step 06: Drift Monitor ──────► 06_monitor.py        (Checks error rates, exits 1 if retraining needed)
```

### Script Reference

#### `01_collect.py` — Data Collection
Fetches raw NSL-KDD CSV templates into `training/datasets/raw/` and merges analyst feedback from `training/datasets/feedback/`.

#### `02_prepare.py` — Data Preparation
Fits and applies `LabelEncoder` for categorical columns, `StandardScaler` for normalization, and outputs clean 41-feature vectors to `training/datasets/processed/`.

#### `03_train.py` — Model Training
Trains candidate Random Forest and Isolation Forest models using the processed dataset. Saves candidates to `ml_models/candidate/`.

#### `04_evaluate.py` — Evaluation
Compares candidate model metrics (Macro F1, Precision, Recall) against active production models. Saves scores to `evaluation_report.json`.

#### `05_promote.py` — Promotion
Moves candidates to `ml_models/production/` if they exceed production baseline metrics. Replaced production models are archived in `ml_models/versions/`.

#### `06_monitor.py` — Production Drift Monitor
Scans active analyst feedback over the last N days. Computes False Positive and False Negative rates and exits with code `1` if thresholds are breached, signalling that retraining is required.

#### `train_threat.py` — Standalone High-Performance Trainer
A dedicated, self-contained script that trains the XGBoost threat detector and Random Forest attack-type classifier end-to-end directly on the NSL-KDD dataset. Includes pre-flight validation, cross-validation, confusion matrices, feature importance logging, and a smoke test. Use this for direct/rapid retraining.

```bash
python training/train_threat.py
# With options:
python training/train_threat.py --dataset path/to/kdd_train.csv --models-dir ml_models --test-size 0.2 --cv-folds 5
```

---

## ✍️ Analyst Feedback Loop

The system operates in a closed loop. Analyst verdicts submitted from the React dashboard are published to the `soc.feedback` Kafka topic by the API agent.

To bridge feedback back into the training dataset:

**1. Background Consumer** — listens to `soc.feedback` and writes monthly feedback CSVs:

```bash
python training/consume_feedback.py
```

**2. Manual CLI** — record verdicts directly without Kafka:

```bash
# Interactive mode
python training/collect_feedback.py

# Direct command
python training/collect_feedback.py \
    --alert-id "alert-98247192" \
    --label fp \
    --confidence 0.90 \
    --notes "Normal backup traffic flagged as Exfiltration"
```

Verdicts are stored as `training/datasets/feedback/feedback_YYYY-MM.csv` and are merged automatically in the next `01_collect.py` run.

---

## 🚀 Quick Start

### 1. Installation

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Automated Pipeline Execution

Run the entire MLOps sequence from collection to promotion:

```powershell
# Windows PowerShell:
.\run_pipeline.ps1
```

```bash
# Python master wrapper:
python training/pipeline.py
```

### 3. Manual Step-by-Step

```bash
python training/01_collect.py
python training/02_prepare.py
python training/03_train.py --skip-cv
python training/04_evaluate.py
python training/05_promote.py --force
```

Check `pipeline_output.log` for a full run log.

### 4. Direct Model Training (standalone)

For fast, full retraining of the threat and attack-type models on NSL-KDD:

```bash
python training/train_threat.py
```

---

## 📁 Directory Layout

```text
soc-ai-training/
├── training/
│   ├── 01_collect.py           # Data ingestion & feedback merge
│   ├── 02_prepare.py           # Feature engineering & encoding
│   ├── 03_train.py             # Candidate model training
│   ├── 04_evaluate.py          # Candidate vs production comparison
│   ├── 05_promote.py           # Model promotion gate
│   ├── 06_monitor.py           # Production drift monitor
│   ├── train_threat.py         # Standalone XGBoost + RF trainer
│   ├── pipeline.py             # Master wrapper (runs all steps)
│   ├── training_utils.py       # Shared utilities
│   ├── collect_feedback.py     # CLI feedback recorder
│   ├── consume_feedback.py     # Kafka feedback consumer
│   └── datasets/
│       ├── raw/                # Raw NSL-KDD CSV files
│       ├── processed/          # Preprocessed feature vectors
│       └── feedback/           # Monthly analyst verdict CSVs
├── ml_models/
│   ├── candidate/              # Freshly trained, pending evaluation
│   ├── production/             # Active models loaded by agents
│   └── versions/               # Archived prior production models
├── run_pipeline.ps1            # PowerShell automation script
└── pipeline_output.log         # Latest pipeline run log
```
