# 🧠 SOC AI Training & MLOps Pipeline

Machine Learning Operations (MLOps) pipeline for the SOC AI system. This repository handles the end-to-end training, evaluation, drift monitoring, and promotion of models used by the `soc-ai-agents` pipeline.

---

## 🔗 Repository Split & Linkage

The SOC AI system is structured into two companion repositories:
1. **`soc-ai-training`** (This repo): MLOps pipeline (data preparation, training, evaluation, model promotion, drift checks).
2. **`soc-ai-agents`**: Software engineering pipeline (ingesting raw feeds, agent event backbone, playbook mitigation, frontend).

### How They Share Intelligence
* **Local Mode:** Live agents are configured to import pickle (`.pkl`) models directly from this repository's `ml_models/production/` folder. When a model is promoted here, agents hot-reload the updated models instantly.
* **Docker/Production Mode:** Prior to building or updating the Docker stack, the promoted models must be copied over to the `soc-ai-agents/ml_models/` directory so they are successfully mounted into the containers:
  ```bash
  cp ./ml_models/production/*.pkl ../soc-ai-agents/ml_models/
  ```

---

## 🧠 Models Trained

| Model Artifact | Algorithm | Purpose | Output Location |
|---|---|---|---|
| `threat_model.pkl` | Random Forest | Binary classifier (Benign vs Malicious threat probability) | `ml_models/production/` |
| `attack_type_model.pkl` | Random Forest | Multi-class categorizer (DoS, Probe, U2R, R2L) | `ml_models/production/` |
| `anomaly_model.pkl` | Isolation Forest | Zero-day anomaly detection | `ml_models/production/` |
| `fp_model.pkl` / `fp_classifier.pkl` | Scikit-Learn | Tuned false positive filter | `ml_models/production/` |
| `preprocessor.pkl` / `encoders.pkl` | scikit-learn Pipeline | Cleans inputs and maps raw category features into 41-feature vectors | `ml_models/production/` |

---

## ⚙️ Pipeline Lifecycle & Scripts

The MLOps lifecycle is divided into modular steps located under `training/`:

```text
  [ Analyst Feedback / CLI ] ──► (datasets/feedback/)
                                       │
                                       ▼
  Step 01: Ingest Data ────────► `01_collect.py`       (Fetches raw CSVs & merges feedback)
                                       │
                                       ▼
  Step 02: Prepare Data ───────► `02_prepare.py`       (Applies preprocessing & encoders)
                                       │
                                       ▼
  Step 03: Train Candidates ───► `03_train.py`         (Trains threat, attack, anomaly models)
                                       │
                                       ▼
  Step 04: Evaluate ───────────► `04_evaluate.py`      (Compares candidates vs production)
                                       │
                                       ▼
  Step 05: Promote Model ──────► `05_promote.py`       (Moves candidate to prod if F1 passes)
                                       │
                                       ▼
  Step 06: Drift Monitor ──────► `06_monitor.py`       (Checks error rates, triggers retrain)
```

### 1. `01_collect.py` (Data Collection)
Fetches raw data templates into `training/datasets/raw/` and merges analyst feedback collected from the live dashboard or CLI.

### 2. `02_prepare.py` (Data Preparation)
Fits/applies encoders, normalizes columns, and outputs clean feature vectors to `training/datasets/processed/`.

### 3. `03_train.py` (Model Training)
Fits candidate Random Forest and Isolation Forest models using the processed vectors. Saves candidates to `ml_models/candidate/`.

### 4. `04_evaluate.py` (Evaluation)
Compares candidate model metrics (Macro F1, Precision, Recall) against the active production models and saves scores to `evaluation_report.json`.

### 5. `05_promote.py` (Promotion)
Safely moves candidate models to `ml_models/production/` if they exceed the production model metrics. Replaced production models are archived in `ml_models/versions/`.

### 6. `06_monitor.py` (Production Drift Monitor)
Scans active analyst feedback over the last N days. Computes False Positive and False Negative rates, and exits with code `1` if thresholds are breached, indicating retraining is required.

---

## ✍️ Analyst Feedback Loop
 
The system operates in a closed loop. Live analyst feedback submitted from the React dashboard is pushed to the `soc.feedback` topic in Kafka. 

To bridge this feedback back into the training dataset:
1. **Background Consumer**: Run the background consumer script to listen to the Kafka topic and write feedback to the monthly CSVs:
   ```bash
   python training/consume_feedback.py
   ```
2. **Manual CLI**: You can also record analyst verdicts manually via the CLI tool:
 
```bash
# Run interactive feedback collection CLI
python training/collect_feedback.py
 
# Run direct input command
python training/collect_feedback.py \
    --alert-id "alert-98247192" \
    --label fp \
    --confidence 0.90 \
    --notes "Normal backup traffic flagged as Exfiltration"
```
Verdicts are saved as monthly CSV files in `training/datasets/feedback/feedback_YYYY-MM.csv` and are automatically incorporated into the next training run.

---

## 🚀 Quick Start

### 1. Installation
Setup your virtual environment and install dependencies:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Automated Pipeline Execution
To execute the entire MLOps sequence from collection to promotion automatically:

* **Windows PowerShell:**
  ```powershell
  .\run_pipeline.ps1
  ```
* **Python Master Wrapper:**
  ```bash
  python training/pipeline.py
  ```

### 3. Manual Step-by-Step Training
```bash
# Ingest and train
python training/01_collect.py
python training/02_prepare.py
python training/03_train.py --skip-cv
python training/04_evaluate.py
python training/05_promote.py --force
```
Check `pipeline_output.log` for logs and outcomes of the run.

