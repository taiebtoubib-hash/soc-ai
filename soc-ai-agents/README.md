# SOC AI Agents

AI-powered Security Operations Center automation system.
Multi-agent pipeline that detects, analyzes, and responds
to security threats in real time.

## Architecture

```
Collector (01)
    ↓ raw_alerts_queue
Analysis (02)          ← IP reputation, feature engineering
    ↓ enriched_alerts_queue
Detection (03)         ← Rule-based detection
    ↓ detection_results_queue
ML Classifier (04)     ← Threat scoring (Random Forest + Isolation Forest)
    ↓ classification_results_queue
FP Detector (04b)      ← False positive filtering
    ↓ true_positive_queue
Orchestrator (05)      ← Playbook selection
    ↓ orchestration_queue
Response (06)          ← Block IP, notify, isolate host
    ↓ incident_report_queue
```

## Agents

| Agent | Role |
|---|---|
| `01_collector` | Ingests Wazuh + Suricata alerts, normalizes to `NormalizedAlert` |
| `02_analysis` | IP reputation (AbuseIPDB), 41-feature ML vector |
| `03_detection` | Rule-based detection (port scan, brute force, C2) |
| `04_ml_classifier` | Random Forest threat scoring + Isolation Forest anomaly |
| `04b_fp_detector` | False positive filtering before response |
| `05_orchestrator` | Selects YAML playbook based on attack type |
| `06_response` | Executes block/isolate/notify actions |

## Tech Stack
- Python 3.11
- XGBoost + scikit-learn (ML)
- Docker + docker-compose
- Wazuh (SIEM/EDR)
- Suricata (IDS)
- Shuffle (SOAR)

## Quick Start

### Prerequisites
- Python 3.11+
- Docker Desktop
- soc-ai-training repo (for ML models)

### Setup
```bash
# Clone both repos in same parent folder
git clone <soc-ai-agents>
git clone <soc-ai-training>

# Setup environment
cd soc-ai-agents
cp .env.example .env
# Fill in your credentials in .env

# Install dependencies
pip install -r requirements.txt

# Run simulator (development mode)
python scripts/simulate_alerts.py
```

### Run with Docker
```bash
docker-compose up --build
```

## ML Models
Models are stored in soc-ai-training repository.
See soc-ai-training/README.md for training instructions.

Models used:
- `threat_model.pkl` — Random Forest binary classifier
- `attack_type_model.pkl` — Multi-class attack categorizer
- `anomaly_model.pkl` — Isolation Forest for zero-day detection
- `fp_model.pkl` / `fp_classifier.pkl` — False positive filter

## Related Repository
- soc-ai-training: ML training pipeline

## Project Structure

```
soc-ai-agents/
├── agents/
│   ├── 01_collector/
│   ├── 02_analysis/
│   ├── 03_detection/
│   ├── 04_ml_classifier/
│   ├── 04b_fp_detector/
│   ├── 05_orchestrator/
│   └── 06_response/
├── shared/          # Models, config, logger, queue bus
├── playbooks/       # YAML response playbooks
├── scripts/         # simulate_alerts.py, etc.
├── tests/
├── ml_models/
├── logs/
├── main.py          # Starts all agents as threads
├── docker-compose.yml
├── docker-compose.dev.yml
├── requirements.txt
├── .env.example
└── .gitignore
```

## Running Tests

```bash
# Agent 02 Analysis smoke test
python tests/test_analysis.py

# Collector smoke test
python tests/test_collector.py
```
