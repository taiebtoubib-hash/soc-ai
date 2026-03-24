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

## Quick Start

```bash
# 1. Clone and setup
git clone https://github.com/YOUR_USERNAME/soc-ai-agents
cd soc-ai-agents
cp .env.example .env

# 2. Install dependencies
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r agents/01_collector/requirements.txt

# 3. Run in simulation mode (no real Wazuh/Suricata needed)
python main.py
```

## Configuration

Copy `.env.example` to `.env` and fill in your credentials.
See each key's comment for details.

**Required for production:**
- `WAZUH_HOST`, `WAZUH_USER`, `WAZUH_PASSWORD`
- `ABUSEIPDB_KEY` — get free key at abuseipdb.com
- `SLACK_WEBHOOK_URL` — for alert notifications

**Development mode** (`COLLECTOR_MODE=simulate`):
All keys can be left empty. Fake alerts are generated locally.

## ML Models

Pre-trained models live in `../soc-ai-training/ml_models/production/`.
See the `soc-ai-training` repo for training scripts.

Models used:
- `threat_model.pkl` — Random Forest binary classifier
- `attack_type_model.pkl` — Multi-class attack categorizer
- `anomaly_model.pkl` — Isolation Forest for zero-day detection
- `fp_model.pkl` / `fp_classifier.pkl` — False positive filter

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
├── main.py          # Starts all agents as threads
├── .env.example
└── docker-compose.yml
```

## Running Tests

```bash
# Agent 02 Analysis smoke test
python tests/test_analysis.py

# Collector smoke test
python tests/test_collector.py
```

## Docker

```bash
# Full stack
docker-compose up

# Development (no external services)
docker-compose -f docker-compose.dev.yml up
```
