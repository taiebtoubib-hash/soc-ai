# 🤖 SOC AI Agents

AI-powered Security Operations Center (SOC) automation system. This repository contains an event-driven, multi-agent pipeline that ingests, enriches, detects, classifies, and responds to network security threats in real time.

---

## 🏛️ System Architecture

The pipeline is built on an **Apache Kafka** event backbone. Each agent is a standalone microservice that consumes from an upstream topic, processes the message, and publishes to the next.

```text
                            [ Wazuh / Suricata / Simulator ]
                                           │
                                           ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 01_collector      Ingests & normalizes raw logs → NormalizedAlert     │
       └──────────────────────────────────┬────────────────────────────────────┘
                                          │  Topic: soc.raw
                                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 02_analysis       AbuseIPDB IP reputation + 41-feature vector         │
       └──────────────────────────────────┬────────────────────────────────────┘
                                          │  Topic: soc.enriched
                                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 03_detection      Rule chain (Port Scan / Brute Force / C2 / Exfil)  │
       │                   + optional Ollama/Mistral LLM advisory summary      │
       └──────────────────────────────────┬────────────────────────────────────┘
                                          │  Topic: soc.analyzed
                                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 04_ml_classifier  XGBoost threat scoring + RF attack-type classifier  │
       └──────────────────────────────────┬────────────────────────────────────┘
                                          │  Topic: soc.classified
                                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 04b_fp_detector   IsolationForest + LogisticRegression FP filter      │
       └──────────┬───────────────────────────────────────┬────────────────────┘
                  │ Topic: soc.true_positives             │ Topic: soc.false_positives
                  ▼                                       ▼
       ┌──────────────────────────────────┐    ┌──────────────────────────────┐
       │ 05_orchestrator                  │    │  [ Logged for MLOps retraining│
       │  YAML playbook selection         │    │    via drift monitor ]        │
       │  + optional LLM incident         │    └──────────────────────────────┘
       │    narrative (Ollama)            │
       └──────────────────┬───────────────┘
                          │  Topic: soc.orchestrated
                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 06_response       Slack webhooks, Shuffle SOAR, host isolation, logs  │
       └──────────────────────────────────┬────────────────────────────────────┘
                                          │  Topic: soc.frontend
                                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 07_api (FastAPI)  SSE stream to dashboard + analyst feedback POST     │
       └──────────────────────────────────┬────────────────────────────────────┘
                                          │  Server-Sent Events (SSE)
                                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ soc-dashboard     React + Vite: alert feed, metrics, verdict buttons  │
       └───────────────────────────────────────────────────────────────────────┘
```

---

## 👥 Agents & Services Reference

| Agent / Service | Role | Input Topic | Output Topic |
|---|---|---|---|
| **`01_collector`** | Ingests raw Wazuh/Suricata logs or simulated alerts and normalizes them into `NormalizedAlert` objects. | None (file / API / simulator) | `soc.raw` |
| **`02_analysis`** | Queries AbuseIPDB for IP reputation and assembles the 41-feature ML input vector. | `soc.raw` | `soc.enriched` |
| **`03_detection`** | Evaluates a rule chain (Port Scan, Brute Force, C2, Data Exfiltration) and optionally adds an Ollama LLM advisory summary. | `soc.enriched` | `soc.analyzed` |
| **`04_ml_classifier`** | Scores threats via XGBoost (binary) and categorizes attack types via Random Forest (multiclass). | `soc.analyzed` | `soc.classified` |
| **`04b_fp_detector`** | Three-tier FP filter: fast-path for benigns, high-confidence pass-through, then IsolationForest + LogisticRegression scoring. | `soc.classified` | `soc.true_positives` or `soc.false_positives` |
| **`05_orchestrator`** | Selects the matching YAML playbook (by `rule_name`, with `attack_type` fallback) and optionally adds an Ollama LLM incident narrative. | `soc.true_positives` | `soc.orchestrated` |
| **`06_response`** | Executes playbook actions: Slack webhooks, Shuffle SOAR registration, host isolation, and structured log entries. | `soc.orchestrated` | `soc.frontend` |
| **`07_api` (FastAPI)** | Replays historical incidents on startup, streams live events via SSE, and accepts analyst feedback POSTs. | `soc.frontend` | `soc.feedback` |
| **`soc-dashboard`** | React + Vite single-page application providing an alert feed, incident metrics, geo data, and override buttons. | — | API endpoints |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Runtime** | Python 3.11 |
| **Event backbone** | Apache Kafka + Zookeeper (Confluent 7.5.3) |
| **ML — Threat scoring** | XGBoost (binary classifier) |
| **ML — Attack type** | Random Forest (multiclass: normal / dos / probe / r2l / u2r) |
| **ML — FP filtering** | IsolationForest + LogisticRegression |
| **Vector DB** | ChromaDB (alert history embedding) |
| **LLM Engine** | Ollama running `tinyllama` (local/air-gapped advisory) |
| **API** | FastAPI + SSE |
| **Frontend** | React + Vite |
| **SOAR / Notifications** | Shuffle SOAR & Slack Webhooks |
| **Orchestration** | Docker Compose |

---

## 🔑 Environment Variables

Copy `.env.example` to `.env` and configure as needed. Key toggles:

| Variable | Default | Description |
|---|---|---|
| `USE_KAFKA` | `false` | Route agents through Kafka (`true`) or run as in-memory threads (`false`) |
| `LLM_ENABLED` | `false` | Enable Ollama LLM enrichment in detection & orchestrator agents |
| `OLLAMA_MODEL` | `mistral:7b` | Ollama model name |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama endpoint |
| `ABUSEIPDB_KEY` | — | API key for IP reputation lookups |
| `SLACK_WEBHOOK_URL` | — | Slack incoming webhook for alerts |
| `SHUFFLE_WEBHOOK_URL` | — | Shuffle SOAR webhook |
| `SHUFFLE_ENABLED` | `false` | Enable Shuffle SOAR actions |
| `FP_SCORE_THRESHOLD` | `0.60` | FP probability above which an alert is routed to `soc.false_positives` |
| `ML_THREAT_THRESHOLD` | `0.75` | Score above which a malicious label skips the FP models entirely |
| `COLLECTOR_MODE` | `simulate` | `simulate`, `wazuh`, or `suricata` |

---

## 🚀 Getting Started

### Prerequisites

* Python 3.11+
* Docker Desktop (for containerized setup)
* Trained ML models from the `soc-ai-training` pipeline

### Model Provisioning

Copy the trained `.pkl` artifacts from the `soc-ai-training` production directory before starting:

```bash
# Linux/macOS:
cp ../soc-ai-training/ml_models/production/*.pkl ./ml_models/

# Windows (PowerShell):
Copy-Item -Path "..\soc-ai-training\ml_models\production\*.pkl" -Destination ".\ml_models\" -Force
```

> [!WARNING]
> **Windows Git line endings:** Set `git config core.autocrlf input` to prevent CRLF corruption of `.pkl` binary files. The `.gitattributes` file enforces binary tracking.

Required model artifacts (loaded via `joblib.load()` inside the agents):

| File | Purpose |
|---|---|
| `threat_model.pkl` | XGBoost binary threat scorer |
| `attack_type_model.pkl` | Random Forest attack categorizer |
| `preprocessor.pkl` | StandardScaler for feature normalization |
| `encoders.pkl` | LabelEncoders for categorical columns |
| `fp_model.pkl` | IsolationForest false-positive pre-filter |
| `fp_classifier.pkl` | LogisticRegression FP probability scorer |

---

## 🏃 Running the Application

### Option 1: Docker Compose (Recommended)

Builds and orchestrates the complete topology including Zookeeper, Kafka, Kafka UI, ChromaDB, Ollama (pulls `tinyllama`), all seven agents, the FastAPI API, and the React dashboard.

```bash
docker-compose up --build
```

### Option 2: Local Thread Runner (Development)

Runs agents as in-memory threads — no Kafka or Docker needed.

```bash
# Install dependencies
pip install -r requirements.txt

# Terminal 1: start the alert simulator
python scripts/simulate_alerts.py

# Terminal 2: run the local agent manager
ENV=development USE_KAFKA=false python main.py
```

---

## 🖥️ Services & Endpoints

When running in Docker Compose:

| Service | URL |
|---|---|
| **Analyst Dashboard** | [http://localhost:3000](http://localhost:3000) |
| **FastAPI + Swagger** | [http://localhost:8001/docs](http://localhost:8001/docs) |
| **GET /stream** | [http://localhost:8001/stream](http://localhost:8001/stream) — Live SSE feed |
| **GET /api/incidents** | [http://localhost:8001/api/incidents](http://localhost:8001/api/incidents) — Historical incidents |
| **POST /api/feedback** | `http://localhost:8001/api/feedback` — Submit analyst verdict |
| **GET /api/health** | [http://localhost:8001/api/health](http://localhost:8001/api/health) — Health check + Kafka status |
| **Kafka UI** | [http://localhost:8080](http://localhost:8080) |
| **ChromaDB** | [http://localhost:8000](http://localhost:8000) |
| **Ollama** | [http://localhost:11434](http://localhost:11434) |
| **Kafka Broker** | `localhost:29092` |

---

## 📂 YAML Playbooks

The orchestrator loads all playbooks at startup from `playbooks/`. Selection priority:

1. **`rule_name`** exact match via `RULE_TO_PLAYBOOK` mapping
2. **`attack_type`** fallback — scans all playbooks for a matching field
3. If no match → default `log` action (pipeline never stalls)

| File | Rule / Attack Type |
|---|---|
| `port_scan.yaml` | `PORT_SCAN` |
| `brute_force.yaml` | `BRUTE_FORCE` |
| `c2_communication.yaml` | `C2_COMMUNICATION` |
| `data_exfiltration.yaml` | `DATA_EXFILTRATION` |

---

## 🧪 Testing

Run smoke tests for individual agents:

```bash
# Agent 02 Analysis smoke test
python tests/test_analysis.py

# Collector alert generation test
python tests/test_collector.py

# LLM connectivity check
python tests/test_llm_integration.py
```

---

## 🔄 Analyst Feedback Loop

Analyst verdicts submitted from the React dashboard are published to the `soc.feedback` Kafka topic. The `07_api` agent relays these to the training pipeline, where `consume_feedback.py` writes them as monthly CSV files. They are incorporated automatically in the next retraining run.
