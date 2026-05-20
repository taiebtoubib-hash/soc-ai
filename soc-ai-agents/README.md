# 🤖 SOC AI Agents

AI-powered Security Operations Center (SOC) automation system. This repository contains an event-driven, multi-agent pipeline that ingests, enriches, detects, classifies, and responds to network security threats in real time.

---

## 🏛️ System Architecture

The pipeline leverages an event backbone powered by **Apache Kafka** where each agent acts as a standalone microservice processing messages in real time.

```text
                                [ Wazuh / Suricata Logs ]
                                           │
                                           ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 01_collector           Ingests & Normalizes raw logs                  │
       └──────────────────────────────────┬────────────────────────────────────┘
                                          │  Topic: `soc.raw`
                                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 02_analysis            IP reputation (AbuseIPDB) & features vector    │
       └──────────────────────────────────┬────────────────────────────────────┘
                                          │  Topic: `soc.enriched`
                                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 03_detection           Rule-based detection & Ollama LLM Advisory     │
       └──────────────────────────────────┬────────────────────────────────────┘
                                          │  Topic: `soc.analyzed`
                                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 04_ml_classifier       Random Forest threat & attack type classification│
       └──────────────────────────────────┬────────────────────────────────────┘
                                          │  Topic: `soc.classified`
                                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 04b_fp_detector        False positive filtering                       │
       └──────────┬───────────────────────────────────────┬────────────────────┘
                  │ Topic: `soc.true_positives`           │ Topic: `soc.false_positives`
                  ▼                                       ▼
       ┌──────────────────────────────────────┐  ┌─────────────────────────────┐
       │ 05_orchestrator  YAML playbooks & AI │  │ [ Logged for MLOps analysis]│
       └──────────────────┬───────────────────┘  └─────────────────────────────┘
                          │  Topic: `soc.orchestrated`
                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 06_response            Mitigates threat: Block IP, Slack, Isolate Host│
       └──────────────────────────────────┬────────────────────────────────────┘
                                          │  Topic: `soc.frontend`
                                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ 07_api (FastAPI)       Bridges Kafka SSE feed & handles feedback POST │
       └──────────────────────────────────┬────────────────────────────────────┘
                                          │  Server-Sent Events (SSE)
                                          ▼
       ┌───────────────────────────────────────────────────────────────────────┐
       │ React Dashboard        Analyst UI for monitoring and verdict submission│
       └───────────────────────────────────────────────────────────────────────┘
```

---

## 👥 Agents & Services Reference

| Agent / Service | Role / Purpose | Input Topic | Output Topic |
|---|---|---|---|
| **`01_collector`** | Ingests raw Wazuh/Suricata alerts and normalizes them into `NormalizedAlert` objects. | None (File/API) | `soc.raw` |
| **`02_analysis`** | Queries AbuseIPDB for IP reputation and prepares a 41-feature ML input vector. | `soc.raw` | `soc.enriched` |
| **`03_detection`** | Evaluates a rule chain (Port Scan, Brute Force, C2, Exfiltration) and adds Ollama/Mistral advisory summaries. | `soc.enriched` | `soc.analyzed` |
| **`04_ml_classifier`** | Classifies threats using Random Forest models, generating binary threat scores and attack types. | `soc.analyzed` | `soc.classified` |
| **`04b_fp_detector`** | Evaluates alerts using a trained ML filter to separate real attacks from false alarms. | `soc.classified` | `soc.true_positives` or `soc.false_positives` |
| ****`05_orchestrator`** | Selects YAML playbooks and queries Ollama to construct natural language incident narratives. | `soc.true_positives` | `soc.orchestrated` |
| **`06_response`** | Triggers Slack webhooks, registers Shuffle SOAR actions, isolates hosts, and logs verdicts. | `soc.orchestrated` | `soc.frontend` |
| **`07_api` (FastAPI)** | Serves SSE logs to the dashboard and pushes analyst overrides back to the MLOps pipeline. | `soc.frontend` | `soc.feedback` |
| **`soc-dashboard`** | React + Vite single-page dashboard providing alert feeds, metrics, and override buttons. | None | API endpoints |

---

## 🛠️ Tech Stack

* **Core Runtime:** Python 3.11
* **Event backbone:** Apache Kafka + Zookeeper
* **Vector DB:** ChromaDB (for alert history embedding)
* **LLM Engine:** Ollama running `mistral:7b` (local/air-gapped advisory)
* **Web framework:** FastAPI (Backend) & React + Vite (Frontend)
* **Machine Learning:** XGBoost, scikit-learn, pandas, numpy
* **External SOAR Integrations:** Shuffle SOAR & Slack Webhooks

---

## 🚀 Getting Started

### Prerequisites
* Python 3.11+
* Docker Desktop (for containerized setup)
* Trained ML models (from the `soc-ai-training` pipeline)

### Setup Environment
1. Clone the repository and copy the environment template:
   ```bash
   cp .env.example .env
   ```
2. Configure your environment in `.env`. Key toggles include:
   * `USE_KAFKA=true` — Routes agents through Kafka (set to `false` for in-memory threads).
   * `LLM_ENABLED=true` — Enables AI enrichment using the Ollama service.
   * Add your API keys (e.g., `ABUSEIPDB_KEY`, `SLACK_WEBHOOK_URL`).

### Model Provisioning
Copy the trained `.pkl` models from the `soc-ai-training` production directory into the local model folder before starting:
```bash
cp ../soc-ai-training/ml_models/production/*.pkl ./ml_models/
```

Required models:
* `threat_model.pkl` — Threat scoring classifier
* `attack_type_model.pkl` — Attack categorizer
* `preprocessor.pkl` / `encoders.pkl` — Feature transformations
* `fp_model.pkl` / `fp_classifier.pkl` — False positive filters

---

## 🏃 Running the Application

### Option 1: Docker Compose (All services - Recommended)
Builds and orchestrates the complete topology:
```bash
docker-compose up --build
```
This boots Zookeeper, Kafka, Kafka UI, ChromaDB, Ollama, the Ollama init task (pulls `mistral:7b`), the seven agents, the FastAPI server, and the dashboard.

### Option 2: Local Thread Runner (Development)
For fast iteration without spinning up Docker or Kafka, run in-memory:
```bash
# Install dependencies
pip install -r requirements.txt

# Start the simulator in one terminal
python scripts/simulate_alerts.py

# Run the local agent manager in another terminal
ENV=development USE_KAFKA=false python main.py
```

---

## 🖥️ Services UI & Endpoints

When running in Docker Compose:
* **Analyst Dashboard:** [http://localhost:3000](http://localhost:3000)
* **API Documentation:** [http://localhost:8001/docs](http://localhost:8001/docs)
* **Kafka UI Dashboard:** [http://localhost:8080](http://localhost:8080)
* **Ollama Endpoint:** [http://localhost:11434](http://localhost:11434)

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

