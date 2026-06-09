# 🛡️ SOC AI — Project Workspace

An AI-powered, event-driven Security Operations Center (SOC) automation system. SOC AI leverages a multi-agent orchestration pipeline to ingest, enrich, detect, classify, and automatically mitigate security alerts in real time.

The project is split into two specialized sub-repositories that work in tandem:

1. **[soc-ai-agents](./soc-ai-agents/)** — The software engineering pipeline: Kafka event bus, rule-based detection, LLM advisory analysis, YAML playbook orchestration, auto-response, FastAPI bridge, and React dashboard.
2. **[soc-ai-training](./soc-ai-training/)** — The MLOps pipeline: data collection, preprocessing, model training (XGBoost + Random Forest), evaluation, promotion, and drift monitoring.

---

## 📂 Project Structure

```text
soc-ai/
├── soc-ai-agents/      # AI agents pipeline, API, & React dashboard
└── soc-ai-training/    # ML model training & MLOps pipeline
```

---

## 🔗 How the Pipelines Link

The agents and MLOps pipelines are decoupled but integrated through shared machine learning model artifacts:

* **Model Serialization**: Models are serialized using `joblib` in the training pipeline and loaded via `joblib.load()` inside the agents.
* **Local Development (`USE_KAFKA=false`):**
  The agents run in-memory and read `.pkl` models directly from `../soc-ai-training/ml_models/production/`. When the training pipeline promotes a new model, running agents hot-reload the updated intelligence instantly.
* **Production / Docker (`USE_KAFKA=true`):**
  The agents run as containerized microservices. Models from `soc-ai-training/ml_models/production/` are copied or bind-mounted into `soc-ai-agents/ml_models/` so they are available to Docker containers.

> [!WARNING]
> **Windows Git line endings warning:**
> If you clone or pull this repository on Windows, ensure your git config is set to `git config core.autocrlf input` to prevent Windows from converting line endings in binary files (like `.pkl` models) to CRLF, which corrupts the models. The repository includes a `.gitattributes` file that enforces binary tracking of these files.

---

## 🚀 Quick Start

### 1. Train the ML Models

Before running the agent pipeline, train and promote the ML models.

```bash
# Navigate to the training repository
cd soc-ai-training

# Initialize virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run the complete MLOps pipeline (Windows PowerShell):
.\run_pipeline.ps1

# Or run manually step by step:
python training/01_collect.py
python training/02_prepare.py
python training/03_train.py --skip-cv
python training/04_evaluate.py
python training/05_promote.py --force
```

This prepares and promotes the models to `soc-ai-training/ml_models/production/`.

> [!TIP]
> You can also run the standalone high-performance trainer directly:
> `python training/train_threat.py`

### 2. Run the Agents Pipeline

You can run the agent pipeline either locally (for development) or using Docker Compose (recommended for full orchestration).

#### Option A: Docker Compose (Full Event-Driven Pipeline)

Launches Kafka, Zookeeper, ChromaDB, Ollama, all agents, the FastAPI bridge, and the React dashboard.

```bash
# Navigate to the agents repository
cd soc-ai-agents

# Copy promoted models from the training repository
# Linux/macOS:
cp ../soc-ai-training/ml_models/production/*.pkl ./ml_models/
# Windows (PowerShell):
Copy-Item -Path "..\soc-ai-training\ml_models\production\*.pkl" -Destination ".\ml_models\" -Force

# Set up environment variables
cp .env.example .env
# Edit .env — key toggles: USE_KAFKA=true, LLM_ENABLED=true, ABUSEIPDB_KEY, SLACK_WEBHOOK_URL

# Launch all services
docker-compose up --build
```

#### Option B: Local Thread Runner (Development)

Runs the collector and all agents as in-memory threads — no Docker or Kafka required.

```bash
cd soc-ai-agents
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# In one terminal: run the alert simulator
python scripts/simulate_alerts.py

# In another terminal: run the local agent manager
ENV=development USE_KAFKA=false python main.py
```

---

## 🖥️ Services & Ports

When running via Docker Compose, the following services are available:

| Service | URL | Description |
|---|---|---|
| **React Dashboard** | [http://localhost:3000](http://localhost:3000) | Analyst UI |
| **FastAPI Backend** | [http://localhost:8001](http://localhost:8001) | REST + SSE bridge |
| **Swagger Docs** | [http://localhost:8001/docs](http://localhost:8001/docs) | Interactive API docs |
| **Kafka UI** | [http://localhost:8080](http://localhost:8080) | Topic monitor |
| **ChromaDB API** | [http://localhost:8000](http://localhost:8000) | Vector database |
| **Ollama API** | [http://localhost:11434](http://localhost:11434) | Local LLM engine (`tinyllama`) |
| **Kafka Broker** | `localhost:29092` | External Kafka access |
