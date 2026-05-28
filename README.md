# 🛡️ SOC AI — Project Workspace

An AI-powered, event-driven Security Operations Center (SOC) automation system. SOC AI leverages a multi-agent orchestration pipeline to ingest, enrich, detect, classify, and automatically mitigate security alerts in real time. 

The project is split into two specialized repositories that work in tandem:
1. **[soc-ai-agents](file:///c:/Users/taieb/.gemini/antigravity/scratch/soc-ai/soc-ai-agents)** — The software engineering pipeline (Kafka event bus, rule-based detection, LLM advisory analysis, auto-response playbooks, FastAPI bridge, and React dashboard).
2. **[soc-ai-training](file:///c:/Users/taieb/.gemini/antigravity/scratch/soc-ai/soc-ai-training)** — The MLOps pipeline (data collection, preprocessing, training candidate threat/attack/FP models, evaluation, promotion, and drift monitoring).

---

## 📂 Project Structure

```text
soc-ai/
├── soc-ai-agents/      # AI agents pipeline, API, & React dashboard
└── soc-ai-training/    # ML model training & MLOps pipeline
```

---

## 🔗 How the Pipelines Link

The agents and MLOps pipelines are decoupled but integrated through the machine learning models they share:
 
* **Model Serialization**: Models are serialized using `joblib` in the training pipeline and loaded using `joblib.load()` inside the agents.
* **Local Development (`USE_KAFKA=false`):** 
  The agents run in-memory and read the `.pkl` models directly from `../soc-ai-training/ml_models/production/`. When the training pipeline promotes a new model, the running agents hot-reload the updated intelligence instantly.
* **Production / Docker (`USE_KAFKA=true`):** 
  The agents run as containerized microservices. The models in `soc-ai-training/ml_models/production/` are copied or mounted to `soc-ai-agents/ml_models/` so they can be loaded by the Docker containers.
 
> [!WARNING]
> **Windows Git line endings warning:**
> If you clone or pull this repository on Windows, ensure that your git config is set to `git config core.autocrlf input` to prevent Windows from converting line endings in binary files (like `.pkl` models) to CRLF, which corrupts the models. The repository contains a `.gitattributes` file to enforce binary tracking of these files.

---

## 🚀 Quick Start

### 1. Train the ML Models
Before running the agent pipeline, you need to train and promote the ML models.

```bash
# Navigate to the training repository
cd soc-ai-training

# Initialize virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt # or install scikit-learn xgboost pandas numpy joblib loguru

# Run the complete MLOps pipeline
# Windows (PowerShell):
.\run_pipeline.ps1

# Manual step-by-step pipeline:
python training/01_collect.py
python training/02_prepare.py
python training/03_train.py --skip-cv
python training/04_evaluate.py
python training/05_promote.py --force
```
This prepares and promotes the models to `soc-ai-training/ml_models/production/`.

### 2. Run the Agents Pipeline
You can run the agent pipeline either locally (for debugging) or using Docker Compose (recommended for full system orchestration).

#### Option A: Docker Compose (Full Event-Driven Pipeline)
This launches Kafka, Zookeeper, ChromaDB, Ollama, all agents, the FastAPI bridge, and the React frontend.

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
# Edit .env to set LLM_ENABLED=true or USE_KAFKA=true

# Launch all services
docker-compose up --build
```

#### Option B: Local Runner (In-Memory / Development)
Runs the collector and analyzer agents as threads without needing Docker or Kafka.

```bash
cd soc-ai-agents
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run the simulator to feed alerts
python scripts/simulate_alerts.py

# In another terminal: Run the local thread manager
ENV=development USE_KAFKA=false python main.py
```

---

## 🖥️ Services & Ports
When running via Docker Compose, the following services are available:

* **React Dashboard:** [http://localhost:3000](http://localhost:3000) (Analyst UI)
* **FastAPI Backend API:** [http://localhost:8001](http://localhost:8001) / [Swagger Docs](http://localhost:8001/docs)
* **Kafka UI:** [http://localhost:8080](http://localhost:8080) (Topic monitor)
* **ChromaDB API:** [http://localhost:8000](http://localhost:8000)
* **Ollama API:** [http://localhost:11434](http://localhost:11434)

