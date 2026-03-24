# SOC AI Repository Split

The SOC AI system is now split into two specialized repositories to separate Software Engineering (Agents) from Machine Learning Engineering (CT pipelines).

## 1. `soc-ai-agents`
This repository contains the software implementation: Python agents, Wazuh/Suricata integrations, Slack alerting, and unit tests.
* **CI/CD Pipeline**: `.github/workflows/ci-cd-pipeline.yml` runs unit tests and linters when code is pushed.
* **Environment Configuration**: Model paths in `.env` are now configured to resolve models from the adjacent training repository:
  ```env
  ML_THREAT_MODEL_PATH=../soc-ai-training/ml_models/production/threat_model.pkl
  ```

## 2. `soc-ai-training`
This repository contains datasets, notebooks, and the 6-step MLOps pipeline we built.
* **ML Continuous Training (CT)**: `.github/workflows/ml-pipeline.yml` orchestrates the training, evaluation, validation, and promotion of models.
* **Model Storage**: All candidate, versioned, and production models (`.pkl` files) live solely in this repository. 

## How they are Linked
In a local development environment, simply place both repositories in the same parent directory:
```text
parent_folder/
 ├── soc-ai-agents/
 └── soc-ai-training/
```
Because the `soc-ai-agents/` `.env` references `../soc-ai-training/`, whenever the ML pipeline inside `soc-ai-training` successfully promotes a new candidate into `ml_models/production/`, the agents simply reload and instantly have access to the latest intelligence.
