# SOC AI — Project Root

This folder contains two repositories that work together:

## Structure
  soc-ai/
    ├── soc-ai-agents/      # Python agents pipeline
    └── soc-ai-training/    # ML training pipeline

## How They Are Linked
soc-ai-agents reads ML models directly from soc-ai-training/ml_models/production/
When soc-ai-training promotes new models → agents hot-reload automatically.
No copying needed.

## Quick Start

### Train Models
  cd soc-ai-training
  python training/01_collect.py
  python training/02_prepare.py
  python training/03_train.py --skip-cv
  python training/04_evaluate.py
  python training/05_promote.py --force

### Run Agents
  cd soc-ai-agents
  python scripts/simulate_alerts.py
