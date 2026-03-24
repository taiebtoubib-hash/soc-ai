#!/bin/bash
# Weekly retraining script for SOC models

echo "Starting model retraining..."
python training/train_threat.py
python training/train_attack_type.py
python training/train_anomaly.py
echo "Retraining complete."
