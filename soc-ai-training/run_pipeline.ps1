$ErrorActionPreference = "Stop"
Write-Host "Running 01_collect.py..."
python training/01_collect.py
Write-Host "Running 02_prepare.py..."
python training/02_prepare.py
Write-Host "Running 03_train.py..."
python training/03_train.py
Write-Host "Running 04_evaluate.py..."
python training/04_evaluate.py
Write-Host "PIPELINE COMPLETED SUCCESSFULLY"
