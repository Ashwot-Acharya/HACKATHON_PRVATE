#!/bin/bash
echo "=========================================="
echo "    GIBL Model Accuracy & Validation Test"
echo "=========================================="

source venv/bin/activate
export PYTHONPATH=$(pwd)

echo "[+] Running all model inference tests (test_all_models_working.py)..."
python tests/test_all_models_working.py

echo ""
echo "[+] Model tests completed."
