#!/bin/bash
echo "=========================================="
echo "    GIBL Unit Test Suite"
echo "=========================================="

source venv/bin/activate
export PYTHONPATH=$(pwd)

echo "[+] Running pytest on tests/ directory..."
pytest tests/ -v --tb=short

echo ""
echo "[+] Unit test suite completed."
