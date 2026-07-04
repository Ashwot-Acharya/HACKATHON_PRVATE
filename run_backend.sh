#!/bin/bash
echo "Starting BankSentinel Backend API Server..."
source venv/bin/activate
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
