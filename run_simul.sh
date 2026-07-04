#!/bin/bash
echo "=========================================="
echo "    GIBL Demonstration Simulator"
echo "=========================================="

# Trap Ctrl+C to kill all background processes
trap "echo 'Stopping all services...'; kill 0; exit" SIGINT SIGTERM

echo "[+] Starting Backend (FastAPI)..."
source venv/bin/activate
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload &

echo "[+] Starting Frontend (Vite)..."
cd frontend
npm run dev &
cd ..

echo "[+] Waiting for backend to initialize..."
sleep 4

echo "[+] Starting Simulation Injector..."
python demo/simul.py &

echo "=========================================="
echo " All services running! Press Ctrl+C to stop."
echo " Frontend: http://localhost:5173"
echo " Backend:  http://localhost:8000"
echo " Simulation traffic is now being injected."
echo "=========================================="

# Keep the script running to hold the trap
wait
