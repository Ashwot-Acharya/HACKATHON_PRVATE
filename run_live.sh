#!/bin/bash
echo "=========================================="
echo "    GIBL Live Network Environment"
echo "=========================================="

# Cache sudo credentials upfront so Zeek/Suricata don't block in the background
echo "[!] We need sudo privileges to start Zeek and Suricata network sensors."
sudo -v

# Cleanup any orphaned processes from previous crashed runs
echo "[+] Cleaning up any orphaned sensor processes..."
sudo pkill -f zeek || true
sudo pkill -f suricata || true

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

echo "[+] Starting Network Sensors (Zeek & Suricata)..."
python run_sensors.py &

echo "=========================================="
echo " All services running! Press Ctrl+C to stop."
echo " Frontend: http://localhost:5173"
echo " Backend:  http://localhost:8000"
echo "=========================================="

# Keep the script running to hold the trap
wait
