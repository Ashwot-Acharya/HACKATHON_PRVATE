@echo off
REM ============================================================
REM  BankSentinel — Windows Deployment Script
REM  Run this in Command Prompt (as Administrator)
REM ============================================================

echo.
echo  ====================================================
echo   BankSentinel IDS — Windows Server Setup
echo  ====================================================
echo.

REM 1. Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Install Python 3.10+ from python.org
    echo         Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)
echo [OK] Python found

REM 2. Check pip
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip not found
    pause
    exit /b 1
)
echo [OK] pip found

REM 3. Install requirements
echo.
echo [*] Installing Python dependencies...
pip install -r requirements.txt
pip install cicflowmeter scapy[complete] cryptography

REM 4. Check Npcap
if exist "C:\Program Files\Npcap\npcap.dll" (
    echo [OK] Npcap found
) else (
    echo.
    echo [WARNING] Npcap not detected!
    echo          Download from: https://npcap.com/
    echo          Install with "WinPcap API-compatible mode" checked.
    echo.
)

REM 5. Open firewall ports for the backend and attack traffic
echo.
echo [*] Configuring Windows Firewall rules...
netsh advfirewall firewall add rule name="BankSentinel API" dir=in action=allow protocol=tcp localport=8000 >nul 2>&1
netsh advfirewall firewall add rule name="BankSentinel HTTP" dir=in action=allow protocol=tcp localport=80 >nul 2>&1
netsh advfirewall firewall add rule name="BankSentinel HTTPS" dir=in action=allow protocol=tcp localport=443 >nul 2>&1
netsh advfirewall firewall add rule name="BankSentinel 8080" dir=in action=allow protocol=tcp localport=8080 >nul 2>&1
netsh advfirewall firewall add rule name="BankSentinel ATM" dir=in action=allow protocol=udp localport=8583 >nul 2>&1
netsh advfirewall firewall add rule name="BankSentinel SMB" dir=in action=allow protocol=tcp localport=445 >nul 2>&1
echo [OK] Firewall rules added

echo.
echo  ====================================================
echo   Setup Complete! Next steps:
echo  ====================================================
echo.
echo   1. Start the backend:
echo      uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
echo.
echo   2. Start the sensor (new terminal, as Admin):
echo      cd live_sensor
echo      python sensor.py
echo.
echo   3. Open the dashboard in your browser:
echo      http://localhost:8000
echo.
echo   4. From Parrot OS, attack this machine at your
echo      Windows IP address using nmap, hping3, etc.
echo  ====================================================
pause
