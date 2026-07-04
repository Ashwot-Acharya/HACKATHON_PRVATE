import os
import time
import json
import subprocess
import requests
import psutil
import threading

# Configuration
LOGS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "logs"))
ZEEK_LOGS_DIR = os.path.join(LOGS_DIR, "zeek")
SURICATA_LOGS_DIR = os.path.join(LOGS_DIR, "suricata")

ZEEK_LOG_PATH = os.path.join(ZEEK_LOGS_DIR, "conn.log")
SURICATA_LOG_PATH = os.path.join(SURICATA_LOGS_DIR, "eve.json")

BACKEND_URL_ZEEK = "http://localhost:8000/pipeline/zeek_live_ingest"
BACKEND_URL_SURICATA = "http://localhost:8000/pipeline/suricata"

def get_default_interface():
    # Find the first non-loopback interface that is up and has an IPv4 address
    interfaces = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    
    for iface, stats in interfaces.items():
        if iface != 'lo' and stats.isup:
            if iface in addrs and any(a.family.name == 'AF_INET' for a in addrs[iface]):
                return iface
    return None

def cleanup_logs():
    for d in [ZEEK_LOGS_DIR, SURICATA_LOGS_DIR]:
        os.makedirs(d, exist_ok=True)
        for filename in os.listdir(d):
            file_path = os.path.join(d, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)

def start_zeek(interface):
    print(f"[*] Starting ZEEK on interface: {interface}")
    zeek_cmd = [
        "sudo", "zeek", "-i", interface, "-C",
        "-e", "redef LogAscii::use_json=T;"
    ]
    process = subprocess.Popen(
        zeek_cmd,
        cwd=ZEEK_LOGS_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return process

def start_suricata(interface):
    print(f"[*] Starting SURICATA on interface: {interface}")
    suricata_cmd = [
        "sudo", "suricata", "-i", interface, "-l", SURICATA_LOGS_DIR
    ]
    process = subprocess.Popen(
        suricata_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return process

def tail_and_ingest(name, filepath, backend_url, json_check_key=None):
    print(f"[*] [{name.upper()}] Waiting for {filepath}...")
    while not os.path.exists(filepath):
        time.sleep(1)
        
    print(f"[*] [{name.upper()}] Tailing {filepath} -> {backend_url}")
    with open(filepath, 'r') as f:
        # Go to the end of the file
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
                
            line = line.strip()
            if not line:
                continue
                
            try:
                payload = json.loads(line)
                
                # Pre-filtering
                if json_check_key and json_check_key not in payload:
                    continue
                if name == "suricata" and payload.get("event_type") not in ["flow", "alert"]:
                    continue
                    
                response = requests.post(backend_url, json=payload, timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    corr = data.get("correlation_result", {})
                    # Print critical/high alerts
                    if corr and corr.get("priority") in ["CRITICAL", "HIGH"]:
                        print(f"  [!] {name.upper()} {corr.get('priority')} ALERT. CRS: {corr.get('crs')}")
                else:
                    print(f"[-] [{name.upper()}] Backend Error {response.status_code}: {response.text}")
                    
            except json.JSONDecodeError:
                pass
            except requests.exceptions.RequestException as e:
                # Backend might be down, suppress noisy errors and just wait
                time.sleep(1)

import signal
import sys

def handle_sigterm(signum, frame):
    print("\n[*] Received SIGTERM, shutting down gracefully...")
    sys.exit(0)  # This will trigger the finally block

def main():
    signal.signal(signal.SIGTERM, handle_sigterm)
    print("========================================")
    print("  DUAL SENSOR LIVE NETWORK MONITOR      ")
    print("========================================")
    
    interface = get_default_interface()
    if not interface:
        print("[!] Could not auto-detect a valid network interface. Please ensure you are connected to a network.")
        return
        
    cleanup_logs()
    
    zeek_proc = None
    suricata_proc = None
    
    try:
        zeek_proc = start_zeek(interface)
        suricata_proc = start_suricata(interface)
        
        # Start tail threads
        zeek_thread = threading.Thread(target=tail_and_ingest, args=("zeek", ZEEK_LOG_PATH, BACKEND_URL_ZEEK), daemon=True)
        suricata_thread = threading.Thread(target=tail_and_ingest, args=("suricata", SURICATA_LOG_PATH, BACKEND_URL_SURICATA), daemon=True)
        
        zeek_thread.start()
        suricata_thread.start()
        

        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[*] Shutting down Dual Monitor...")
    finally:
        print("[*] Killing sensor subprocesses...")
        if zeek_proc:
            subprocess.run(["sudo", "pkill", "-P", str(zeek_proc.pid)], check=False, stderr=subprocess.DEVNULL)
            zeek_proc.terminate()
            zeek_proc.wait()
        if suricata_proc:
            subprocess.run(["sudo", "pkill", "-P", str(suricata_proc.pid)], check=False, stderr=subprocess.DEVNULL)
            suricata_proc.terminate()
            suricata_proc.wait()

if __name__ == "__main__":
    main()
