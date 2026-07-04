import os
import time
import json
import subprocess
import requests
import psutil

# Configuration
LOGS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "logs", "zeek"))
BACKEND_URL = "http://localhost:8000/pipeline/zeek_live_ingest"
CONN_LOG_PATH = os.path.join(LOGS_DIR, "conn.log")

def get_default_interface():
    # Find the first non-loopback interface that is up and has an IPv4 address
    interfaces = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    
    for iface, stats in interfaces.items():
        if iface != 'lo' and stats.isup:
            if iface in addrs and any(a.family.name == 'AF_INET' for a in addrs[iface]):
                return iface
    return None

def start_zeek(interface):
    print(f"[*] Starting ZEEK on interface: {interface}")
    os.makedirs(LOGS_DIR, exist_ok=True)
    
    # Clean up old logs so we start fresh
    for filename in os.listdir(LOGS_DIR):
        file_path = os.path.join(LOGS_DIR, filename)
        if os.path.isfile(file_path):
            os.remove(file_path)
            
    # Run Zeek as root in the logs directory, forcing JSON format
    # Note: requires sudo privileges without a password prompt, or run this python script as root.
    zeek_cmd = [
        "sudo", "zeek", "-i", interface, "-C",
        "-e", "redef LogAscii::use_json=T;"
    ]
    
    print(f"[*] Executing: {' '.join(zeek_cmd)}")
    process = subprocess.Popen(
        zeek_cmd,
        cwd=LOGS_DIR, # Zeek drops logs in its current working directory
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return process

def tail_and_ingest():
    print(f"[*] Waiting for Zeek to create {CONN_LOG_PATH}...")
    while not os.path.exists(CONN_LOG_PATH):
        time.sleep(1)
        
    print(f"[*] Tailing {CONN_LOG_PATH} and forwarding to ML Pipeline...")
    with open(CONN_LOG_PATH, 'r') as f:
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
                # Ensure we only process connections
                if "_path" not in payload or payload["_path"] != "conn":
                    continue
                    
                response = requests.post(BACKEND_URL, json=payload, timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    corr = data.get("correlation_result", {})
                    if corr.get("priority") in ["CRITICAL", "HIGH"]:
                        print(f"[ALERT] Sent Zeek flow | Result: {corr.get('priority')} | Score: {corr.get('crs')}")
                else:
                    print(f"[-] Backend Error {response.status_code}: {response.text}")
                    
            except json.JSONDecodeError:
                pass
            except requests.exceptions.RequestException as e:
                print(f"[-] Connection to ML backend failed: {e}")
                time.sleep(1)

def main():
    print("========================================")
    print("  LIVE ZEEK NETWORK MONITOR -> ML FEED  ")
    print("========================================")
    
    interface = get_default_interface()
    if not interface:
        print("[!] Could not auto-detect a valid network interface. Please ensure you are connected to a network.")
        return
        
    zeek_proc = None
    try:
        zeek_proc = start_zeek(interface)
        tail_and_ingest()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Monitor...")
    finally:
        if zeek_proc:
            print("[*] Killing Zeek subprocess...")
            subprocess.run(["sudo", "pkill", "-P", str(zeek_proc.pid)], check=False)
            zeek_proc.terminate()
            zeek_proc.wait()

if __name__ == "__main__":
    main()
