import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

"""
BankSentinel Attack Demo Script (Direct API Mode)
===================================================
Run this script on an attacker machine to generate realistic traffic targeting the BankSentinel IDS.
This version bypasses raw packet sniffing and directly injects events into the BankSentinel
pipeline API, meaning it works instantly without needing root privileges or a packet sniffer.

Dependencies: 
  pip install requests rich

Usage: python3 attack_demo.py --target <defender_ip>
"""

import sys
import time
import socket
import threading
import random
import argparse
import requests
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()
running_scenario = False

# Base feature dict required by the BankSentinel pipeline
BASE_FEATURES = {
    "Flow Duration": 1.2,
    "Total Fwd Packets": 10.0,
    "Total Backward Packets": 10.0,
    "Total Length of Fwd Packets": 500.0,
    "Total Length of Bwd Packets": 5000.0,
    "Flow Bytes/s": 4500.0,
    "Flow Packets/s": 18.0,
    "Flow IAT Mean": 0.1,
    "Flow IAT Std": 0.05,
    "Fwd IAT Total": 1.0,
    "Fwd IAT Mean": 0.1,
    "Fwd IAT Std": 0.02,
    "Bwd IAT Mean": 0.1,
    "Bwd IAT Std": 0.02,
    "Destination Port": 443.0
}

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def send_to_pipeline(target_ip, payload):
    url = f"http://{target_ip}:8000/pipeline/run"
    try:
        requests.post(url, json=payload, timeout=2.0)
    except Exception:
        pass

def sc_1(target_ip):
    console.print("\n[bold blue]━━━━━━━━━━━━━━━━━━━━━━[/bold blue]")
    console.print("[bold blue]SCENARIO 1 — [C4] Known Malware JA3 Fingerprint[/bold blue]")
    console.print("[bold blue]━━━━━━━━━━━━━━━━━━━━━━[/bold blue]")
    
    payload = {
        "src_ip": get_local_ip(),
        "dst_ip": target_ip,
        "src_port": random.randint(10000, 60000),
        "dst_port": 443,
        "protocol": 6,
        "features": BASE_FEATURES,
        "label": "APT-C2",
        "regime": "off_hours",
        "ja3_hash": "0b32309a26951912be7dba376398abc3" # Cobalt Strike JA3
    }

    while running_scenario:
        send_to_pipeline(target_ip, payload)
        console.print(f"[dim]{time.strftime('%X')}[/dim] [red]JA3: b32309a26951912be7dba376398abc3 → Cobalt Strike (Injected)[/red]")
        time.sleep(3)

def sc_2(target_ip):
    console.print("\n[bold blue]━━━━━━━━━━━━━━━━━━━━━━[/bold blue]")
    console.print("[bold blue]SCENARIO 2 — [C4] C2 Beacon Timing (Layer 3)[/bold blue]")
    console.print("[bold blue]━━━━━━━━━━━━━━━━━━━━━━[/bold blue]")
    intervals = []
    
    while running_scenario:
        jitter = random.uniform(-0.15, 0.15)
        interval = 10.0 + jitter
        time.sleep(interval)
        if not running_scenario: break
        
        payload = {
            "src_ip": get_local_ip(),
            "dst_ip": target_ip,
            "src_port": random.randint(10000, 60000),
            "dst_port": 8080,
            "protocol": 6,
            "features": BASE_FEATURES,
            "label": "APT-C2",
            "regime": "normal"
        }
        
        send_to_pipeline(target_ip, payload)
        intervals.append(interval)
        mean = sum(intervals)/len(intervals)
        std = (sum((x-mean)**2 for x in intervals)/len(intervals))**0.5
        cv = std/mean if mean > 0 else 0
        console.print(f"[dim]{time.strftime('%X')}[/dim] [red]Beacon sent. Interval: {interval:.2f}s, Running CV: {cv:.3f}[/red]")

def sc_3(target_ip):
    console.print("\n[bold yellow]━━━━━━━━━━━━━━━━━━━━━━[/bold yellow]")
    console.print("[bold yellow]SCENARIO 3 — [C2] ATM Reconciliation Window Flood[/bold yellow]")
    console.print("[bold yellow]━━━━━━━━━━━━━━━━━━━━━━[/bold yellow]")
    count = 0
    start = time.time()
    
    payload = {
        "src_ip": "10.22.15.55", # Simulated ATM IP
        "dst_ip": target_ip,
        "src_port": 49152,
        "dst_port": 8583, # ATM port
        "protocol": 6,
        "features": {**BASE_FEATURES, "Flow Bytes/s": 9500000.0, "Total Fwd Packets": 8800.0},
        "label": "BENIGN",
        "regime": "atm_recon" # This tells the Flow Agent to use the ATM model and avoid False Positives
    }

    while running_scenario and count < 200:
        send_to_pipeline(target_ip, payload)
        count += 1
        elapsed = time.time() - start
        rate = count / elapsed if elapsed > 0 else 0
        console.print(f"[yellow]Sent {count}/200 massive ATM sync requests. Rate: {rate:.1f} req/s[/yellow]", end="\r")
    console.print("\n[dim]Flood complete. Check dashboard to see how noise was suppressed.[/dim]")

def sc_4(target_ip):
    console.print("\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
    console.print("[bold cyan]SCENARIO 4 — [C1] Insider Lateral Movement[/bold cyan]")
    console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
    ports = [445, 3389, 1433, 3306, 5432, 8443, 22, 1521, 5900, 9200]
    names = ["SMB", "RDP", "SQL Server", "MySQL", "PostgreSQL", "HTTPS alt", "SSH", "Oracle", "VNC", "Elasticsearch"]
    
    while running_scenario:
        for p, n in zip(ports, names):
            if not running_scenario: break
            
            payload = {
                "src_ip": get_local_ip(),
                "dst_ip": target_ip,
                "src_port": random.randint(10000, 60000),
                "dst_port": p,
                "protocol": 6,
                "features": BASE_FEATURES,
                "label": "Insider-Access", # Triggers C1 Zero-Day logic
                "regime": "off_hours"
            }
            
            send_to_pipeline(target_ip, payload)
            console.print(f"[dim]{time.strftime('%X')}[/dim] [red]Lateral SYN payload sent to {n} (port {p})[/red]")
            time.sleep(0.3)
        time.sleep(1)

def run_scenario(scenario_func, target_ip):
    global running_scenario
    running_scenario = True
    t = threading.Thread(target=scenario_func, args=(target_ip,), daemon=True)
    t.start()
    input()
    running_scenario = False
    t.join(timeout=1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", help="Defender IP address (where backend is running)")
    args = parser.parse_args()
    
    target_ip = args.target
    if not target_ip:
        target_ip = Prompt.ask("Enter Target (Defender) IP or localhost", default="127.0.0.1")

    local_ip = get_local_ip()

    panel = Panel(
        f"Attacker IP:  {local_ip}\n"
        f"Target IP:    {target_ip}\n"
        f"Status:       [green]API INJECTION READY[/green]",
        title="[bold red]BankSentinel Attack Simulator (Direct API)[/bold red]",
        expand=False
    )
    console.print(panel)

    while True:
        console.print("\n[bold]Select a scenario to run (Press Enter to stop scenario):[/bold]")
        console.print("  1. [C4] Known Malware JA3 Fingerprint")
        console.print("  2. [C4] C2 Beacon Timing (Layer 3)")
        console.print("  3. [C2] ATM Reconciliation Window Flood")
        console.print("  4. [C1] Insider Lateral Movement")
        console.print("  q. Quit")
        
        choice = Prompt.ask("Choice", choices=["1", "2", "3", "4", "q", "Q"])
        if choice.lower() == 'q':
            break
        elif choice == '1':
            run_scenario(sc_1, target_ip)
        elif choice == '2':
            run_scenario(sc_2, target_ip)
        elif choice == '3':
            run_scenario(sc_3, target_ip)
        elif choice == '4':
            run_scenario(sc_4, target_ip)

if __name__ == "__main__":
    main()