import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# live_attack.py

import socket
import time
import random
import threading
import argparse
import ssl
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()
running_scenario = False

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def sc_1(target_ip):
    console.print("\n[bold blue]━━━━━━━━━━━━━━━━━━━━━━[/bold blue]")
    console.print("[bold blue]SCENARIO 1 — [C4] Known Malware JA3 Fingerprint[/bold blue]")
    console.print("[bold blue]━━━━━━━━━━━━━━━━━━━━━━[/bold blue]")
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    while running_scenario:
        try:
            with socket.create_connection((target_ip, 443), timeout=2.0) as sock:
                with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                    ssock.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
            console.print(f"[dim]{time.strftime('%X')}[/dim] [red]Sent TLS Client Hello to {target_ip}:443 (Sensor will calculate True JA3)[/red]")
        except Exception as e:
            console.print(f"[dim]{time.strftime('%X')}[/dim] [yellow]TLS connection failed: {e}[/yellow]")
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
        
        try:
            with socket.create_connection((target_ip, 8080), timeout=2.0) as sock:
                sock.send(b"GET /login HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
            intervals.append(interval)
            mean = sum(intervals)/len(intervals)
            std = (sum((x-mean)**2 for x in intervals)/len(intervals))**0.5
            cv = std/mean if mean > 0 else 0
            console.print(f"[dim]{time.strftime('%X')}[/dim] [red]Beacon sent. Interval: {interval:.2f}s, Running CV: {cv:.3f}[/red]")
        except Exception as e:
            console.print(f"[dim]{time.strftime('%X')}[/dim] [yellow]Beacon failed: {e}[/yellow]")

def sc_3(target_ip):
    console.print("\n[bold yellow]━━━━━━━━━━━━━━━━━━━━━━[/bold yellow]")
    console.print("[bold yellow]SCENARIO 3 — [C2] ATM Reconciliation Window Flood[/bold yellow]")
    console.print("[bold yellow]━━━━━━━━━━━━━━━━━━━━━━[/bold yellow]")
    
    payload = b"A" * 1400  # Large payload
    start = time.time()
    count = 0
    
    # We will flood port 8583 to spike the Bytes/s and Packets/s metrics
    while running_scenario and count < 20000:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(payload, (target_ip, 8583))
            count += 1
            if count % 1000 == 0:
                elapsed = time.time() - start
                rate = count / elapsed if elapsed > 0 else 0
                console.print(f"[yellow]Sent {count} UDP packets to ATM port. Rate: {rate:.1f} pkts/s[/yellow]", end="\r")
        except Exception:
            pass
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
            try:
                with socket.create_connection((target_ip, p), timeout=0.1) as sock:
                    pass
            except Exception:
                pass
            console.print(f"[dim]{time.strftime('%X')}[/dim] [red]TCP SYN scan -> {n} (port {p})[/red]")
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
    parser.add_argument("--target", help="Server IP address")
    args = parser.parse_args()
    
    target_ip = args.target
    if not target_ip:
        target_ip = Prompt.ask("Enter Target Server IP or localhost", default="127.0.0.1")

    local_ip = get_local_ip()

    panel = Panel(
        f"Attacker IP:  {local_ip}\n"
        f"Target IP:    {target_ip}\n"
        f"Status:       [green]RAW NETWORK ATTACK READY[/green]",
        title="[bold red]BankSentinel Live Attack Simulator[/bold red]",
        expand=False
    )
    console.print(panel)

    while True:
        console.print("\n[bold]Select a scenario to run (Press Enter to stop scenario):[/bold]")
        console.print("  1. [C4] Known Malware JA3 Fingerprint (TLS Hello)")
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
