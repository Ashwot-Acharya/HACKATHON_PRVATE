import time
import json
import random
import requests
import datetime

ZEEK_URL = "http://localhost:8000/pipeline/zeek_live_ingest"
SURICATA_URL = "http://localhost:8000/pipeline/suricata"

# Known malicious JA3 hash (TrickBot) to reliably trigger the Packet Agent
TRICKBOT_JA3 = "e7d705a3286e19ea42f587b344ee6865"

def send_normal_zeek():
    payload = {
        "id.orig_h": f"10.22.18.{random.randint(10, 50)}",
        "id.resp_h": f"104.21.55.{random.randint(1, 250)}",
        "id.orig_p": random.randint(10000, 60000),
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": random.uniform(0.1, 2.0),
        "orig_pkts": random.randint(5, 20),
        "resp_pkts": random.randint(5, 20),
        "orig_bytes": random.randint(500, 2000),
        "resp_bytes": random.randint(1000, 5000),
        # Normal JA3
        "ja3": "d41d8cd98f00b204e9800998ecf8427e" 
    }
    try:
        requests.post(ZEEK_URL, json=payload, timeout=2)
        print("[+] Sent NORMAL Zeek flow")
    except Exception as e:
        print("[-] Error sending Zeek:", e)

def send_malicious_zeek():
    # Simulate a C2 beaconing pattern (low duration, small uniform bytes, malicious JA3)
    payload = {
        "id.orig_h": "10.22.15.10", # Core banking subnet
        "id.resp_h": "185.15.247.140", # External C2
        "id.orig_p": random.randint(10000, 60000),
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 0.05,
        "orig_pkts": 3,
        "resp_pkts": 3,
        "orig_bytes": 150,
        "resp_bytes": 150,
        "ja3": TRICKBOT_JA3
    }
    try:
        requests.post(ZEEK_URL, json=payload, timeout=2)
        print("[!] Sent MALICIOUS Zeek flow (TrickBot JA3)")
    except Exception as e:
        print("[-] Error sending Zeek:", e)

def send_normal_suricata():
    payload = {
        "src_ip": f"10.22.18.{random.randint(10, 50)}",
        "dest_ip": f"104.21.55.{random.randint(1, 250)}",
        "src_port": random.randint(10000, 60000),
        "dest_port": 80,
        "proto": "TCP",
        "event_type": "flow",
        "flow": {
            "duration": random.uniform(1.0, 5.0),
            "pkts_toserver": random.randint(10, 30),
            "pkts_toclient": random.randint(10, 30),
            "bytes_toserver": random.randint(1000, 3000),
            "bytes_toclient": random.randint(5000, 15000)
        }
    }
    try:
        requests.post(SURICATA_URL, json=payload, timeout=2)
        print("[+] Sent NORMAL Suricata flow")
    except Exception as e:
        print("[-] Error sending Suricata:", e)

def send_anomalous_suricata():
    # Massive data exfiltration simulation to trigger Flow Agent
    payload = {
        "src_ip": "10.22.14.1", # SWIFT subnet
        "dest_ip": "1.1.1.1",
        "src_port": 53,
        "dest_port": 53,
        "proto": "UDP",
        "event_type": "flow",
        "flow": {
            "duration": 120.5,
            "pkts_toserver": 50000,
            "pkts_toclient": 2,
            "bytes_toserver": 10500000, # 10.5 MB over DNS (DNS Tunneling exfiltration)
            "bytes_toclient": 120
        }
    }
    try:
        requests.post(SURICATA_URL, json=payload, timeout=2)
        print("[!] Sent ANOMALOUS Suricata flow (DNS Exfiltration)")
    except Exception as e:
        print("[-] Error sending Suricata:", e)

def send_behavioral_threat():
    features = {
        "start_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.000"),
        "bytes_recv": 500,
        "bytes_sent": 500,
        "dst_port": 445,
        "duration_sec": 1.5,
        "is_internal_dst": 1,
        "is_internal_src": 1,
        "packets_recv": 10,
        "packets_sent": 10,
        "src_port": 50000,
        "protocol": "TCP",
        "tcp_flags": "NONE",
        "segment": "UNKNOWN",
        "application_guess": "SMB"
    }
    seq = [[random.uniform(50, 100) for _ in range(8)] for _ in range(10)]
    payload = {
        "src_ip": "10.22.12.55",
        "dst_ip": "10.22.12.1",
        "src_port": 50000,
        "dst_port": 445,
        "protocol": 6,
        "features": features,
        "label": "SIMULATED",
        "regime": "normal",
        "behavior_sequence": seq,
        "account": "svc_admin"
    }
    try:
        PIPELINE_RUN_URL = "http://localhost:8000/pipeline/run"
        requests.post(PIPELINE_RUN_URL, json=payload, timeout=2)
        print("[!] Sent BEHAVIORAL THREAT (Anomalous Lateral Movement)")
    except Exception as e:
        print("[-] Error sending Behavioral Threat:", e)

def send_correlation_apt():
    features = {
        "start_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.000"),
        "bytes_recv": 120,
        "bytes_sent": 10500000,
        "dst_port": 53,
        "duration_sec": 120.5,
        "is_internal_dst": 0,
        "is_internal_src": 1,
        "packets_recv": 2,
        "packets_sent": 50000,
        "src_port": 53,
        "protocol": "UDP",
        "tcp_flags": "NONE",
        "segment": "UNKNOWN",
        "application_guess": "DNS"
    }
    seq = [[random.uniform(50, 100) for _ in range(8)] for _ in range(10)]
    payload = {
        "src_ip": "10.22.14.1",
        "dst_ip": "185.220.101.32",
        "src_port": 53,
        "dst_port": 53,
        "protocol": 17,
        "features": features,
        "label": "SIMULATED",
        "regime": "normal",
        "ja3_hash": TRICKBOT_JA3,
        "behavior_sequence": seq,
        "account": "sysadmin"
    }
    try:
        PIPELINE_RUN_URL = "http://localhost:8000/pipeline/run"
        requests.post(PIPELINE_RUN_URL, json=payload, timeout=2)
        print("[!] Sent CORRELATION APT THREAT (Multi-Agent Firing)")
    except Exception as e:
        print("[-] Error sending Correlation APT:", e)

def main():
    print("========================================")
    print("  GIBL LIVE DEMONSTRATION SIMULATOR     ")
    print("========================================")
    print("This script simulates live network traffic to demonstrate")
    print("the firing of the Packet, Flow, Behavior, and Correlation ML Agents.")
    
    while True:
        # Send normal traffic frequently to show "INFO" processing
        send_normal_zeek()
        send_normal_suricata()
        
        # 15% chance to inject an attack at any given tick
        if random.random() < 0.15:
            threat_type = random.choice(["packet", "flow", "behavior", "apt"])
            if threat_type == "packet":
                print("\n>>> INJECTING THREAT: TrickBot C2 Beacon <<<")
                send_malicious_zeek()
            elif threat_type == "flow":
                print("\n>>> INJECTING ANOMALY: DNS Tunneling Exfiltration <<<")
                send_anomalous_suricata()
            elif threat_type == "behavior":
                print("\n>>> INJECTING ANOMALY: Highly Anomalous User Behavior <<<")
                send_behavioral_threat()
            elif threat_type == "apt":
                print("\n>>> INJECTING APT: Multi-Vector Advanced Persistent Threat <<<")
                send_correlation_apt()
                
        time.sleep(2)

if __name__ == "__main__":
    main()
