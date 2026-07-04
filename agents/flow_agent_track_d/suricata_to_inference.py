import json
import glob
import os
import pandas as pd
import ipaddress
try:
    from agents.flow_agent_track_d.inference import run_inference_batch
except ModuleNotFoundError:
    from inference import run_inference_batch

def is_internal(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False

def parse_suricata_flows(json_file):
    records = []
    with open(json_file, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
                
            if data.get("event_type") == "flow":
                # Extract fields
                flow_data = data.get("flow", {})
                
                # We map suricata fields to the expected flow agent schema
                record = {
                    "flow_id": data.get("flow_id", "UNKNOWN"),
                    "start_time": pd.to_datetime(data.get("timestamp")),
                    "src_ip": data.get("src_ip"),
                    "dst_ip": data.get("dest_ip"),
                    "src_port": data.get("src_port", 0),
                    "dst_port": data.get("dest_port", 0),
                    "protocol": data.get("proto", "UNKNOWN"),
                    "app_protocol": data.get("app_proto", "UNKNOWN"),
                    "bytes_sent": flow_data.get("bytes_toserver", 0),
                    "bytes_recv": flow_data.get("bytes_toclient", 0),
                    "packets_sent": flow_data.get("pkts_toserver", 0),
                    "packets_recv": flow_data.get("pkts_toclient", 0),
                    "duration_sec": flow_data.get("age", 0),
                    "tcp_flags": data.get("tcp", {}).get("tcp_flags", "NONE"), # Often missing in flow logs
                    
                    # Synthesize structural fields needed by our specific agent
                    "segment": "USER", # Default assumption if we don't know the vlan
                    "application_guess": data.get("app_proto", "UNKNOWN").upper(),
                    "is_internal_src": int(is_internal(data.get("src_ip", ""))),
                    "is_internal_dst": int(is_internal(data.get("dest_ip", "")))
                }
                records.append(record)
                
    return pd.DataFrame(records)

if __name__ == "__main__":
    print("Parsing Suricata JSON logs...")
    df = parse_suricata_flows("suricata_data.json")
    print(f"Extracted {len(df)} flow records from Suricata.")
    
    if len(df) == 0:
        print("No flow records found!")
        exit(0)
        
    model_files = glob.glob("models/*.pkl")
    if not model_files:
        print("No models found. Train the model first.")
        exit(1)
        
    latest_model = max(model_files, key=os.path.getctime)
    print(f"Loading latest model: {latest_model}")
    
    # Run Inference
    print("Running Flow Agent Inference on Suricata Data...")
    result_df = run_inference_batch(df, latest_model, "data/host_profiles.csv", verbose=False, is_batch=True)
    
    # Display Results
    alerts = result_df[result_df["is_alert"] == True]
    print(f"\nScan Complete! Found {len(alerts)} alerts out of {len(result_df)} flows.")
    
    if len(alerts) > 0:
        print("\nTOP ALERTS:")
        top_alerts = alerts.sort_values("predicted_attack_score", ascending=False).head(10)
        print(top_alerts[["start_time", "src_ip", "dst_ip", "dst_port", "protocol", "application_guess", "predicted_attack_score", "alert_severity"]])
    else:
        print("\nNo anomalous traffic detected in the Suricata logs.")
