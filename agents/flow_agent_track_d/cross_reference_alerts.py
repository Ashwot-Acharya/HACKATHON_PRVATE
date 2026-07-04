import json
import glob
import os
import pandas as pd
try:
    from agents.flow_agent_track_d.suricata_to_inference import parse_suricata_flows
    from agents.flow_agent_track_d.inference import run_inference_batch
except ModuleNotFoundError:
    from suricata_to_inference import parse_suricata_flows
    from inference import run_inference_batch

def load_suricata_alerts(json_file):
    alerts = {}
    with open(json_file, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except:
                continue
                
            if data.get("event_type") == "alert":
                flow_id = data.get("flow_id")
                sig = data.get("alert", {}).get("signature", "Unknown Signature")
                cat = data.get("alert", {}).get("category", "Unknown Category")
                
                if flow_id not in alerts:
                    alerts[flow_id] = set()
                alerts[flow_id].add(f"[{cat}] {sig}")
                
    return {k: " | ".join(v) for k, v in alerts.items()}

if __name__ == "__main__":
    print("1. Parsing Suricata Alerts...")
    suricata_alerts = load_suricata_alerts("suricata_data.json")
    print(f"   Found {len(suricata_alerts)} unique flows with Suricata signature alerts.")
    
    print("\n2. Parsing Suricata Flows for ML Model...")
    df = parse_suricata_flows("suricata_data.json")
    
    model_files = glob.glob("models/*.pkl")
    latest_model = max(model_files, key=os.path.getctime)
    
    print("\n3. Running ML Inference (This takes a few seconds)...")
    result_df = run_inference_batch(df, latest_model, "data/host_profiles.csv", verbose=False, is_batch=True)
    
    result_df["suricata_signatures"] = result_df["flow_id"].map(suricata_alerts).fillna("NO_SIGNATURE")
    result_df["has_suricata_alert"] = result_df["suricata_signatures"] != "NO_SIGNATURE"
    
    ml_alerts = result_df[result_df["is_alert"] == True]
    ml_benign = result_df[result_df["is_alert"] == False]
    
    true_positives = ml_alerts[ml_alerts["has_suricata_alert"] == True]
    potential_zerodays_or_fp = ml_alerts[ml_alerts["has_suricata_alert"] == False]
    false_negatives = ml_benign[ml_benign["has_suricata_alert"] == True]
    
    print("\n=======================================================")
    print("                CROSS-REFERENCE RESULTS")
    print("=======================================================")
    print(f"Total Flows Processed         : {len(result_df)}")
    print(f"Total ML Alerts Triggered     : {len(ml_alerts)}")
    print(f"Total Suricata Rule Alerts    : {len(suricata_alerts)}")
    print("-------------------------------------------------------")
    print(f"[+] HIGH CONFIDENCE ATTACKS (ML + Signature Match): {len(true_positives)}")
    print(f"[?] ANOMALIES (ML Flagged, No Signature)          : {len(potential_zerodays_or_fp)}")
    print(f"[-] MISSED ATTACKS (Signature Flagged, ML Missed) : {len(false_negatives)}")
    print("=======================================================\n")
    
    if len(true_positives) > 0:
        print("SAMPLE HIGH CONFIDENCE MATCHES:")
        print(true_positives[["start_time", "src_ip", "dst_ip", "suricata_signatures", "predicted_attack_score"]].head(5))
        print("\n")
        
    if len(potential_zerodays_or_fp) > 0:
        print("SAMPLE ANOMALIES (ML Alert Only):")
        print(potential_zerodays_or_fp[["start_time", "src_ip", "dst_ip", "dst_port", "predicted_attack_score"]].head(5))
        print("\n")
        
    if len(false_negatives) > 0:
        print("SAMPLE MISSED ATTACKS (Suricata Alert Only):")
        print(false_negatives[["start_time", "src_ip", "dst_ip", "suricata_signatures", "predicted_attack_score"]].head(5))
