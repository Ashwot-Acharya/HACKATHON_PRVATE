import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os
import argparse
from config import FLOW_FEATURES

def retrain_model(data_path, output_dir="agents/models/flow"):
    print(f"[*] Loading data from {data_path}...")
    df = pd.read_csv(data_path)
    
    # Ensure all required features are present
    missing = [f for f in FLOW_FEATURES if f not in df.columns]
    if missing:
        print(f"[*] Missing features in dataset: {missing}")
        print("[*] Attempting to map standard Zeek names...")
        # Common Zeek mappings
        mapping = {
            "bytes_recv": "resp_bytes",
            "bytes_sent": "orig_bytes",
            "dst_port": "id.resp_p",
            "src_port": "id.orig_p",
            "duration_sec": "duration",
            "packets_recv": "resp_pkts",
            "packets_sent": "orig_pkts"
        }
        for f in missing:
            if f in mapping and mapping[f] in df.columns:
                df[f] = df[mapping[f]]
            elif f.startswith("is_internal"):
                df[f] = 0 # Default if missing
            else:
                df[f] = 0.0 # Default fallback
    
    X = df[FLOW_FEATURES].fillna(0).values
    
    print("[*] Performing 80-20 Train/Test split for evaluation...")
    X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)
    
    print("[*] Fitting StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("[*] Training Isolation Forest (Normal Regime)...")
    clf = IsolationForest(
        n_estimators=200, 
        max_samples='auto', 
        contamination=5e-4, 
        random_state=42
    )
    clf.fit(X_train_scaled)
    
    # Quick evaluation
    test_preds = clf.predict(X_test_scaled)
    anomalies = (test_preds == -1).sum()
    print(f"[*] Test Set Evaluation: Flagged {anomalies} out of {len(X_test)} as anomalous ({(anomalies/len(X_test))*100:.2f}%).")
    
    print(f"[*] Saving models to {output_dir}...")
    os.makedirs(output_dir, exist_ok=True)
    
    context_models_path = os.path.join(output_dir, "flow_context_models.pkl")
    if os.path.exists(context_models_path):
        context_models = joblib.load(context_models_path)
    else:
        context_models = {}
        
    context_models["normal"] = clf
    
    joblib.dump(context_models, context_models_path)
    joblib.dump(scaler, os.path.join(output_dir, "flow_scaler.pkl"))
        
    print("[+] Retraining complete! You can now restart run_sensors.py.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Retrain Flow Agent")
    parser.add_argument("--data", required=True, help="Path to CSV dataset")
    args = parser.parse_args()
    retrain_model(args.data, output_dir="models")
