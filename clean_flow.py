import sys
import pandas as pd
import pickle
from pathlib import Path
import os

# Adjust path to find root packages
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))

from pipeline.ingestion import assign_regime

def main():
    if len(sys.argv) < 2:
        print("Usage: python clean_flow.py <path_to_file>")
        sys.exit(1)

    csv_path = sys.argv[1]
    if not os.path.exists(csv_path):
        print(f"Error: File '{csv_path}' not found.")
        sys.exit(1)

    print(f"Loading data from {csv_path}...")
    df = pd.read_csv(csv_path)

    # 1. Ensure start_time is datetime
    if "start_time" not in df.columns:
        print("Error: 'start_time' column missing from dataset.")
        sys.exit(1)

    df["start_time"] = pd.to_datetime(df["start_time"], errors='coerce')
    df = df.dropna(subset=["start_time"])

    # 2. Assign Regimes
    print("Assigning regimes based on start_time...")
    def get_regime(row):
        ts = row["start_time"]
        return assign_regime(ts.hour, ts.minute, ts.weekday(), ts.day)
    
    df["regime"] = df.apply(get_regime, axis=1)

    # 3. Filter to benign only for training
    # If the user data has a flow_label, we separate it. 
    # If there is no label, we assume all is benign.
    if "flow_label" in df.columns:
        benign_mask = df["flow_label"].astype(str).str.upper().isin(["BENIGN", "NORMAL", "0"])
        attack_df = df[~benign_mask].copy()
        benign_df = df[benign_mask].copy()
        print(f"Found {len(benign_df)} benign flows and {len(attack_df)} attack flows.")
    else:
        print("No 'flow_label' column found, assuming all data is benign.")
        benign_df = df.copy()
        attack_df = pd.DataFrame(columns=df.columns)

    # 4. Drop non-numeric features
    # IsolationForest only takes numeric features
    cols_to_drop = [
        "flow_id", "start_time", "end_time", "src_ip", "dst_ip", 
        "tcp_flags", "segment", "application_guess", "flow_label",
        "protocol"  # Drop protocol if it's a string, or you can one-hot encode it later
    ]
    
    benign_by_regime = {}
    for regime in df["regime"].unique():
        regime_df = benign_df[benign_df["regime"] == regime].copy()
        
        # Drop non-numeric string columns
        for col in cols_to_drop:
            if col in regime_df.columns:
                regime_df = regime_df.drop(columns=[col])
                
        # Drop any remaining object columns to be safe
        regime_df = regime_df.select_dtypes(include=['number', 'bool'])
        
        # Fill missing numeric values with 0
        regime_df = regime_df.fillna(0)
        
        benign_by_regime[regime] = regime_df

    # 5. Save to models directory
    models_dir = Path("models")
    models_dir.mkdir(exist_ok=True)
    
    out_benign = models_dir / "benign_by_regime.pkl"
    out_attack = models_dir / "attack_df.pkl"

    with open(out_benign, "wb") as f:
        pickle.dump(benign_by_regime, f)
        
    with open(out_attack, "wb") as f:
        pickle.dump(attack_df, f)

    print("--- Success ---")
    print(f"Saved {len(benign_by_regime)} regime contexts to {out_benign}")
    for k, v in benign_by_regime.items():
        print(f"  - {k}: {len(v)} rows, {len(v.columns)} numeric features")
    print(f"Saved {len(attack_df)} attack flows to {out_attack}")
    
    print("\nYou can now run: python training/train_flow.py")

if __name__ == "__main__":
    main()
