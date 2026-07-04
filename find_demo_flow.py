import pickle
import pandas as pd
import numpy as np
from pathlib import Path
import joblib

def main():
    models_dir = Path("models")
    scaler = joblib.load(models_dir / "flow_scaler.pkl")
    global_model = joblib.load(models_dir / "flow_global_model.pkl")
    context_models = joblib.load(models_dir / "flow_context_models.pkl")
    thresholds = joblib.load(models_dir / "flow_thresholds.pkl")

    with open(models_dir / "benign_by_regime.pkl", "rb") as f:
        benign_by_regime = pickle.load(f)
    
    first_regime_df = list(benign_by_regime.values())[0]
    numeric_df = first_regime_df.select_dtypes(include=['number', 'bool'])
    feature_cols = sorted([c for c in numeric_df.columns if c not in ["label", "regime", "dataset_source", "flow_label"]])

    # We want to find a row in off_hours or atm_recon that is globally anomalous but contextually normal
    for regime in ["off_hours", "atm_recon", "month_end"]:
        if regime not in benign_by_regime: continue
        
        df = benign_by_regime[regime]
        X = df[feature_cols].values
        X_scaled = scaler.transform(X)

        global_raw = -global_model.score_samples(X_scaled)
        context_raw = -context_models[regime].score_samples(X_scaled)

        # Global threshold is 99th percentile (so 1% of normal data is globally anomalous)
        # Context threshold is 99th percentile (so 1% is contextually anomalous)
        g_thresh = thresholds["normal"]
        c_thresh = thresholds[regime]

        # Find rows where global_raw > g_thresh AND context_raw < c_thresh
        mask = (global_raw > g_thresh) & (context_raw < c_thresh)
        candidates = df[mask]

        if not candidates.empty:
            print(f"Found {len(candidates)} candidates in {regime}!")
            best = candidates.iloc[0]
            print(f"Features: {best[feature_cols].to_dict()}")
            
            # Let's also see what its scores are
            g_score = global_raw[mask][0]
            c_score = context_raw[mask][0]
            print(f"Global Raw: {g_score:.4f} > {g_thresh:.4f}")
            print(f"Context Raw: {c_score:.4f} < {c_thresh:.4f}")
            return

    print("No candidates found.")

if __name__ == "__main__":
    main()
