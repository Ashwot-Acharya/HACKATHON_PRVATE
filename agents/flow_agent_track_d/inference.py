import pandas as pd
import numpy as np

try:
    from agents.flow_agent_track_d.flow_utils import (
        ALL_FEATURE_COLS, NUMERIC_COLS, CATEGORICAL_COLS, BOOL_COLS,
        engineer_features, freq_encode_apply
    )
except ModuleNotFoundError:
    from flow_utils import (
        ALL_FEATURE_COLS, NUMERIC_COLS, CATEGORICAL_COLS, BOOL_COLS,
        engineer_features, freq_encode_apply
    )

def predict_final(nf_features_row, bundle, verbose=False, is_batch=False):
    """
    Inference wrapper for the flow agent.
    
    nf_features_row: A pandas DataFrame containing one or more rows of raw netflow data.
                     It does NOT need to be run through engineer_features yet.
    bundle: The loaded joblib bundle dictionary from training.
    verbose: If True, prints step-by-step scores to the console for debugging.
    is_batch: If True, computes historical stateful rolling features across the entire DataFrame.
    """
    if verbose: print(f"[inference debug] Starting inference for {len(nf_features_row)} rows")
    
    nf_features_row = engineer_features(nf_features_row, bundle["hosts_df_placeholder"], is_inference=(not is_batch))

    for c in CATEGORICAL_COLS:
        if c in nf_features_row.columns:
            nf_features_row[c] = pd.Categorical(nf_features_row[c], categories=bundle["categorical_levels"][c])
    
    # 3. XGBoost Inference
    X = nf_features_row[ALL_FEATURE_COLS]
    xgb_p = bundle["xgb_model"].predict_proba(X)[:, 1]
    if verbose: print(f"[inference debug] XGBoost raw scores: {np.round(xgb_p, 4).tolist()}")

    # 4. Isolation Forest Inference
    freq_maps = bundle["if_freq_maps"]
    num_bool = nf_features_row[NUMERIC_COLS + BOOL_COLS].astype(float)
    freq = freq_encode_apply(nf_features_row, CATEGORICAL_COLS, freq_maps)
    X_if = pd.concat([num_bool.reset_index(drop=True), freq.reset_index(drop=True)], axis=1)
    X_if_scaled = bundle["if_scaler"].transform(X_if)
    if_score = -bundle["iso_forest"].score_samples(X_if_scaled)
    if verbose: print(f"[inference debug] Isolation Forest raw scores: {np.round(if_score, 4).tolist()}")

    # 5. Blend Scores
    xgb_min, xgb_max = bundle["blend"]["xgb_minmax"]
    if_min, if_max = bundle["blend"]["if_minmax"]
    alpha = bundle["blend"]["alpha"]
    
    def norm(x, lo, hi):
        return (x - lo) / (hi - lo + 1e-9)
        
    blended = alpha * norm(xgb_p, xgb_min, xgb_max) + (1 - alpha) * norm(if_score, if_min, if_max)
    if verbose: print(f"[inference debug] Blended scores (alpha={alpha}): {np.round(blended, 4).tolist()}")

    # 6. Apply Business Rules
    if bundle["business_rules"]["honeypot_override"]:
        honeypot_hit = (nf_features_row["dst_is_honeypot"] | nf_features_row["src_is_honeypot"]).values.astype(bool)
        if verbose and honeypot_hit.any():
            print(f"[inference debug] HONEYPOT OVERRIDE TRIGGERED! Forcing 1.0 score.")
        blended = np.where(honeypot_hit, 1.0, blended)

    if verbose:
        thr = bundle["thresholds"]["f1"]
        print(f"[inference debug] Final Threshold: {thr:.4f}")
        print(f"[inference debug] Final Decisions: {(blended >= thr).tolist()}")

    return blended, nf_features_row["dst_criticality"]

def run_inference_batch(df, bundle_path, hosts_path, verbose=False, is_batch=False):
    import joblib
    import numpy as np
    bundle = joblib.load(bundle_path)
    hosts = pd.read_csv(hosts_path)
    hosts = hosts.drop_duplicates(subset="ip_address", keep="last")
    bundle["hosts_df_placeholder"] = hosts
    
    scores, criticalities = predict_final(df, bundle, verbose=verbose, is_batch=is_batch)
    df["predicted_attack_score"] = scores
    df["is_alert"] = scores >= bundle["thresholds"]["f1"]
    
    # Banking Context: Tag Alerts with Severity based on the destination regime
    conditions = [
        (df["is_alert"] == True) & (criticalities.isin(["HIGH", "SWIFT"])),
        (df["is_alert"] == True) & (criticalities == "MEDIUM"),
        (df["is_alert"] == True)
    ]
    choices = ["CRITICAL_SEVERITY", "HIGH_SEVERITY", "ELEVATED_SEVERITY"]
    df["alert_severity"] = np.select(conditions, choices, default="NONE")
    
    return df

if __name__ == "__main__":
    import argparse
    import glob
    import os
    
    parser = argparse.ArgumentParser(description="Run flow agent inference")
    parser.add_argument("--verbose", action="store_true", help="Print debug logs")
    args = parser.parse_args()
    
    model_files = glob.glob("models/*.pkl")
    if not model_files:
        print("No models found in models/ directory. Train the model first.")
        exit(1)
        
    latest_model = max(model_files, key=os.path.getctime)
    print(f"Loading latest model: {latest_model}")
    
    # Load 5 sample rows from the CSV
    sample_df = pd.read_csv("data/netflow_records.csv", nrows=5)
    
    # Needs to match the datetime format
    sample_df["start_time"] = pd.to_datetime(sample_df["start_time"], format="%Y-%m-%d %H:%M:%S.%f")
    
    result = run_inference_batch(sample_df, latest_model, "data/host_profiles.csv", verbose=args.verbose)
    
    print("\nInference Results:")
    print(result[["flow_id", "src_ip", "dst_ip", "predicted_attack_score", "is_alert"]])
