#!/usr/bin/env python3
"""Calibrate Layer 3 (CTU-13 RF) threshold for optimal benign/attack separation.

Usage:
    python scripts/calibrate_l3_threshold.py [--target-fpr 0.05]

This script:
  1. Loads the CTU-13 Random Forest from models/
  2. Generates synthetic benign and attack test sets
  3. Computes ROC curve and optimal threshold
  4. Recommends new threshold to achieve target FPR
  5. Shows impact on detection rate and false positive rate
"""

import numpy as np
from pathlib import Path
from sklearn.metrics import roc_curve, auc
import joblib
import json
import argparse

MODELS_DIR = Path(__file__).parent.parent / "models"
L3_THREAT_THRESHOLD = 0.40  # Current hardcoded value in packet_agent.py


def load_feature_names():
    """Load the 20 feature names expected by the RF model."""
    with open(MODELS_DIR / "packet_rf_features.json") as f:
        return json.load(f)


import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
from train_packet import compute_beacon_features_df


def calibrate_threshold(dataset_path: Path):
    """Calibrate optimal threshold for Layer 3 using real data."""
    print(f"\n{'='*70}")
    print(f"Layer 3 (CTU-13 RF) Threshold Calibration")
    print(f"{'='*70}\n")
    
    # Load model and scaler
    try:
        rf_model = joblib.load(MODELS_DIR / "packet_rf_ctu.pkl")
        rf_scaler = joblib.load(MODELS_DIR / "packet_rf_scaler.pkl")
        features = load_feature_names()
        n_features = len(features)
        print(f"✓ Loaded RF model from {MODELS_DIR / 'packet_rf_ctu.pkl'}")
        print(f"✓ Model expects {n_features} features")
    except FileNotFoundError as e:
        print(f"✗ Error: {e}")
        return
        
    print(f"\nLoading real data from {dataset_path}...")
    df = pd.read_csv(dataset_path)
    if 'is_anomaly' not in df.columns:
        print("✗ Error: Dataset must contain an 'is_anomaly' column")
        return
        
    y_true = df['is_anomaly'].astype(str).str.lower().map({'true': 1, 'false': 0}).fillna(0).astype(int)
    
    print("\nExtracting features...")
    X_df = compute_beacon_features_df(df)
    X = X_df.values
    
    # Split for metric tracking
    benign_mask = (y_true == 0)
    attack_mask = (y_true == 1)
    
    X_benign = X[benign_mask]
    X_attack = X[attack_mask]
    
    print(f"  Benign samples : {len(X_benign)}")
    print(f"  Attack samples : {len(X_attack)}")
    
    # Scale and predict
    print("\nScoring flows with RF model...")
    X_scaled = rf_scaler.transform(X)
    X_benign_scaled = rf_scaler.transform(X_benign)
    X_attack_scaled = rf_scaler.transform(X_attack)
    
    # RandomForest returns probabilities (higher = more anomalous)
    y_scores = rf_model.predict_proba(X_scaled)[:, 1]
    y_benign_proba = rf_model.predict_proba(X_benign_scaled)[:, 1]  # anomaly prob
    y_attack_proba = rf_model.predict_proba(X_attack_scaled)[:, 1]
    
    print(f"  Benign scores : min={y_benign_proba.min():.4f}, "
          f"max={y_benign_proba.max():.4f}, "
          f"mean={y_benign_proba.mean():.4f}")
    print(f"  Attack scores : min={y_attack_proba.min():.4f}, "
          f"max={y_attack_proba.max():.4f}, "
          f"mean={y_attack_proba.mean():.4f}")
    
    # Build ROC curve
    fpr, tpr, thresholds = roc_curve(y_true, y_scores)
    roc_auc = auc(fpr, tpr)
    
    print(f"\n  ROC AUC : {roc_auc:.4f}")
    
    # Calculate Youden's J statistic to find the mathematically optimal threshold
    j_scores = tpr - fpr
    best_idx = np.argmax(j_scores)
    optimal_threshold = thresholds[best_idx]
    actual_fpr = fpr[best_idx]
    actual_tpr = tpr[best_idx]
    max_j = j_scores[best_idx]
    
    print(f"\n{'─'*70}")
    print(f"Optimal Threshold (Maximized Youden's J = {max_j:.4f}):")
    print(f"{'─'*70}")
    print(f"  Threshold       : {optimal_threshold:.4f}")
    print(f"  Actual FPR      : {actual_fpr:.1%}  (false positives on benign)")
    print(f"  Detection Rate  : {actual_tpr:.1%}  (true positives on attacks)")
    print(f"  Current value   : {L3_THREAT_THRESHOLD:.4f}")
    
    # Compare with current threshold
    print(f"\n{'─'*70}")
    print(f"Impact of Current Threshold ({L3_THREAT_THRESHOLD:.4f}):")
    print(f"{'─'*70}")
    
    benign_flagged = (y_benign_proba > L3_THREAT_THRESHOLD).sum()
    attack_detected = (y_attack_proba > L3_THREAT_THRESHOLD).sum()
    
    current_fpr = benign_flagged / len(y_benign_proba) if len(y_benign_proba) > 0 else 0.0
    current_tpr = attack_detected / len(y_attack_proba) if len(y_attack_proba) > 0 else 0.0
    
    print(f"  False Positive Rate : {current_fpr:.1%}  ({benign_flagged}/{len(y_benign_proba)})")
    print(f"  Detection Rate      : {current_tpr:.1%}  ({attack_detected}/{len(y_attack_proba)})")
    
    print(f"\n{'='*70}")
    print(f"RECOMMENDATION:")
    print(f"{'='*70}")
    print(f"""
Update _THREAT_THRESHOLD in agents/packet_agent.py from {L3_THREAT_THRESHOLD} to {optimal_threshold:.4f}

This will achieve:
  - False Positive Rate: {actual_fpr:.1%} (legitimate traffic incorrectly flagged)
  - Detection Rate:      {actual_tpr:.1%} (attacks correctly detected)
""")
    
    # Save the dynamic threshold
    out_file = MODELS_DIR / "packet_threshold.pkl"
    joblib.dump(optimal_threshold, out_file)
    print(f"\n✅ Optimal dynamic threshold successfully saved to {out_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=str, help="Path to packet test CSV dataset")
    args = parser.parse_args()
    
    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"✗ Error: Dataset not found: {dataset_path}")
        sys.exit(1)
        
    calibrate_threshold(dataset_path)
