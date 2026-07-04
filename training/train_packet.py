#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

"""
train_packet.py

Trains the Packet Agent (Layer 3) Random Forest on a custom Zeek CSV dataset.

Usage:
    python train_packet.py /path/to/zeek_conn_logs.csv
"""

import sys
import json
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import RobustScaler

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

MODELS_DIR = Path("models")

# The exact feature names expected by the model
FEATURE_NAMES = [
    "dur", "tot_pkts", "tot_bytes", "src_bytes",
    "bytes_per_pkt", "bytes_per_sec", "pkts_per_sec",
    "iat_mean_proxy", "iat_cv_proxy", "regularity",
    "size_consistency", "flow_efficiency", "beacon_score_raw",
    "proto_tcp", "proto_udp", "dir_unidirectional", "bwd_fwd_ratio",
    "iat_mean", "iat_std",
    "dst_port"
]

def compute_beacon_features_df(df: pd.DataFrame) -> pd.DataFrame:
    """Compute all 20 beacon features directly on a pandas DataFrame."""
    eps = 1e-9
    
    # Basic extracted features
    dur = df['duration'].fillna(0.0).astype(float)
    src_bytes = df['orig_bytes'].fillna(0.0).astype(float)
    resp_bytes = df['resp_bytes'].fillna(0.0).astype(float)
    fwd_pkts = df['orig_pkts'].fillna(1.0).astype(float) # Prevent div by zero
    bwd_pkts = df['resp_pkts'].fillna(0.0).astype(float)
    
    tot_bytes = np.maximum(src_bytes + resp_bytes, 1.0)
    tot_pkts = np.maximum(fwd_pkts + bwd_pkts, 1.0)
    
    # Rates
    bytes_per_pkt = tot_bytes / (tot_pkts + eps)
    bytes_per_sec = tot_bytes / (dur + eps)
    pkts_per_sec = tot_pkts / (dur + eps)
    
    # Proxies for missing IAT
    iat_mean_proxy = dur / (tot_pkts + eps)
    iat_cv_proxy = bytes_per_pkt / (bytes_per_sec + eps)
    regularity = 1.0 / (pkts_per_sec + eps + 1.0)
    size_consistency = src_bytes / (tot_bytes + eps)
    flow_efficiency = tot_pkts / (dur + eps + 1.0)
    beacon_score_raw = (
        regularity * 0.4
        + size_consistency * 0.3
        + (1.0 / (iat_mean_proxy + eps + 1.0)) * 0.3
    )
    
    # Protocol & Ports
    proto_tcp = (df['proto'].str.lower() == 'tcp').astype(float)
    proto_udp = (df['proto'].str.lower() == 'udp').astype(float)
    
    # Replace '-' with 0.0 for ports if necessary
    dst_port = pd.to_numeric(df['id_resp_p'], errors='coerce').fillna(0.0).astype(float)
    
    # Flow direction
    dir_unidirectional = (bwd_pkts == 0.0).astype(float)
    bwd_fwd_ratio = bwd_pkts / (fwd_pkts + eps)
    
    # Missing IAT features (fill with 0 or proxy since dataset lacks them)
    iat_mean = iat_mean_proxy
    iat_std = iat_cv_proxy * iat_mean_proxy
    
    # Build the final DataFrame in exact order
    feat_df = pd.DataFrame({
        "dur": dur,
        "tot_pkts": tot_pkts,
        "tot_bytes": tot_bytes,
        "src_bytes": src_bytes,
        "bytes_per_pkt": bytes_per_pkt,
        "bytes_per_sec": bytes_per_sec,
        "pkts_per_sec": pkts_per_sec,
        "iat_mean_proxy": iat_mean_proxy,
        "iat_cv_proxy": iat_cv_proxy,
        "regularity": regularity,
        "size_consistency": size_consistency,
        "flow_efficiency": flow_efficiency,
        "beacon_score_raw": beacon_score_raw,
        "proto_tcp": proto_tcp,
        "proto_udp": proto_udp,
        "dir_unidirectional": dir_unidirectional,
        "bwd_fwd_ratio": bwd_fwd_ratio,
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "dst_port": dst_port
    })
    
    # Replace inf and NaN just in case
    feat_df = feat_df.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return feat_df

def main():
    if len(sys.argv) < 2:
        print("Usage: python train_packet.py <path_to_zeek_dataset.csv>")
        sys.exit(1)
        
    csv_path = Path(sys.argv[1])
    if not csv_path.exists():
        logger.error(f"Dataset not found: {csv_path}")
        sys.exit(1)
        
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Loading Zeek dataset from {csv_path}...")
    # Read the dataset
    df = pd.read_csv(csv_path)
    
    if 'is_anomaly' not in df.columns:
        logger.error("Dataset must contain an 'is_anomaly' column to train the model!")
        sys.exit(1)
        
    # Standardize label
    y = df['is_anomaly'].astype(str).str.lower().map({'true': 1, 'false': 0}).fillna(0).astype(int)
    
    logger.info(f"Dataset loaded. Total rows: {len(df)}")
    logger.info(f"Class distribution - Normal: {(y==0).sum()}, Malicious: {(y==1).sum()}")
    
    if (y==1).sum() == 0:
        logger.error("Cannot train model: there are 0 malicious rows (is_anomaly=True) in the dataset.")
        sys.exit(1)
        
    logger.info("Computing beacon features (this may take a minute)...")
    X_df = compute_beacon_features_df(df)
    X = X_df.values
    
    logger.info("Fitting RobustScaler...")
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)
    
    logger.info("Training RandomForestClassifier...")
    rf = RandomForestClassifier(
        n_estimators=100, 
        max_depth=15, 
        class_weight='balanced_subsample',
        random_state=42, 
        n_jobs=-1
    )
    rf.fit(X_scaled, y)
    
    logger.info(f"Training accuracy: {rf.score(X_scaled, y):.4f}")
    
    logger.info("Saving new artifacts to models/ directory...")
    joblib.dump(rf, MODELS_DIR / "packet_rf_trackd.pkl")
    joblib.dump(scaler, MODELS_DIR / "packet_scaler_trackd.pkl")
    
    with open(MODELS_DIR / "packet_features_trackd.json", "w") as f:
        json.dump(FEATURE_NAMES, f, indent=4)
        
    logger.info("✅ Packet Agent successfully trained and saved!")

if __name__ == "__main__":
    main()
