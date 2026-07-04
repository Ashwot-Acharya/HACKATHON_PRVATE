#!/usr/bin/env python3
"""
evaluate_test_packet_csv.py

Loads a testing dataset for the Packet Agent (e.g. cleaned packet CSV), 
extracts the 20-dimensional beacon features using train_packet's logic, 
and evaluates the trained RandomForestClassifier against it.

Usage:
    python evaluate_test_packet_csv.py <path_to_packet_test_dataset.csv>
"""

import sys
import logging
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from training.train_packet import compute_beacon_features_df, FEATURE_NAMES
from config import MODELS_DIR

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

def main():
    if len(sys.argv) < 2:
        print("Usage: python evaluate_test_packet_csv.py <packet_test_dataset.csv>")
        sys.exit(1)
        
    test_csv_path = Path(sys.argv[1])
    if not test_csv_path.exists():
        logger.error(f"Test dataset not found: {test_csv_path}")
        sys.exit(1)
        
    logger.info("Loading test dataset...")
    df = pd.read_csv(test_csv_path)
    
    if 'is_anomaly' not in df.columns:
        logger.error("Dataset must contain an 'is_anomaly' column for evaluation!")
        sys.exit(1)
        
    # Standardize label
    y_true = df['is_anomaly'].astype(str).str.lower().map({'true': 1, 'false': 0}).fillna(0).astype(int)
    
    logger.info("Extracting features using unified logic...")
    X_df = compute_beacon_features_df(df)
    X = X_df.values
    
    try:
        logger.info("Loading Packet Agent (RandomForest) and Scaler...")
        rf = joblib.load(MODELS_DIR / "packet_rf_ctu.pkl")
        scaler = joblib.load(MODELS_DIR / "packet_rf_scaler.pkl")
        dynamic_threshold = joblib.load(MODELS_DIR / "packet_threshold.pkl")
    except FileNotFoundError as e:
        logger.error(f"Could not load agent artifacts: {e}")
        logger.error("Make sure you have trained the model and generated the threshold first.")
        sys.exit(1)
        
    logger.info(f"Scaling features and running inference (Dynamic Threshold: {dynamic_threshold:.4f})...")
    X_scaled = scaler.transform(X)
    
    y_probs = rf.predict_proba(X_scaled)[:, 1]
    y_pred = (y_probs >= dynamic_threshold).astype(int)
    
    # Split results into Normal vs Anomaly groups
    normal_idx = np.where(y_true == 0)[0]
    anomaly_idx = np.where(y_true == 1)[0]
    
    false_positives = np.sum(y_pred[normal_idx] == 1)
    true_positives = np.sum(y_pred[anomaly_idx] == 1)
    
    # Print Report
    print("\n" + "="*50)
    print("PACKET AGENT EVALUATION RESULTS ON TEST DATASET")
    print("="*50)
    
    if len(normal_idx) > 0:
        tn = len(normal_idx) - false_positives
        fpr = (false_positives / len(normal_idx)) * 100
        print(f"Normal Flows Scored     : {len(normal_idx)}")
        print(f"Correctly identified    : {tn}")
        print(f"False Positives         : {false_positives}")
        print(f"False Positive Rate     : {fpr:.2f}%\n")
    else:
        print("No normal flows available for False Positive Rate calculation.\n")
        
    if len(anomaly_idx) > 0:
        fn = len(anomaly_idx) - true_positives
        dr = (true_positives / len(anomaly_idx)) * 100
        print(f"Anomaly Flows Scored    : {len(anomaly_idx)}")
        print(f"Correctly identified    : {true_positives}")
        print(f"False Negatives         : {fn}")
        print(f"Detection Rate (Recall) : {dr:.2f}%\n")
    else:
        print("No anomaly flows available for Detection Rate calculation.\n")
        
    print(f"Overall Accuracy        : {np.mean(y_pred == y_true) * 100:.2f}%")
    print("="*50)

if __name__ == "__main__":
    main()
