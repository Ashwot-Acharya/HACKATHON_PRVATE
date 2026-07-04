#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

"""
Script to train the Dual-Dataset Behavior Agent BiLSTM Autoencoder.
Takes two cleaned CSVs, merges them by user, extracts unified features,
creates sequences, and trains the model.

Usage:
    python train_behavior.py <cleaned_csv_1> <cleaned_csv_2>
"""

import sys
import logging
import pickle
import hashlib
from pathlib import Path

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

from config import MODELS_DIR
from agents.behaviour_agent import (
    BehaviorLSTM, 
    BEHAVIOR_SEQUENCE_LENGTH,
    BEHAVIOR_ANOMALY_PERCENTILE,
    BEHAVIOR_INPUT_SIZE
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

def hash_string_to_float(s: str) -> float:
    """Hash a string deterministically to a float between 0 and 1."""
    if pd.isna(s):
        return 0.0
    h = hashlib.md5(str(s).encode()).hexdigest()
    return int(h[:7], 16) / 0xFFFFFFF

def prepare_sequences(df: pd.DataFrame) -> tuple:
    """Engineer features and extract fixed-length sequences."""
    logger.info("Engineering unified features...")
    
    # Sort chronologically per user
    df = df.sort_values(by=['username', 'timestamp']).reset_index(drop=True)
    
    # 0. dataset_source (0 for DS1, 1 for DS2)
    f_source = (df['dataset_source'] == 2).astype(float)
    
    # 1 & 2. Time features
    hours = df['timestamp'].dt.hour + df['timestamp'].dt.minute / 60.0
    f_hour_sin = np.sin(2 * np.pi * hours / 24.0)
    f_hour_cos = np.cos(2 * np.pi * hours / 24.0)
    
    # 3. event_id_norm
    f_event_id = df['event_id'].apply(hash_string_to_float)
    
    # 4 to 9. DS1 specific features
    f_bytes = np.log1p(df['ds1_bytes_transferred'].fillna(0))
    f_dur = df['ds1_duration_sec'].fillna(0)
    f_off_hours = df['ds1_is_off_hours'].fillna(0)
    f_new_res = df['ds1_is_new_resource'].fillna(0)
    f_failed = df['ds1_failed_attempts'].fillna(0)
    f_peer = df['ds1_peer_deviation'].fillna(0)
    
    # 10 & 11. DS2 specific features
    f_logon = (df['ds2_logon_type'].fillna(-1) + 1) / 15.0 # roughly normalized
    f_sensitive = (df['ds2_target_username'].str.lower().str.contains('admin|system', na=False)).astype(float)
    
    # 12. ip_cluster
    f_ip = df['source_ip'].apply(hash_string_to_float)
    
    # 13. query_rate (rolling 5 min count per user)
    logger.info("Computing rolling query rates...")
    temp = df[['timestamp', 'username']].copy()
    temp['count_val'] = 1.0
    temp.set_index('timestamp', inplace=True)
    f_query_rate = temp.groupby('username')['count_val'].rolling('5min').count().values
    
    features = np.column_stack([
        f_source, f_hour_sin, f_hour_cos, f_event_id, 
        f_bytes, f_dur, f_off_hours, f_new_res, f_failed, f_peer,
        f_logon, f_sensitive, f_ip, f_query_rate
    ]).astype(np.float32)
    
    if features.shape[1] != BEHAVIOR_INPUT_SIZE:
        logger.error(f"Feature size {features.shape[1]} does not match config ({BEHAVIOR_INPUT_SIZE})")
        sys.exit(1)
        
    logger.info("Chunking into sequences...")
    normal_seqs = []
    anomaly_seqs = []
    
    is_anom = df['is_anomaly'].values
    usernames = df['username'].values
    
    # Chunk sequences per user
    unique_users = np.unique(usernames)
    for u in unique_users:
        idx = np.where(usernames == u)[0]
        user_feats = features[idx]
        user_anoms = is_anom[idx]
        
        n = len(user_feats)
        for i in range(0, n - BEHAVIOR_SEQUENCE_LENGTH + 1, BEHAVIOR_SEQUENCE_LENGTH):
            seq = user_feats[i:i+BEHAVIOR_SEQUENCE_LENGTH]
            anoms = user_anoms[i:i+BEHAVIOR_SEQUENCE_LENGTH]
            
            if np.any(anoms):
                anomaly_seqs.append(seq)
            else:
                normal_seqs.append(seq)
                
    return np.array(normal_seqs), np.array(anomaly_seqs)

def main():
    if len(sys.argv) < 3:
        print("Usage: python train_behavior.py <cleaned_csv_1> <cleaned_csv_2>")
        sys.exit(1)
        
    csv1_path = Path(sys.argv[1])
    csv2_path = Path(sys.argv[2])
    
    if not csv1_path.exists() or not csv2_path.exists():
        logger.error("One or both cleaned datasets not found.")
        sys.exit(1)
        
    logger.info("Loading unified datasets...")
    df1 = pd.read_csv(csv1_path)
    df2 = pd.read_csv(csv2_path)
    
    # Ensure timestamps are parsed
    df1['timestamp'] = pd.to_datetime(df1['timestamp'])
    df2['timestamp'] = pd.to_datetime(df2['timestamp'])
    
    # Concat both
    df = pd.concat([df1, df2], ignore_index=True)
    logger.info(f"Total merged rows: {len(df)}")
    
    X_normal, X_anomaly = prepare_sequences(df)
    logger.info(f"Generated NORMAL sequences: {len(X_normal)}")
    logger.info(f"Generated ANOMALOUS sequences: {len(X_anomaly)}")
    
    if len(X_normal) == 0:
        logger.error("No normal sequences generated. Cannot train!")
        sys.exit(1)
        
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Save the test dataset (anomalies) for future evaluation
    if len(X_anomaly) > 0:
        test_file = MODELS_DIR / "behavior_test_attacks.pkl"
        with open(test_file, "wb") as f:
            pickle.dump(X_anomaly, f)
        logger.info(f"Saved {len(X_anomaly)} test sequences to {test_file}")

    # 2. Normalize the features
    logger.info("Normalizing behavioral features...")
    X_flat = X_normal.reshape(-1, X_normal.shape[-1])
    feat_mean = X_flat.mean(axis=0)
    feat_std = X_flat.std(axis=0)
    feat_std[feat_std == 0] = 1.0  
    
    X_train_norm = (X_normal - feat_mean) / feat_std
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    dataset = TensorDataset(torch.tensor(X_train_norm, dtype=torch.float32))
    loader = DataLoader(dataset, batch_size=64, shuffle=True)

    logger.info(f"Initializing BiLSTM Autoencoder (Input Size: {BEHAVIOR_INPUT_SIZE})...")
    model = BehaviorLSTM().to(device)
    optimizer = optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.MSELoss()

    epochs = 20
    logger.info(f"Training for {epochs} epochs...")
    model.train()
    
    for epoch in range(epochs):
        total_loss = 0.0
        for (batch,) in loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            recon = model(batch)
            loss = criterion(recon, batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * batch.size(0)
            
        avg_loss = total_loss / len(dataset)
        logger.info(f"  Epoch {epoch+1}/{epochs} - Loss: {avg_loss:.6f}")

    logger.info("Calculating anomaly threshold from training data...")
    model.eval()
    recon_errors_list = []
    batch_size = 1024
    with torch.no_grad():
        for i in range(0, len(X_train_norm), batch_size):
            batch_x = torch.tensor(X_train_norm[i : i + batch_size], dtype=torch.float32).to(device)
            errs = model.reconstruction_error(batch_x).cpu().numpy()
            recon_errors_list.append(errs)
    recon_errors = np.concatenate(recon_errors_list)
        
    threshold = float(np.percentile(recon_errors, BEHAVIOR_ANOMALY_PERCENTILE))
    logger.info(f"95th percentile threshold set to: {threshold:.6f}")

    logger.info("Saving Behavior Agent models to models/ directory...")
    torch.save(model.state_dict(), MODELS_DIR / "behavior_model.pt")
    
    with open(MODELS_DIR / "behaviour_threshold.pkl", "wb") as f:
        pickle.dump(threshold, f)
        
    scaler_params = {"feat_mean": feat_mean, "feat_std": feat_std}
    with open(MODELS_DIR / "behaviour_scaler.pkl", "wb") as f:
        pickle.dump(scaler_params, f)

    logger.info("✅ Dual-Dataset Behavior models successfully trained and saved!")

if __name__ == "__main__":
    main()
