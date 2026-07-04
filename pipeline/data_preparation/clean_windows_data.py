#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

"""
clean_windows_data.py

Cleans a custom Windows Event Log CSV dataset and maps it into the
8-dimensional sequence format required by the BankSentinel Behavior Agent.

Features extracted:
  [0] event_id_norm       Normalised Windows Event ID
  [1] hour_sin            sin(2π × hour/24)
  [2] hour_cos            cos(2π × hour/24)
  [3] src_ip_cluster      Source IP hash (proxy for IP cluster)
  [4] target_resource     Target resource hash
  [5] privilege_level     Privilege level (heuristic)
  [6] query_rate          Rolling 5-min event count
  [7] peer_z_score        Z-score deviation from global average rate

Usage:
    python clean_windows_data.py /path/to/windows_events.csv
"""

import sys
import logging
import pickle
import hashlib
import re
from pathlib import Path

import numpy as np
import pandas as pd

from config import MODELS_DIR
from agents.behaviour_agent import _EVENT_ID_INDEX, BEHAVIOR_SEQUENCE_LENGTH

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

def string_to_float_hash(s: str) -> float:
    """Hash a string deterministically to a float between 0 and 1."""
    if not isinstance(s, str):
        s = str(s)
    h = hashlib.md5(s.encode()).hexdigest()
    # Take first 7 hex digits (~28 bits) to easily fit in standard ints
    val = int(h[:7], 16)
    return val / 0xFFFFFFF

def clean_event_id(eid_str) -> int:
    """Extract numeric event ID from obfuscated strings like '51XX'."""
    s = str(eid_str)
    # Strip any non-digit character (e.g., 'X')
    cleaned = re.sub(r'[^0-9]', '', s)
    if cleaned:
        return int(cleaned)
    return -1

def main():
    if len(sys.argv) < 2:
        print("Usage: python clean_windows_data.py <path_to_windows_csv>")
        sys.exit(1)

    csv_path = Path(sys.argv[1])
    if not csv_path.exists():
        logger.error(f"File not found: {csv_path}")
        sys.exit(1)

    save_dir = Path("models")
    save_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Loading raw Windows Event data from {csv_path}...")
    df = pd.read_csv(csv_path)

    # 1. Clean Time
    logger.info("Parsing timestamps...")
    # Replacing obfuscated 'X' in dates might be tricky if they are in the literal date.
    # We will try standard parsing, but if it fails we might need to coerce.
    # The user provided: 2026-XX-XX 0X:XX:XX.XXX -> this is strictly invalid for datetime.
    # Let's write a small helper to replace 'X' with '0' if it's there.
    df['timestamp'] = df['timestamp'].astype(str).str.replace('X', '0', regex=False)
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    
    # Drop rows without valid timestamps or users
    df = df.dropna(subset=['timestamp', 'subject_username'])
    df = df.sort_values(by=['subject_username', 'timestamp']).reset_index(drop=True)

    # 2. Build 8-dimensional features
    logger.info("Engineering 8-dimensional behavioral features...")
    
    # [0] event_id_norm
    # Fallback to 0.5 for unknown event IDs
    df['clean_event_id'] = df['event_id'].apply(clean_event_id)
    df['event_id_norm'] = df['clean_event_id'].apply(lambda x: _EVENT_ID_INDEX.get(x, 0.5))

    # [1, 2] hour_sin, hour_cos
    hours = df['timestamp'].dt.hour + df['timestamp'].dt.minute / 60.0
    df['hour_sin'] = np.sin(2 * np.pi * hours / 24.0)
    df['hour_cos'] = np.cos(2 * np.pi * hours / 24.0)

    # [3] src_ip_cluster
    df['src_ip_cluster'] = df['source_ip'].apply(string_to_float_hash)

    # [4] target_resource
    # Combine target_username and process_name as the resource
    df['target_resource_str'] = df['target_username'].astype(str) + "_" + df['process_name'].astype(str)
    df['target_resource'] = df['target_resource_str'].apply(string_to_float_hash)

    # [5] privilege_level
    # Heuristic: if subject username contains 'admin', 'svc', 'system', 'root'
    def estimate_privilege(username):
        u = str(username).lower()
        if any(x in u for x in ['admin', 'svc', 'system', 'root']):
            return 1.0
        return 0.1
    df['privilege_level'] = df['subject_username'].apply(estimate_privilege)

    # [6] query_rate
    # Rolling 5-minute event count per user
    logger.info("Calculating rolling query rates (this may take a moment)...")
    df.set_index('timestamp', inplace=True)
    # Count events in a 5-minute rolling window for each user
    # Select a single column (e.g., 'event_id') so .count() returns a Series instead of a DataFrame
    df['rolling_count'] = df.groupby('subject_username')['event_id'].rolling('5min').count().values
    df.reset_index(inplace=True)
    
    # Min-max scale the query rate approximately [0, 1] based on observed data
    max_count = df['rolling_count'].max() or 1.0
    df['query_rate'] = df['rolling_count'] / max_count

    # [7] peer_z_score
    # Compare each user's mean query rate to the global mean
    global_mean = df['query_rate'].mean()
    global_std = df['query_rate'].std() or 1.0
    df['peer_z_score'] = (df['query_rate'] - global_mean) / global_std

    # Collect the exact 8 features
    features = [
        "event_id_norm", "hour_sin", "hour_cos", "src_ip_cluster",
        "target_resource", "privilege_level", "query_rate", "peer_z_score"
    ]
    
    # Ensure is_anomaly is boolean
    if 'is_anomaly' in df.columns:
        df['is_anomaly'] = df['is_anomaly'].astype(str).str.lower().map({'true': True, 'false': False}).fillna(False)
    else:
        df['is_anomaly'] = False

    # 3. Chunk into sequences of length 20
    logger.info(f"Chunking data into sequences of length {BEHAVIOR_SEQUENCE_LENGTH}...")
    normal_sequences = []
    anomaly_sequences = []
    
    # Group by user to ensure sequences only contain one user's actions
    for user, group in df.groupby('subject_username'):
        # Sort chronologically just in case
        group = group.sort_values('timestamp')
        features_array = group[features].values.astype(np.float32)
        anomaly_array = group['is_anomaly'].values
        
        # Slide window of size 20 (non-overlapping for training efficiency, but can be overlapping)
        n = len(features_array)
        for i in range(0, n - BEHAVIOR_SEQUENCE_LENGTH + 1, BEHAVIOR_SEQUENCE_LENGTH):
            seq_feats = features_array[i:i+BEHAVIOR_SEQUENCE_LENGTH]
            seq_anomalies = anomaly_array[i:i+BEHAVIOR_SEQUENCE_LENGTH]
            
            # If any event in the sequence is anomalous, mark the sequence as anomalous
            if np.any(seq_anomalies):
                anomaly_sequences.append(seq_feats)
            else:
                normal_sequences.append(seq_feats)

    if not normal_sequences:
        logger.error("No valid normal sequences of length 20 could be generated. Dataset might be too small.")
        sys.exit(1)

    X_normal = np.stack(normal_sequences)
    logger.info(f"Generated {len(X_normal)} NORMAL sequences of shape {X_normal.shape}")
    
    X_anomalous = np.stack(anomaly_sequences) if anomaly_sequences else np.empty((0, BEHAVIOR_SEQUENCE_LENGTH, len(features)))
    logger.info(f"Generated {len(X_anomalous)} ANOMALOUS sequences of shape {X_anomalous.shape}")

    # 4. Save to disk
    logger.info("Saving processed sequences to models/ directory...")
    with open(save_dir / "behavior_train_normal.pkl", "wb") as f:
        pickle.dump(X_normal, f)
        
    with open(save_dir / "behavior_test_attacks.pkl", "wb") as f:
        pickle.dump(X_anomalous, f)

    logger.info("✅ Data cleaning complete. You can now update train_behavior.py to load these pickles!")

if __name__ == "__main__":
    main()
