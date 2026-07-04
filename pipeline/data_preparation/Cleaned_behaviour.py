#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

"""
Cleaned_behaviour.py

Script to parse and clean the two distinct behavioral datasets:
1. User Behavior Dataset
2. Windows Event Logs Dataset

It outputs three standardized CSV files:
- cleaned_dataset_1_train.csv (80% of dataset 1 for training)
- cleaned_dataset_2_train.csv (80% of dataset 2 for training)
- cleaned_dataset_test.csv (20% of dataset 1 + 20% of dataset 2, combined for testing)

Usage:
    python Cleaned_behaviour.py <dataset_1.csv> <dataset_2.csv> <output_dir>
"""

import sys
import logging
from pathlib import Path
import pandas as pd
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

def parse_bool(col: pd.Series) -> pd.Series:
    return col.astype(str).str.strip().str.lower().map({
        'true': True, '1': True, '1.0': True, 
        'false': False, '0': False, '0.0': False
    }).fillna(False)

def clean_dataset_1(df: pd.DataFrame) -> pd.DataFrame:
    logger.info("Cleaning Dataset 1 (User Behavior)...")
    # Clean missing values
    df = df.replace(['-', '', ' '], np.nan)
    
    out = pd.DataFrame()
    out['dataset_source'] = [1] * len(df)
    out['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    out['username'] = df['username'].astype(str)
    out['source_ip'] = df['source_ip'].astype(str)
    out['event_id'] = pd.to_numeric(df['event_id'], errors='coerce').fillna(-1)
    out['is_anomaly'] = parse_bool(df['is_anomaly'])
    
    # Dataset-specific features
    out['ds1_bytes_transferred'] = pd.to_numeric(df['bytes_transferred'], errors='coerce').fillna(0)
    out['ds1_duration_sec'] = pd.to_numeric(df['duration_sec'], errors='coerce').fillna(0)
    out['ds1_is_off_hours'] = parse_bool(df['is_off_hours']).astype(float)
    out['ds1_is_new_resource'] = parse_bool(df['is_new_resource']).astype(float)
    out['ds1_failed_attempts'] = pd.to_numeric(df['failed_attempts_prior_1h'], errors='coerce').fillna(0)
    out['ds1_peer_deviation'] = pd.to_numeric(df['peer_group_deviation_score'], errors='coerce').fillna(0)
    
    # Fill DS2 features with defaults for this dataset
    out['ds2_logon_type'] = -1
    out['ds2_target_username'] = 'unknown'
    out['ds2_process_name'] = 'unknown'
    
    out = out.dropna(subset=['timestamp', 'username'])
    return out

def clean_dataset_2(df: pd.DataFrame) -> pd.DataFrame:
    logger.info("Cleaning Dataset 2 (Windows Event Logs)...")
    df = df.replace(['-', '', ' '], np.nan)
    
    out = pd.DataFrame()
    out['dataset_source'] = [2] * len(df)
    out['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    
    # Map subject_username to username
    out['username'] = df['subject_username'].astype(str)
    out['source_ip'] = df['source_ip'].astype(str)
    out['event_id'] = pd.to_numeric(df['event_id'], errors='coerce').fillna(-1)
    out['is_anomaly'] = parse_bool(df['is_anomaly'])
    
    # Dataset-specific features
    out['ds1_bytes_transferred'] = 0.0
    out['ds1_duration_sec'] = 0.0
    out['ds1_is_off_hours'] = 0.0
    out['ds1_is_new_resource'] = 0.0
    out['ds1_failed_attempts'] = 0.0
    out['ds1_peer_deviation'] = 0.0
    
    # Specific Windows Event features
    out['ds2_logon_type'] = pd.to_numeric(df['logon_type'], errors='coerce').fillna(-1)
    out['ds2_target_username'] = df['target_username'].astype(str)
    out['ds2_process_name'] = df['process_name'].astype(str)
    
    out = out.dropna(subset=['timestamp', 'username'])
    return out

def main():
    if len(sys.argv) < 4:
        print("Usage: python Cleaned_behaviour.py <dataset_1.csv> <dataset_2.csv> <output_dir>")
        sys.exit(1)
        
    ds1_path = Path(sys.argv[1])
    ds2_path = Path(sys.argv[2])
    out_dir = Path(sys.argv[3])
    
    if not ds1_path.exists():
        logger.error(f"Dataset 1 not found: {ds1_path}")
        sys.exit(1)
    if not ds2_path.exists():
        logger.error(f"Dataset 2 not found: {ds2_path}")
        sys.exit(1)
        
    out_dir.mkdir(parents=True, exist_ok=True)
    
    df1 = pd.read_csv(ds1_path)
    clean_df1 = clean_dataset_1(df1).sort_values('timestamp')
    
    df2 = pd.read_csv(ds2_path)
    clean_df2 = clean_dataset_2(df2).sort_values('timestamp')
    
    # 80/20 Split
    split_idx_1 = int(len(clean_df1) * 0.8)
    split_idx_2 = int(len(clean_df2) * 0.8)
    
    train_df1 = clean_df1.iloc[:split_idx_1]
    test_df1 = clean_df1.iloc[split_idx_1:]
    
    train_df2 = clean_df2.iloc[:split_idx_2]
    test_df2 = clean_df2.iloc[split_idx_2:]
    
    # Output 2 training files
    out_train_1 = out_dir / "cleaned_dataset_1_train.csv"
    train_df1.to_csv(out_train_1, index=False)
    logger.info(f"Saved {len(train_df1)} training rows to {out_train_1}")
    
    out_train_2 = out_dir / "cleaned_dataset_2_train.csv"
    train_df2.to_csv(out_train_2, index=False)
    logger.info(f"Saved {len(train_df2)} training rows to {out_train_2}")
    
    # Output 1 combined testing file
    test_df_combined = pd.concat([test_df1, test_df2]).sort_values('timestamp')
    out_test = out_dir / "cleaned_dataset_test.csv"
    test_df_combined.to_csv(out_test, index=False)
    logger.info(f"Saved {len(test_df_combined)} combined testing rows to {out_test}")
    
    logger.info("✅ Cleaning and splitting completed successfully.")

if __name__ == "__main__":
    main()
