#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

"""
clean_packet.py

Cleans a custom Zeek connection log CSV dataset to ensure it is 
ready for training the Packet Agent via train_packet.py.

Usage:
    python clean_packet.py /path/to/raw_zeek_logs.csv /path/to/cleaned_zeek_logs.csv
"""

import sys
import logging
from pathlib import Path
import pandas as pd
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

def clean_zeek_csv(input_path: Path, output_path: Path):
    logger.info(f"Loading Zeek logs from {input_path}...")
    
    # Read the dataset
    df = pd.read_csv(input_path)
    
    # In Zeek logs, missing values are often represented as '-'
    df = df.replace('-', np.nan)
    # Also replace empty strings or spaces
    df = df.replace(r'^\s*$', np.nan, regex=True)
    
    # Required columns for train_packet.py
    required_cols = [
        'duration', 'orig_bytes', 'resp_bytes', 
        'orig_pkts', 'resp_pkts', 'proto', 'id_resp_p', 'is_anomaly'
    ]
    
    # Check if all required columns exist
    missing = [col for col in required_cols if col not in df.columns]
    if missing:
        logger.error(f"Dataset is missing required columns: {missing}")
        sys.exit(1)
        
    logger.info("Cleaning numeric columns...")
    numeric_cols = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts', 'id_resp_p']
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')
        
    logger.info("Standardizing 'is_anomaly' column...")
    # Convert 'true'/'false' strings to boolean
    df['is_anomaly'] = df['is_anomaly'].astype(str).str.strip().str.lower()
    df['is_anomaly'] = df['is_anomaly'].map({'true': True, '1': True, '1.0': True, 'false': False, '0': False, '0.0': False}).fillna(False)
    
    # Drop rows where protocol or destination port is completely missing
    df = df.dropna(subset=['proto', 'id_resp_p'])
    
    logger.info(f"Cleaned dataset shape: {df.shape}")
    logger.info(f"Class distribution - Normal: {(df['is_anomaly'] == False).sum()}, Malicious: {(df['is_anomaly'] == True).sum()}")
    
    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Save the cleaned dataset
    logger.info(f"Saving cleaned dataset to {output_path}...")
    df.to_csv(output_path, index=False)
    logger.info("✅ Dataset cleaned successfully! You can now use it with train_packet.py")

def main():
    if len(sys.argv) < 3:
        print("Usage: python clean_packet.py <input_csv> <output_csv>")
        sys.exit(1)
        
    input_csv = Path(sys.argv[1])
    output_csv = Path(sys.argv[2])
    
    if not input_csv.exists():
        logger.error(f"Input file not found: {input_csv}")
        sys.exit(1)
        
    clean_zeek_csv(input_csv, output_csv)

if __name__ == "__main__":
    main()
