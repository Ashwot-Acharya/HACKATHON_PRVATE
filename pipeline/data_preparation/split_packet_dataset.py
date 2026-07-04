#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

"""
split_packet_dataset.py

Splits a raw or cleaned Packet Agent CSV dataset into an 80% training 
dataset and a 20% testing dataset based on chronological order.

Usage:
    python split_packet_dataset.py <input_dataset.csv> <output_dir>
"""

import sys
import logging
from pathlib import Path
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

def main():
    if len(sys.argv) < 3:
        print("Usage: python split_packet_dataset.py <input_dataset.csv> <output_dir>")
        sys.exit(1)
        
    input_csv = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    
    if not input_csv.exists():
        logger.error(f"Input dataset not found: {input_csv}")
        sys.exit(1)
        
    out_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Loading dataset from {input_csv}...")
    df = pd.read_csv(input_csv)
    
    # Sort chronologically if a timestamp column exists
    if 'ts' in df.columns:
        logger.info("Sorting by 'ts' (timestamp) column for chronological split...")
        df['ts'] = pd.to_datetime(df['ts'], errors='coerce')
        df = df.sort_values(by='ts')
    elif 'timestamp' in df.columns:
        logger.info("Sorting by 'timestamp' column for chronological split...")
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.sort_values(by='timestamp')
    else:
        logger.warning("No 'ts' or 'timestamp' column found. Performing a raw split based on current row order.")
        
    split_idx = int(len(df) * 0.8)
    
    train_df = df.iloc[:split_idx]
    test_df = df.iloc[split_idx:]
    
    # Generate output filenames based on input filename
    base_name = input_csv.stem
    train_out = out_dir / f"{base_name}_train.csv"
    test_out = out_dir / f"{base_name}_test.csv"
    
    logger.info("Saving training dataset (80%)...")
    train_df.to_csv(train_out, index=False)
    logger.info(f" -> Saved {len(train_df)} rows to {train_out}")
    
    logger.info("Saving testing dataset (20%)...")
    test_df.to_csv(test_out, index=False)
    logger.info(f" -> Saved {len(test_df)} rows to {test_out}")
    
    logger.info("✅ Packet dataset successfully split!")

if __name__ == "__main__":
    main()
