#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

"""
Standalone script to clean and prepare a custom flow CSV dataset for GIBL.

Usage:
    python cleandata.py path/to/your/custom_flows.csv
"""

import sys
import logging
from pathlib import Path
from pipeline.ingestion import prepare_custom_dataset

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

def main():
    if len(sys.argv) < 2:
        print("Usage: python cleandata.py <path_to_custom_csv>")
        sys.exit(1)

    csv_path = sys.argv[1]
    if not Path(csv_path).exists():
        logger.error(f"File not found: {csv_path}")
        sys.exit(1)

    logger.info(f"Starting custom data preparation for: {csv_path}")
    
    try:
        # This calls the function we added to pipeline/ingestion.py
        benign_by_regime, attacks = prepare_custom_dataset(csv_path)
        
        print("\n=== Data Preparation Summary ===")
        for regime, df in benign_by_regime.items():
            print(f"  {regime:12s}: {len(df):>8,} rows")
        print(f"  {'ATTACKS':12s}: {len(attacks):>8,} rows")
        print("================================\n")
        logger.info("Custom data preparation completed successfully. Pickles saved to models/ directory.")
        
    except Exception as e:
        logger.error(f"Failed to prepare custom dataset: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
