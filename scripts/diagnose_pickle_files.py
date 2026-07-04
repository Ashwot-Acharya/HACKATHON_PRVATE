#!/usr/bin/env python3
"""Diagnose corrupted pickle files and suggest fixes."""

import pickle
import joblib
from pathlib import Path
import sys

MODELS_DIR = Path(__file__).parent.parent / "models"

FILES_TO_CHECK = [
    "packet_rf_ctu.pkl",
    "packet_rf_scaler.pkl",
    "packet_rf_features.json",
    "packet_xgb_cicids.pkl",
    "packet_xgb_scaler.pkl",
    "packet_xgb_features.json",
    "packet_xgb_threshold.pkl",
    "packet_metrics.json",
]

def diagnose():
    print(f"\n{'='*70}")
    print(f"Diagnosing pickle files in {MODELS_DIR}")
    print(f"{'='*70}\n")
    
    all_ok = True
    for fname in FILES_TO_CHECK:
        fpath = MODELS_DIR / fname
        
        if not fpath.exists():
            print(f"❌ {fname:<30} NOT FOUND")
            all_ok = False
            continue
        
        size_kb = fpath.stat().st_size / 1024
        print(f"✓  {fname:<30} {size_kb:>8.1f} KB", end="")
        
        # Try to read first few bytes to check format
        with open(fpath, "rb") as f:
            header = f.read(4)
        
        # Check pickle magic number
        if fname.endswith(".pkl"):
            if header in (b'\x80\x03', b'\x80\x04', b'\x80\x05'):
                print(f" [VALID pickle]")
            elif header in (b'\x80\x02', b'\x80\x01', b'\x80\x00'):
                print(f" [OLD pickle protocol - try loading with joblib]")
            else:
                # Try joblib load
                try:
                    obj = joblib.load(fpath)
                    print(f" [joblib load OK, type={type(obj).__name__}]")
                except Exception as e:
                    print(f" [CORRUPTED: {type(e).__name__}: {str(e)[:40]}]")
                    all_ok = False
                continue
            
            # Try to load
            try:
                with open(fpath, "rb") as f:
                    obj = pickle.load(f)
                print(f" [PICKLE VALID, type={type(obj).__name__}]")
            except Exception as e:
                print(f" [PICKLE ERROR: {type(e).__name__}: {str(e)[:40]}]")
                all_ok = False
        
        elif fname.endswith(".json"):
            import json
            try:
                with open(fpath) as f:
                    obj = json.load(f)
                print(f" [JSON OK]")
            except Exception as e:
                print(f" [JSON ERROR: {str(e)[:40]}]")
                all_ok = False
    
    print(f"\n{'='*70}")
    if all_ok:
        print("✓  All files are valid!")
    else:
        print("❌ Some files are corrupted or missing.")
        print("\nRECOMMENDED FIX:")
        print("  1. Re-download models from Colab notebook")
        print("  2. Ensure files are saved in BINARY mode (joblib.dump)")
        print("  3. Verify file transfer (not converted to text)")
        print("  4. Or: Create stub models for testing (see scripts/create_packet_stubs.py)")
    print(f"{'='*70}\n")
    
    return all_ok

if __name__ == "__main__":
    ok = diagnose()
    sys.exit(0 if ok else 1)
