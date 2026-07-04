"""Recalibrate FlowAgent thresholds using CICIDS benign samples.

Usage examples:
  # Use existing regime pickles under MODELS_DIR (default)
  python3 scripts/recalibrate_thresholds.py

  # Recompute using a CICIDS CSV and save thresholds back to models dir
  python3 scripts/recalibrate_thresholds.py --cicids-csv data/Wednesday-workingHours.pcap_ISCX.csv

The script will:
  - load persisted context IsolationForest models and scaler
  - load benign_by_regime (from MODELS_DIR or from --cicids-csv)
  - compute per-regime raw scores and set thresholds at the percentile
    that corresponds to the saved `target_ctx_fpr` (defaults)
  - save updated `flow_thresholds.pkl` back to the models directory

This is a non-destructive helper: it prints a summary before persisting.
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path
import pprint

import joblib
import numpy as np
import pandas as pd

from pipeline.ingestion import prepare_cicids, load_regime_data
from config import MODELS_DIR


def load_models(models_dir: Path):
    base = Path(models_dir)
    ctx = joblib.load(base / "flow_context_models.pkl")
    global_model = joblib.load(base / "flow_global_model.pkl")
    scaler = joblib.load(base / "flow_scaler.pkl")
    thresholds = joblib.load(base / "flow_thresholds.pkl")
    return ctx, global_model, scaler, thresholds


def compute_thresholds(models_dir: Path, cicids_csv: Path | None = None):
    base = Path(models_dir)
    ctx_models, global_model, scaler, thresholds = load_models(base)

    # Load or prepare benign_by_regime
    if cicids_csv:
        benign_by_regime, attacks = prepare_cicids(cicids_csv, save_to=base)
    else:
        benign_by_regime = load_regime_data(models_dir=base)
        attacks_path = base / "attack_flows.pkl"
        attacks = pd.read_pickle(attacks_path) if attacks_path.exists() else None

    summary = {}
    for regime, df in benign_by_regime.items():
        if df is None or len(df) == 0:
            print(f"Skipping empty regime: {regime}")
            continue
        clean = df[["Flow Duration", "Total Fwd Packets", "Destination Port"]].copy()
        clean.replace([np.inf, -np.inf], np.nan, inplace=True)
        for c in ["Flow Duration", "Total Fwd Packets", "Destination Port"]:
            if clean[c].isna().any():
                clean[c] = clean[c].fillna(clean[c].median())

        X = scaler.transform(clean.values)
        model = ctx_models.get(regime, ctx_models.get("normal"))
        raw_scores = -model.score_samples(X)

        # Determine percentile to match target_ctx_fpr if present
        target_fpr = thresholds.get("target_ctx_fpr", {}).get(regime)
        if target_fpr is None:
            # fallback to existing global percentile if available
            gp = thresholds.get("global_fpr_percentile", {}).get(regime, 99.0)
            perc = float(gp)
        else:
            perc = float((1.0 - float(target_fpr)) * 100.0)

        new_thr = float(np.percentile(raw_scores, perc))

        # Estimate detection rate against saved attacks if present
        est_dr = None
        if attacks is not None and len(attacks) > 0:
            clean_att = attacks[["Flow Duration", "Total Fwd Packets", "Destination Port"]].copy()
            clean_att.replace([np.inf, -np.inf], np.nan, inplace=True)
            for c in ["Flow Duration", "Total Fwd Packets", "Destination Port"]:
                if clean_att[c].isna().any():
                    clean_att[c] = clean_att[c].fillna(clean_att[c].median())
            X_att = scaler.transform(clean_att.values)
            att_raw = -model.score_samples(X_att)
            est_dr = float((att_raw > new_thr).sum()) / max(len(att_raw), 1)

        summary[regime] = {
            "old_thr": thresholds.get("thr_fpr", {}).get(regime),
            "new_thr": new_thr,
            "percentile_used": perc,
            "est_detection_rate": est_dr,
            "n_benign": len(raw_scores),
        }

        # update thresholds dict
        thresholds.setdefault("thr_fpr", {})[regime] = new_thr
        if est_dr is not None:
            thresholds.setdefault("thr_dr", {})[regime] = est_dr

    # Print summary
    print("Recalibration summary:")
    pprint.pprint(summary)

    # Persist updated thresholds (backup existing)
    bak = base / "flow_thresholds.pkl.bak"
    (base / "flow_thresholds.pkl").rename(bak)
    joblib.dump(thresholds, base / "flow_thresholds.pkl")
    print(f"Saved updated thresholds to {base / 'flow_thresholds.pkl'} (backup at {bak})")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--models-dir", default=str(MODELS_DIR))
    p.add_argument("--cicids-csv", default=None,
                   help="Optional path to CICIDS CSV for fresh benign_by_regime")
    args = p.parse_args()

    models_dir = Path(args.models_dir)
    cicids_csv = Path(args.cicids_csv) if args.cicids_csv else None

    if not models_dir.exists():
        raise SystemExit(f"Models dir not found: {models_dir}")

    compute_thresholds(models_dir, cicids_csv)


if __name__ == "__main__":
    main()
