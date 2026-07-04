#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pickle
import logging
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import KFold
from sklearn.metrics import recall_score

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

MODELS_DIR = Path("models")

REGIME_CONTAMINATION = {
    "month_end": 1e-3, 
    "atm_recon": 5e-4, 
    "rtgs":      5e-4,
    "off_hours": 1e-4, 
    "weekend":   1e-4, 
    "normal":    5e-4
}


def extract_features(df):
    numeric_df = df.select_dtypes(include=['number', 'bool'])
    cols = [c for c in numeric_df.columns if c not in ["label", "regime", "dataset_source", "flow_label"]]
    return sorted(cols)

def main():
    if not (MODELS_DIR / "benign_by_regime.pkl").exists() or not (MODELS_DIR / "attack_df.pkl").exists():
        logger.error("Missing benign_by_regime.pkl or attack_df.pkl. Run clean_flow.py first.")
        sys.exit(1)

    logger.info("Loading regime data and attack data...")
    with open(MODELS_DIR / "benign_by_regime.pkl", "rb") as f:
        benign_by_regime = pickle.load(f)
    with open(MODELS_DIR / "attack_df.pkl", "rb") as f:
        attack_df = pickle.load(f)

    logger.info(f"Loaded {len(benign_by_regime)} regimes and {len(attack_df)} attacks.")

    kf = KFold(n_splits=5, shuffle=True, random_state=42)
    
    cv_fpr = []
    cv_dr = []

    logger.info("\n" + "="*50)
    logger.info("Starting 5-Fold Cross Validation")
    logger.info("="*50)

    # 5-fold Cross validation across ALL data to get global Detection Rates
    all_benign_list = []
    first_regime_df = list(benign_by_regime.values())[0]
    feature_cols = extract_features(first_regime_df)

    for regime, df in benign_by_regime.items():
        all_benign_list.append(df[feature_cols])
    
    all_benign_df = pd.concat(all_benign_list, ignore_index=True)
    X_benign_all = all_benign_df.values
    
    # Ensure attack_df uses the exact same numeric feature columns
    X_attack_all = attack_df[feature_cols].values if not attack_df.empty else np.array([])

    if len(X_attack_all) > 0:
        fold = 1
        # Split benign and attack into 5 folds
        benign_splits = list(kf.split(X_benign_all))
        attack_splits = list(kf.split(X_attack_all))

        for (b_train_idx, b_test_idx), (a_train_idx, a_test_idx) in zip(benign_splits, attack_splits):
            X_b_train = X_benign_all[b_train_idx]
            X_b_test = X_benign_all[b_test_idx]
            X_a_test = X_attack_all[a_test_idx]

            # Fit Scaler
            scaler_cv = StandardScaler()
            X_b_train_scaled = scaler_cv.fit_transform(X_b_train)
            X_b_test_scaled = scaler_cv.transform(X_b_test)
            X_a_test_scaled = scaler_cv.transform(X_a_test)

            # Fit Global Isolation Forest for CV eval
            clf = IsolationForest(n_estimators=200, contamination=5e-4, random_state=42, n_jobs=-1)
            clf.fit(X_b_train_scaled)

            # Dynamically compute threshold based on 99.0th percentile of training scores
            b_train_scores = -clf.score_samples(X_b_train_scaled)
            threshold = float(np.percentile(b_train_scores, 99.0))

            # Evaluate using custom threshold
            b_test_scores = -clf.score_samples(X_b_test_scaled)
            a_test_scores = -clf.score_samples(X_a_test_scaled)

            fpr = (b_test_scores > threshold).sum() / len(b_test_scores)
            dr = (a_test_scores > threshold).sum() / len(a_test_scores)

            cv_fpr.append(fpr)
            cv_dr.append(dr)

            logger.info(f"Fold {fold} | False Positive Rate: {fpr:.4%} | Detection Rate: {dr:.4%}")
            fold += 1

        logger.info("-" * 50)
        logger.info(f"Average FPR: {np.mean(cv_fpr):.4%} ± {np.std(cv_fpr):.4%}")
        logger.info(f"Average DR:  {np.mean(cv_dr):.4%} ± {np.std(cv_dr):.4%}")
        logger.info("=" * 50 + "\n")
    else:
        logger.warning("No attack data found! Skipping CV Detection Rate evaluation.")

    # ---------------------------------------------------------
    # FINAL MODEL TRAINING (on all data)
    # ---------------------------------------------------------
    logger.info("Training final production models on all available data...")

    scaler = StandardScaler()
    X_all_scaled = scaler.fit_transform(X_benign_all)
    
    logger.info("Training Global Isolation Forest model...")
    global_model = IsolationForest(
        n_estimators=200, 
        contamination=5e-4, 
        random_state=42,
        n_jobs=-1
    )
    global_model.fit(X_all_scaled)

    context_models = {}
    thresholds = {}
    
    raw_global_scores = -global_model.score_samples(X_all_scaled)
    thresholds["normal"] = float(np.percentile(raw_global_scores, 99.0))

    for regime, df in benign_by_regime.items():
        logger.info(f"Training context model for '{regime}' ({len(df):,} rows)...")
        X_regime = df[feature_cols].values
        X_scaled = scaler.transform(X_regime)
        
        contam = REGIME_CONTAMINATION.get(regime, 5e-4)
        model = IsolationForest(
            n_estimators=300, 
            contamination=contam, 
            random_state=42,
            n_jobs=-1
        )
        model.fit(X_scaled)
        context_models[regime] = model
        
        raw_scores = -model.score_samples(X_scaled)
        threshold = float(np.percentile(raw_scores, 99.0))
        thresholds[regime] = threshold
        logger.info(f"  -> Threshold set at {threshold:.4f}")

    logger.info("Saving trained models to models/ directory...")
    thresholds["thr_fpr"] = {k: v for k, v in thresholds.items() if isinstance(v, float)}
    thresholds["thr_dr"] = {k: v for k, v in thresholds.items() if isinstance(v, float)}
    
    joblib.dump(scaler, MODELS_DIR / "flow_scaler.pkl")
    joblib.dump(global_model, MODELS_DIR / "flow_global_model.pkl")
    joblib.dump(context_models, MODELS_DIR / "flow_context_models.pkl")
    joblib.dump(thresholds, MODELS_DIR / "flow_thresholds.pkl")
    
    logger.info("✅ Flow models successfully trained and saved!")

if __name__ == "__main__":
    main()
