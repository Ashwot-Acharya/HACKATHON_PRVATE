import os
import time
import json
import warnings
from datetime import datetime

import numpy as np
import pandas as pd
import xgboost as xgb
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score, roc_curve, precision_recall_fscore_support

try:
    from agents.flow_agent_track_d.flow_utils import (
        NUMERIC_COLS, CATEGORICAL_COLS, BOOL_COLS, ALL_FEATURE_COLS,
        freq_encode_fit, freq_encode_apply
    )
    from agents.flow_agent_track_d.data_processing import process_data
except ModuleNotFoundError:
    from flow_utils import (
        NUMERIC_COLS, CATEGORICAL_COLS, BOOL_COLS, ALL_FEATURE_COLS,
        freq_encode_fit, freq_encode_apply
    )
    from data_processing import process_data

warnings.filterwarnings("ignore", category=FutureWarning)

OUTPUT_DIR = "models"
RANDOM_SEED = 42
TRAIN_QUANTILE = 0.70          
VAL_QUANTILE = 0.85
XGB_DEVICE = "cuda"            
IF_SEEDS_FOR_VARIANCE = [42, 43, 44]

def train_xgboost(nf, masks):
    X_train = nf.loc[masks["train"], ALL_FEATURE_COLS]
    y_train = nf.loc[masks["train"], "is_attack"].astype(int)
    X_val = nf.loc[masks["val"], ALL_FEATURE_COLS]
    y_val = nf.loc[masks["val"], "is_attack"].astype(int)

    scale_pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
    print(f"[xgb] scale_pos_weight={scale_pos_weight:.2f}")

    print("\n[xgb] --- Running 5-Fold Stratified CV on Training Data ---")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    cv_aurocs = []
    
    robust_params = {
        "n_estimators": 50,
        "max_depth": 4,
        "learning_rate": 0.1,
        "tree_method": "hist",
        "device": XGB_DEVICE,
        "enable_categorical": True,
        "scale_pos_weight": scale_pos_weight,
        "eval_metric": "aucpr",
        "random_state": RANDOM_SEED,
        "n_jobs": -1,
        "subsample": 0.6,
        "colsample_bytree": 0.6,
        "reg_lambda": 2.0,
    }
    
    for fold, (train_idx, val_idx) in enumerate(skf.split(X_train, y_train)):
        X_fold_train, X_fold_val = X_train.iloc[train_idx], X_train.iloc[val_idx]
        y_fold_train, y_fold_val = y_train.iloc[train_idx], y_train.iloc[val_idx]
        
        cv_model = xgb.XGBClassifier(early_stopping_rounds=10, **robust_params)
        cv_model.set_params(random_state=RANDOM_SEED + fold)
        
        cv_model.fit(X_fold_train, y_fold_train, eval_set=[(X_fold_val, y_fold_val)], verbose=False)
        preds = cv_model.predict_proba(X_fold_val)[:, 1]
        auroc = roc_auc_score(y_fold_val, preds)
        
        print(f"[xgb] Fold {fold+1}: AUROC={auroc:.4f}")
        cv_aurocs.append(auroc)
        
    print(f"[xgb] CV AUROC: {np.mean(cv_aurocs):.4f} \u00b1 {np.std(cv_aurocs):.4f}")
    print("[xgb] ---------------------------------------------------\n")

    print("[xgb] Training final production model...")
    robust_params["n_estimators"] = 400
    model = xgb.XGBClassifier(early_stopping_rounds=50, **robust_params)
    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=50)
    print(f"[xgb] best_iteration={model.best_iteration}")
    return model

def build_if_matrix(nf, mask, freq_maps, scaler=None, fit_scaler=False):
    num_bool = nf.loc[mask, NUMERIC_COLS + BOOL_COLS].astype(float)
    freq = freq_encode_apply(nf.loc[mask], CATEGORICAL_COLS, freq_maps)
    X = pd.concat([num_bool.reset_index(drop=True), freq.reset_index(drop=True)], axis=1)
    if fit_scaler:
        scaler = StandardScaler().fit(X)
    X_scaled = scaler.transform(X)
    return X_scaled, scaler, X.columns.tolist()

def train_isolation_forest(nf, masks):
    freq_maps = freq_encode_fit(nf.loc[masks["if_train"]], CATEGORICAL_COLS)
    X_if_train, if_scaler, if_cols = build_if_matrix(nf, masks["if_train"], freq_maps, fit_scaler=True)
    X_if_val, _, _ = build_if_matrix(nf, masks["val"], freq_maps, scaler=if_scaler)
    y_val = nf.loc[masks["val"], "is_attack"].astype(int).values

    print(f"[iso] fitting on {X_if_train.shape[0]} rows (unsupervised, labeled+unlabeled)")

    seed_aurocs = []
    for seed in IF_SEEDS_FOR_VARIANCE:
        m = IsolationForest(n_estimators=300, contamination=0.018, n_jobs=-1, random_state=seed)
        m.fit(X_if_train)
        score = -m.score_samples(X_if_val)
        auroc = roc_auc_score(y_val, score)
        seed_aurocs.append(auroc)
        print(f"[iso] seed={seed} val_AUROC={auroc:.4f}")
    print(f"[iso] mean_AUROC={np.mean(seed_aurocs):.4f}  std={np.std(seed_aurocs):.4f}")

    iso_forest = IsolationForest(n_estimators=300, contamination=0.018, n_jobs=-1, random_state=RANDOM_SEED)
    iso_forest.fit(X_if_train)

    return iso_forest, if_scaler, freq_maps, if_cols, {"seed_aurocs": seed_aurocs}

def find_best_threshold_f1(y_true, scores):
    best_thr, best_f1 = 0.5, -1
    for thr in np.arange(0.01, 1.00, 0.01):
        pred = (scores >= thr).astype(int)
        p, r, f1, _ = precision_recall_fscore_support(y_true, pred, average="binary", zero_division=0)
        if f1 > best_f1:
            best_f1, best_thr = f1, thr
    return best_thr, best_f1

def find_threshold_at_fpr(y_true, scores, target_fpr=0.05):
    fpr, tpr, thr = roc_curve(y_true, scores)
    idx = np.searchsorted(fpr, target_fpr, side="right") - 1
    idx = max(idx, 0)
    return thr[idx], fpr[idx], tpr[idx]

def evaluate(y_true, scores, thr):
    pred = (scores >= thr).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(y_true, pred, average="binary", zero_division=0)
    auroc = roc_auc_score(y_true, scores)
    return {"auroc": auroc, "precision": p, "recall": r, "f1": f1, "threshold": float(thr)}

def norm(x, lo, hi):
    return (x - lo) / (hi - lo + 1e-9)

def blend_search(xgb_val, if_val, y_val):
    xgb_min, xgb_max = xgb_val.min(), xgb_val.max()
    if_min, if_max = if_val.min(), if_val.max()
    results = []
    for alpha in np.arange(0.0, 1.01, 0.05):
        blended = alpha * norm(xgb_val, xgb_min, xgb_max) + (1 - alpha) * norm(if_val, if_min, if_max)
        auroc = roc_auc_score(y_val, blended)
        results.append((round(alpha, 2), auroc))
    best_alpha = max(results, key=lambda r: r[1])[0]
    print(f"[blend] best_alpha={best_alpha}")
    return best_alpha, (xgb_min, xgb_max), (if_min, if_max), results

def measure_latency(model, X_sample, n_reps=500):
    times = []
    row = X_sample.iloc[[0]]
    for _ in range(n_reps):
        t0 = time.perf_counter()
        model.predict_proba(row)
        times.append((time.perf_counter() - t0) * 1000)
    times = np.array(times)
    return {"mean_ms": float(times.mean()), "p95_ms": float(np.percentile(times, 95))}

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    np.random.seed(RANDOM_SEED)

    nf, masks, categorical_levels = process_data(
        train_quantile=TRAIN_QUANTILE, val_quantile=VAL_QUANTILE
    )

    xgb_model = train_xgboost(nf, masks)
    iso_forest, if_scaler, freq_maps, if_cols, if_variance = train_isolation_forest(nf, masks)

    X_val = nf.loc[masks["val"], ALL_FEATURE_COLS]
    y_val = nf.loc[masks["val"], "is_attack"].astype(int).values
    X_test = nf.loc[masks["test"], ALL_FEATURE_COLS]
    y_test = nf.loc[masks["test"], "is_attack"].astype(int).values

    xgb_val_p = xgb_model.predict_proba(X_val)[:, 1]
    xgb_test_p = xgb_model.predict_proba(X_test)[:, 1]

    X_if_val, _, _ = build_if_matrix(nf, masks["val"], freq_maps, scaler=if_scaler)
    X_if_test, _, _ = build_if_matrix(nf, masks["test"], freq_maps, scaler=if_scaler)
    if_val_score = -iso_forest.score_samples(X_if_val)
    if_test_score = -iso_forest.score_samples(X_if_test)

    best_alpha, xgb_minmax, if_minmax, blend_grid = blend_search(xgb_val_p, if_val_score, y_val)

    blended_val = best_alpha * norm(xgb_val_p, *xgb_minmax) + (1 - best_alpha) * norm(if_val_score, *if_minmax)
    blended_test = best_alpha * norm(xgb_test_p, *xgb_minmax) + (1 - best_alpha) * norm(if_test_score, *if_minmax)

    thr_f1, val_f1 = find_best_threshold_f1(y_val, blended_val)
    thr_fpr5, achieved_fpr, achieved_tpr = find_threshold_at_fpr(y_val, blended_val, target_fpr=0.05)
    print(f"[thresholds] thr_f1={thr_f1:.3f} (val_f1={val_f1:.4f})  "
          f"thr_fpr5={thr_fpr5:.3f} (achieved_fpr={achieved_fpr:.4f}, tpr={achieved_tpr:.4f})")

    val_metrics = evaluate(y_val, blended_val, thr_f1)
    test_metrics = evaluate(y_test, blended_test, thr_f1)
    test_metrics_fpr5 = evaluate(y_test, blended_test, thr_fpr5)

    print("\n=== FINAL TEST METRICS (thr = val-selected F1 threshold) ===")
    print(json.dumps(test_metrics, indent=2))

    latency = measure_latency(xgb_model, X_test)
    print(f"\n[latency] mean={latency['mean_ms']:.2f}ms  p95={latency['p95_ms']:.2f}ms")

    bundle = {
        "model_version": f"v2_track_d_{datetime.now():%Y%m%d_%H%M%S}",
        "xgb_model": xgb_model,
        "iso_forest": iso_forest,
        "if_scaler": if_scaler,
        "if_freq_maps": freq_maps,
        "categorical_levels": categorical_levels,
        "feature_cols": {"numeric": NUMERIC_COLS, "categorical": CATEGORICAL_COLS, "bool": BOOL_COLS},
        "thresholds": {"f1": float(thr_f1), "fpr5": float(thr_fpr5)},
        "blend": {"alpha": float(best_alpha), "xgb_minmax": xgb_minmax, "if_minmax": if_minmax, "grid": blend_grid},
        "business_rules": {"honeypot_override": True},
        "split_boundaries": {"t_train_end": str(masks["t_train_end"]), "t_val_end": str(masks["t_val_end"])},
        "metrics": {"val": val_metrics, "test": test_metrics, "test_fpr5": test_metrics_fpr5,
                    "if_variance": if_variance, "latency": latency},
        "labeled_flow_ids": {
            "train": nf.loc[masks["train"], "flow_id"].tolist(),
            "val": nf.loc[masks["val"], "flow_id"].tolist(),
            "test": nf.loc[masks["test"], "flow_id"].tolist(),
        }
    }
    out_path = os.path.join(OUTPUT_DIR, f"{bundle['model_version']}.pkl")
    joblib.dump(bundle, out_path)
    print(f"\n[save] bundle written to {out_path}")
    print("\n[success] Training complete. Run inference using inference.py")

if __name__ == "__main__":
    main()
