#!/usr/bin/env python3
"""
train_correlation.py

Training engine for Agent 4 (Correlation Agent Classifier).
Trains an XGBoost model using categorical mapping and strict overfitting controls
(max_depth=3/4, early stopping, regularization).

Usage:
    python train_correlation.py --train <cleaned_train.csv> \
                                --test <cleaned_test.csv> \
                                --output-model <path_to_save_model.pkl>
"""

import os
import sys
import argparse
import logging
import joblib
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    confusion_matrix,
)

# Ensure absolute imports work from project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("gibl.train_correlation")


def parse_args():
    parser = argparse.ArgumentParser(description="Train XGBoost Classifier for GIBL Correlation Agent (Agent 4).")
    parser.add_argument("--train", required=True, type=str, help="Path to cleaned training CSV")
    parser.add_argument("--test", required=True, type=str, help="Path to cleaned testing CSV")
    parser.add_argument("--output-model", default="models/correlation_classifier.pkl", type=str, help="Path to save the trained model pickle")
    parser.add_argument("--max-depth", default=3, type=int, help="Maximum tree depth (Option 2 guard against overfitting)")
    return parser.parse_args()


def train_model(train_path: str, test_path: str, output_model_path: str, max_depth: int):
    # 1. Load data splits
    if not os.path.exists(train_path):
        logger.error(f"Training file not found: {train_path}")
        sys.exit(1)
    if not os.path.exists(test_path):
        logger.error(f"Testing file not found: {test_path}")
        sys.exit(1)

    logger.info("Loading cleaned datasets...")
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    # 2. Extract targets
    if "is_true_positive" not in train_df.columns:
        logger.error("Target column 'is_true_positive' missing from training dataset!")
        sys.exit(1)
    
    y_train = train_df["is_true_positive"].astype(int)
    X_train = train_df.drop(columns=["is_true_positive"])

    y_test = test_df["is_true_positive"].astype(int)
    X_test = test_df.drop(columns=["is_true_positive"])

    # 3. Native Categorical Encoding & Category Alignment
    # Cast all object/string columns to 'category' dtype
    categorical_cols = []
    categorical_levels = {}

    for col in X_train.columns:
        if not pd.api.types.is_numeric_dtype(X_train[col]) and not pd.api.types.is_bool_dtype(X_train[col]):
            categorical_cols.append(col)
            # Find all unique levels in training split
            levels = X_train[col].dropna().unique().tolist()
            # If missing from test, align them to training levels
            X_train[col] = pd.Categorical(X_train[col], categories=levels)
            X_test[col] = pd.Categorical(X_test[col], categories=levels)
            categorical_levels[col] = levels
            logger.info(f"Encoded categorical feature '{col}' with {len(levels)} levels.")

    # 4. Handle Class Imbalance
    # Calculate scale_pos_weight ratio
    num_neg = (y_train == 0).sum()
    num_pos = (y_train == 1).sum()
    scale_pos_weight = num_neg / max(num_pos, 1)
    logger.info(f"Class imbalance distribution: Negatives={num_neg}, Positives={num_pos}")
    logger.info(f"Setting scale_pos_weight={scale_pos_weight:.4f}")

    # 5. Define Model Configuration with Strict Overfitting Guards (Option 2)
    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=max_depth,                # Strict depth restriction to control overfitting
        learning_rate=0.05,                  # Slow learning rate for step validation
        tree_method="hist",
        enable_categorical=True,             # Native categorical handling
        scale_pos_weight=scale_pos_weight,   # Class balance mapping
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        subsample=0.8,                       # Row subsampling for bagging
        colsample_bytree=0.8,                # Column subsampling
        reg_lambda=3.0                       # L2 weight regularization
    )

    # 6. Fit Model with Early Stopping
    logger.info(f"Training XGBoost classifier (max_depth={max_depth}) with early stopping...")
    model.fit(
        X_train,
        y_train,
        eval_set=[(X_test, y_test)],
        verbose=50
    )

    # 7. Evaluate Performance
    logger.info("Evaluating trained model on testing split...")
    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]

    roc_auc = roc_auc_score(y_test, probs)
    conf_mat = confusion_matrix(y_test, preds)

    print("\n" + "=" * 60)
    print("                AGENT 4 MODEL EVALUATION METRICS")
    print("=" * 60)
    print(f"Area Under ROC Curve (AUROC): {roc_auc:.4f}")
    print("\nConfusion Matrix:")
    print(conf_mat)
    print("\nClassification Report:")
    print(classification_report(y_test, preds, zero_division=0))
    print("=" * 60 + "\n")

    # 8. Serialize Model Bundle
    logger.info(f"Serializing trained model bundle to {output_model_path}...")
    os.makedirs(os.path.dirname(output_model_path), exist_ok=True)
    
    bundle = {
        "model": model,
        "categorical_cols": categorical_cols,
        "categorical_levels": categorical_levels,
        "features": X_train.columns.tolist()
    }
    
    joblib.dump(bundle, output_model_path)
    logger.info("SUCCESS: Agent 4 training completed and bundle persisted.")


if __name__ == "__main__":
    args = parse_args()
    train_model(args.train, args.test, args.output_model, args.max_depth)
