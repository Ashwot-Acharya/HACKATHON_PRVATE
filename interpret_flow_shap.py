import sys
import pickle
import joblib
import pandas as pd
import numpy as np
import shap
import logging
import matplotlib.pyplot as plt
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

MODELS_DIR = Path("models")

def main():
    if not (MODELS_DIR / "flow_global_model.pkl").exists():
        logger.error("Models not found. Run train_flow.py first.")
        sys.exit(1)

    logger.info("Loading Global Model and Scaler...")
    global_model = joblib.load(MODELS_DIR / "flow_global_model.pkl")
    scaler = joblib.load(MODELS_DIR / "flow_scaler.pkl")

    logger.info("Loading evaluation dataset...")
    with open(MODELS_DIR / "benign_by_regime.pkl", "rb") as f:
        benign_by_regime = pickle.load(f)
    with open(MODELS_DIR / "attack_df.pkl", "rb") as f:
        attack_df = pickle.load(f)

    # We will compute SHAP values on a mix of normal and attack data
    # Extract features from a regime
    first_regime_df = list(benign_by_regime.values())[0]
    numeric_df = first_regime_df.select_dtypes(include=['number', 'bool'])
    feature_cols = sorted([c for c in numeric_df.columns if c not in ["label", "regime", "dataset_source", "flow_label"]])

    # Take 500 normal samples and 500 attack samples for SHAP
    b_sample = first_regime_df[feature_cols].sample(n=min(500, len(first_regime_df)), random_state=42)
    
    if not attack_df.empty:
        a_sample = attack_df[feature_cols].sample(n=min(500, len(attack_df)), random_state=42)
        X_sample = pd.concat([b_sample, a_sample], ignore_index=True).values
    else:
        X_sample = b_sample.values

    X_scaled = scaler.transform(X_sample)

    logger.info("Computing SHAP values (this may take a moment)...")
    
    # IsolationForest uses TreeExplainer
    explainer = shap.TreeExplainer(global_model)
    shap_values = explainer.shap_values(X_scaled)
    
    # Calculate mean absolute SHAP values for global feature importance
    mean_abs_shap = np.mean(np.abs(shap_values), axis=0)
    
    # Map to feature names
    importance_dict = {feat: float(imp) for feat, imp in zip(feature_cols, mean_abs_shap)}
    sorted_importance = sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
    
    logger.info("\n==================================================")
    logger.info("Global Feature Importance (SHAP)")
    logger.info("==================================================")
    for feat, imp in sorted_importance:
        logger.info(f"  {feat:<20}: {imp:.5f}")
    logger.info("==================================================\n")

    logger.info("The model relies heavily on the top features above to detect anomalies.")
    logger.info("The result is reliable if these features intuitively correspond to attack patterns.")

    logger.info("Generating SHAP summary plot...")
    plt.figure(figsize=(10, 8))
    # SHAP summary plot for Isolation Forest
    shap.summary_plot(shap_values, X_sample, feature_names=feature_cols, show=False)
    plot_path = "shap_summary_plot.png"
    plt.savefig(plot_path, bbox_inches='tight')
    logger.info(f"SHAP summary plot saved to {plot_path}")

if __name__ == "__main__":
    main()
