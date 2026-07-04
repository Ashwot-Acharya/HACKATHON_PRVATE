import os
import joblib
import glob
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import shap

try:
    from agents.flow_agent_track_d.flow_utils import engineer_features
except ModuleNotFoundError:
    from flow_utils import engineer_features

print("Loading dataset...")
nf = pd.read_csv("data/netflow_records.csv")
labels = pd.read_csv("data/ids_labels_train.csv")
hosts = pd.read_csv("data/host_profiles.csv").drop_duplicates(subset="ip_address", keep="last")

nf["start_time"] = pd.to_datetime(nf["start_time"], format="%Y-%m-%d %H:%M:%S.%f")
labels["is_attack"] = labels["is_attack"].astype(bool)

df = nf.merge(labels[["flow_id", "is_attack"]], on="flow_id", how="left")
# Only use labeled rows for plotting
df_labeled = df[df["is_attack"].notna()].copy()

artifact_dir = r"C:\Users\Royas Shakya\.gemini\antigravity-ide\brain\ee251ac2-5c2b-458a-bc4e-cc3894facb87"
os.makedirs(artifact_dir, exist_ok=True)

# 1. Distribution Plot
print("Generating Distribution Plot...")
plt.figure(figsize=(10, 6))
# Clip extreme outliers for visual clarity on KDE
clip_val = df_labeled["bytes_recv"].quantile(0.95)
df_labeled["bytes_recv_clipped"] = df_labeled["bytes_recv"].clip(upper=clip_val)
sns.kdeplot(data=df_labeled, x="bytes_recv_clipped", hue="is_attack", common_norm=False, fill=True)
plt.title("Distribution of bytes_recv (Benign vs Attack)")
plt.xlabel("Bytes Received (clipped at 95th percentile)")
plt.ylabel("Density")
dist_path = os.path.join(artifact_dir, "bytes_recv_dist.png")
plt.savefig(dist_path, bbox_inches='tight')
plt.close()
print(f"Saved distribution plot to {dist_path}")

# 2. SHAP Plot
print("Loading model for SHAP...")
model_files = glob.glob("models/*.pkl")
if not model_files:
    print("No model found!")
    exit(1)
latest_model = max(model_files, key=os.path.getctime)
bundle = joblib.load(latest_model)
xgb_model = bundle["xgb_model"]
categorical_levels = bundle["categorical_levels"]
numeric = bundle["feature_cols"]["numeric"]
categorical = bundle["feature_cols"]["categorical"]
bool_cols = bundle["feature_cols"]["bool"]
all_cols = numeric + categorical + bool_cols

# We need engineered features for SHAP. We sample 1000 rows to make SHAP fast.
sample_df = engineer_features(df_labeled.sample(1000, random_state=42), hosts, is_inference=False)
# Apply categorical levels
for c in categorical:
    sample_df[c] = pd.Categorical(sample_df[c], categories=categorical_levels[c])

X_sample = sample_df[all_cols]

print("Computing SHAP values...")
explainer = shap.TreeExplainer(xgb_model)
shap_values = explainer(X_sample)

plt.figure(figsize=(10, 8))
shap.summary_plot(shap_values, X_sample, show=False)
plt.title("SHAP Summary Plot (Feature Impact on Predictions)")
shap_path = os.path.join(artifact_dir, "shap_summary.png")
plt.savefig(shap_path, bbox_inches='tight')
plt.close()
print(f"Saved SHAP plot to {shap_path}")

print("Done generating plots.")
