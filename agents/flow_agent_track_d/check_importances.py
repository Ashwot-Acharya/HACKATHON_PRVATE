import joblib
import glob
import os

model_files = glob.glob("models/*.pkl")
if not model_files:
    print("No model found!")
    exit(1)
latest_model = max(model_files, key=os.path.getctime)
print(f"Loading {latest_model}")

bundle = joblib.load(latest_model)
xgb_model = bundle["xgb_model"]
all_cols = bundle["feature_cols"]["numeric"] + bundle["feature_cols"]["categorical"] + bundle["feature_cols"]["bool"]

importances = xgb_model.feature_importances_
for col, imp in sorted(zip(all_cols, importances), key=lambda x: x[1], reverse=True):
    print(f"{col:30} : {imp:.4f}")
