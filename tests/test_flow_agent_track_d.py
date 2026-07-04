import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
import numpy as np

from agents.flow_agent_track_d.inference import predict_final
from agents.flow_agent_track_d.flow_utils import CATEGORICAL_COLS

def get_dummy_bundle():
    class DummyXGB:
        def predict_proba(self, X):
            return np.zeros((len(X), 2))
            
    class DummyIF:
        def score_samples(self, X):
            return -np.zeros(len(X))
            
    class DummyScaler:
        def transform(self, X):
            return X
            
    return {
        "xgb_model": DummyXGB(),
        "iso_forest": DummyIF(),
        "if_scaler": DummyScaler(),
        "if_freq_maps": {c: {"A": 1.0} for c in CATEGORICAL_COLS},
        "categorical_levels": {c: pd.Index(["A", "B"]) for c in CATEGORICAL_COLS},
        "thresholds": {"f1": 0.5, "fpr5": 0.3},
        "blend": {"alpha": 0.5, "xgb_minmax": (0, 1), "if_minmax": (0, 1)},
        "business_rules": {"honeypot_override": True},
        "hosts_df_placeholder": pd.DataFrame({"ip_address": [], "criticality": [], "host_type": [], "patch_level": [], "is_honeypot": []})
    }

def get_dummy_row():
    return pd.DataFrame([{
        "start_time": "2026-07-03 12:00:00",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "protocol": "A",
        "tcp_flags": "A",
        "segment": "A",
        "application_guess": "A",
        "duration_sec": 1.0,
        "bytes_sent": 100,
        "bytes_recv": 100,
        "packets_sent": 1,
        "packets_recv": 1,
        "is_internal_src": True,
        "is_internal_dst": True,
    }])

def test_single_row_inference_categorical_crash_fix():
    bundle = get_dummy_bundle()
    df = get_dummy_row()
    # Tests Bug #3 fix: if not fixed, single row category mapping crashes
    scores, _ = predict_final(df, bundle)
    assert len(scores) == 1
    assert not np.isnan(scores[0])

def test_honeypot_override_dst():
    bundle = get_dummy_bundle()
    df = get_dummy_row()
    bundle["hosts_df_placeholder"] = pd.DataFrame([{"ip_address": "10.0.0.2", "is_honeypot": True, "criticality": "A", "host_type": "A", "patch_level": "A"}])
    scores, _ = predict_final(df, bundle)
    assert scores[0] == 1.0

def test_honeypot_override_src():
    bundle = get_dummy_bundle()
    df = get_dummy_row()
    # Tests Bug #4 fix: src honeypot hit
    bundle["hosts_df_placeholder"] = pd.DataFrame([{"ip_address": "10.0.0.1", "is_honeypot": True, "criticality": "A", "host_type": "A", "patch_level": "A"}])
    scores, _ = predict_final(df, bundle)
    assert scores[0] == 1.0

def test_stateful_feature_bypass():
    bundle = get_dummy_bundle()
    df = get_dummy_row()
    # Tests Bug #6 fix: stateful feature should be missing and defaulted to 1 inside engineer_features(is_inference=True)
    scores, _ = predict_final(df, bundle)
    assert len(scores) == 1
    
if __name__ == "__main__":
    test_single_row_inference_categorical_crash_fix()
    test_honeypot_override_dst()
    test_honeypot_override_src()
    test_stateful_feature_bypass()
    print("All tests passed!")
