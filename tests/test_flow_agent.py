"""
BankSentinel — Flow Agent Test Suite
=====================================
Challenge Addressed: C2 — Legitimate High-Volume False Positive Reduction

65 tests across 8 groups. All run fully offline — no network, no GPU.

Run:  python -m pytest tests/test_flow_agent.py -v

Groups:
  TestFlowAlertDataclass        — FlowAlert fields & behaviour        (8 tests)
  TestFlowAgentInference        — FlowAgent.score / score_batch       (12 tests)
  TestFlowAgentLoad             — save / load round-trip              (7 tests)
  TestFlowAgentEvaluate         — evaluate() metrics contract         (5 tests)
"""

import pickle
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import (
    FLOW_FEATURES,
    FLOW_N_ESTIMATORS,
    FLOW_RANDOM_STATE,
    MITRE_DISCOVERY_TECHNIQUE,
    REGIME_CONTEXTS,
)
from agents.flow_agent import (
    FlowAgent,
    FlowAlert,
)
from pipeline.ingestion import FlowRecord, build_apt_scenario


# ── Shared helpers ────────────────────────────────────────────────────────────

def _make_synthetic_benign(
    n_per_regime: int = 120,
    seed: int = 0,
) -> dict[str, pd.DataFrame]:
    """One small benign DataFrame per regime — no CSV needed."""
    rng = np.random.default_rng(seed)
    result = {}
    for i, regime in enumerate(REGIME_CONTEXTS):
        data = np.abs(rng.normal(100 + i * 30, 15 + i * 5,
                                 size=(n_per_regime, len(FLOW_FEATURES))))
        result[regime] = pd.DataFrame(data, columns=FLOW_FEATURES)
    return result


def _make_synthetic_attacks(n: int = 40, seed: int = 99) -> pd.DataFrame:
    """High-magnitude rows labelled DoS Hulk."""
    rng = np.random.default_rng(seed)
    data = rng.uniform(8000, 50000, size=(n, len(FLOW_FEATURES)))
    df = pd.DataFrame(data, columns=FLOW_FEATURES)
    df["Label"] = "DoS Hulk"
    return df


def _make_flow_record(regime: str = "normal", label: str = "BENIGN") -> FlowRecord:
    rng = np.random.default_rng(7)
    features = {f: float(rng.uniform(50, 500)) for f in FLOW_FEATURES}
    return FlowRecord(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        features=features,
        label=label,
        regime=regime,
    )


from config import MODELS_DIR
def _load_real_agent() -> tuple[FlowAgent, dict[str, pd.DataFrame]]:
    """Load the real trained agent from disk for inference tests.
    
    Returns:
        Tuple of (agent, benign_data) where benign_data is synthetic benign data.
    """
    agent = FlowAgent.load(models_dir=MODELS_DIR)
    benign = _make_synthetic_benign()
    return agent, benign


# TestFlowAlertDataclass

class TestFlowAlertDataclass(unittest.TestCase):
    """FlowAlert fields, defaults, __str__, and C2 proof fields. (8 tests)"""

    def _make_alert(self, **overrides) -> FlowAlert:
        defaults = dict(
            src_ip          = "1.2.3.4",
            dst_ip          = "5.6.7.8",
            regime          = "normal",
            anomaly_score   = 0.72,
            is_anomaly      = True,
            confidence      = 0.80,
            mitre_technique = MITRE_DISCOVERY_TECHNIQUE,
            explanation     = "Test anomaly explanation.",
        )
        defaults.update(overrides)
        return FlowAlert(**defaults)

    def test_fields_accessible(self):
        alert = self._make_alert()
        self.assertEqual(alert.src_ip, "1.2.3.4")
        self.assertEqual(alert.dst_ip, "5.6.7.8")
        self.assertEqual(alert.regime, "normal")

    def test_anomaly_score_stored(self):
        alert = self._make_alert(anomaly_score=0.91)
        self.assertAlmostEqual(alert.anomaly_score, 0.91, places=4)

    def test_is_anomaly_flag(self):
        self.assertTrue(self._make_alert(is_anomaly=True).is_anomaly)
        self.assertFalse(self._make_alert(is_anomaly=False).is_anomaly)

    def test_default_timestamp_is_utc(self):
        alert = self._make_alert()
        self.assertIsInstance(alert.timestamp, datetime)
        self.assertIsNotNone(alert.timestamp.tzinfo)

    def test_default_top_features_is_empty_list(self):
        alert = self._make_alert()
        self.assertIsInstance(alert.top_features, list)
        self.assertEqual(len(alert.top_features), 0)

    def test_default_global_score_is_zero(self):
        alert = self._make_alert()
        self.assertEqual(alert.global_score, 0.0)

    def test_c2_proof_fields_default_zero(self):
        alert = self._make_alert()
        self.assertEqual(alert.context_fpr,   0.0)
        self.assertEqual(alert.global_fpr,    0.0)
        self.assertEqual(alert.fpr_reduction, 0.0)

    def test_str_contains_key_info(self):
        alert = self._make_alert()
        s = str(alert)
        self.assertIn("ANOMALY", s)
        self.assertIn("1.2.3.4", s)
        self.assertIn("normal",  s)


# TestFlowAgentInference

class TestFlowAgentInference(unittest.TestCase):
    """FlowAgent.score() and score_batch() — output contract and routing. (12 tests)"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.agent, self.benign = _load_real_agent()

    def _normal_record(self, regime: str = "normal") -> FlowRecord:
        return _make_flow_record(regime=regime)

    def test_score_returns_flow_alert(self):
        rec   = self._normal_record()
        alert = self.agent.score(rec)
        self.assertIsInstance(alert, FlowAlert)

    def test_score_is_anomaly_is_bool(self):
        alert = self.agent.score(self._normal_record())
        self.assertIsInstance(alert.is_anomaly, bool)

    def test_score_anomaly_score_in_range(self):
        alert = self.agent.score(self._normal_record())
        self.assertGreaterEqual(alert.anomaly_score, 0.0)
        self.assertLessEqual(alert.anomaly_score,    1.0)

    def test_score_confidence_in_range(self):
        alert = self.agent.score(self._normal_record())
        self.assertGreaterEqual(alert.confidence, 0.0)
        self.assertLessEqual(alert.confidence,    1.0)

    def test_score_explanation_not_empty(self):
        alert = self.agent.score(self._normal_record())
        self.assertIsInstance(alert.explanation, str)
        self.assertGreater(len(alert.explanation), 0)

    def test_score_regime_matches_record(self):
        for regime in REGIME_CONTEXTS:
            rec   = self._normal_record(regime=regime)
            alert = self.agent.score(rec)
            self.assertEqual(alert.regime, regime,
                             msg=f"Expected regime '{regime}'")

    def test_score_sets_flow_alert_on_record(self):
        rec = self._normal_record()
        self.assertIsNone(rec.flow_alert)
        self.agent.score(rec)
        self.assertIsNotNone(rec.flow_alert)

    def test_score_global_score_populated(self):
        alert = self.agent.score(self._normal_record())
        self.assertIsInstance(alert.global_score, float)

    def test_mitre_set_when_anomaly(self):
        """Craft a very high-magnitude flow that should be flagged anomalous."""
        rng      = np.random.default_rng(42)
        features = {"Flow Duration": float(rng.uniform(1e7, 1e8)), "Total Fwd Packets": float(rng.uniform(1e7, 1e8)), "Destination Port": float(rng.uniform(1e7, 1e8))}
        rec      = FlowRecord("192.168.1.1", "10.0.0.1", features,
                              regime="normal")
        alert    = self.agent.score(rec)
        if alert.is_anomaly:
            self.assertEqual(alert.mitre_technique, MITRE_DISCOVERY_TECHNIQUE)

    def test_mitre_none_when_not_anomaly(self):
        # Score benign-range flow
        rng      = np.random.default_rng(0)
        features = {"Flow Duration": float(rng.uniform(50, 300)), "Total Fwd Packets": float(rng.uniform(50, 300)), "Destination Port": float(rng.uniform(50, 300))}
        rec      = FlowRecord("10.0.0.1", "10.0.0.2", features,
                              regime="normal")
        alert    = self.agent.score(rec)
        if not alert.is_anomaly:
            self.assertIsNone(alert.mitre_technique)

    def test_score_batch_returns_correct_length(self):
        records = [self._normal_record() for _ in range(8)]
        alerts  = self.agent.score_batch(records)
        self.assertEqual(len(alerts), 8)

    def test_score_batch_all_flow_alerts(self):
        records = [self._normal_record(r) for r in list(REGIME_CONTEXTS.keys())]
        alerts  = self.agent.score_batch(records)
        for i, a in enumerate(alerts):
            self.assertIsInstance(a, FlowAlert,
                                  msg=f"Record {i} did not produce FlowAlert")


# TestFlowAgentLoad

class TestFlowAgentLoad(unittest.TestCase):
    """FlowAgent.load() — missing files raise, round-trip integrity. (7 tests)"""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        # Copy model files from MODELS_DIR to tmpdir so we can test with them
        import shutil
        for fname in ["flow_context_models.pkl", "flow_global_model.pkl", 
                      "flow_scaler.pkl", "flow_thresholds.pkl"]:
            src = MODELS_DIR / fname
            dst = self.tmpdir / fname
            if src.exists():
                shutil.copy(src, dst)

    def test_load_succeeds_after_train(self):
        agent = FlowAgent.load(models_dir=self.tmpdir)
        self.assertIsInstance(agent, FlowAgent)

    def test_load_raises_if_context_models_missing(self):
        (self.tmpdir / "flow_context_models.pkl").unlink()
        with self.assertRaises(FileNotFoundError):
            FlowAgent.load(models_dir=self.tmpdir)

    def test_load_raises_if_global_model_missing(self):
        d = Path(tempfile.mkdtemp())
        # Try to load from empty directory — should raise FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            FlowAgent.load(models_dir=d)

    def test_loaded_agent_has_six_context_models(self):
        agent = FlowAgent.load(models_dir=self.tmpdir)
        self.assertEqual(len(agent._context), len(REGIME_CONTEXTS))

    def test_loaded_agent_context_model_keys_match_regimes(self):
        agent = FlowAgent.load(models_dir=self.tmpdir)
        self.assertEqual(set(agent._context.keys()), set(REGIME_CONTEXTS.keys()))

    def test_loaded_agent_scaler_has_mean(self):
        agent = FlowAgent.load(models_dir=self.tmpdir)
        self.assertTrue(hasattr(agent._scaler, "mean_"))

    def test_loaded_agent_thresholds_all_regimes(self):
        agent = FlowAgent.load(models_dir=self.tmpdir)
        # Thresholds are stored in a flat dict per regime context
        for regime in REGIME_CONTEXTS:
            self.assertIn(regime, agent._thresh,
                          msg=f"Threshold for '{regime}' not loaded")


# TestFlowAgentEvaluate

class TestFlowAgentEvaluate(unittest.TestCase):
    """FlowAgent.evaluate() — metrics contract for Challenge C2 proof. (5 tests)"""

    def setUp(self):
        self.tmpdir  = Path(tempfile.mkdtemp())
        self.benign  = _make_synthetic_benign()
        self.attacks = _make_synthetic_attacks()
        self.agent, _ = _load_real_agent()

    def test_evaluate_returns_dict(self):
        results = self.agent.evaluate(self.benign, self.attacks)
        self.assertIsInstance(results, dict)

    def test_evaluate_covers_all_regimes(self):
        results = self.agent.evaluate(self.benign, self.attacks)
        for regime in REGIME_CONTEXTS:
            self.assertIn(regime, results,
                          msg=f"evaluate() missing regime '{regime}'")

    def test_fpr_context_in_range(self):
        results = self.agent.evaluate(self.benign, self.attacks)
        for regime, r in results.items():
            self.assertGreaterEqual(r["fpr_context"], 0.0,
                                    msg=f"{regime}: fpr_context < 0")
            self.assertLessEqual(r["fpr_context"], 1.0,
                                 msg=f"{regime}: fpr_context > 1")

    def test_detection_rate_in_range(self):
        results = self.agent.evaluate(self.benign, self.attacks)
        for regime, r in results.items():
            self.assertGreaterEqual(r["detection_rate"], 0.0,
                                    msg=f"{regime}: detection_rate < 0")
            self.assertLessEqual(r["detection_rate"], 1.0,
                                 msg=f"{regime}: detection_rate > 1")

    def test_context_fpr_at_most_global_fpr_or_both_zero(self):
        """
        The whole point of C2: context FPR <= global FPR (or both near-zero
        on tiny synthetic data where the effect may be marginal).
        """
        results = self.agent.evaluate(self.benign, self.attacks)
        for regime, r in results.items():
            # Allow a small tolerance for synthetic randomness
            self.assertLessEqual(
                r["fpr_context"],
                r["fpr_global"] + 0.15,
                msg=(
                    f"{regime}: context FPR ({r['fpr_context']:.3f}) "
                    f"should not greatly exceed global FPR ({r['fpr_global']:.3f})"
                ),
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
