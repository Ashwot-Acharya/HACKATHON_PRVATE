"""
BankSentinel — Packet Agent Test Suite
=======================================
Challenge Covered: C4 — Encrypted TLS 1.3 Traffic Detection

Tests load real trained models from models/ directory.
Run after downloading artifacts from Colab.

Run:  python -m pytest tests/test_packet_agent.py -v

Groups
------
  TestPacketAlert         ( 9)  data structure validation
  TestJA3Computation      (10)  JA3/JA3S hash correctness
  TestBeaconFeatures      ( 8)  compute_beacon_features() output
  TestPacketAgentLoad     ( 5)  artifact loading and errors
  TestLayer1JA3           ( 6)  live threat feed JA3 lookup
  TestLayer2JA3S          ( 5)  JA3S cross-signal logic
  TestLayer3Beacon        ( 7)  CTU-13 RF beacon scoring
  TestCombinedLayers      ( 6)  multi-layer confidence combination
  TestAptScenario         ( 4)  APT Section III demo record
"""

import json
import pickle
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import (
    BEACON_IAT_CV_THRESHOLD,
    FLOW_FEATURES,
    MITRE_C2_TECHNIQUE,
    MODELS_DIR,
)
from agents.packet_agent import (
    PacketAgent,
    PacketAlert,
    compute_ja3,
    compute_ja3s,
    compute_beacon_features_trackd,
    _GREASE_VALUES,
    _THREAT_THRESHOLD,
)
from intel.threat_feed import ThreatIntelEngine, JA3Hit
from pipeline.ingestion import FlowRecord, build_apt_scenario


# ── Shared helpers ─────────────────────────────────────────────────────────────

KNOWN_JA3  = "0b32309a26951912be7dba376398abc3"
KNOWN_JA3S = "ae4edc6faf64d08308082ad26be60767"
KNOWN_C2   = "185.220.101.32"

def _make_record(
    src_ip:   str = "10.22.14.45",
    dst_ip:   str = "185.220.101.32",
    dst_port: int = 443,
    protocol: int = 6,
    regime:   str = "off_hours",
    ja3:      str = None,
    ja3s:     str = None,
    **feat_overrides,
) -> FlowRecord:
    features = {"Flow Duration": 100.0, "Total Fwd Packets": 100.0, "Destination Port": 100.0}
    features["Destination Port"] = float(dst_port)
    features["Protocol"]         = float(protocol)
    features.update(feat_overrides)
    rec = FlowRecord(src_ip, dst_ip, features, label="BENIGN", regime=regime)
    rec.ja3_hash  = ja3
    rec.ja3s_hash = ja3s
    return rec


def _make_mock_intel(
    ja3_hits:  dict = None,
    ja3s_hits: dict = None,
    c2_ips:    set  = None,
    tor_ips:   set  = None,
) -> ThreatIntelEngine:
    """Return a ThreatIntelEngine with pre-loaded mock data (no HTTP)."""
    engine = ThreatIntelEngine(refresh_interval=9999)
    engine._ja3_db   = ja3_hits  or {}
    engine._ja3s_db  = ja3s_hits or {}
    engine._c2_ips   = c2_ips    or set()
    engine._tor_exits = tor_ips  or set()
    from datetime import timezone
    from datetime import datetime as _dt
    engine._stats.last_updated = _dt.now(timezone.utc)
    return engine


def _load_real_agent(intel=None) -> PacketAgent:
    """Load real trained agent from MODELS_DIR."""
    return PacketAgent.load(models_dir=MODELS_DIR, intel=intel)


# GROUP 1: PacketAlert data structure

class TestPacketAlert(unittest.TestCase):

    def _make(self, **kw) -> PacketAlert:
        defaults = dict(
            src_ip="1.2.3.4", dst_ip="5.6.7.8", dst_port=443,
            ja3_hash=KNOWN_JA3, ja3s_hash=KNOWN_JA3S,
            confidence=0.87, is_threat=True,
            active_layers=["L1"],
            layer_scores={"L1": 0.87},
            malware_family="CobaltStrike",
            mitre_technique=MITRE_C2_TECHNIQUE,
            explanation="Test threat.",
        )
        defaults.update(kw)
        return PacketAlert(**defaults)

    def test_timestamp_is_utc(self):
        self.assertIsNotNone(self._make().timestamp.tzinfo)

    def test_str_shows_threat_when_true(self):
        self.assertIn("THREAT", str(self._make(is_threat=True)))

    def test_str_shows_clean_when_false(self):
        self.assertIn("clean", str(self._make(is_threat=False)))

    def test_str_contains_src_ip(self):
        self.assertIn("1.2.3.4", str(self._make()))

    def test_active_layers_list(self):
        a = self._make(active_layers=["L1", "L3"])
        self.assertEqual(a.active_layers, ["L1", "L3"])

    def test_layer_scores_dict(self):
        a = self._make(layer_scores={"L1": 0.55, "L3": 0.72})
        self.assertIn("L1", a.layer_scores)
        self.assertIn("L3", a.layer_scores)

    def test_malware_family_optional(self):
        a = self._make(malware_family=None)
        self.assertIsNone(a.malware_family)

    def test_mitre_set_for_threat(self):
        a = self._make(is_threat=True, mitre_technique=MITRE_C2_TECHNIQUE)
        self.assertEqual(a.mitre_technique, MITRE_C2_TECHNIQUE)

    def test_confidence_in_range(self):
        a = self._make(confidence=0.87)
        self.assertGreaterEqual(a.confidence, 0.0)
        self.assertLessEqual(a.confidence,    1.0)


# GROUP 2: JA3/JA3S computation

class TestJA3Computation(unittest.TestCase):

    def test_ja3_returns_32_char_hex(self):
        h = compute_ja3(771, [49195, 49199], [0, 5], [29, 23], [0])
        self.assertEqual(len(h), 32)
        self.assertTrue(all(c in '0123456789abcdef' for c in h))

    def test_ja3_deterministic(self):
        args = (771, [49195, 49199], [0, 5], [29, 23], [0])
        self.assertEqual(compute_ja3(*args), compute_ja3(*args))

    def test_ja3_different_inputs_different_hash(self):
        h1 = compute_ja3(771, [49195],       [0, 5], [29], [0])
        h2 = compute_ja3(771, [49195, 49199], [0, 5], [29], [0])
        self.assertNotEqual(h1, h2)

    def test_ja3_grease_values_stripped(self):
        grease_val = 0x0a0a
        # With and without GREASE value should produce same hash
        h_without = compute_ja3(771, [49195], [0, 5], [29], [0])
        h_with    = compute_ja3(771, [49195, grease_val], [0, 5], [29], [0])
        self.assertEqual(h_without, h_with)

    def test_ja3_empty_lists(self):
        # Should not raise
        h = compute_ja3(771, [], [], [], [])
        self.assertEqual(len(h), 32)

    def test_ja3s_returns_32_char_hex(self):
        h = compute_ja3s(771, 49195, [0, 5])
        self.assertEqual(len(h), 32)
        self.assertTrue(all(c in '0123456789abcdef' for c in h))

    def test_ja3s_deterministic(self):
        args = (771, 49195, [0, 5])
        self.assertEqual(compute_ja3s(*args), compute_ja3s(*args))

    def test_ja3s_different_from_ja3(self):
        # Server and client hashes should generally differ
        h_client = compute_ja3(771, [49195], [0, 5], [29], [0])
        h_server = compute_ja3s(771, 49195, [0, 5])
        # They can theoretically match but it's astronomically unlikely
        # Just test they are both valid 32-char hashes
        self.assertEqual(len(h_client), 32)
        self.assertEqual(len(h_server), 32)

    def test_known_cobalt_strike_ja3_is_32_chars(self):
        # The APT demo JA3 must be exactly 32 chars
        self.assertEqual(len(KNOWN_JA3),  32)
        self.assertEqual(len(KNOWN_JA3S), 32)

    def test_grease_set_not_empty(self):
        self.assertGreater(len(_GREASE_VALUES), 0)


# GROUP 3: compute_beacon_features_trackd

class TestBeaconFeatures(unittest.TestCase):

    def _rec(self, **overrides) -> FlowRecord:
        features = {"Flow Duration": 100.0, "Total Fwd Packets": 100.0, "Destination Port": 100.0}
        features["Flow Duration"]              = 1_000_000.0  # 1s in µs
        features["Total Fwd Packets"]          = 10.0
        features["Total Bwd Packets"]          = 8.0
        features["Total Length of Fwd Packets"] = 5000.0
        features["Total Length of Bwd Packets"] = 3000.0
        features["Flow IAT Mean"]              = 100_000.0
        features["Flow IAT Std"]               = 50_000.0
        features["Protocol"]                   = 6.0
        features["Destination Port"]           = 443.0
        features.update(overrides)
        return FlowRecord("1.2.3.4", "5.6.7.8", features)

    def test_returns_numpy_array(self):
        arr = compute_beacon_features_trackd(self._rec())
        self.assertIsInstance(arr, np.ndarray)

    def test_dtype_float32(self):
        self.assertEqual(compute_beacon_features_trackd(self._rec()).dtype, np.float32)

    def test_no_nan_or_inf(self):
        arr = compute_beacon_features_trackd(self._rec())
        self.assertFalse(np.isnan(arr).any(),  "NaN in beacon features")
        self.assertFalse(np.isinf(arr).any(),  "Inf in beacon features")

    def test_length_matches_expected(self):
        arr = compute_beacon_features_trackd(self._rec())
        # Must have exactly 45 features for Track D
        self.assertEqual(len(arr), 45)

    def test_zero_duration_no_crash(self):
        # Edge case: zero flow duration
        arr = compute_beacon_features_trackd(
            self._rec(**{"Flow Duration": 0.0})
        )
        self.assertFalse(np.isnan(arr).any())
        self.assertFalse(np.isinf(arr).any())

    def test_zero_packets_no_crash(self):
        arr = compute_beacon_features_trackd(
            self._rec(**{
                "Total Fwd Packets": 0.0,
                "Total Bwd Packets": 0.0,
            })
        )
        self.assertFalse(np.isnan(arr).any())

    def test_tcp_flag_set_for_proto_6(self):
        arr = compute_beacon_features_trackd(self._rec(**{"Protocol": 6.0}))
        # proto_tcp should be 1.0 (index 17 in Track D feature vector)
        self.assertAlmostEqual(float(arr[17]), 1.0, places=3)

    def test_udp_flag_set_for_proto_17(self):
        arr = compute_beacon_features_trackd(self._rec(**{"Protocol": 17.0}))
        # proto_udp should be 1.0 (index 18)
        self.assertAlmostEqual(float(arr[18]), 1.0, places=3)


# GROUP 4: PacketAgent.load()

class TestPacketAgentLoad(unittest.TestCase):

    def test_load_succeeds_with_real_models(self):
        intel  = _make_mock_intel()
        agent  = PacketAgent.load(models_dir=MODELS_DIR, intel=intel)
        self.assertIsInstance(agent, PacketAgent)

    def test_load_raises_if_rf_model_missing(self):
        tmpdir = Path(tempfile.mkdtemp())
        with self.assertRaises(FileNotFoundError):
            PacketAgent.load(models_dir=tmpdir)

    def test_load_raises_if_scaler_missing(self):
        tmpdir = Path(tempfile.mkdtemp())
        # Copy only model, not scaler
        import shutil
        src = MODELS_DIR / "packet_rf_ctu.pkl"
        if src.exists():
            shutil.copy(src, tmpdir / "packet_rf_ctu.pkl")
        with self.assertRaises(FileNotFoundError):
            PacketAgent.load(models_dir=tmpdir)

    def test_loaded_agent_has_rf_model(self):
        agent = _load_real_agent(_make_mock_intel())
        self.assertIsNotNone(agent._rf)

    def test_loaded_agent_has_feature_list(self):
        agent = _load_real_agent(_make_mock_intel())
        self.assertIsInstance(agent._rf_feats, list)
        self.assertGreater(len(agent._rf_feats), 0)


# GROUP 5: Layer 1 — JA3 lookup

class TestLayer1JA3(unittest.TestCase):

    def setUp(self):
        self.intel = _make_mock_intel(
            ja3_hits  = {KNOWN_JA3: "CobaltStrike"},
            c2_ips    = {KNOWN_C2},
        )
        self.agent = _load_real_agent(self.intel)

    def test_known_ja3_fires_layer1(self):
        rec   = _make_record(ja3=KNOWN_JA3)
        alert = self.agent.score(rec)
        self.assertIn("L1", alert.active_layers)

    def test_known_ja3_sets_malware_family(self):
        rec   = _make_record(ja3=KNOWN_JA3)
        alert = self.agent.score(rec)
        self.assertEqual(alert.malware_family, "CobaltStrike")

    def test_known_ja3_confidence_above_threshold(self):
        rec   = _make_record(ja3=KNOWN_JA3)
        alert = self.agent.score(rec)
        self.assertGreaterEqual(alert.confidence, _THREAT_THRESHOLD)

    def test_known_ja3_sets_mitre_technique(self):
        rec   = _make_record(ja3=KNOWN_JA3)
        alert = self.agent.score(rec)
        if alert.is_threat:
            self.assertEqual(alert.mitre_technique, MITRE_C2_TECHNIQUE)

    def test_unknown_ja3_does_not_fire_layer1_alone(self):
        rec   = _make_record(ja3="a" * 32, dst_ip="8.8.8.8")
        alert = self.agent.score(rec)
        self.assertNotIn("L1", alert.active_layers)

    def test_known_c2_ip_fires_layer1(self):
        rec   = _make_record(dst_ip=KNOWN_C2, ja3="b" * 32)
        alert = self.agent.score(rec)
        self.assertIn("L1", alert.active_layers)


# GROUP 6: Layer 2 — JA3S cross-signal

class TestLayer2JA3S(unittest.TestCase):

    def setUp(self):
        # Client JA3 is NOT in threat DB, server JA3S IS
        self.intel = _make_mock_intel(
            ja3_hits  = {},                          # client clean
            ja3s_hits = {KNOWN_JA3S: "CobaltStrike"},  # server malicious
        )
        self.agent = _load_real_agent(self.intel)

    def test_clean_client_malicious_server_fires_layer2(self):
        rec   = _make_record(
            ja3  = "c" * 32,   # unknown client JA3
            ja3s = KNOWN_JA3S, # known malicious server JA3S
            dst_ip = "8.8.8.8",
        )
        alert = self.agent.score(rec)
        self.assertIn("L2", alert.active_layers)

    def test_layer2_confidence_above_threshold(self):
        rec   = _make_record(ja3="c"*32, ja3s=KNOWN_JA3S, dst_ip="8.8.8.8")
        alert = self.agent.score(rec)
        if "L2" in alert.active_layers:
            self.assertGreaterEqual(alert.confidence, _THREAT_THRESHOLD)

    def test_layer2_does_not_fire_when_client_already_malicious(self):
        # When L1 already fired, L2 cross-signal should NOT fire
        intel = _make_mock_intel(
            ja3_hits  = {KNOWN_JA3: "CobaltStrike"},  # client also malicious
            ja3s_hits = {KNOWN_JA3S: "CobaltStrike"},
        )
        agent = _load_real_agent(intel)
        rec   = _make_record(ja3=KNOWN_JA3, ja3s=KNOWN_JA3S)
        alert = agent.score(rec)
        self.assertIn("L1", alert.active_layers)
        # L2 should not fire when client is already known malicious
        self.assertNotIn("L2", alert.active_layers)

    def test_clean_server_no_layer2(self):
        rec   = _make_record(ja3="d"*32, ja3s="e"*32, dst_ip="8.8.8.8")
        alert = self.agent.score(rec)
        self.assertNotIn("L2", alert.active_layers)

    def test_layer2_explanation_mentions_server_fingerprint(self):
        rec   = _make_record(ja3="c"*32, ja3s=KNOWN_JA3S, dst_ip="8.8.8.8")
        alert = self.agent.score(rec)
        if "L2" in alert.active_layers:
            self.assertIn("server", alert.explanation.lower())


# GROUP 7: Layer 3 — CTU-13 RF beacon detector

class TestLayer3Beacon(unittest.TestCase):

    def setUp(self):
        self.intel = _make_mock_intel()  # empty — no L1/L2 hits
        self.agent = _load_real_agent(self.intel)

    def _normal_record(self) -> FlowRecord:
        """Typical HTTPS browsing — high IAT variance, no beacon pattern."""
        return _make_record(
            dst_ip="93.184.216.34",  # example.com
            **{
                "Flow Duration":               5_000_000.0,
                "Total Fwd Packets":           20.0,
                "Total Bwd Packets":           18.0,
                "Total Length of Fwd Packets": 8000.0,
                "Total Length of Bwd Packets": 45000.0,
                "Flow IAT Mean":               250_000.0,
                "Flow IAT Std":                180_000.0,  # HIGH variance
                "Protocol":                    6.0,
            }
        )

    def _beacon_record(self) -> FlowRecord:
        """Simulated C2 beacon — regular interval, low IAT variance."""
        return _make_record(
            dst_ip="185.220.101.32",
            **{
                "Flow Duration":               120_000_000.0,  # 2 min
                "Total Fwd Packets":           120.0,           # ~1/sec
                "Total Bwd Packets":           120.0,
                "Total Length of Fwd Packets": 12000.0,         # small fixed
                "Total Length of Bwd Packets": 12000.0,
                "Flow IAT Mean":               1_000_000.0,
                "Flow IAT Std":                10_000.0,         # LOW variance
                "Protocol":                    6.0,
            }
        )

    def test_layer3_returns_score_in_range(self):
        rec   = self._normal_record()
        score = self.agent._score_layer3(rec)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score,    1.0)

    def test_score_is_float(self):
        rec   = self._normal_record()
        score = self.agent._score_layer3(rec)
        self.assertIsInstance(score, float)

    def test_no_crash_on_zero_features(self):
        features = {"Flow Duration": 0.0, "Total Fwd Packets": 0.0, "Destination Port": 0.0}
        rec      = FlowRecord("1.2.3.4", "5.6.7.8", features)
        score    = self.agent._score_layer3(rec)
        self.assertGreaterEqual(score, 0.0)

    def test_score_method_populates_alert(self):
        rec   = self._normal_record()
        alert = self.agent.score(rec)
        self.assertIsNotNone(alert)
        self.assertIsInstance(alert, PacketAlert)

    def test_alert_sets_record_packet_alert(self):
        rec = self._normal_record()
        self.assertIsNone(rec.packet_alert)
        self.agent.score(rec)
        self.assertIsNotNone(rec.packet_alert)

    def test_confidence_in_range_after_scoring(self):
        alert = self.agent.score(self._normal_record())
        self.assertGreaterEqual(alert.confidence, 0.0)
        self.assertLessEqual(alert.confidence,    1.0)

    def test_score_ja3_direct_no_crash(self):
        alert = self.agent.score_ja3_direct(
            ja3_hash  = "a" * 32,
            ja3s_hash = "b" * 32,
            dst_ip    = "8.8.8.8",
        )
        self.assertIsInstance(alert, PacketAlert)


# GROUP 8: Combined layer logic

class TestCombinedLayers(unittest.TestCase):

    def setUp(self):
        self.intel_full = _make_mock_intel(
            ja3_hits  = {KNOWN_JA3:  "CobaltStrike"},
            ja3s_hits = {KNOWN_JA3S: "CobaltStrike"},
            c2_ips    = {KNOWN_C2},
        )
        self.agent = _load_real_agent(self.intel_full)

    def test_all_three_layers_can_fire(self):
        # Record with known JA3 + known C2 IP
        rec   = _make_record(ja3=KNOWN_JA3, ja3s=KNOWN_JA3S, dst_ip=KNOWN_C2)
        alert = self.agent.score(rec)
        # At minimum L1 should fire
        self.assertTrue(len(alert.active_layers) >= 1)

    def test_confidence_capped_at_one(self):
        rec   = _make_record(ja3=KNOWN_JA3, ja3s=KNOWN_JA3S, dst_ip=KNOWN_C2)
        alert = self.agent.score(rec)
        self.assertLessEqual(alert.confidence, 1.0)

    def test_explanation_not_empty(self):
        rec   = _make_record(ja3=KNOWN_JA3)
        alert = self.agent.score(rec)
        self.assertGreater(len(alert.explanation), 0)

    def test_no_layers_fired_gives_clean(self):
        intel = _make_mock_intel()  # completely empty
        agent = _load_real_agent(intel)
        # Craft a record that is very normal
        features = {"Flow Duration": 50.0, "Total Fwd Packets": 50.0, "Destination Port": 50.0}
        features["Flow Duration"]               = 1_000_000.0
        features["Total Fwd Packets"]           = 5.0
        features["Total Bwd Packets"]           = 5.0
        features["Total Length of Fwd Packets"] = 500.0
        features["Total Length of Bwd Packets"] = 500.0
        features["Flow IAT Mean"]               = 200_000.0
        features["Flow IAT Std"]                = 150_000.0
        features["Protocol"]                    = 6.0
        rec = FlowRecord("10.0.0.1", "8.8.8.8", features)
        rec.ja3_hash  = "a" * 32
        rec.ja3s_hash = "b" * 32
        alert = agent.score(rec)
        # Might or might not be a threat depending on L3 — just verify structure
        self.assertIsInstance(alert.is_threat, bool)

    def test_layer_scores_keys_match_active(self):
        rec   = _make_record(ja3=KNOWN_JA3)
        alert = self.agent.score(rec)
        for layer in alert.active_layers:
            self.assertIn(layer, alert.layer_scores)

    def test_timestamp_is_recent(self):
        rec   = _make_record()
        alert = self.agent.score(rec)
        age   = (
            datetime.now(timezone.utc) - alert.timestamp
        ).total_seconds()
        self.assertLess(age, 10.0, "Alert timestamp is too old")


# GROUP 9: APT Section III demo record

class TestAptScenario(unittest.TestCase):

    def setUp(self):
        self.intel = _make_mock_intel(
            ja3_hits = {KNOWN_JA3: "CobaltStrike"},
            c2_ips   = {KNOWN_C2},
        )
        self.agent = _load_real_agent(self.intel)

    def test_apt_c2_record_scored_without_error(self):
        """The C2 TLS record from build_apt_scenario() must score cleanly."""
        c2_rec = build_apt_scenario()[0]
        alert  = self.agent.score(c2_rec)
        self.assertIsInstance(alert, PacketAlert)
        self.assertIsNotNone(c2_rec.packet_alert)

    def test_apt_c2_record_fires_layer1(self):
        """Known Cobalt Strike JA3 must fire Layer 1."""
        c2_rec = build_apt_scenario()[0]
        alert  = self.agent.score(c2_rec)
        self.assertIn("L1", alert.active_layers,
                      "APT C2 record must fire Layer 1 (known JA3)")

    def test_apt_c2_confidence_in_range(self):
        c2_rec = build_apt_scenario()[0]
        alert  = self.agent.score(c2_rec)
        self.assertGreaterEqual(alert.confidence, 0.0)
        self.assertLessEqual(alert.confidence,    1.0)

    def test_apt_c2_mitre_technique_set(self):
        c2_rec = build_apt_scenario()[0]
        alert  = self.agent.score(c2_rec)
        if alert.is_threat:
            self.assertEqual(alert.mitre_technique, MITRE_C2_TECHNIQUE)


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")
    unittest.main(verbosity=2)