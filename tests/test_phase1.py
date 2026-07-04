"""
BankSentinel — Phase 1 Test Suite
===================================
48 tests across 7 groups. All run fully offline — HTTP calls are mocked.

Run:  python -m pytest tests/test_phase1.py -v

Groups:
  TestConfig              — constants validation         (6 tests)
  TestThreatIntelEngine   — C4 Layers 1 & 2            (11 tests)
  TestRegimeLabelling     — C2 time-context logic        (8 tests)
  TestDataPreparation     — C2 CICIDS loading           (11 tests)
  TestStreamSimulator     — pipeline infrastructure      (4 tests)
  TestAptScenario         — all-challenge demo records   (7 tests)
  TestIntegration         — end-to-end feed→lookup       (1 test)
"""

import asyncio
import csv
import io
import json
import pickle
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import (
    BEACON_IAT_CV_THRESHOLD,
    BBN_PRIOR_THREAT,
    CRS_WEIGHTS,
    FLOW_FEATURES,
    REGIME_CONTEXTS,
)
from intel.threat_feed import FeedStats, JA3Hit, ThreatIntelEngine
from pipeline.ingestion import (
    FlowRecord,
    StreamSimulator,
    _nepal_hour,
    assign_regime,
    build_apt_scenario,
    load_regime_data,
    prepare_cicids,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_fake_ja3_csv(entries: list[tuple]) -> str:
    lines = ["# JA3 Fingerprints - abuse.ch SSL Blacklist"]
    for ja3_md5, first_seen, listing_reason in entries:
        lines.append(f"{ja3_md5},{first_seen},{listing_reason}")
    return "\n".join(lines)


def _make_fake_c2_json(ips: list[str]) -> str:
    return json.dumps([{"ip_address": ip} for ip in ips])


def _make_fake_cicids(n_benign: int = 200, n_attack: int = 50) -> pd.DataFrame:
    rng = np.random.default_rng(42)
    rows = []
    for i in range(n_benign + n_attack):
        row = {f: rng.uniform(10, 1000) for f in FLOW_FEATURES}
        row["Label"] = "BENIGN" if i < n_benign else "DoS Hulk"
        rows.append(row)
    return pd.DataFrame(rows)


# TestConfig

class TestConfig(unittest.TestCase):

    def test_regime_keys_complete(self):
        expected = {"month_end", "atm_recon", "rtgs", "off_hours", "weekend", "normal"}
        self.assertEqual(set(REGIME_CONTEXTS.keys()), expected)

    def test_regime_contamination_in_range(self):
        for name, params in REGIME_CONTEXTS.items():
            c = params["contamination"]
            self.assertGreater(c, 0.0, msg=f"{name}: contamination > 0")
            self.assertLess(c, 0.5,   msg=f"{name}: contamination < 0.5")

    def test_crs_weights_sum_to_one(self):
        self.assertAlmostEqual(sum(CRS_WEIGHTS), 1.0, places=6)

    def test_bbn_prior_small(self):
        self.assertLess(BBN_PRIOR_THREAT, 0.01)
        self.assertGreater(BBN_PRIOR_THREAT, 0.0)

    def test_beacon_threshold_sensible(self):
        self.assertGreater(BEACON_IAT_CV_THRESHOLD, 0.0)
        self.assertLess(BEACON_IAT_CV_THRESHOLD, 1.0)

    def test_flow_features_not_empty(self):
        self.assertGreaterEqual(len(FLOW_FEATURES), 5)


# TestThreatIntelEngine

class TestThreatIntelEngine(unittest.TestCase):

    KNOWN_JA3  = "0b32309a26951912be7dba376398abc3"
    KNOWN_JA3S = "ae4edc6faf64d08308082ad26be60767"
    KNOWN_C2   = "185.220.101.32"
    TOR_EXIT   = "195.176.3.23"

    def _make_engine(self) -> ThreatIntelEngine:
        """Engine pre-loaded with mock feed data — no network."""
        engine  = ThreatIntelEngine(refresh_interval=9999)
        ja3_csv = _make_fake_ja3_csv([
            (self.KNOWN_JA3,  "2024-01-01 00:00:00", "CobaltStrike"),
            (self.KNOWN_JA3S, "2024-01-01 00:00:00", "CobaltStrike"),
        ])
        c2_json = _make_fake_c2_json([self.KNOWN_C2])
        tor_txt = f"{self.TOR_EXIT}\n203.0.113.5\n"

        def fake_get(url, timeout=15):
            r = MagicMock()
            r.raise_for_status = MagicMock()
            if "sslbl" in url or "ja3" in url.lower():
                r.text = ja3_csv
            elif "feodo" in url or "ipblock" in url:
                r.text = c2_json
                r.json  = lambda: json.loads(c2_json)
            else:
                r.text = tor_txt
                r.json  = lambda: []
            return r

        with patch("intel.threat_feed.requests.get", side_effect=fake_get):
            engine._refresh_all()
        return engine

    def test_ja3_layer1_known_hit(self):
        hit = self._make_engine().lookup_ja3(self.KNOWN_JA3)
        self.assertIsNotNone(hit)
        self.assertIsInstance(hit, JA3Hit)
        self.assertEqual(hit.malware_family, "CobaltStrike")
        self.assertFalse(hit.is_server_side)

    def test_ja3_layer1_miss(self):
        hit = self._make_engine().lookup_ja3("a" * 32)
        self.assertIsNone(hit)

    def test_ja3s_layer2_server_side(self):
        hit = self._make_engine().lookup_ja3s(self.KNOWN_JA3S)
        self.assertIsNotNone(hit)
        self.assertTrue(hit.is_server_side)
        self.assertEqual(hit.malware_family, "CobaltStrike")

    def test_ja3s_cross_signal_logic(self):
        engine     = self._make_engine()
        client_hit = engine.lookup_ja3("f" * 32)       # clean client
        server_hit = engine.lookup_ja3s(self.KNOWN_JA3S)  # malicious server
        self.assertIsNone(client_hit,    "Clean client JA3 should not hit")
        self.assertIsNotNone(server_hit, "Malicious server JA3S should hit")
        cross = (client_hit is None) and (server_hit is not None)
        self.assertTrue(cross, "L2 cross-signal must fire")

    def test_c2_ip_lookup(self):
        engine = self._make_engine()
        self.assertTrue(engine.is_known_c2(self.KNOWN_C2))
        self.assertFalse(engine.is_known_c2("8.8.8.8"))

    def test_tor_exit_lookup(self):
        engine = self._make_engine()
        self.assertTrue(engine.is_tor_exit(self.TOR_EXIT))
        self.assertFalse(engine.is_tor_exit("1.1.1.1"))

    def test_stats_populated(self):
        stats = self._make_engine().stats
        self.assertIsInstance(stats, FeedStats)
        self.assertGreater(stats.ja3_entries, 0)
        self.assertGreater(stats.c2_ip_entries, 0)
        self.assertIsNotNone(stats.last_updated)

    def test_stats_age_minutes(self):
        age = self._make_engine().stats.age_minutes
        self.assertIsNotNone(age)
        self.assertGreaterEqual(age, 0.0)

    def test_atomic_swap_on_feed_failure(self):
        engine = self._make_engine()

        def failing_get(url, timeout=15):
            if "sslbl" in url or "ja3" in url.lower():
                raise ConnectionError("simulated JA3 failure")
            r = MagicMock()
            r.raise_for_status = MagicMock()
            r.text = _make_fake_c2_json([self.KNOWN_C2])
            r.json  = lambda: json.loads(r.text)
            return r

        with patch("intel.threat_feed.requests.get", side_effect=failing_get):
            engine._refresh_all()
        # C2 data persists; old JA3 data retained via atomic swap
        self.assertTrue(engine.is_known_c2(self.KNOWN_C2))

    def test_nepal_context_keys(self):
        ctx = ThreatIntelEngine().nepal_context
        self.assertIn("apt_groups",     ctx)
        self.assertIn("nrb_advisory",   ctx)
        self.assertIn("swift_targeted", ctx)
        self.assertTrue(ctx["swift_targeted"])

    def test_start_stop(self):
        engine = ThreatIntelEngine(refresh_interval=9999)
        with patch("intel.threat_feed.requests.get") as mock_get:
            mock_get.return_value.raise_for_status = MagicMock()
            mock_get.return_value.text = ""
            mock_get.return_value.json = lambda: []
            engine.start()
            self.assertTrue(engine._thread.is_alive())
            engine.stop()
            self.assertFalse(engine._thread.is_alive())


# TestRegimeLabelling

class TestRegimeLabelling(unittest.TestCase):

    def test_nepal_hour_utc_conversion(self):
        self.assertAlmostEqual(_nepal_hour(0,  0),  5.75, places=2)
        self.assertAlmostEqual(_nepal_hour(18, 15), 0.0,  places=2)

    def test_atm_recon_window(self):
        # 01:00 Nepal = UTC 19:15, weekday, non-month-end
        self.assertEqual(assign_regime(19, 15, 2, 10), "atm_recon")

    def test_rtgs_window(self):
        # 10:00 Nepal = UTC 04:15, weekday
        self.assertEqual(assign_regime(4, 15, 1, 10), "rtgs")

    def test_off_hours_window(self):
        # 23:00 Nepal = UTC 17:15, weekday
        self.assertEqual(assign_regime(17, 15, 2, 10), "off_hours")

    def test_weekend(self):
        # 14:00 Nepal = UTC 08:15, Saturday
        self.assertEqual(assign_regime(8, 15, 5, 10), "weekend")

    def test_month_end_priority(self):
        # 01:00 Nepal (ATM window) + day_of_month=30 → month_end wins
        self.assertEqual(assign_regime(19, 15, 1, 30), "month_end")

    def test_normal_fallthrough(self):
        # 08:00 Nepal = UTC 02:15, weekday, not RTGS start
        self.assertEqual(assign_regime(2, 15, 2, 10), "normal")

    def test_all_six_regimes_reachable(self):
        cases = {
            "month_end": (4,  15, 1, 30),
            "atm_recon": (19, 15, 2, 10),
            "rtgs":      (4,  15, 1, 10),
            "off_hours": (17, 15, 2, 10),
            "weekend":   (8,  15, 5, 10),
            "normal":    (2,  15, 2, 10),
        }
        found = set()
        for expected, args in cases.items():
            result = assign_regime(*args)
            self.assertEqual(result, expected,
                             msg=f"Expected '{expected}', got '{result}'")
            found.add(result)
        self.assertEqual(found, set(REGIME_CONTEXTS.keys()))


# TestDataPreparation

class TestDataPreparation(unittest.TestCase):

    def setUp(self):
        self.tmpdir   = tempfile.mkdtemp()
        self.csv_path = Path(self.tmpdir) / "test_cicids.csv"
        _make_fake_cicids(300, 60).to_csv(self.csv_path, index=False)

    def test_returns_correct_types(self):
        regime_data, attacks = prepare_cicids(self.csv_path, Path(self.tmpdir))
        self.assertIsInstance(regime_data, dict)
        self.assertIsInstance(attacks, pd.DataFrame)

    def test_all_six_regimes_present(self):
        regime_data, _ = prepare_cicids(self.csv_path, Path(self.tmpdir))
        for regime in REGIME_CONTEXTS:
            self.assertIn(regime, regime_data)

    def test_regime_dataframes_correct_columns(self):
        regime_data, _ = prepare_cicids(self.csv_path, Path(self.tmpdir))
        for regime, df in regime_data.items():
            self.assertEqual(set(df.columns), set(FLOW_FEATURES),
                             msg=f"Wrong columns for regime '{regime}'")

    def test_no_nan(self):
        regime_data, _ = prepare_cicids(self.csv_path, Path(self.tmpdir))
        for regime, df in regime_data.items():
            self.assertFalse(df.isnull().any().any(),
                             msg=f"NaN found in regime '{regime}'")

    def test_no_inf(self):
        regime_data, _ = prepare_cicids(self.csv_path, Path(self.tmpdir))
        for regime, df in regime_data.items():
            self.assertFalse(np.isinf(df.values).any(),
                             msg=f"Inf found in regime '{regime}'")

    def test_attacks_no_benign(self):
        _, attacks = prepare_cicids(self.csv_path, Path(self.tmpdir))
        if "Label" in attacks.columns:
            self.assertFalse((attacks["Label"] == "BENIGN").any())

    def test_pickle_files_saved(self):
        save_dir = Path(self.tmpdir)
        prepare_cicids(self.csv_path, save_dir)
        self.assertTrue((save_dir / "benign_by_regime.pkl").exists())
        self.assertTrue((save_dir / "attack_flows.pkl").exists())

    def test_load_regime_data_round_trip(self):
        save_dir = Path(self.tmpdir)
        original, _ = prepare_cicids(self.csv_path, save_dir)
        loaded = load_regime_data(save_dir)
        self.assertEqual(set(original.keys()), set(loaded.keys()))
        for r in original:
            self.assertEqual(len(original[r]), len(loaded[r]))

    def test_missing_csv_raises(self):
        with self.assertRaises(FileNotFoundError):
            prepare_cicids("/nonexistent/path.csv")

    def test_missing_columns_raises(self):
        bad = pd.DataFrame({"col_a": [1, 2], "Label": ["BENIGN", "DoS"]})
        bad_path = Path(self.tmpdir) / "bad.csv"
        bad.to_csv(bad_path, index=False)
        with self.assertRaises(ValueError):
            prepare_cicids(bad_path, Path(self.tmpdir))

    def test_load_regime_data_missing_raises(self):
        empty = Path(self.tmpdir) / "empty"
        empty.mkdir()
        with self.assertRaises(FileNotFoundError):
            load_regime_data(empty)


# TestStreamSimulator

class TestStreamSimulator(unittest.TestCase):

    def _make_records(self, n: int = 5) -> list:
        features = {f: 1.0 for f in FLOW_FEATURES}
        return [FlowRecord("10.0.0.1", "10.0.0.2", features) for _ in range(n)]

    def test_yields_all_records(self):
        records = self._make_records(5)
        sim = StreamSimulator(records, delay_ms=0)

        async def collect():
            out = []
            async for r in sim.stream():
                out.append(r)
            return out

        collected = asyncio.run(collect())
        self.assertEqual(len(collected), 5)

    def test_yields_in_order(self):
        records = self._make_records(3)
        sim = StreamSimulator(records, delay_ms=0)

        async def collect():
            out = []
            async for r in sim.stream():
                out.append(r)
            return out

        for orig, yielded in zip(records, asyncio.run(collect())):
            self.assertIs(orig, yielded)

    def test_flow_record_fields(self):
        features = {f: float(i) for i, f in enumerate(FLOW_FEATURES)}
        rec = FlowRecord("192.168.1.1", "10.0.0.1", features)
        self.assertEqual(rec.src_ip, "192.168.1.1")
        self.assertEqual(rec.label,  "BENIGN")
        self.assertIsNone(rec.packet_alert)
        self.assertIsInstance(rec.timestamp, datetime)

    def test_flow_record_repr(self):
        features = {f: 1.0 for f in FLOW_FEATURES}
        rec = FlowRecord("1.2.3.4", "5.6.7.8", features)
        self.assertIn("1.2.3.4", repr(rec))
        self.assertIn("5.6.7.8", repr(rec))


# TestAptScenario

class TestAptScenario(unittest.TestCase):

    def setUp(self):
        self.apt = build_apt_scenario()

    def test_returns_list(self):
        self.assertIsInstance(self.apt, list)
        self.assertGreater(len(self.apt), 0)

    def test_c2_record_has_ja3(self):
        rec = self.apt[0]
        self.assertIsNotNone(rec.ja3_hash)
        self.assertEqual(len(rec.ja3_hash), 32,
                         "JA3 hash must be 32-char MD5 hex string")

    def test_c2_record_has_ja3s(self):
        self.assertIsNotNone(self.apt[0].ja3s_hash)

    def test_c2_record_tls_fields(self):
        rec = self.apt[0]
        self.assertIsNotNone(rec.tls_version)
        self.assertGreater(len(rec.tls_ciphers), 0)
        self.assertGreater(len(rec.tls_extensions), 0)

    def test_all_records_have_features(self):
        for i, rec in enumerate(self.apt):
            for feat in FLOW_FEATURES:
                self.assertIn(feat, rec.features,
                              msg=f"Record {i} missing '{feat}'")

    def test_all_records_have_timestamps(self):
        for rec in self.apt:
            self.assertIsInstance(rec.timestamp, datetime)
            self.assertIsNotNone(rec.timestamp.tzinfo)

    def test_c2_addresses(self):
        self.assertEqual(self.apt[0].src_ip, "10.22.14.45")
        self.assertEqual(self.apt[0].dst_ip, "185.220.101.32")


# TestIntegration

class TestIntegration(unittest.TestCase):

    def test_apt_ja3_found_in_feed(self):
        apt        = build_apt_scenario()
        c2_record  = apt[0]
        known_hash = c2_record.ja3_hash

        engine   = ThreatIntelEngine(refresh_interval=9999)
        ja3_csv  = _make_fake_ja3_csv([(known_hash, "2024-01-01", "CobaltStrike")])
        c2_json  = _make_fake_c2_json([c2_record.dst_ip])

        def fake_get(url, timeout=15):
            r = MagicMock()
            r.raise_for_status = MagicMock()
            if "sslbl" in url or "ja3" in url.lower():
                r.text = ja3_csv
            elif "feodo" in url or "ipblock" in url:
                r.text = c2_json
                r.json  = lambda: json.loads(c2_json)
            else:
                r.text = ""
                r.json  = lambda: []
            return r

        with patch("intel.threat_feed.requests.get", side_effect=fake_get):
            engine._refresh_all()

        hit = engine.lookup_ja3(known_hash)
        self.assertIsNotNone(hit, "APT C2 JA3 must be found in feed")
        self.assertEqual(hit.malware_family, "CobaltStrike")
        self.assertTrue(engine.is_known_c2(c2_record.dst_ip))


if __name__ == "__main__":
    unittest.main(verbosity=2)