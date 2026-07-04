"""
BankSentinel — Data Ingestion Pipeline
=======================================
Challenge Addressed: C2 (regime labelling), C4 (IAT feature extraction)

Two responsibilities:
  1. prepare_cicids()  — loads CICIDS-2018, assigns Nepal banking time-regime
                         labels to every benign flow, saves six context-split
                         pickles for Flow Agent training (C2 foundation)
  2. StreamSimulator   — asyncio queue that replays FlowRecord objects as if
                         they were arriving from Apache Kafka

The regime labelling step is the direct foundation of Challenge C2.
Without correctly tagging each flow with its Nepal time-context, the
six-model Isolation Forest approach cannot be trained.

Usage:
    # Training data preparation
    from pipeline.ingestion import prepare_cicids
    benign_by_regime, attacks = prepare_cicids("data/Wednesday.csv")

    # Stream simulation
    from pipeline.ingestion import StreamSimulator, build_apt_scenario
    sim = StreamSimulator(build_apt_scenario(), delay_ms=2000)
    async for record in sim.stream():
        await agent.process(record)
"""

import asyncio
import logging
import pickle
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from config import (
    CAUSAL_CHAIN_WINDOW_SEC,
    DEDUP_WINDOW_SEC,
    FLOW_FEATURES,
    MODELS_DIR,
    NEPAL_UTC_OFFSET_MINUTES,
    REGIME_CONTEXTS,
)

logger = logging.getLogger(__name__)


# REGIME LABELLING — Core of Challenge C2

def _nepal_hour(utc_hour: int, utc_minute: int = 0) -> float:
    """
    Convert UTC hour + minute to Nepal local time as a float.

    Nepal is UTC+05:45 (one of only two countries on a 45-min offset).
    UTC 00:00 → Nepal 05:45 = 5.75
    UTC 18:15 → Nepal 00:00 = 0.0

    Args:
        utc_hour:   Hour in UTC (0–23)
        utc_minute: Minute in UTC (0–59)

    Returns:
        Nepal local hour as float (e.g. 1:30 Nepal = 1.5)
    """
    total_minutes = utc_hour * 60 + utc_minute + NEPAL_UTC_OFFSET_MINUTES
    return (total_minutes % (24 * 60)) / 60.0


def assign_regime(
    hour_utc:     int,
    minute_utc:   int = 0,
    weekday:      int = 0,    # 0=Monday … 6=Sunday
    day_of_month: int = 15,
) -> str:
    """
    Assign a Nepal banking traffic regime label to a network flow.

    This function is the core of Challenge C2. It maps any flow timestamp
    to one of six contexts. Each context gets its own Isolation Forest model
    trained on traffic that is normal for that specific time window.

    Priority order (first match wins — order is important):
      1. month_end  — last 3 business days of month (highest FPR risk)
      2. atm_recon  — 00:00–02:00 Nepal time (nightly ATM reconciliation)
      3. rtgs       — weekday 09:00–17:00 Nepal (RTGS settlement)
      4. off_hours  — 22:00–06:00 Nepal (low baseline, any spike suspicious)
      5. weekend    — Saturday or Sunday
      6. normal     — everything else (standard business hours)

    Args:
        hour_utc:     UTC hour of the flow (0–23)
        minute_utc:   UTC minute of the flow (0–59)
        weekday:      Day of week (0=Monday, 6=Sunday)
        day_of_month: Calendar day (1–31)

    Returns:
        One of: "month_end", "atm_recon", "rtgs", "off_hours",
                "weekend", "normal"
    """
    nepal_hour = _nepal_hour(hour_utc, minute_utc)
    is_weekend = weekday >= 5

    # Priority 1: month-end batch processing (highest contamination)
    if day_of_month >= 28 and not is_weekend:
        return "month_end"

    # Priority 2: ATM reconciliation window
    if 0.0 <= nepal_hour < 2.0:
        return "atm_recon"

    # Priority 3: RTGS settlement — weekday business hours
    if not is_weekend and 9.0 <= nepal_hour < 17.0:
        return "rtgs"

    # Priority 4: off-hours baseline
    if nepal_hour >= 22.0 or nepal_hour < 6.0:
        return "off_hours"

    # Priority 5: weekend
    if is_weekend:
        return "weekend"

    # Priority 6: normal fallthrough
    return "normal"


# CICIDS-2017 DATA PREPARATION

_LABEL_COL = "Label"


def prepare_cicids(
    csv_path: str | Path,
    save_to:  Optional[Path] = None,
) -> Tuple[Dict[str, pd.DataFrame], pd.DataFrame]:
    """
    Load and preprocess CICIDS-2018 Wednesday CSV for Flow Agent training.

    Steps:
      1. Strip column name whitespace
      2. Dynamically extract feature columns
      3. Replace infinite values with NaN, then fill NaN with column median
      4. Split into benign and attack rows
      5. Assign Nepal time-regime label to each benign row (C2 foundation)
      6. Build benign_by_regime dict — one DataFrame per regime
      7. Save both outputs as pickle files

    Args:
        csv_path: Path to Wednesday-workingHours.pcap_ISCX.csv
                  Download from: https://www.unb.ca/cic/datasets/ids-2018.html
                  Or via Kaggle: cicdatasetgroup/cicids2018
        save_to:  Directory for output pickle files.
                  Defaults to config.MODELS_DIR.

    Returns:
        Tuple of:
          benign_by_regime — Dict[regime_name, DataFrame] (6 entries)
          attacks          — DataFrame with all attack rows + Label column

    Raises:
        FileNotFoundError: if csv_path does not exist
    """
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"CICIDS CSV not found: {csv_path}")

    save_dir = Path(save_to) if save_to else MODELS_DIR
    save_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Loading CICIDS-2018 from {csv_path} …")
    df = pd.read_csv(csv_path, low_memory=False)

    # Step 1: clean column names
    df.columns = df.columns.str.strip()

    if _LABEL_COL not in df.columns:
        raise ValueError(f"Label column '{_LABEL_COL}' not found in CSV")

    # Step 2: Extract feature columns dynamically, ensuring FLOW_FEATURES are present
    for col in FLOW_FEATURES:
        if col not in df.columns:
            raise ValueError(f"Required feature column '{col}' not found in CSV")
            
    features = [c for c in df.columns if c not in [_LABEL_COL]]

    # Step 3: clean infinite and NaN values
    feature_df = df[features].copy()
    feature_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    for col in features:
        median_val = feature_df[col].median()
        feature_df[col] = feature_df[col].fillna(median_val)
    df[features] = feature_df
    df.dropna(subset=[_LABEL_COL], inplace=True)
    df.reset_index(drop=True, inplace=True)
    logger.info(f"  Rows after cleaning: {len(df):,}")

    # Step 4: split benign / attacks
    benign  = df[df[_LABEL_COL] == "BENIGN"].copy()
    attacks = df[df[_LABEL_COL] != "BENIGN"].copy()
    logger.info(f"  Benign: {len(benign):,}  |  Attacks: {len(attacks):,}")

    # Step 5: assign regime labels
    # CICIDS-2018 Wednesday is a single captured day so we distribute rows
    # proportionally across a synthetic 24-hour period. In a live deployment
    # the actual flow timestamp is used instead.
    logger.info("  Assigning regime labels (Challenge C2) …")
    rng = np.random.default_rng(42)
    n   = len(benign)

    benign = benign.copy()
    benign["hour_utc"]     = rng.integers(0, 24, size=n)
    benign["minute_utc"]   = rng.integers(0, 60, size=n)
    benign["weekday"]      = rng.integers(0, 5,  size=n)   # weekdays only
    # skew slightly toward month-end to ensure that regime gets samples
    day_pool = list(range(1, 29)) + [28, 29, 30, 31] * 3
    benign["day_of_month"] = rng.choice(day_pool, size=n)

    benign["regime"] = benign.apply(
        lambda r: assign_regime(
            int(r["hour_utc"]),
            int(r["minute_utc"]),
            int(r["weekday"]),
            int(r["day_of_month"]),
        ),
        axis=1,
    )

    # Step 6: build regime dict
    benign_by_regime: Dict[str, pd.DataFrame] = {}
    for regime in REGIME_CONTEXTS:
        slice_df = benign[benign["regime"] == regime][features]
        if len(slice_df) == 0:
            logger.warning(
                f"  Regime '{regime}' has 0 rows — using random 10% fallback."
            )
            slice_df = benign.sample(frac=0.1, random_state=42)[features]
        benign_by_regime[regime] = slice_df.reset_index(drop=True)
        logger.info(f"  Regime '{regime}': {len(slice_df):,} rows")

    # Step 7: save to disk
    regime_path  = save_dir / "benign_by_regime.pkl"
    attacks_path = save_dir / "attack_flows.pkl"

    with open(regime_path, "wb") as f:
        pickle.dump(benign_by_regime, f)
    attacks[features + [_LABEL_COL]].to_pickle(attacks_path)

    logger.info(f"  Saved: {regime_path}")
    logger.info(f"  Saved: {attacks_path}")
    return benign_by_regime, attacks


def prepare_custom_dataset(
    csv_path: str | Path,
    save_to:  Optional[Path] = None,
) -> Tuple[Dict[str, pd.DataFrame], pd.DataFrame]:
    """Clean and transform a user‑provided flow CSV.

    Expected columns (as documented by the user):
        flow_id, start_time, end_time, duration_sec, src_ip, src_port,
        dst_ip, dst_port, protocol, bytes_sent, bytes_recv,
        packets_sent, packets_recv, tcp_flags, is_internal_src,
        is_internal_dst, segment, application_guess, flow_label

    The function:
        • parses timestamps (assumes ISO‑like format with optional milliseconds)
        • derives additional numeric features required by the Flow Agent
        • maps the column names to the feature set defined in ``config.FLOW_FEATURES``
        • assigns Nepal banking regime labels using the real timestamps
        • splits benign (flow_label == "NORMAL") from attack rows
    """
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"Custom CSV not found: {csv_path}")

    save_dir = Path(save_to) if save_to else MODELS_DIR
    save_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Loading custom flow data from {csv_path} …")
    df = pd.read_csv(csv_path)

    # 1️⃣  Basic cleaning / type conversion
    df["start_time"] = pd.to_datetime(df["start_time"], errors="coerce")
    df["end_time"]   = pd.to_datetime(df["end_time"],   errors="coerce")
    df.dropna(subset=["start_time", "end_time"], inplace=True)

    numeric_cols = [
        "duration_sec", "bytes_sent", "bytes_recv",
        "packets_sent", "packets_recv", "src_port", "dst_port",
    ]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df.dropna(subset=numeric_cols, inplace=True)

    # 2️⃣  Build the feature DataFrame expected by the Flow Agent
    feature_map = {
        "Flow Duration":            df["duration_sec"],
        "Total Fwd Packets":        df["packets_sent"],
        "Total Backward Packets":   df["packets_recv"],
        "Total Length of Fwd Packets": df["bytes_sent"],
        "Total Length of Bwd Packets": df["bytes_recv"],
        "Flow Bytes/s":            (df["bytes_sent"] + df["bytes_recv"]) / df["duration_sec"].replace(0, np.nan),
        "Flow Packets/s":          (df["packets_sent"] + df["packets_recv"]) / df["duration_sec"].replace(0, np.nan),
        "Flow IAT Mean":           0.0,
        "Flow IAT Std":            0.0,
        "Fwd IAT Total":           0.0,
        "Fwd IAT Mean":            0.0,
        "Fwd IAT Std":             0.0,
        "Bwd IAT Mean":            0.0,
        "Bwd IAT Std":             0.0,
        "Destination Port":        df["dst_port"],
    }
    feature_df = pd.DataFrame(feature_map)

    feature_df = feature_df.replace([np.inf, -np.inf], np.nan)
    for col in feature_df.columns:
        median_val = feature_df[col].median()
        feature_df[col] = feature_df[col].fillna(median_val)

    # 3️⃣  Assign regime labels based on the *start_time* (UTC assumed)
    logger.info("  Assigning regime labels for custom data …")
    utc_times = df["start_time"].dt.tz_convert(None) if df["start_time"].dt.tz is not None else df["start_time"]
    df["hour_utc"]   = utc_times.dt.hour
    df["minute_utc"] = utc_times.dt.minute
    df["weekday"]    = utc_times.dt.weekday  # Monday=0
    df["day_of_month"] = utc_times.dt.day

    df["regime"] = df.apply(
        lambda r: assign_regime(
            int(r["hour_utc"]),
            int(r["minute_utc"]),
            int(r["weekday"]),
            int(r["day_of_month"]),
        ),
        axis=1,
    )

    # 4️⃣  Split benign vs. attack rows
    benign = df[df["flow_label"].str.upper() == "NORMAL"].copy()
    attacks = df[df["flow_label"].str.upper() != "NORMAL"].copy()
    logger.info(f"  Cleaned rows: {len(df):,} – benign: {len(benign):,}, attacks: {len(attacks):,}")

    # 5️⃣  Build regime dictionaries
    benign_by_regime: Dict[str, pd.DataFrame] = {}
    # Align the index of the features with the index of the benign subset
    benign_features = feature_df.loc[benign.index]
    
    for regime in REGIME_CONTEXTS:
        slice_df = benign_features.loc[benign["regime"] == regime]
        if slice_df.empty:
            logger.warning(f"  Regime '{regime}' has 0 rows in custom data – using random 10% fallback.")
            slice_df = benign_features.sample(frac=0.1, random_state=42)
        benign_by_regime[regime] = slice_df.reset_index(drop=True)
        logger.info(f"  Regime '{regime}': {len(slice_df):,} rows")

    # 6️⃣  Persist the artefacts
    regime_path  = save_dir / "benign_by_regime.pkl"
    attacks_path = save_dir / "attack_flows.pkl"
    with open(regime_path, "wb") as f:
        pickle.dump(benign_by_regime, f)
    
    attacks_out = attacks.copy()
    for col in feature_df.columns:
        attacks_out[col] = feature_df[col]
    attacks_out.to_pickle(attacks_path)

    logger.info(f"  Saved regime data: {regime_path}")
    logger.info(f"  Saved attacks data: {attacks_path}")
    return benign_by_regime, attacks_out

def load_regime_data(
    models_dir: Path = MODELS_DIR,
) -> Dict[str, pd.DataFrame]:
    """
    Load pre-saved regime data from disk.

    Call this in Phase 2 instead of re-running prepare_cicids().

    Args:
        models_dir: Directory containing benign_by_regime.pkl

    Returns:
        Dict[regime_name, DataFrame]

    Raises:
        FileNotFoundError: if benign_by_regime.pkl is not found
    """
    path = Path(models_dir) / "benign_by_regime.pkl"
    if not path.exists():
        raise FileNotFoundError(
            f"Regime data not found at {path}. "
            "Run prepare_cicids() first."
        )
    with open(path, "rb") as f:
        return pickle.load(f)


# FLOW RECORD — shared data structure for the full pipeline

class FlowRecord:
    """
    A single network flow event passed between all five agents.

    Fields are populated progressively as the record moves through the
    pipeline. Every agent receives a FlowRecord, reads what it needs,
    and writes its result into the corresponding _alert field.

    TLS fields are only populated when the flow contains TLS metadata
    (used by Packet Agent for C4 Layer 1 and Layer 2).
    """

    __slots__ = (
        "record_id", "timestamp", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol",
        "features", "label", "regime",
        # TLS metadata (C4)
        "tls_version", "tls_ciphers", "tls_extensions",
        "tls_curves", "tls_point_formats",
        "ja3_hash", "ja3s_hash",
        # Agent results (populated by each agent in turn)
        "packet_alert", "flow_alert", "behavior_alert",
        "correlation_result", "response_actions",
        # Custom testing/example fields
        "behavior_sequence", "account",
    )

    def __init__(
        self,
        src_ip:   str,
        dst_ip:   str,
        features: Dict[str, Any],
        label:    str = "BENIGN",
        regime:   str = "normal",
        src_port: int = 0,
        dst_port: int = 0,
        protocol: int = 6,      # TCP = 6
    ):
        self.record_id = id(self)
        self.timestamp = datetime.now(timezone.utc)
        self.src_ip    = src_ip
        self.dst_ip    = dst_ip
        self.src_port  = src_port
        self.dst_port  = dst_port
        self.protocol  = protocol
        self.features  = features
        self.label     = label
        self.regime    = regime

        # TLS fields
        self.tls_version       = None
        self.tls_ciphers:    list = []
        self.tls_extensions: list = []
        self.tls_curves:     list = []
        self.tls_point_formats: list = []
        self.ja3_hash:  Optional[str] = None
        self.ja3s_hash: Optional[str] = None

        # Agent results
        self.packet_alert       = None
        self.flow_alert         = None
        self.behavior_alert     = None
        self.correlation_result = None
        self.response_actions:  list = []

        # Custom fields
        self.behavior_sequence = None
        self.account           = None

    def __repr__(self) -> str:
        return (
            f"FlowRecord({self.src_ip}→{self.dst_ip} "
            f"label={self.label} regime={self.regime})"
        )


# STREAM SIMULATOR — asyncio replacement for Apache Kafka

class StreamSimulator:
    """
    In-memory asyncio stream that replays FlowRecord objects.

    Replaces Apache Kafka for the hackathon demo. Records are yielded
    one at a time with a configurable inter-record delay so the demo
    animation has time to render each stage.

    Usage:
        sim = StreamSimulator(records, delay_ms=2000)
        async for record in sim.stream():
            await packet_agent.process(record)
    """

    def __init__(
        self,
        records:      List[FlowRecord],
        delay_ms:     float = 50.0,
        loop_forever: bool  = False,
    ):
        """
        Args:
            records:      Pre-built FlowRecord objects to stream.
            delay_ms:     Milliseconds between records.
                          Set to 0 for maximum throughput.
                          Set to 2000 for demo pacing (2s per stage).
            loop_forever: If True, replay records indefinitely.
        """
        self._records      = records
        self._delay        = delay_ms / 1000.0
        self._loop_forever = loop_forever
        self._running      = False

    async def stream(self) -> AsyncIterator[FlowRecord]:
        """
        Async generator — yields FlowRecord objects in order.

        Yields:
            FlowRecord instances with optional inter-record delay.
        """
        self._running = True
        try:
            while True:
                for record in self._records:
                    if not self._running:
                        return
                    yield record
                    if self._delay > 0:
                        await asyncio.sleep(self._delay)
                if not self._loop_forever:
                    break
        finally:
            self._running = False

    def stop(self) -> None:
        """Stop yielding after the current record."""
        self._running = False


# APT SCENARIO BUILDER — Section III of paper, reproduced as FlowRecords

def build_apt_scenario() -> List[FlowRecord]:
    """
    Build the coordinated APT campaign from Section III of the paper.

    Creates three FlowRecord objects representing the attack chain:
      Record 0 — C4: TLS C2 beaconing with known Cobalt Strike JA3 hash
      Record 1 — C2: SWIFT subnet flow deviation during off-hours
      Record 2 — C1: svc_corebanking DB query spike (zero-day pattern)

    The Correlation Agent (Phase 3) fuses all three into CRS=0.94
    and the Response Agent isolates 10.22.14.45 within 38 seconds.

    Returns:
        List of three FlowRecord objects representing the APT chain.
    """
    rng = random.Random(42)

    # Record 0: C2 TLS connection — triggers Packet Agent (C4)
    c2_record = FlowRecord(
        src_ip   = "10.22.14.45",
        dst_ip   = "185.220.101.32",
        src_port = 49271,
        dst_port = 443,
        protocol = 6,
        features = {f: rng.uniform(100, 500) for f in FLOW_FEATURES},
        label    = "APT-C2",
        regime   = "off_hours",
    )
    # Known Cobalt Strike C2 TLS fingerprint fields
    c2_record.tls_version       = 771
    c2_record.tls_ciphers       = [49195, 49199, 52393, 52392, 49196, 49200]
    c2_record.tls_extensions    = [0, 5, 10, 11, 13, 18, 23, 65281]
    c2_record.tls_curves        = [29, 23, 24]
    c2_record.tls_point_formats = [0]
    # 32-character MD5 hex JA3 hash (Cobalt Strike default profile)
    c2_record.ja3_hash  = "0b32309a26951912be7dba376398abc3"
    c2_record.ja3s_hash = "ae4edc6faf64d08308082ad26be60767"

    # Record 1: SWIFT subnet lateral flow — triggers Flow Agent (C2)
    swift_record = FlowRecord(
        src_ip   = "10.22.14.45",
        dst_ip   = "10.22.14.1",
        src_port = 49272,
        dst_port = 4711,
        features = {f: rng.uniform(8000, 15000) for f in FLOW_FEATURES},
        label    = "APT-Lateral",
        regime   = "off_hours",
    )

    # Record 2: DB query spike — triggers Behavior Agent (C1)
    db_record = FlowRecord(
        src_ip   = "10.22.15.10",
        dst_ip   = "10.22.15.10",
        src_port = 1521,
        dst_port = 1521,
        features = {f: rng.uniform(50, 200) for f in FLOW_FEATURES},
        label    = "APT-Collection",
        regime   = "off_hours",
    )
    # Attach synthetic behavioral context (normally from Windows Event Logs)
    db_record.features["Flow Packets/s"] = 200.0   # 400 queries in 2 min

    return [c2_record, swift_record, db_record]


# ── Smoke test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    if len(sys.argv) > 1:
        csv_file = sys.argv[1]
        logger.info(f"Running prepare_cicids on: {csv_file}")
        regime_data, attack_data = prepare_cicids(csv_file)
        for regime, df in regime_data.items():
            print(f"  {regime:12s}: {len(df):>8,} rows")
        print(f"  {'attacks':12s}: {len(attack_data):>8,} rows")
    else:
        logger.info("Building APT scenario …")
        records = build_apt_scenario()
        for r in records:
            print(f"  {r}  ja3={r.ja3_hash}")
        print(f"\nRegime test: assign_regime(19, 15, 2, 10) = "
              f"{assign_regime(19, 15, 2, 10)}")   # → atm_recon
        print(f"Regime test: assign_regime(4,  15, 1, 10) = "
              f"{assign_regime(4,  15, 1, 10)}")   # → rtgs