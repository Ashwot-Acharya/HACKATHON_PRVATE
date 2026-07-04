"""
BankSentinel — Central Configuration
=====================================
All constants, paths, and settings live here.
Import this module in every agent to keep magic numbers in one place.

Challenge coverage:
  C1 Zero-day:          BEHAVIOR_* constants
  C2 False Positives:   REGIME_* constants
  C3 Alert Fatigue:     SUPPRESSION_* constants
  C4 Encrypted Traffic: JA3_* and BEACON_* constants
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Root paths ────────────────────────────────────────────────────────────────
ROOT_DIR      = Path(__file__).parent
DATA_DIR      = ROOT_DIR / "data"
MODELS_DIR    = ROOT_DIR / "models"
FORENSICS_DIR = ROOT_DIR / "forensics"
LOGS_DIR      = ROOT_DIR / "logs"

for d in [DATA_DIR, MODELS_DIR, FORENSICS_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)



DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
# GEMINI_API_KEYS = [k.strip() for k in _keys_env.split(",")] if _keys_env else ([GEMINI_API_KEY] if GEMINI_API_KEY else [])
OTX_API_KEY    = os.getenv("OTX_API_KEY", "")

# CHALLENGE C2 — Traffic Regime Contexts
# Six separate Isolation Forest models prevent false positives during
# legitimate high-volume banking operations (month-end, ATM recon, RTGS).
REGIME_CONTEXTS = {
    "month_end": {
        "contamination": 8e-4,
        "description":   "Last 3 business days of month",
        "trigger":       "day_of_month >= 28",
    },
    "atm_recon": {
        "contamination": 6e-4,
        "description":   "ATM reconciliation window 00:00–02:00 UTC+5:45",
        "trigger":       "hour_utc545 in [0, 1]",
    },
    "rtgs": {
        "contamination": 5e-4,
        "description":   "RTGS settlement — banking hours weekdays",
        "trigger":       "weekday and 9 <= hour_utc545 <= 17",
    },
    "off_hours": {
        "contamination": 4e-4,
        "description":   "Off-hours baseline 22:00–06:00 UTC+5:45",
        "trigger":       "hour_utc545 >= 22 or hour_utc545 < 6",
    },
    "weekend": {
        "contamination": 3e-4,
        "description":   "Weekend baseline Saturday–Sunday",
        "trigger":       "weekday in [5, 6]",
    },
    "normal": {
        "contamination": 5e-4,
        "description":   "Default business-hours baseline",
        "trigger":       "fallthrough",
    },
}

# Nepal is UTC+05:45 = 345 minutes ahead
NEPAL_UTC_OFFSET_MINUTES = 345

# CHALLENGE C4 — Encrypted Traffic Detection
# Three independent layers — all operate without payload decryption.
JA3_FEED_URL    = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv" # fetches known malware TLS fingerprints.
C2_IP_FEED_URL  = "https://feodotracker.abuse.ch/downloads/ipblocklist.json" # fetches active Command & Control server IP addresses
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/" # returns URLs recently reported as C2 or malware distribution points
TOR_EXIT_URL    = "https://check.torproject.org/torbulkexitlist" # fetches current Tor exit nodes

# Layer 2: JA3S bidirectional cross-signal confidence
JA3S_CROSS_CONFIDENCE = 0.65

# Layer 3: Beacon IAT variance threshold
# C2 beaconing has LOW inter-arrival time variance (calls home on schedule)
# Human HTTPS browsing has HIGH variance (unpredictable clicks)
BEACON_IAT_CV_THRESHOLD = 0.30
BEACON_MIN_FLOW_COUNT   = 10
BEACON_L3_CONFIDENCE    = 0.72

# Layer 1 confidence weights
JA3_FAMILY_HIT_WEIGHT = 0.55
C2_IP_HIT_WEIGHT      = 0.32
TOR_EXIT_WEIGHT       = 0.13

# Feed refresh interval in seconds (30 minutes)
THREAT_FEED_REFRESH_SEC = 1800

# CHALLENGE C3 — Alert Fatigue Suppression
DEDUP_WINDOW_SEC        = 300    # 5-min sliding deduplication window
CONFIDENCE_GATE_LOW     = 0.40   # below → queue only, no notification
CONFIDENCE_GATE_HIGH    = 0.85   # above → automated response triggers
CAUSAL_CHAIN_WINDOW_SEC = 600    # same source IP within 10 min → merge

# Bayesian prior: P(true threat campaign) =# BBN Threat prior P(C=1)
BBN_PRIOR_THREAT = 3.2e-4

# CHALLENGE C1 — Zero-Day Behavioral Detection
# BiLSTM autoencoder trained only on NORMAL sequences.
BEHAVIOR_SEQUENCE_LENGTH    = 20
BEHAVIOR_INPUT_SIZE         = 14
BEHAVIOR_HIDDEN_SIZE        = 128
BEHAVIOR_NUM_LAYERS         = 2
BEHAVIOR_DROPOUT            = 0.3
BEHAVIOR_ANOMALY_PERCENTILE = 95

# ── Flow Agent ────────────────────────────────────────────────────────────────
FLOW_FEATURES = [
    "bytes_recv",
    "bytes_sent",
    "dst_port",
    "duration_sec",
    "is_internal_dst",
    "is_internal_src",
    "packets_recv",
    "packets_sent",
    "src_port"
]
FLOW_N_ESTIMATORS = 200
FLOW_RANDOM_STATE = 42
CRS_WEIGHTS = [0.28, 0.24, 0.26, 0.22]

# ── Nepal Banking Network Segments ────────────────────────────────────────────
NETWORK_SEGMENTS = {
    "swift_subnet":   "10.22.14.0/24",
    "core_banking":   "10.22.15.0/24",
    "atm_switch":     "10.22.16.0/24",
    "nrb_regulatory": "10.22.17.0/24",
    "corporate_lan":  "10.22.18.0/24",
}

# ── Nepal-Specific APT Context ────────────────────────────────────────────────
NEPAL_APT_GROUPS = ["Lazarus", "APT38", "Chimera"]
NRB_ADVISORY_REF = "NRB-CYBER-2024-07"

# ── MITRE ATT&CK Technique IDs ────────────────────────────────────────────────
MITRE_C2_TECHNIQUE        = "T1071.001"
MITRE_DISCOVERY_TECHNIQUE = "T1046"
MITRE_COLLECTION_TECHNIQUE = "T1213"
MITRE_LATERAL_TECHNIQUE   = "T1021"
MITRE_PRIV_ESC_TECHNIQUE  = "T1078"
MITRE_EXFIL_TECHNIQUE     = "T1048"