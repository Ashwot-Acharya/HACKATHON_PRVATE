"""
BankSentinel — Behavior Agent
==============================
Challenge Addressed: C1 — Zero-Day Attacks (no known signature)

WHY THIS MATTERS
----------------
Zero-day attacks have no known signature. Signature-based systems cannot
catch them. The Behavior Agent solves this by learning ONLY what normal
behavior looks like. Any sequence that deviates from that learned normal
is flagged — regardless of whether it has ever been seen before.

The model has literally never been shown an attack during training.
It fires because deviation from normal is anomalous — not because the
attack matches a pattern.

HOW IT WORKS
------------
A Bidirectional LSTM (BiLSTM) autoencoder is trained exclusively on
normal behavioral sequences. It learns to reconstruct normal patterns
with low error. When it encounters an anomalous sequence, the
reconstruction error spikes — because it has never learned how to
reconstruct that kind of behavior.

Detection threshold = 95th percentile of reconstruction errors on the
normal training set.

INPUT FEATURES (14 dimensions per event, sequence length = 20)
-------------------------------------------------------------
  [0] dataset_source          Source indicator (1=User, 2=Win)
  [1] hour_sin                sin(2π × hour/24)
  [2] hour_cos                cos(2π × hour/24)
  [3] event_id_norm           Normalised Event ID
  [4] ds1_bytes_transferred   Log bytes transferred
  [5] ds1_duration_sec        Duration in seconds
  [6] ds1_is_off_hours        Off-hours indicator
  [7] ds1_is_new_resource     New resource indicator
  [8] ds1_failed_attempts     Failed attempts prior 1h
  [9] ds1_peer_deviation      Peer group deviation score
  [10] ds2_logon_type_norm    Normalised logon type
  [11] is_sensitive_target    Sensitive target indicator
  [12] ip_cluster             Source IP cluster index
  [13] query_rate             Normalised query rate

ATTACK SCENARIOS DETECTED (zero-day — no signature for any)
------------------------------------------------------------
  credential_abuse      Account from new IP at off-hours
  privilege_escalation  Standard user added to privileged group
  data_staging          400+ DB queries then large file creation
  lateral_movement      Sequential RDP across multiple servers
  insider_exfil         Slow-drip exfiltration over 48 hours

PAPER REFERENCE
---------------
  Section V-C, Table II (Windows Event IDs), Table IX (UEBA performance)
  BiLSTM: 2 layers, hidden_size=64, bidirectional=True, dropout=0.2
  Target: overall DR=94.9%, FPR=1.3%

Usage:
    # Training (run in Google Colab)
    from agents.behavior_agent import BehaviorAgentTrainer
    trainer = BehaviorAgentTrainer()
    trainer.train(n_users=500, n_per_user=20)
    trainer.save()

    # Inference
    from agents.behavior_agent import BehaviorAgent
    agent = BehaviorAgent.load()
    alert = agent.score(flow_record)
"""

from __future__ import annotations

import logging
import math
import pickle
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

from config import (
    BEHAVIOR_ANOMALY_PERCENTILE,
    BEHAVIOR_DROPOUT,
    BEHAVIOR_HIDDEN_SIZE,
    BEHAVIOR_INPUT_SIZE,
    BEHAVIOR_NUM_LAYERS,
    BEHAVIOR_SEQUENCE_LENGTH,
    MITRE_COLLECTION_TECHNIQUE,
    MITRE_LATERAL_TECHNIQUE,
    MITRE_PRIV_ESC_TECHNIQUE,
    MODELS_DIR,
)
from pipeline.ingestion import FlowRecord

logger = logging.getLogger(__name__)

# Windows Event IDs monitored (Table II of paper)
MONITORED_EVENT_IDS = {
    4624: "successful_logon",
    4625: "failed_logon",
    4648: "explicit_credential_logon",   # Pass-the-Hash indicator
    4688: "process_creation",
    4698: "scheduled_task_creation",
    4720: "user_account_creation",
    4728: "group_membership_change",
    4732: "group_membership_change",
    4769: "kerberos_ticket_request",
}

_EVENT_ID_LIST  = sorted(MONITORED_EVENT_IDS.keys())
_EVENT_ID_INDEX = {
    eid: i / max(len(_EVENT_ID_LIST) - 1, 1)
    for i, eid in enumerate(_EVENT_ID_LIST)
}


# DATA STRUCTURES

@dataclass
class BehaviorAlert:
    """
    Structured alert emitted by the Behavior Agent for every scored sequence.

    The Correlation Agent uses recon_error, is_anomaly, and mitre_technique
    in the Bayesian BBN fusion (Phase 3).

    Fields
    ------
    account          Windows account name or service principal.
    src_ip           Source workstation IP.
    recon_error      Mean squared reconstruction error of the BiLSTM.
                     Higher = more anomalous.
    threshold        95th-percentile threshold from training.
    is_anomaly       True when recon_error > threshold.
    confidence       Calibrated [0, 1] score for Correlation Agent.
    scenario_hint    Which behavioral attack scenario this most resembles.
    mitre_technique  MITRE ATT&CK technique if anomalous, else None.
    explanation      Human-readable reason for the SOC dashboard.
    top_dims         Top-3 input dimensions by reconstruction error.
    peer_z_score     Deviation from role-peer group centroid.
    timestamp        UTC creation time.
    """
    account:         str
    src_ip:          str
    recon_error:     float
    threshold:       float
    is_anomaly:      bool
    confidence:      float
    scenario_hint:   Optional[str]
    mitre_technique: Optional[str]
    explanation:     str
    top_dims:        List[Tuple[str, float]] = field(default_factory=list)
    peer_z_score:    float                   = 0.0
    timestamp:       datetime               = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __str__(self) -> str:
        status = "ANOMALY" if self.is_anomaly else "NORMAL"
        return (
            f"[BehaviorAlert {status}] "
            f"account={self.account} "
            f"recon_error={self.recon_error:.4f} "
            f"threshold={self.threshold:.4f} "
            f"conf={self.confidence:.3f} "
            f"scenario={self.scenario_hint}"
        )


# BILSTM AUTOENCODER

class DecoderSequential(nn.Sequential):
    @property
    def out_features(self):
        for layer in reversed(self):
            if hasattr(layer, 'out_features'):
                return layer.out_features
        raise AttributeError("No layer with out_features in Sequential")


class BehaviorLSTM(nn.Module):
    """
    Bidirectional LSTM autoencoder for zero-day behavioral detection.

    Architecture (Section V-C of paper):
      Encoder: BiLSTM(input=8, hidden=128, layers=2, dropout=0.3)
      Decoder: Sequential linear layers with LayerNorm
    """

    def __init__(
        self,
        input_size:  int   = BEHAVIOR_INPUT_SIZE,
        hidden_size: int   = BEHAVIOR_HIDDEN_SIZE,
        num_layers:  int   = BEHAVIOR_NUM_LAYERS,
        dropout:     float = BEHAVIOR_DROPOUT,
    ):
        super().__init__()
        self.input_size  = input_size
        self.hidden_size = hidden_size
        self.num_layers  = num_layers

        self.encoder = nn.LSTM(
            input_size    = input_size,
            hidden_size   = hidden_size,
            num_layers    = num_layers,
            batch_first   = True,
            bidirectional = True,
            dropout       = dropout if num_layers > 1 else 0.0,
        )
        self.layer_norm = nn.LayerNorm(hidden_size * 2)
        self.decoder = DecoderSequential(
            nn.Linear(hidden_size * 2, hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, input_size),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Encode input sequence, then reconstruct it.

        Args:
            x: (batch, seq_len, input_size)

        Returns:
            Reconstructed tensor of same shape as x.
        """
        lstm_out, _ = self.encoder(x)          # (batch, seq_len, hidden*2)
        lstm_out = self.layer_norm(lstm_out)
        return self.decoder(lstm_out)           # (batch, seq_len, input_size)

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """
        Per-sample mean squared reconstruction error.

        Args:
            x: (batch, seq_len, input_size)

        Returns:
            1-D tensor of shape (batch,) with per-sample MSE.
        """
        recon = self.forward(x)
        return ((x - recon) ** 2).mean(dim=(1, 2))


SCENARIO_NAMES = [
    "credential_abuse",
    "privilege_escalation",
    "data_staging",
    "lateral_movement",
    "insider_exfil",
]

SCENARIO_MITRE = {
    "credential_abuse":     MITRE_PRIV_ESC_TECHNIQUE,    # T1078
    "privilege_escalation": MITRE_PRIV_ESC_TECHNIQUE,    # T1078
    "data_staging":         MITRE_COLLECTION_TECHNIQUE,  # T1213
    "lateral_movement":     MITRE_LATERAL_TECHNIQUE,     # T1021
    "insider_exfil":        MITRE_COLLECTION_TECHNIQUE,  # T1213
}


# BEHAVIOR AGENT (INFERENCE)

class BehaviorAgent:
    """
    Runtime Behavior Agent — loads trained model and scores behavioral sequences.

    Accepts two input forms:
      1. A FlowRecord with behavioral context in its features dict.
      2. A raw numpy sequence array via score_sequence() directly.
    """

    def __init__(
        self,
        model:     BehaviorLSTM,
        threshold: float,
        feat_mean: np.ndarray,
        feat_std:  np.ndarray,
        device:    torch.device = torch.device("cpu"),
    ):
        self._model     = model.to(device)
        self._model.eval()
        self._threshold = threshold
        self._feat_mean = feat_mean
        self._feat_std  = feat_std
        self._device    = device

    @classmethod
    def load(
        cls,
        models_dir: Path = MODELS_DIR,
        device:     str  = "auto",
    ) -> "BehaviorAgent":
        """
        Load trained model artifacts and return a ready BehaviorAgent.

        Raises:
            FileNotFoundError: if any required artifact is missing.
        """
        base = Path(models_dir)
        for fname in [
            "behavior_model.pt",
            "behaviour_threshold.pkl",
            "behaviour_scaler.pkl",
        ]:
            if not (base / fname).exists():
                raise FileNotFoundError(
                    f"BehaviorAgent: missing {base / fname} — "
                    "run BehaviorAgentTrainer.train() first."
                )

        dev = torch.device(
            "cuda" if (device == "auto" and torch.cuda.is_available())
            else ("cpu" if device == "auto" else device)
        )

        model = BehaviorLSTM(
            input_size  = BEHAVIOR_INPUT_SIZE,
            hidden_size = BEHAVIOR_HIDDEN_SIZE,
            num_layers  = BEHAVIOR_NUM_LAYERS,
            dropout     = BEHAVIOR_DROPOUT,
        )
        state = torch.load(
            base / "behavior_model.pt",
            map_location=dev,
            weights_only=True,
        )
        model.load_state_dict(state)
        model.eval()

        with open(base / "behaviour_threshold.pkl", "rb") as f:
            threshold = pickle.load(f)
        with open(base / "behaviour_scaler.pkl", "rb") as f:
            scaler = pickle.load(f)

        logger.info(
            f"BehaviorAgent: loaded from {base} "
            f"(threshold={threshold:.6f}, device={dev})"
        )
        return cls(
            model     = model,
            threshold = threshold,
            feat_mean = scaler["feat_mean"],
            feat_std  = scaler["feat_std"],
            device    = dev,
        )

    # ── Core scoring ───────────────────────────────────────────────────────────

    def score(self, record: FlowRecord) -> BehaviorAlert:
        """
        Score a FlowRecord and return a BehaviorAlert.

        Reads from record.features:
          Flow Packets/s   → query_rate dimension
          privilege_level  → privilege dimension
          peer_z_score     → peer deviation dimension
          account          → account name for the alert
        """
        seq     = self._record_to_sequence(record)
        account = str(getattr(record, "account", None) or record.features.get("account", "unknown_account"))
        alert   = self.score_sequence(seq, src_ip=record.src_ip, account=account)
        record.behavior_alert = alert
        return alert

    def score_batch(self, records: List[FlowRecord]) -> List[BehaviorAlert]:
        """Score a list of FlowRecord objects and return a list of BehaviorAlerts."""
        return [self.score(rec) for rec in records]

    def score_sequence(
        self,
        sequence: np.ndarray,
        src_ip:   str = "0.0.0.0",
        account:  str = "unknown",
    ) -> BehaviorAlert:
        """
        Score a raw behavioral sequence.

        Args:
            sequence: ndarray (seq_len, input_size) or (1, seq_len, input_size).
            src_ip:   Source IP for the alert.
            account:  Account name for the alert.

        Returns:
            BehaviorAlert with all fields populated.
        """
        seq = np.array(sequence, dtype=np.float32)
        if seq.ndim == 2:
            seq = seq[np.newaxis, :]
            
        if seq.shape[2] != self._feat_mean.shape[0]:
            raise ValueError(
                f"Behavior sequence must have {self._feat_mean.shape[0]} features per timestep, "
                f"but got {seq.shape[2]}."
            )

        seq_norm = (seq - self._feat_mean) / self._feat_std
        tensor   = torch.tensor(seq_norm, dtype=torch.float32).to(self._device)

        with torch.no_grad():
            error = self._model.reconstruction_error(tensor)
        recon_error = float(error.cpu().numpy()[0])

        is_anomaly  = recon_error > self._threshold
        confidence  = self._normalise_error(recon_error)
        scenario, mitre = self._identify_scenario(seq[0])
        explanation = self._build_explanation(
            is_anomaly, recon_error, account, src_ip, scenario
        )
        top_dims = self._top_dim_errors(seq_norm[0], tensor[0])

        return BehaviorAlert(
            account         = account,
            src_ip          = src_ip,
            recon_error     = recon_error,
            threshold       = self._threshold,
            is_anomaly      = is_anomaly,
            confidence      = confidence,
            scenario_hint   = scenario if is_anomaly else None,
            mitre_technique = mitre   if is_anomaly else None,
            explanation     = explanation,
            top_dims        = top_dims,
            peer_z_score    = float(seq[0, :, 9].mean()),
        )

    @property
    def model(self) -> BehaviorLSTM:
        return self._model

    @property
    def threshold(self) -> float:
        return self._threshold

    # ── Private helpers ────────────────────────────────────────────────────────

    def _record_to_sequence(self, record: FlowRecord) -> np.ndarray:
        """
        Build a (seq_len, input_size) sequence from FlowRecord features.

        NOTE: This previously fell back to a synthetic-data generator when
        record.behavior_sequence was absent. That fallback has been removed.
        Callers must supply a real behavioral sequence (e.g. from Winlogbeat/
        Elastic SIEM event history for this account) on record.behavior_sequence.
        """
        if getattr(record, "behavior_sequence", None) is not None:
            return record.behavior_sequence

        raise ValueError(
            "FlowRecord has no behavior_sequence. The Behavior Agent requires "
            "a real sequence of the account's recent Windows Event Log activity "
            "(see MONITORED_EVENT_IDS) — synthetic fallback generation has been "
            "removed. Populate record.behavior_sequence from the event pipeline "
            "before calling score()."
        )

    def _normalise_error(self, error: float) -> float:
        """Sigmoid normalisation centred on threshold → [0, 1]."""
        k = 8.0
        x = (error - self._threshold) * k
        return float(1.0 / (1.0 + math.exp(-max(-50, min(50, x)))))

    def _identify_scenario(
        self, seq: np.ndarray
    ) -> Tuple[Optional[str], Optional[str]]:
        """Heuristically identify which attack scenario this resembles."""
        mean_hour   = seq[:, 1].mean()
        mean_priv   = seq[:, 11].mean()
        mean_query  = seq[:, 13].mean()
        mean_peer_z = seq[:, 9].mean()
        ip_variance = seq[:, 12].var()

        if ip_variance > 0.1:
            return "lateral_movement", SCENARIO_MITRE["lateral_movement"]
        if mean_priv > 0.6 and mean_peer_z > 1.5:
            return "privilege_escalation", SCENARIO_MITRE["privilege_escalation"]
        if mean_query > 0.7:
            return "data_staging", SCENARIO_MITRE["data_staging"]
        if mean_hour < -0.3:
            return "credential_abuse", SCENARIO_MITRE["credential_abuse"]
        if mean_peer_z > 1.0:
            return "insider_exfil", SCENARIO_MITRE["insider_exfil"]
        return "unknown_zero_day", MITRE_COLLECTION_TECHNIQUE

    def _build_explanation(
        self,
        is_anomaly:  bool,
        recon_error: float,
        account:     str,
        src_ip:      str,
        scenario:    Optional[str],
    ) -> str:
        if not is_anomaly:
            return (
                f"Account '{account}' behavior is consistent with "
                f"30-day learned normal profile "
                f"(recon_error={recon_error:.4f} < "
                f"threshold={self._threshold:.4f})."
            )
        margin = (
            (recon_error - self._threshold) / self._threshold * 100
        )
        return (
            f"ZERO-DAY behavioral anomaly for account '{account}' "
            f"from {src_ip}. "
            f"Reconstruction error={recon_error:.4f} exceeds threshold "
            f"by {margin:.0f}%. "
            f"Most likely scenario: {scenario}. "
            f"NOTE: No attack signature matched — detected by deviation "
            f"from learned normal behavior only."
        )

    def _top_dim_errors(
        self,
        seq_norm:   np.ndarray,
        seq_tensor: torch.Tensor,
        top_n:      int = 3,
    ) -> List[Tuple[str, float]]:
        """Top-N input dimensions by reconstruction error contribution."""
        dim_names = [
            "dataset_source", "hour_sin", "hour_cos", "event_id_norm",
            "ds1_bytes_transferred", "ds1_duration_sec", "ds1_is_off_hours", 
            "ds1_is_new_resource", "ds1_failed_attempts", "ds1_peer_deviation",
            "ds2_logon_type_norm", "is_sensitive_target", "ip_cluster", "query_rate"
        ]
        with torch.no_grad():
            recon = self._model(seq_tensor.unsqueeze(0))[0]
        dim_errors  = ((seq_norm - recon.cpu().numpy()) ** 2).mean(axis=0)
        top_indices = np.argsort(dim_errors)[::-1][:top_n]
        return [(dim_names[i], float(dim_errors[i])) for i in top_indices]


# SMOKE TEST

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )
    from pipeline.ingestion import build_apt_scenario

    logger.info("BehaviorAgent smoke test …")
    logger.info(
        "Training data generation has been removed from this module — "
        "run BehaviorAgentTrainer against real historical Windows Event "
        "Log sequences before loading the agent."
    )

    agent = BehaviorAgent.load(models_dir=MODELS_DIR)
    for rec in build_apt_scenario():
        alert = agent.score(rec)
        flag  = "⚑ ANOMALY" if alert.is_anomaly else "  normal "
        logger.info(
            f"  {flag}  acc={alert.account}  "
            f"err={alert.recon_error:.4f}  "
            f"scenario={alert.scenario_hint}"
        )
    logger.info("Smoke test complete.")