"""
BankSentinel — Flow Agent
=========================
Challenge Addressed: C2 — Legitimate High-Volume False Positives

The Flow Agent solves Challenge C2 by training six separate Isolation
Forest models — one per Nepal banking traffic regime context.

WHY THIS MATTERS
----------------
A global single model trained on all traffic scores ATM reconciliation
traffic (00:00–02:00 Nepal) as anomalous at a 22.7% false positive rate
because the model has never seen that volume as "normal".  The context-
aware approach reduces this to 2.1% by routing each incoming flow to the
model that was trained specifically on traffic from that time window.

THE SIX CONTEXTS
----------------
  month_end  — last 3 business days: batch jobs push huge volumes
  atm_recon  — nightly 00:00–02:00 Nepal: ATM settlement spikes
  rtgs       — business hours: RTGS payment bursts
  off_hours  — 22:00–06:00 Nepal: low baseline, any spike suspicious
  weekend    — Sat/Sun: minimal traffic, very sensitive model
  normal     — standard daytime baseline

ARCHITECTURE
------------
  FlowAgentTrainer  — builds and persists the six models + scaler
  FlowAgent         — loads models at runtime, scores live FlowRecords
  FlowAlert         — structured result emitted for the Correlation Agent

PAPER REFERENCE
---------------
  Section V-B, Table I (regime contexts), Table VII (FPR comparison)
  Contamination parameter ψ = 5×10⁻⁴ base, adjusted per regime
  Rolling re-training cycle: 7 days (implemented via retrain())

Usage:
    # ── Training (Phase 2, run once) ─────────────────────────────────────
    from agents.flow_agent import FlowAgentTrainer
    trainer = FlowAgentTrainer()
    metrics = trainer.train(benign_by_regime, attack_df)
    trainer.save()

    # ── Inference (Phase 3 onwards, per live flow) ────────────────────────
    from agents.flow_agent import FlowAgent
    agent = FlowAgent.load()
    alert = agent.score(flow_record)
    if alert.is_anomaly:
        print(alert.explanation)
"""

from __future__ import annotations

import logging
import pickle
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler

from config import (
    FLOW_FEATURES,
    MITRE_DISCOVERY_TECHNIQUE,
    MODELS_DIR,
    REGIME_CONTEXTS,
)
from pipeline.ingestion import FlowRecord, assign_regime

logger = logging.getLogger(__name__)


# DATA STRUCTURES

@dataclass
class FlowAlert:
    """
    Structured alert emitted by the Flow Agent for every scored flow.

    The Correlation Agent reads anomaly_score, is_anomaly, regime,
    and mitre_technique to compute the Composite Risk Score.

    Fields
    ------
    src_ip          Source IP of the flow.
    dst_ip          Destination IP of the flow.
    regime          Which of the 6 context models was used.
    anomaly_score   Raw Isolation Forest score in [0, 1].
                    Higher → more anomalous.
                    (Internally IF returns negative values; we normalise.)
    is_anomaly      True when anomaly_score exceeds the regime threshold.
    confidence      Calibrated confidence sent to the Correlation Agent.
    mitre_technique MITRE ATT&CK technique if anomalous, else None.
    explanation     Human-readable reason string for the SOC dashboard.
    top_features    Top-3 features by SHAP contribution (populated if
                    SHAP is available; empty list otherwise).
    timestamp       UTC time this alert was created.
    global_score    Score from the global baseline model (for comparison).
    """
    src_ip:          str
    dst_ip:          str
    regime:          str
    anomaly_score:   float
    is_anomaly:      bool
    confidence:      float
    mitre_technique: Optional[str]
    explanation:     str
    top_features:    List[Tuple[str, float]] = field(default_factory=list)
    timestamp:       datetime               = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    global_score:    float = 0.0

    # ── Challenge C2 proof fields ──────────────────────────────────────────────
    context_fpr:     float = 0.0
    global_fpr:      float = 0.0
    fpr_reduction:   float = 0.0

    def __str__(self) -> str:
        status = "ANOMALY" if self.is_anomaly else "NORMAL"
        return (
            f"[FlowAlert {status}] "
            f"{self.src_ip}→{self.dst_ip} "
            f"regime={self.regime} "
            f"score={self.anomaly_score:.3f} "
            f"conf={self.confidence:.3f}"
        )




# FLOW AGENT (INFERENCE)

class FlowAgent:
    """
    Runtime Flow Agent — loads trained models and scores live FlowRecords.

    Called by the pipeline for every incoming network flow. It:
      1. Determines which regime model to use from the flow's timestamp
      2. Normalises the flow features using the shared scaler
      3. Scores with the context-appropriate Isolation Forest model
      4. Optionally scores with the global model for comparison
      5. Returns a structured FlowAlert for the Correlation Agent
    """

    def __init__(
        self,
        context_models: Dict[str, IsolationForest],
        global_model:   IsolationForest,
        scaler:         StandardScaler,
        thresholds:     Dict[str, float],
        shap_enabled:   bool = False,
    ):
        self._context = context_models
        self._global  = global_model
        self._scaler  = scaler
        self._thresh  = thresholds
        self._shap    = shap_enabled
        self._explainer = None
        if shap_enabled:
            self._init_shap()

    @classmethod
    def load(
        cls,
        models_dir:   Path = MODELS_DIR,
        shap_enabled: bool = False,
    ) -> "FlowAgent":
        """
        Load all persisted artifacts and return a ready FlowAgent.

        Raises:
            FileNotFoundError: if any required artifact is missing.
        """
        base = Path(models_dir)
        for fname in [
            "flow_context_models.pkl",
            "flow_global_model.pkl",
            "flow_scaler.pkl",
            "flow_thresholds.pkl",
        ]:
            if not (base / fname).exists():
                raise FileNotFoundError(
                    f"FlowAgent: missing {base / fname} — "
                    "train flow agent first."
                )

        context_models = joblib.load(base /"flow_context_models.pkl")
        global_model = joblib.load(base / "flow_global_model.pkl")
        scaler = joblib.load(base / "flow_scaler.pkl")
        thresholds = joblib.load(base / "flow_thresholds.pkl")

        logger.info(
            f"FlowAgent: loaded {len(context_models)} context models from {base}"
        )
        return cls(context_models, global_model, scaler, thresholds, shap_enabled)

    def score(self, record: FlowRecord) -> FlowAlert:
        """
        Score a single FlowRecord and return a FlowAlert.

        The regime is taken from record.regime if already set by the
        ingestion layer. If not set, it is derived from the timestamp.
        """
        regime    = self._resolve_regime(record)
        X_raw     = self._extract_features(record)
        X_scaled  = self._scaler.transform(X_raw.reshape(1, -1))

        model     = self._context.get(regime, self._context.get("normal"))
        raw_score = float(-model.score_samples(X_scaled)[0])
        threshold = self._thresh.get(regime, self._thresh.get("normal", 0.5))
        is_anomaly = raw_score > threshold

        anomaly_score = self._normalise_score(raw_score, threshold)
        confidence    = (
            min(anomaly_score * 1.2, 1.0) if is_anomaly
            else anomaly_score * 0.5
        )

        global_raw   = float(-self._global.score_samples(X_scaled)[0])
        global_score = self._normalise_score(
            global_raw, self._thresh.get("normal", 0.5)
        )

        mitre, explanation = self._explain(
            is_anomaly, regime, anomaly_score, record, X_raw
        )

        top_features: List[Tuple[str, float]] = []
        if self._shap and self._explainer is not None:
            top_features = self._shap_top_features(X_scaled, model, regime)

        alert = FlowAlert(
            src_ip          = record.src_ip,
            dst_ip          = record.dst_ip,
            regime          = regime,
            anomaly_score   = anomaly_score,
            is_anomaly      = is_anomaly,
            confidence      = confidence,
            mitre_technique = mitre,
            explanation     = explanation,
            top_features    = top_features,
            global_score    = global_score,
        )
        record.flow_alert = alert
        return alert

    def score_batch(self, records: List[FlowRecord]) -> List[FlowAlert]:
        """
        Score a list of FlowRecords efficiently using vectorised operations.

        Groups records by regime so each model is called once per regime
        rather than once per record.
        """
        if not records:
            return []

        regime_groups: Dict[str, List[int]] = {}
        for i, rec in enumerate(records):
            r = self._resolve_regime(rec)
            regime_groups.setdefault(r, []).append(i)

        alerts: List[Optional[FlowAlert]] = [None] * len(records)

        for regime, indices in regime_groups.items():
            model     = self._context.get(regime, self._context["normal"])
            threshold = self._thresh.get(regime, self._thresh.get("normal", 0.5))

            X_raw_list = np.array([
                self._extract_features(records[i]) for i in indices
            ])
            X_scaled    = self._scaler.transform(X_raw_list)
            raw_scores  = -model.score_samples(X_scaled)
            anom_scores = np.array([
                self._normalise_score(s, threshold) for s in raw_scores
            ])
            is_anom     = raw_scores > threshold
            global_raw  = -self._global.score_samples(X_scaled)
            global_norm = np.array([
                self._normalise_score(s, self._thresh.get("normal", 0.5))
                for s in global_raw
            ])

            for local_i, global_i in enumerate(indices):
                rec  = records[global_i]
                anom = bool(is_anom[local_i])
                mitre, expl = self._explain(
                    anom, regime, float(anom_scores[local_i]),
                    rec, X_raw_list[local_i]
                )
                conf = (
                    min(float(anom_scores[local_i]) * 1.2, 1.0)
                    if anom else float(anom_scores[local_i]) * 0.5
                )
                alert = FlowAlert(
                    src_ip          = rec.src_ip,
                    dst_ip          = rec.dst_ip,
                    regime          = regime,
                    anomaly_score   = float(anom_scores[local_i]),
                    is_anomaly      = anom,
                    confidence      = conf,
                    mitre_technique = mitre,
                    explanation     = expl,
                    global_score    = float(global_norm[local_i]),
                )
                rec.flow_alert = alert
                alerts[global_i] = alert

        return alerts  # type: ignore[return-value]

    def evaluate(
        self,
        benign_by_regime: Dict[str, pd.DataFrame],
        attack_df:        pd.DataFrame,
    ) -> Dict[str, Dict]:
        """
        Re-evaluate trained models against held-out data.
        Produces the Table VII equivalent for your presentation.
        """
        results: Dict[str, Dict] = {}
        X_attack = self._scaler.transform(
            self._clean_df(attack_df).values
        )
        for regime in REGIME_CONTEXTS:
            regime_df = benign_by_regime.get(regime)
            if regime_df is None or len(regime_df) == 0:
                continue
            X_benign  = self._scaler.transform(
                self._clean_df(regime_df).values
            )
            model      = self._context.get(regime, self._context["normal"])
            threshold  = self._thresh.get(regime, 0.5)

            benign_preds = model.predict(X_benign)
            fpr_context  = float((benign_preds == -1).sum()) / len(X_benign)

            global_preds = self._global.predict(X_benign)
            fpr_global   = float((global_preds == -1).sum()) / len(X_benign)

            attack_preds = model.predict(X_attack)
            dr = float((attack_preds == -1).sum()) / max(len(X_attack), 1)

            results[regime] = {
                "fpr_context":       fpr_context,
                "fpr_global":        fpr_global,
                "fpr_reduction_pct": (
                    ((fpr_global - fpr_context) / fpr_global * 100)
                    if fpr_global > 0 else 0.0
                ),
                "detection_rate":    dr,
                "n_benign_test":     len(X_benign),
                "n_attack_test":     len(X_attack),
            }
            logger.info(
                f"[EVAL] {regime:<12} | "
                f"FPR global={fpr_global:.1%} → "
                f"context={fpr_context:.1%} "
                f"({results[regime]['fpr_reduction_pct']:.0f}% reduction) | "
                f"DR={dr:.1%}"
            )
        return results

    # ── Private helpers ────────────────────────────────────────────────────────

    def _resolve_regime(self, record: FlowRecord) -> str:
        if record.regime and record.regime in self._context:
            return record.regime
        ts = record.timestamp
        return assign_regime(
            hour_utc     = ts.hour,
            minute_utc   = ts.minute,
            weekday      = ts.weekday(),
            day_of_month = ts.day,
        )

    def _extract_features(self, record: FlowRecord) -> np.ndarray:
        legacy_mapping = {
            "dst_port": ["dst_port", "Destination Port"],
            "duration_sec": ["duration_sec", "Flow Duration"],
            "packets_sent": ["packets_sent", "Total Fwd Packets"],
            "packets_recv": ["packets_recv", "Total Backward Packets"],
            "bytes_sent": ["bytes_sent", "Total Length of Fwd Packets"],
            "bytes_recv": ["bytes_recv", "Total Length of Bwd Packets"],
            "src_port": ["src_port", "Source Port"],
            "is_internal_src": ["is_internal_src"],
            "is_internal_dst": ["is_internal_dst"],
        }
        
        vals = []
        for f in sorted(FLOW_FEATURES):
            val = None
            keys_to_check = legacy_mapping.get(f, [f])
            for key in keys_to_check:
                if key in record.features:
                    val = record.features[key]
                    break
            
            if val is None:
                if f == "dst_port":
                    val = record.dst_port
                elif f == "src_port":
                    val = record.src_port
                else:
                    val = 0.0
            
            vals.append(float(val))
            
        return np.array(vals, dtype=np.float64)

    @staticmethod
    def _normalise_score(raw: float, threshold: float) -> float:
        """Sigmoid normalisation centred on threshold → [0, 1]."""
        k = 5.0
        x = (raw - threshold) * k
        return float(1.0 / (1.0 + np.exp(-np.clip(x, -50, 50))))

    def _explain(
        self,
        is_anomaly: bool,
        regime:     str,
        score:      float,
        record:     FlowRecord,
        X_raw:      np.ndarray,
    ) -> Tuple[Optional[str], str]:
        regime_desc = REGIME_CONTEXTS.get(regime, {}).get("description", regime)
        if not is_anomaly:
            return None, (
                f"Flow is consistent with {regime_desc} baseline "
                f"(score={score:.3f})."
            )
        deviation_info = ""
        flow_bps = record.features.get("Flow Bytes/s", 0)
        flow_pps = record.features.get("Flow Packets/s", 0)
        dst_port = record.features.get("Destination Port", 0)
        if flow_bps > 1e6:
            deviation_info += f"high flow bytes/s ({flow_bps:.0f}); "
        if flow_pps > 1e4:
            deviation_info += f"high packet rate ({flow_pps:.0f} pps); "
        if dst_port in (4444, 4445, 8443, 31337):
            deviation_info += f"suspicious port ({int(dst_port)}); "
        explanation = (
            f"Flow anomaly in '{regime}' context [{regime_desc}]. "
            f"Score={score:.3f}. {deviation_info}"
            f"{record.src_ip} → {record.dst_ip}"
        )
        return MITRE_DISCOVERY_TECHNIQUE, explanation

    def _init_shap(self) -> None:
        try:
            import shap
            normal_model = self._context.get("normal")
            if normal_model is not None:
                self._explainer = shap.TreeExplainer(normal_model)
                logger.info("FlowAgent: SHAP TreeExplainer initialised.")
        except ImportError:
            logger.warning("FlowAgent: shap not installed — explanations disabled.")
            self._shap = False

    def _shap_top_features(
        self,
        X_scaled: np.ndarray,
        model:    IsolationForest,
        regime:   str,
        top_n:    int = 3,
    ) -> List[Tuple[str, float]]:
        try:
            import shap
            explainer   = shap.TreeExplainer(model)
            shap_vals   = explainer.shap_values(X_scaled)
            mean_abs    = np.abs(shap_vals[0])
            top_indices = np.argsort(mean_abs)[::-1][:top_n]
            return [
                (FLOW_FEATURES[i], float(shap_vals[0][i]))
                for i in top_indices
            ]
        except Exception as exc:
            logger.debug(f"SHAP failed: {exc}")
            return []

    @staticmethod
    def _clean_df(df: pd.DataFrame) -> pd.DataFrame:
        clean = df[FLOW_FEATURES].copy()
        clean.replace([np.inf, -np.inf], np.nan, inplace=True)
        for col in FLOW_FEATURES:
            if clean[col].isna().any():
                clean[col] = clean[col].fillna(clean[col].median())
        return clean


# SMOKE TEST — python -m agents.flow_agent

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )
    from pipeline.ingestion import build_apt_scenario

    logger.info("FlowAgent smoke test — generating synthetic data …")
    rng = np.random.default_rng(0)
    synthetic = {
        regime: pd.DataFrame(
            np.abs(rng.normal(100 + i*50, 20 + i*10,
                              size=(500, len(FLOW_FEATURES)))),
            columns=FLOW_FEATURES,
        )
        for i, regime in enumerate(REGIME_CONTEXTS)
    }
    attack_arr = rng.uniform(5000, 50000, size=(100, len(FLOW_FEATURES)))
    attack_df  = pd.DataFrame(attack_arr, columns=FLOW_FEATURES)
    attack_df["Label"] = "DoS"

    # trainer = FlowAgentTrainer(models_dir=MODELS_DIR)
    # metrics = trainer.train(synthetic, attack_df)

    logger.info("\nPer-regime summary:")
    # for regime, m in metrics.items():
    #     logger.info(f"  {m}")

    agent = FlowAgent.load(models_dir=MODELS_DIR)
    logger.info("\nScoring APT scenario records:")
    for rec in build_apt_scenario():
        alert = agent.score(rec)
        flag  = "⚑ ANOMALY" if alert.is_anomaly else "  normal "
        logger.info(
            f"  {flag}  {alert.src_ip}→{alert.dst_ip}  "
            f"regime={alert.regime}  score={alert.anomaly_score:.3f}"
        )

    logger.info("Smoke test complete.")