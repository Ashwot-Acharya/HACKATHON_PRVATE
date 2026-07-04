"""
BankSentinel — Correlation Agent
==================================
Challenge Addressed: C3 — Alert Fatigue Suppression

The Correlation Agent is the central coordinator of BankSentinel. It
receives alerts from all three analytical agents (Packet, Flow, Behavior),
correlates them in space and time, suppresses benign background noise,
and computes a unified Composite Risk Score (CRS).

MATHEMATICAL FORMULATION
------------------------
  1. Bayesian Belief Network (BBN)
     Uses pgmpy to model the joint probability distribution of three
     alert signals given a true threat campaign:
       Nodes:  ThreatCampaign(C), PacketAlert(P), FlowAlert(F), BehaviorAlert(B)
       Edges:  C → P, C → F, C → B
       Prior:  P(C=1) = 3.2 × 10⁻⁴

     Given evidence of which agents fired, we query:
       P(C=1 | P, F, B) via Variable Elimination

  2. Composite Risk Score (CRS)
     CRS = w_pkt·S_pkt + w_flow·S_flow + w_beh·S_beh + w_bbn·P(C=1|evidence)
     Weights: [0.28, 0.24, 0.26, 0.22] (must sum to 1.0)

FOUR SUPPRESSION MECHANISMS (Challenge C3 Solution)
----------------------------------------------------
  1. Deduplication       — 5-min sliding window collapses identical alerts
  2. Causal Chaining     — 10-min window merges alerts by source IP
  3. Confidence Gating   — CRS < 0.40 → background only; CRS ≥ 0.85 → auto-response
  4. Context Filtering   — Suppresses operational calendar noise (ATM , etc.)

PAPER REFERENCE
---------------
  Section V-D (Correlation Agent)
  Equation (4): CRS weighted fusion
  Table X: Suppression results — 48,200 → ~6,350 (87% reduction) 

Usage:
    from agents.correlation_agent import CorrelationAgent
    agent = CorrelationAgent()
    result = agent.correlate(flow_record)
    if result.priority == "CRITICAL":
        print(result.explanation)
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from config import (
    BBN_PRIOR_THREAT,
    CAUSAL_CHAIN_WINDOW_SEC,
    CONFIDENCE_GATE_LOW,
    CONFIDENCE_GATE_HIGH,
    DEDUP_WINDOW_SEC,
    REGIME_CONTEXTS,
)
from pipeline.ingestion import FlowRecord

logger = logging.getLogger(__name__)


# BAYESIAN BELIEF NETWORK — CPD parameters (from implementation plan)

# Conditional probability tables: P(Agent=1 | Campaign)
# Format: { agent_name: (FPR, TPR) }
#   FPR = P(agent fires | no campaign)
#   TPR = P(agent fires | true campaign)
_CPD_PARAMS = {
    "packet":   (0.05, 0.85),   # High sensitivity to C2 signatures
    "flow":     (0.02, 0.78),   # Good volume anomaly capture
    "behavior": (0.01, 0.72),   # Deep user behavior profiling
}


# DATA STRUCTURES

@dataclass
class CorrelationResult:
    """
    Structured result emitted by the Correlation Agent.

    Contains the fused intelligence from all three analytical agents,
    the Bayesian posterior probability, and the final Composite Risk Score.

    Fields
    ------
    record_id           Unique identifier linking back to the FlowRecord.
    src_ip              Source IP address.
    dst_ip              Destination IP address.
    crs                 Composite Risk Score [0, 1].
    bbn_posterior       P(ThreatCampaign=1 | evidence) from BBN.
    priority            Priority level: CRITICAL / HIGH / MEDIUM / LOW / INFO.
    is_suppressed       True if any suppression mechanism filtered this alert.
    suppression_reason  Which mechanism suppressed it (or None).
    agent_scores        Dict of individual agent confidence scores.
    agents_fired        List of agent names that produced an alert.
    campaign_ticket_id  If causal chaining merged this into a campaign, the ID.
    dedup_count         Number of duplicate alerts collapsed into this one.
    explanation         Human-readable summary for SOC dashboard.
    timestamp           UTC creation time.
    """
    record_id:          int
    src_ip:             str
    dst_ip:             str
    crs:                float
    bbn_posterior:       float
    priority:           str
    is_suppressed:      bool
    suppression_reason: Optional[str]
    agent_scores:       Dict[str, float]
    agents_fired:       List[str]
    campaign_ticket_id: Optional[str]       = None
    dedup_count:        int                 = 1
    mitre_technique:    Optional[str]       = None
    explanation:        str                 = ""
    timestamp:          datetime            = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __str__(self) -> str:
        status = "SUPPRESSED" if self.is_suppressed else self.priority
        agents = "+".join(self.agents_fired) if self.agents_fired else "none"
        return (
            f"[CorrelationResult {status}] "
            f"{self.src_ip}->{self.dst_ip} "
            f"CRS={self.crs:.3f} BBN={self.bbn_posterior:.4f} "
            f"agents={agents}"
        )


# BBN INFERENCE ENGINE (pgmpy-backed with manual fallback)

class _BBNInference:
    """
    Bayesian Belief Network for multi-agent threat fusion.

    Attempts to use pgmpy for exact Variable Elimination inference.
    Falls back to direct Bayes' theorem calculation if pgmpy is not
    available (the network is small enough for closed-form computation).
    """

    def __init__(self, prior: float = BBN_PRIOR_THREAT):
        self._prior = prior
        self._cpd = _CPD_PARAMS
        self._pgmpy_model = None
        self._pgmpy_infer = None
        self._use_pgmpy = False
        self._init_pgmpy()

    def _init_pgmpy(self) -> None:
        """Try to initialise the pgmpy BBN model."""
        try:
            try:
                from pgmpy.models import DiscreteBayesianNetwork as BayesianNetwork
            except ImportError:
                from pgmpy.models import BayesianNetwork
            from pgmpy.factors.discrete import TabularCPD
            from pgmpy.inference import VariableElimination

            model = BayesianNetwork([
                ("ThreatCampaign", "PacketAlert"),
                ("ThreatCampaign", "FlowAlert"),
                ("ThreatCampaign", "BehaviorAlert"),
            ])

            # Prior: P(ThreatCampaign)
            cpd_threat = TabularCPD(
                variable="ThreatCampaign",
                variable_card=2,
                values=[[1 - self._prior], [self._prior]],
            )

            # CPD: P(PacketAlert | ThreatCampaign)
            fpr_p, tpr_p = self._cpd["packet"]
            cpd_packet = TabularCPD(
                variable="PacketAlert",
                variable_card=2,
                values=[
                    [1 - fpr_p, 1 - tpr_p],   # P(P=0 | C=0), P(P=0 | C=1)
                    [fpr_p,     tpr_p],        # P(P=1 | C=0), P(P=1 | C=1)
                ],
                evidence=["ThreatCampaign"],
                evidence_card=[2],
            )

            # CPD: P(FlowAlert | ThreatCampaign)
            fpr_f, tpr_f = self._cpd["flow"]
            cpd_flow = TabularCPD(
                variable="FlowAlert",
                variable_card=2,
                values=[
                    [1 - fpr_f, 1 - tpr_f],
                    [fpr_f,     tpr_f],
                ],
                evidence=["ThreatCampaign"],
                evidence_card=[2],
            )

            # CPD: P(BehaviorAlert | ThreatCampaign)
            fpr_b, tpr_b = self._cpd["behavior"]
            cpd_behavior = TabularCPD(
                variable="BehaviorAlert",
                variable_card=2,
                values=[
                    [1 - fpr_b, 1 - tpr_b],
                    [fpr_b,     tpr_b],
                ],
                evidence=["ThreatCampaign"],
                evidence_card=[2],
            )

            model.add_cpds(cpd_threat, cpd_packet, cpd_flow, cpd_behavior)
            assert model.check_model(), "BBN model validation failed"

            self._pgmpy_model = model
            self._pgmpy_infer = VariableElimination(model)
            self._use_pgmpy = True
            logger.info("CorrelationAgent: pgmpy BBN initialised successfully.")

        except ImportError:
            logger.warning(
                "CorrelationAgent: pgmpy not installed — "
                "using manual Bayes fallback. Install with: pip install pgmpy"
            )
            self._use_pgmpy = False

    def query(
        self,
        packet_fired:   bool,
        flow_fired:     bool,
        behavior_fired: bool,
    ) -> float:
        """
        Query the BBN for P(ThreatCampaign=1 | evidence).

        Args:
            packet_fired:   True if Packet Agent flagged this flow.
            flow_fired:     True if Flow Agent flagged this flow.
            behavior_fired: True if Behavior Agent flagged this flow.

        Returns:
            Posterior probability P(C=1 | P, F, B) in [0, 1].
        """
        if self._use_pgmpy:
            return self._query_pgmpy(packet_fired, flow_fired, behavior_fired)
        return self._query_manual(packet_fired, flow_fired, behavior_fired)

    def _query_pgmpy(
        self,
        packet_fired: bool,
        flow_fired:   bool,
        behavior_fired: bool,
    ) -> float:
        """Use pgmpy Variable Elimination for exact inference."""
        evidence = {
            "PacketAlert":   int(packet_fired),
            "FlowAlert":     int(flow_fired),
            "BehaviorAlert": int(behavior_fired),
        }
        result = self._pgmpy_infer.query(
            variables=["ThreatCampaign"],
            evidence=evidence,
        )
        # result.values[1] is P(ThreatCampaign=1 | evidence)
        return float(result.values[1])

    def _query_manual(
        self,
        packet_fired: bool,
        flow_fired:   bool,
        behavior_fired: bool,
    ) -> float:
        """
        Manual Bayes' theorem for the BBN (closed-form for 3-node naive Bayes).

        P(C=1 | P, F, B) = P(P|C=1)·P(F|C=1)·P(B|C=1)·P(C=1)
                           / [ P(P|C=1)·P(F|C=1)·P(B|C=1)·P(C=1)
                             + P(P|C=0)·P(F|C=0)·P(B|C=0)·P(C=0) ]
        """
        prior_1 = self._prior
        prior_0 = 1.0 - prior_1

        def _agent_prob(fired: bool, fpr: float, tpr: float):
            if fired:
                return tpr, fpr
            return 1.0 - tpr, 1.0 - fpr

        p_p1, p_p0 = _agent_prob(packet_fired,   *self._cpd["packet"])
        p_f1, p_f0 = _agent_prob(flow_fired,      *self._cpd["flow"])
        p_b1, p_b0 = _agent_prob(behavior_fired,  *self._cpd["behavior"])

        likelihood_1 = p_p1 * p_f1 * p_b1 * prior_1
        likelihood_0 = p_p0 * p_f0 * p_b0 * prior_0

        total = likelihood_1 + likelihood_0
        if total == 0:
            return 0.0
        return likelihood_1 / total


# SUPPRESSION ENGINE — four layers

class _DedupEntry:
    """Tracks a deduplication bucket for identical alert signatures."""
    __slots__ = ("count", "first_seen", "last_seen")

    def __init__(self, ts: float):
        self.count = 1
        self.first_seen = ts
        self.last_seen = ts


class _CampaignTicket:
    """Groups causally related alerts by source IP within a time window."""
    __slots__ = ("ticket_id", "src_ip", "alert_ids", "first_seen", "last_seen")

    def __init__(self, ticket_id: str, src_ip: str, ts: float):
        self.ticket_id = ticket_id
        self.src_ip = src_ip
        self.alert_ids: List[int] = []
        self.first_seen = ts
        self.last_seen = ts


# Known administrative/operational IP ranges that should not trigger alerts
# during their designated time regimes.
_OPERATIONAL_IPS = {
    # ATM concentrators — expected high volume during atm_recon
    "10.22.16.0/24": {"atm_recon"},
    # Core banking batch servers — expected during month_end
    "10.22.15.0/24": {"month_end"},
}


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """Check if an IP address falls within a CIDR block (simple /24 check)."""
    try:
        ip_parts = ip.split(".")
        cidr_parts = cidr.split("/")[0].split(".")
        prefix_len = int(cidr.split("/")[1])
        if prefix_len == 24:
            return ip_parts[:3] == cidr_parts[:3]
        # For simplicity, only /24 is supported in the demo
        return ip_parts[:3] == cidr_parts[:3]
    except (ValueError, IndexError):
        return False


class _SuppressionEngine:
    """
    Implements the four suppression layers for Challenge C3.

    Designed for streaming use — maintains sliding window state that is
    periodically cleaned to prevent unbounded memory growth.
    """

    def __init__(
        self,
        dedup_window:   float = DEDUP_WINDOW_SEC,
        chain_window:   float = CAUSAL_CHAIN_WINDOW_SEC,
        gate_low:       float = CONFIDENCE_GATE_LOW,
        gate_high:      float = CONFIDENCE_GATE_HIGH,
    ):
        self._dedup_window = dedup_window
        self._chain_window = chain_window
        self._gate_low     = gate_low
        self._gate_high    = gate_high

        # Deduplication state: key → _DedupEntry
        self._dedup_cache: Dict[str, _DedupEntry] = {}

        # Causal chaining state: src_ip → _CampaignTicket
        self._campaigns: Dict[str, _CampaignTicket] = {}

        # Counters for metrics
        self.stats = {
            "total_processed":       0,
            "dedup_suppressed":      0,
            "chain_merged":          0,
            "confidence_suppressed": 0,
            "context_suppressed":    0,
            "alerts_emitted":        0,
        }

    def evaluate(
        self,
        record:   FlowRecord,
        crs:      float,
        agents:   List[str],
    ) -> Tuple[bool, Optional[str], Optional[str], int]:
        """
        Run all four suppression layers sequentially.

        Args:
            record:  The original FlowRecord.
            crs:     Composite Risk Score.
            agents:  List of agent names that fired.

        Returns:
            Tuple of:
              is_suppressed      — True if any layer suppressed this alert.
              suppression_reason — Name of the suppression layer, or None.
              campaign_ticket_id — Campaign ticket ID if chained, or None.
              dedup_count        — Number of duplicates collapsed.
        """
        self.stats["total_processed"] += 1
        now = time.time()

        # ── Layer 1: Deduplication ──────────────────────────────────────────
        dedup_key = self._dedup_signature(record, agents)
        dedup_count = 1

        if dedup_key in self._dedup_cache:
            entry = self._dedup_cache[dedup_key]
            if (now - entry.last_seen) <= self._dedup_window:
                entry.count += 1
                entry.last_seen = now
                dedup_count = entry.count
                self.stats["dedup_suppressed"] += 1
                return True, "deduplication", None, dedup_count
            else:
                # Window expired — start fresh
                self._dedup_cache[dedup_key] = _DedupEntry(now)
        else:
            self._dedup_cache[dedup_key] = _DedupEntry(now)

        # ── Layer 2: Causal Chaining ────────────────────────────────────────
        campaign_ticket_id = None
        src_ip = record.src_ip

        if src_ip in self._campaigns:
            ticket = self._campaigns[src_ip]
            if (now - ticket.last_seen) <= self._chain_window:
                ticket.alert_ids.append(record.record_id)
                ticket.last_seen = now
                campaign_ticket_id = ticket.ticket_id
                self.stats["chain_merged"] += 1
                # Chained alerts are NOT suppressed — they are enriched
                # with the campaign ticket ID and continue downstream.
            else:
                # Window expired — create new campaign ticket
                ticket_id = self._make_ticket_id(src_ip, now)
                self._campaigns[src_ip] = _CampaignTicket(
                    ticket_id, src_ip, now
                )
                self._campaigns[src_ip].alert_ids.append(record.record_id)
                campaign_ticket_id = ticket_id
        else:
            ticket_id = self._make_ticket_id(src_ip, now)
            self._campaigns[src_ip] = _CampaignTicket(
                ticket_id, src_ip, now
            )
            self._campaigns[src_ip].alert_ids.append(record.record_id)
            campaign_ticket_id = ticket_id

        # ── Layer 3: Confidence Gating ──────────────────────────────────────
        if crs < self._gate_low:
            self.stats["confidence_suppressed"] += 1
            return True, "confidence_gating", campaign_ticket_id, dedup_count

        # ── Layer 4: Context-Aware Filtering ────────────────────────────────
        regime = getattr(record, "regime", "normal")
        if self._is_operational_noise(record.src_ip, regime):
            self.stats["context_suppressed"] += 1
            return True, "context_filtering", campaign_ticket_id, dedup_count

        # ── Alert passes all filters ────────────────────────────────────────
        self.stats["alerts_emitted"] += 1
        return False, None, campaign_ticket_id, dedup_count

    def get_suppression_summary(self) -> Dict[str, Any]:
        """Return suppression statistics for reporting."""
        total = max(self.stats["total_processed"], 1)
        suppressed = (
            self.stats["dedup_suppressed"]
            + self.stats["confidence_suppressed"]
            + self.stats["context_suppressed"]
        )
        return {
            **self.stats,
            "total_suppressed":    suppressed,
            "suppression_rate":    suppressed / total,
            "emission_rate":       self.stats["alerts_emitted"] / total,
        }

    def cleanup(self, max_age: float = 3600.0) -> int:
        """
        Remove expired entries from caches to prevent memory growth.

        Args:
            max_age: Maximum age in seconds before an entry is evicted.

        Returns:
            Number of entries evicted.
        """
        now = time.time()
        evicted = 0

        expired_dedup = [
            k for k, v in self._dedup_cache.items()
            if (now - v.last_seen) > max_age
        ]
        for k in expired_dedup:
            del self._dedup_cache[k]
            evicted += 1

        expired_campaigns = [
            k for k, v in self._campaigns.items()
            if (now - v.last_seen) > max_age
        ]
        for k in expired_campaigns:
            del self._campaigns[k]
            evicted += 1

        return evicted

    # ── Private helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _dedup_signature(record: FlowRecord, agents: List[str]) -> str:
        """Create a deduplication key from the alert signature."""
        agents_str = ",".join(sorted(agents))
        raw = f"{record.src_ip}|{record.dst_ip}|{agents_str}"
        return hashlib.md5(raw.encode()).hexdigest()

    @staticmethod
    def _make_ticket_id(src_ip: str, ts: float) -> str:
        """Generate a unique campaign ticket ID."""
        raw = f"CAMP-{src_ip}-{ts:.2f}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16].upper()

    @staticmethod
    def _is_operational_noise(src_ip: str, regime: str) -> bool:
        """Check if this alert is expected operational traffic."""
        for cidr, allowed_regimes in _OPERATIONAL_IPS.items():
            if _ip_in_cidr(src_ip, cidr) and regime in allowed_regimes:
                return True
        return False


# CORRELATION AGENT

class CorrelationAgent:
    """
    Central coordinator that fuses alerts from Packet, Flow, and Behavior
    agents into a unified Composite Risk Score (CRS) and applies four
    suppression layers to reduce alert fatigue.

    Usage:
        agent = CorrelationAgent()
        result = agent.correlate(flow_record)
        if not result.is_suppressed:
            soc_dashboard.push(result)
    """

    def __init__(
        self,
        prior:        float = BBN_PRIOR_THREAT,
        dedup_window: float = DEDUP_WINDOW_SEC,
        chain_window: float = CAUSAL_CHAIN_WINDOW_SEC,
        gate_low:     float = CONFIDENCE_GATE_LOW,
        gate_high:    float = CONFIDENCE_GATE_HIGH,
        crs_weights:  list = None,
    ):
        if crs_weights is not None:
            assert len(crs_weights) == 4, "CRS weights must have length 4"
            assert abs(sum(crs_weights) - 1.0) < 1e-6, "CRS weights must sum to 1.0"
        """
        Initialise the Correlation Agent.

        Args:
            prior:        Bayesian prior P(ThreatCampaign=1).
            dedup_window: Deduplication sliding window in seconds.
            chain_window: Causal chaining window in seconds.
            gate_low:     CRS below this → suppress (background logging only).
            gate_high:    CRS above this → CRITICAL priority.
        """
        self._gate_low  = gate_low
        self._gate_high = gate_high

        self._bbn = _BBNInference(prior=prior)
        self._suppression = _SuppressionEngine(
            dedup_window=dedup_window,
            chain_window=chain_window,
            gate_low=gate_low,
            gate_high=gate_high,
        )

        logger.info(
            f"CorrelationAgent: initialised "
            f"(prior={prior:.2e}, "
            f"pgmpy={'yes' if self._bbn._use_pgmpy else 'fallback'})"
        )

    # ── Core API ───────────────────────────────────────────────────────────────

    def correlate(self, record: FlowRecord) -> CorrelationResult:
        """
        Fuse all agent alerts on a FlowRecord into a unified risk assessment.

        This is the main entrypoint. It:
          1. Reads packet_alert, flow_alert, behavior_alert from the record.
          2. Determines which agents fired (is_threat / is_anomaly).
          3. Queries the BBN for P(ThreatCampaign=1 | evidence).
          4. Computes the Composite Risk Score (CRS).
          5. Applies all four suppression layers.
          6. Returns a CorrelationResult attached to the record.

        Args:
            record: FlowRecord with agent alerts already populated.

        Returns:
            CorrelationResult with CRS, priority, suppression status.
        """
        # ── Step 1: Extract agent scores ────────────────────────────────────
        pkt_alert = record.packet_alert
        flow_alert = record.flow_alert
        beh_alert = record.behavior_alert

        pkt_score  = getattr(pkt_alert,  "confidence", 0.0) if pkt_alert else 0.0
        flow_score = getattr(flow_alert, "confidence", 0.0) if flow_alert else 0.0
        beh_score  = getattr(beh_alert,  "confidence", 0.0) if beh_alert else 0.0

        pkt_fired  = getattr(pkt_alert,  "is_threat",  False) if pkt_alert else False
        flow_fired = getattr(flow_alert, "is_anomaly",  False) if flow_alert else False
        beh_fired  = getattr(beh_alert,  "is_anomaly",  False) if beh_alert else False

        # ── Step 2: Build agent list ────────────────────────────────────────
        agents_fired = []
        mitre_technique = None
        
        if pkt_fired:
            agents_fired.append("packet")
            if getattr(pkt_alert, "mitre_technique", None):
                mitre_technique = pkt_alert.mitre_technique
        if flow_fired:
            agents_fired.append("flow")
            if not mitre_technique and getattr(flow_alert, "mitre_technique", None):
                mitre_technique = flow_alert.mitre_technique
        if beh_fired:
            agents_fired.append("behavior")
            if not mitre_technique and getattr(beh_alert, "mitre_technique", None):
                mitre_technique = beh_alert.mitre_technique

        # ── Step 3: BBN posterior ───────────────────────────────────────────
        bbn_posterior = self._bbn.query(pkt_fired, flow_fired, beh_fired)

        # ── Step 4: Composite Risk Score (Probabilistic Noisy-OR) ───────────
        # Uses probabilistic OR fusion so we don't rely on fixed weights,
        # and so that the CRS dynamically scales based on combined inputs
        # rather than being flattened by a weighted average.
        
        # P(A or B or C) = 1 - (1-A)*(1-B)*(1-C)
        crs = 1.0 - (
            (1.0 - pkt_score) * 
            (1.0 - flow_score) * 
            (1.0 - beh_score) * 
            (1.0 - bbn_posterior)
        )
        crs = float(np.clip(crs, 0.0, 1.0))

        # ── Step 5: Determine priority ──────────────────────────────────────
        priority = self._classify_priority(crs, len(agents_fired))

        # ── Step 6: Apply suppression ───────────────────────────────────────
        is_suppressed, reason, ticket_id, dedup_count = (
            self._suppression.evaluate(record, crs, agents_fired)
        )

        # ── Step 7: Build explanation ───────────────────────────────────────
        agent_scores = {
            "packet":   pkt_score,
            "flow":     flow_score,
            "behavior": beh_score,
        }
        explanation = self._build_explanation(
            record, crs, bbn_posterior, agents_fired, agent_scores,
            is_suppressed, reason, priority,
        )

        result = CorrelationResult(
            record_id          = record.record_id,
            src_ip             = record.src_ip,
            dst_ip             = record.dst_ip,
            crs                = crs,
            bbn_posterior       = bbn_posterior,
            priority           = priority,
            is_suppressed      = is_suppressed,
            suppression_reason = reason,
            agent_scores       = agent_scores,
            agents_fired       = agents_fired,
            campaign_ticket_id = ticket_id,
            dedup_count        = dedup_count,
            mitre_technique    = mitre_technique,
            explanation        = explanation,
        )

        record.correlation_result = result
        return result

    def correlate_batch(
        self, records: List[FlowRecord]
    ) -> List[CorrelationResult]:
        """
        Correlate a batch of FlowRecords.

        Args:
            records: List of FlowRecords with agent alerts populated.

        Returns:
            List of CorrelationResult objects.
        """
        return [self.correlate(r) for r in records]

    def get_stats(self) -> Dict[str, Any]:
        """Return suppression statistics for reporting."""
        return self._suppression.get_suppression_summary()

    def cleanup_caches(self, max_age: float = 3600.0) -> int:
        """Evict expired entries from internal caches."""
        return self._suppression.cleanup(max_age)

    @property
    def bbn(self) -> _BBNInference:
        """Expose the BBN inference engine for testing."""
        return self._bbn

    @property
    def suppression(self) -> _SuppressionEngine:
        """Expose the suppression engine for testing."""
        return self._suppression

    # ── Private helpers ────────────────────────────────────────────────────────

    def _classify_priority(
        self, crs: float, n_agents: int
    ) -> str:
        """
        Classify the alert priority based on CRS and agent count.

        Priority levels:
          CRITICAL — CRS ≥ 0.85 (automated response triggers)
          HIGH     — CRS ≥ 0.65 or 3 agents fired
          MEDIUM   — CRS ≥ 0.40
          LOW      — CRS ≥ 0.20
          INFO     — CRS < 0.20
        """
        if crs >= self._gate_high:
            return "CRITICAL"
        if crs >= 0.65 or n_agents >= 3:
            return "HIGH"
        if crs >= self._gate_low:
            return "MEDIUM"
        if crs >= 0.20:
            return "LOW"
        return "INFO"

    def _build_explanation(
        self,
        record:       FlowRecord,
        crs:          float,
        bbn_post:     float,
        agents:       List[str],
        agent_scores: Dict[str, float],
        is_suppressed: bool,
        reason:       Optional[str],
        priority:     str,
    ) -> str:
        """Build a human-readable explanation for the SOC dashboard."""
        parts = [
            f"Correlation Analysis: {record.src_ip} -> {record.dst_ip}",
            f"CRS={crs:.3f} (BBN posterior={bbn_post:.4f})",
            f"Priority: {priority}",
        ]

        if agents:
            fired_str = ", ".join(
                f"{a}={agent_scores.get(a, 0):.3f}" for a in agents
            )
            parts.append(f"Agents fired: {fired_str}")
        else:
            parts.append("No agent alerts triggered.")

        if is_suppressed:
            parts.append(f"SUPPRESSED by {reason}.")
        else:
            if crs >= self._gate_high:
                parts.append(
                    "AUTOMATED RESPONSE RECOMMENDED — "
                    "isolate source IP immediately."
                )

        return "  |  ".join(parts)


# SMOKE TEST — python -m agents.correlation_agent

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )

    # Fix Windows console encoding
    if sys.platform == "win32":
        import io
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace"
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer, encoding="utf-8", errors="replace"
        )

    from pipeline.ingestion import build_apt_scenario

    logger.info("CorrelationAgent smoke test ...")

    agent = CorrelationAgent()

    # Test BBN inference
    logger.info("\n--- BBN Inference Tests ---")
    for combo in [
        (False, False, False),
        (True,  False, False),
        (False, True,  False),
        (False, False, True),
        (True,  True,  False),
        (True,  True,  True),
    ]:
        post = agent.bbn.query(*combo)
        logger.info(f"  P/F/B={combo} -> P(C=1|evidence)={post:.6f}")

    # Test on APT scenario
    logger.info("\n--- APT Scenario Correlation ---")
    apt_records = build_apt_scenario()
    for rec in apt_records:
        # Simulate agent alerts (in real pipeline, agents populate these)
        from agents.packet_agent import PacketAlert
        from agents.flow_agent import FlowAlert
        from agents.behaviour_agent import BehaviorAlert

        # Record 0: Packet Agent fires
        if rec.ja3_hash:
            rec.packet_alert = PacketAlert(
                src_ip=rec.src_ip, dst_ip=rec.dst_ip, dst_port=443,
                ja3_hash=rec.ja3_hash, ja3s_hash=rec.ja3s_hash,
                confidence=0.87, is_threat=True,
                active_layers=["L1", "L3"], layer_scores={"L1": 0.55, "L3": 0.72},
                malware_family="CobaltStrike", mitre_technique="T1071.001",
                explanation="C4 THREAT detected",
            )

        # Record 1: Flow Agent fires
        if rec.label == "APT-Lateral":
            rec.flow_alert = FlowAlert(
                src_ip=rec.src_ip, dst_ip=rec.dst_ip,
                regime="off_hours", anomaly_score=0.92,
                is_anomaly=True, confidence=0.88,
                mitre_technique="T1046",
                explanation="Flow anomaly in off_hours context",
            )

        # Record 2: Behavior Agent fires
        if rec.label == "APT-Collection":
            rec.behavior_alert = BehaviorAlert(
                account="svc_corebanking", src_ip=rec.src_ip,
                recon_error=0.45, threshold=0.30,
                is_anomaly=True, confidence=0.82,
                scenario_hint="data_staging",
                mitre_technique="T1213",
                explanation="ZERO-DAY behavioral anomaly",
            )

        result = agent.correlate(rec)
        logger.info(f"  {result}")
        logger.info(f"    {result.explanation}")

    # Print suppression stats
    stats = agent.get_stats()
    logger.info(f"\nSuppression stats: {stats}")
    logger.info("Smoke test complete.")
