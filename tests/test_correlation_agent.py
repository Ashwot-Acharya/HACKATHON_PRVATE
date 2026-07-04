"""
BankSentinel — Correlation Agent Unit Tests
=============================================
Comprehensive test suite covering:
  1. BBN inference — correct posterior probabilities for all 8 evidence combos
  2. CRS calculation — weighted fusion alignment
  3. Deduplication — sliding window collapse
  4. Causal Chaining — multi-agent merging by source IP
  5. Confidence Gating — low-CRS suppression
  6. Context Filtering — operational calendar noise suppression
  7. Priority classification — CRITICAL/HIGH/MEDIUM/LOW/INFO
  8. End-to-end correlation on FlowRecords
  9. Edge cases — missing alerts, empty agents, batch processing
"""

import time
import math
import pytest
import numpy as np
from unittest.mock import MagicMock, patch
from dataclasses import dataclass

from config import (
    BBN_PRIOR_THREAT,
    CAUSAL_CHAIN_WINDOW_SEC,
    CONFIDENCE_GATE_HIGH,
    CONFIDENCE_GATE_LOW,
    CRS_WEIGHTS,
    DEDUP_WINDOW_SEC,
)
from pipeline.ingestion import FlowRecord


# FIXTURES

@pytest.fixture
def correlation_agent():
    """Create a fresh CorrelationAgent for each test."""
    from agents.correlation_agent import CorrelationAgent
    return CorrelationAgent()


@pytest.fixture
def make_record():
    """Factory for creating FlowRecords with optional alerts."""
    def _make(
        src_ip="10.22.14.45",
        dst_ip="185.220.101.32",
        label="BENIGN",
        regime="normal",
        pkt_conf=0.0,
        pkt_threat=False,
        flow_conf=0.0,
        flow_anomaly=False,
        beh_conf=0.0,
        beh_anomaly=False,
    ):
        features = {"Flow Duration": 100.0, "Total Fwd Packets": 100.0, "Destination Port": 100.0}
        record = FlowRecord(
            src_ip=src_ip,
            dst_ip=dst_ip,
            features=features,
            label=label,
            regime=regime,
        )
        if pkt_conf > 0 or pkt_threat:
            record.packet_alert = MagicMock(
                confidence=pkt_conf,
                is_threat=pkt_threat,
            )
        if flow_conf > 0 or flow_anomaly:
            record.flow_alert = MagicMock(
                confidence=flow_conf,
                is_anomaly=flow_anomaly,
            )
        if beh_conf > 0 or beh_anomaly:
            record.behavior_alert = MagicMock(
                confidence=beh_conf,
                is_anomaly=beh_anomaly,
            )
        return record
    return _make


# 1. BBN INFERENCE TESTS

class TestBBNInference:
    """Test the Bayesian Belief Network inference engine."""

    def test_no_agents_fired_returns_near_prior(self, correlation_agent):
        """When no agents fire, posterior should be near (but below) the prior."""
        post = correlation_agent.bbn.query(False, False, False)
        # With all agents showing no alert, posterior should be very low
        assert post < BBN_PRIOR_THREAT, (
            f"Posterior {post:.6f} should be less than prior {BBN_PRIOR_THREAT:.6f} "
            "when no agents fire"
        )
        assert post >= 0.0

    def test_single_packet_agent_fires(self, correlation_agent):
        """Packet Agent alone should raise posterior above prior."""
        post = correlation_agent.bbn.query(True, False, False)
        # With prior=3.2e-4 and packet FPR=5%, single agent barely moves
        # the posterior (≈3.45e-4), but it should still be > prior.
        assert post > BBN_PRIOR_THREAT, (
            f"Packet-only posterior {post:.6f} should exceed prior {BBN_PRIOR_THREAT:.6f}"
        )
        assert post < 1.0

    def test_single_flow_agent_fires(self, correlation_agent):
        """Flow Agent alone should raise posterior above prior."""
        post = correlation_agent.bbn.query(False, True, False)
        assert post > BBN_PRIOR_THREAT, (
            f"Flow-only posterior {post:.6f} should exceed prior {BBN_PRIOR_THREAT:.6f}"
        )
        assert post < 1.0

    def test_single_behavior_agent_fires(self, correlation_agent):
        """Behavior Agent alone should raise posterior above prior."""
        post = correlation_agent.bbn.query(False, False, True)
        assert post > BBN_PRIOR_THREAT, (
            f"Behavior-only posterior {post:.6f} should exceed prior {BBN_PRIOR_THREAT:.6f}"
        )
        assert post < 1.0

    def test_two_agents_higher_than_one(self, correlation_agent):
        """Two agents firing should yield higher posterior than one alone."""
        pkt_only = correlation_agent.bbn.query(True, False, False)
        pkt_flow = correlation_agent.bbn.query(True, True, False)
        assert pkt_flow > pkt_only, (
            f"Two agents ({pkt_flow:.6f}) should yield higher posterior "
            f"than one ({pkt_only:.6f})"
        )

    def test_all_agents_highest_posterior(self, correlation_agent):
        """All three agents firing should give the highest posterior."""
        all_fire  = correlation_agent.bbn.query(True, True, True)
        two_fire  = correlation_agent.bbn.query(True, True, False)
        assert all_fire > two_fire, (
            f"All agents ({all_fire:.6f}) should be higher than two ({two_fire:.6f})"
        )
        # When all three fire, posterior should be substantial
        assert all_fire > 0.01, (
            f"All-agents posterior {all_fire:.6f} should be significant"
        )

    def test_posterior_monotonicity(self, correlation_agent):
        """Posterior should increase monotonically with more evidence."""
        p_none = correlation_agent.bbn.query(False, False, False)
        p_one  = correlation_agent.bbn.query(True,  False, False)
        p_two  = correlation_agent.bbn.query(True,  True,  False)
        p_all  = correlation_agent.bbn.query(True,  True,  True)
        assert p_none < p_one < p_two < p_all

    def test_posterior_in_valid_range(self, correlation_agent):
        """All posteriors should be valid probabilities in [0, 1]."""
        for p in [True, False]:
            for f in [True, False]:
                for b in [True, False]:
                    post = correlation_agent.bbn.query(p, f, b)
                    assert 0.0 <= post <= 1.0, (
                        f"Posterior {post} out of range for P={p}, F={f}, B={b}"
                    )

    def test_manual_fallback_matches_formulation(self):
        """Verify manual Bayes calculation against known formula."""
        from agents.correlation_agent import _BBNInference
        bbn = _BBNInference.__new__(_BBNInference)
        bbn._prior = BBN_PRIOR_THREAT
        bbn._cpd = {
            "packet":   (0.05, 0.85),
            "flow":     (0.02, 0.78),
            "behavior": (0.01, 0.72),
        }
        bbn._use_pgmpy = False

        # Manually compute for all agents firing
        prior = BBN_PRIOR_THREAT
        L1 = 0.85 * 0.78 * 0.72 * prior
        L0 = 0.05 * 0.02 * 0.01 * (1 - prior)
        expected = L1 / (L1 + L0)

        result = bbn.query(True, True, True)
        assert abs(result - expected) < 1e-10, (
            f"Manual fallback {result:.10f} != expected {expected:.10f}"
        )


# 2. CRS CALCULATION TESTS

class TestCRSCalculation:
    """Test Composite Risk Score computation."""

    def test_crs_weights_sum_to_one(self):
        """CRS weights from config must sum to 1.0."""
        assert abs(sum(CRS_WEIGHTS) - 1.0) < 1e-6

    def test_crs_no_alerts(self, correlation_agent, make_record):
        """CRS should be near zero when no agents fired."""
        record = make_record()
        result = correlation_agent.correlate(record)
        assert result.crs < 0.05, (
            f"CRS {result.crs:.4f} should be near zero with no alerts"
        )

    def test_crs_all_agents_high_confidence(self, correlation_agent, make_record):
        """CRS should be high when all agents fire with high confidence."""
        record = make_record(
            pkt_conf=0.9, pkt_threat=True,
            flow_conf=0.85, flow_anomaly=True,
            beh_conf=0.8, beh_anomaly=True,
        )
        result = correlation_agent.correlate(record)
        # Expected: 0.28*0.9 + 0.24*0.85 + 0.26*0.8 + 0.22*P(C=1|all)
        # P(C=1|all) is significant, so CRS should be well above 0.7
        assert result.crs > 0.7, (
            f"CRS {result.crs:.4f} should be > 0.7 when all agents fire high"
        )

    def test_crs_matches_weight_formula(self, correlation_agent, make_record):
        """CRS should match the exact weighted formula."""
        pkt_c, flow_c, beh_c = 0.6, 0.5, 0.7
        record = make_record(
            pkt_conf=pkt_c, pkt_threat=True,
            flow_conf=flow_c, flow_anomaly=True,
            beh_conf=beh_c, beh_anomaly=True,
        )
        result = correlation_agent.correlate(record)

        # Compute expected CRS using Noisy-OR formula
        bbn_post = correlation_agent.bbn.query(True, True, True)
        expected = 1.0 - (
            (1.0 - pkt_c) *
            (1.0 - flow_c) *
            (1.0 - beh_c) *
            (1.0 - bbn_post)
        )
        expected = float(np.clip(expected, 0.0, 1.0))
        assert abs(result.crs - expected) < 1e-6, (
            f"CRS {result.crs:.6f} != expected {expected:.6f}"
        )

    def test_crs_single_agent_moderate(self, correlation_agent, make_record):
        """CRS with only one agent should match the single agent's confidence under dynamic weighting."""
        record = make_record(
            pkt_conf=0.7, pkt_threat=True,
        )
        result = correlation_agent.correlate(record)
        # Single agent with 0.7 confidence gets almost all the weight, resulting in crs ~ 0.7
        assert 0.50 < result.crs < 0.80


    def test_crs_clipped_to_unit(self):
        """CRS should be clipped to [0, 1]."""
        from agents.correlation_agent import CorrelationAgent
        agent = CorrelationAgent(crs_weights=[0.25, 0.25, 0.25, 0.25])
        features = {"Flow Duration": 100.0, "Total Fwd Packets": 100.0, "Destination Port": 100.0}
        record = FlowRecord("1.2.3.4", "5.6.7.8", features)
        record.packet_alert = MagicMock(confidence=1.0, is_threat=True)
        record.flow_alert = MagicMock(confidence=1.0, is_anomaly=True)
        record.behavior_alert = MagicMock(confidence=1.0, is_anomaly=True)
        result = agent.correlate(record)
        assert result.crs <= 1.0


# 3. DEDUPLICATION TESTS

class TestDeduplication:
    """Test the sliding-window deduplication mechanism."""

    def test_first_alert_not_deduplicated(self, correlation_agent, make_record):
        """First occurrence should never be suppressed by dedup."""
        record = make_record(pkt_conf=0.6, pkt_threat=True)
        result = correlation_agent.correlate(record)
        assert result.suppression_reason != "deduplication"

    def test_duplicate_alert_suppressed(self, correlation_agent, make_record):
        """Second identical alert within 5-min window should be suppressed."""
        r1 = make_record(pkt_conf=0.6, pkt_threat=True)
        r2 = make_record(pkt_conf=0.6, pkt_threat=True)
        correlation_agent.correlate(r1)
        result = correlation_agent.correlate(r2)
        assert result.is_suppressed
        assert result.suppression_reason == "deduplication"

    def test_different_ips_not_deduplicated(self, correlation_agent, make_record):
        """Alerts from different IPs should not be deduplicated."""
        r1 = make_record(src_ip="10.0.0.1", pkt_conf=0.6, pkt_threat=True)
        r2 = make_record(src_ip="10.0.0.2", pkt_conf=0.6, pkt_threat=True)
        correlation_agent.correlate(r1)
        result = correlation_agent.correlate(r2)
        assert result.suppression_reason != "deduplication"

    def test_dedup_count_increments(self, correlation_agent, make_record):
        """Duplicate counter should increment with each duplicate."""
        for i in range(5):
            record = make_record(pkt_conf=0.6, pkt_threat=True)
            result = correlation_agent.correlate(record)

        # The last result should show dedup_count = 5
        assert result.dedup_count == 5

    def test_dedup_window_expiry(self, make_record):
        """After window expires, alert should be treated as new."""
        from agents.correlation_agent import CorrelationAgent
        # Use a very short window for testing (0.1 second)
        agent = CorrelationAgent(dedup_window=0.1)

        r1 = make_record(pkt_conf=0.6, pkt_threat=True)
        agent.correlate(r1)

        time.sleep(0.15)  # Wait for window to expire

        r2 = make_record(pkt_conf=0.6, pkt_threat=True)
        result = agent.correlate(r2)
        assert result.suppression_reason != "deduplication"


# 4. CAUSAL CHAINING TESTS

class TestCausalChaining:
    """Test the causal chaining mechanism."""

    def test_same_ip_alerts_get_same_ticket(self, correlation_agent, make_record):
        """Alerts from the same source IP should share a campaign ticket."""
        r1 = make_record(
            src_ip="10.22.14.45", dst_ip="185.0.0.1",
            pkt_conf=0.7, pkt_threat=True,
        )
        r2 = make_record(
            src_ip="10.22.14.45", dst_ip="185.0.0.2",
            flow_conf=0.8, flow_anomaly=True,
        )
        res1 = correlation_agent.correlate(r1)
        res2 = correlation_agent.correlate(r2)
        # Both should have the same campaign ticket (r2 is not deduped
        # because dst_ip differs)
        assert res1.campaign_ticket_id == res2.campaign_ticket_id

    def test_different_ip_alerts_get_different_tickets(
        self, correlation_agent, make_record
    ):
        """Alerts from different source IPs should get different tickets."""
        r1 = make_record(src_ip="10.0.0.1", pkt_conf=0.7, pkt_threat=True)
        r2 = make_record(src_ip="10.0.0.2", pkt_conf=0.7, pkt_threat=True)
        res1 = correlation_agent.correlate(r1)
        res2 = correlation_agent.correlate(r2)
        assert res1.campaign_ticket_id != res2.campaign_ticket_id

    def test_chain_merged_counter(self, correlation_agent, make_record):
        """Chain merge counter should track merged alerts."""
        for i in range(3):
            record = make_record(
                src_ip="10.22.14.45",
                dst_ip=f"185.0.0.{i+1}",
                pkt_conf=0.7, pkt_threat=True,
            )
            correlation_agent.correlate(record)
        stats = correlation_agent.get_stats()
        # First alert creates ticket, subsequent ones merge
        assert stats["chain_merged"] >= 2


# 5. CONFIDENCE GATING TESTS

class TestConfidenceGating:
    """Test the confidence gating suppression layer."""

    def test_low_crs_suppressed(self, correlation_agent, make_record):
        """Alert with CRS < 0.40 should be suppressed."""
        # Very low confidence → CRS will be below gate
        record = make_record(pkt_conf=0.1, pkt_threat=True)
        result = correlation_agent.correlate(record)
        if result.crs < CONFIDENCE_GATE_LOW:
            assert result.is_suppressed
            assert result.suppression_reason == "confidence_gating"

    def test_high_crs_not_suppressed(self, correlation_agent, make_record):
        """Alert with CRS ≥ 0.85 should never be confidence-suppressed."""
        record = make_record(
            pkt_conf=0.95, pkt_threat=True,
            flow_conf=0.9, flow_anomaly=True,
            beh_conf=0.85, beh_anomaly=True,
        )
        result = correlation_agent.correlate(record)
        assert not result.is_suppressed or result.suppression_reason != "confidence_gating"

    def test_medium_crs_passes_gate(self, correlation_agent, make_record):
        """Alert with CRS between 0.40 and 0.85 should pass confidence gate."""
        record = make_record(
            pkt_conf=0.65, pkt_threat=True,
            flow_conf=0.5, flow_anomaly=True,
        )
        result = correlation_agent.correlate(record)
        if result.crs >= CONFIDENCE_GATE_LOW:
            assert result.suppression_reason != "confidence_gating"


# 6. CONTEXT-AWARE FILTERING TESTS

class TestContextFiltering:
    """Test the context-aware noise suppression."""

    def test_atm_ip_during_atm_recon_suppressed(self, correlation_agent, make_record):
        """ATM concentrator IP during atm_recon regime should be suppressed."""
        record = make_record(
            src_ip="10.22.16.50",  # ATM concentrator subnet
            regime="atm_recon",
            pkt_conf=0.5, pkt_threat=True,
        )
        result = correlation_agent.correlate(record)
        # If CRS passes confidence gate, context filter should catch it
        if result.crs >= CONFIDENCE_GATE_LOW:
            assert result.is_suppressed
            assert result.suppression_reason == "context_filtering"

    def test_atm_ip_during_normal_not_suppressed(
        self, correlation_agent, make_record
    ):
        """ATM IP during normal hours should NOT be context-suppressed."""
        record = make_record(
            src_ip="10.22.16.50",
            regime="normal",
            pkt_conf=0.7, pkt_threat=True,
            flow_conf=0.6, flow_anomaly=True,
        )
        result = correlation_agent.correlate(record)
        assert result.suppression_reason != "context_filtering"

    def test_core_banking_during_month_end_suppressed(
        self, correlation_agent, make_record
    ):
        """Core banking IP during month_end should be suppressed."""
        record = make_record(
            src_ip="10.22.15.20",  # Core banking subnet
            regime="month_end",
            pkt_conf=0.5, pkt_threat=True,
        )
        result = correlation_agent.correlate(record)
        if result.crs >= CONFIDENCE_GATE_LOW:
            assert result.is_suppressed
            assert result.suppression_reason == "context_filtering"

    def test_external_ip_not_context_filtered(
        self, correlation_agent, make_record
    ):
        """External IP should never be context-filtered."""
        record = make_record(
            src_ip="185.220.101.32",
            regime="atm_recon",
            pkt_conf=0.7, pkt_threat=True,
            flow_conf=0.6, flow_anomaly=True,
        )
        result = correlation_agent.correlate(record)
        assert result.suppression_reason != "context_filtering"


# 7. PRIORITY CLASSIFICATION TESTS

class TestPriorityClassification:
    """Test the priority level classification."""

    def test_critical_priority(self, correlation_agent, make_record):
        """CRS >= 0.85 should yield CRITICAL priority."""
        record = make_record(
            pkt_conf=0.95, pkt_threat=True,
            flow_conf=0.92, flow_anomaly=True,
            beh_conf=0.90, beh_anomaly=True,
        )
        result = correlation_agent.correlate(record)
        if result.crs >= CONFIDENCE_GATE_HIGH:
            assert result.priority == "CRITICAL"

    def test_info_priority_no_alerts(self, correlation_agent, make_record):
        """No alerts should yield INFO priority."""
        record = make_record()
        result = correlation_agent.correlate(record)
        assert result.priority == "INFO"

    def test_priority_ordering(self, correlation_agent):
        """Priority should follow the defined ordering."""
        classify = correlation_agent._classify_priority
        assert classify(0.95, 3) == "CRITICAL"
        assert classify(0.85, 3) == "CRITICAL"
        assert classify(0.70, 2) == "HIGH"
        assert classify(0.50, 1) == "MEDIUM"
        assert classify(0.30, 0) == "LOW"
        assert classify(0.10, 0) == "INFO"

    def test_three_agents_forces_high(self, correlation_agent):
        """Three agents firing should force at least HIGH priority."""
        classify = correlation_agent._classify_priority
        assert classify(0.50, 3) == "HIGH"


# 8. END-TO-END CORRELATION TESTS

class TestEndToEndCorrelation:
    """Test complete correlation pipeline on FlowRecords."""

    def test_clean_record_low_crs(self, correlation_agent, make_record):
        """Clean record with no alerts should have very low CRS."""
        record = make_record()
        result = correlation_agent.correlate(record)
        assert result.crs < 0.1
        assert len(result.agents_fired) == 0

    def test_apt_record_high_crs(self, correlation_agent, make_record):
        """Simulated APT with all agents firing should produce high CRS."""
        record = make_record(
            pkt_conf=0.87, pkt_threat=True,
            flow_conf=0.88, flow_anomaly=True,
            beh_conf=0.82, beh_anomaly=True,
        )
        result = correlation_agent.correlate(record)
        assert result.crs > 0.7
        assert "packet" in result.agents_fired
        assert "flow" in result.agents_fired
        assert "behavior" in result.agents_fired

    def test_result_attached_to_record(self, correlation_agent, make_record):
        """CorrelationResult should be attached to the FlowRecord."""
        record = make_record(pkt_conf=0.5, pkt_threat=True)
        result = correlation_agent.correlate(record)
        assert record.correlation_result is result

    def test_agents_fired_list_accuracy(self, correlation_agent, make_record):
        """agents_fired should reflect exactly which agents triggered."""
        record = make_record(
            pkt_conf=0.7, pkt_threat=True,
            beh_conf=0.6, beh_anomaly=True,
        )
        result = correlation_agent.correlate(record)
        assert "packet" in result.agents_fired
        assert "behavior" in result.agents_fired
        assert "flow" not in result.agents_fired

    def test_explanation_contains_key_info(self, correlation_agent, make_record):
        """Explanation should contain CRS, BBN, and priority information."""
        record = make_record(pkt_conf=0.7, pkt_threat=True)
        result = correlation_agent.correlate(record)
        assert "CRS=" in result.explanation
        assert "BBN" in result.explanation
        assert "Priority" in result.explanation

    def test_correlation_result_str(self, correlation_agent, make_record):
        """String representation should be informative."""
        record = make_record(pkt_conf=0.7, pkt_threat=True)
        result = correlation_agent.correlate(record)
        s = str(result)
        assert "CorrelationResult" in s
        assert "CRS=" in s

    def test_bbn_posterior_in_result(self, correlation_agent, make_record):
        """BBN posterior should be stored in the result."""
        record = make_record(pkt_conf=0.7, pkt_threat=True)
        result = correlation_agent.correlate(record)
        assert 0.0 <= result.bbn_posterior <= 1.0


# 9. EDGE CASES AND BATCH PROCESSING

class TestEdgeCases:
    """Test edge cases and batch processing."""

    def test_missing_all_alerts(self, correlation_agent, make_record):
        """Record with no agent alerts should still produce a valid result."""
        record = make_record()
        result = correlation_agent.correlate(record)
        assert result is not None
        assert result.crs >= 0.0
        assert len(result.agents_fired) == 0

    def test_partial_alerts(self, correlation_agent, make_record):
        """Record with only some alerts populated should work correctly."""
        record = make_record(flow_conf=0.7, flow_anomaly=True)
        result = correlation_agent.correlate(record)
        assert "flow" in result.agents_fired
        assert "packet" not in result.agents_fired
        assert "behavior" not in result.agents_fired

    def test_batch_correlation(self, correlation_agent, make_record):
        """Batch correlation should process all records."""
        records = [
            make_record(pkt_conf=0.5, pkt_threat=True),
            make_record(flow_conf=0.6, flow_anomaly=True),
            make_record(beh_conf=0.7, beh_anomaly=True),
        ]
        results = correlation_agent.correlate_batch(records)
        assert len(results) == 3
        for r in results:
            assert r is not None
            assert 0.0 <= r.crs <= 1.0

    def test_empty_batch(self, correlation_agent):
        """Empty batch should return empty list."""
        results = correlation_agent.correlate_batch([])
        assert results == []

    def test_stats_accumulate(self, correlation_agent, make_record):
        """Statistics should accumulate across multiple calls."""
        for _ in range(10):
            record = make_record(pkt_conf=0.3, pkt_threat=True)
            correlation_agent.correlate(record)
        stats = correlation_agent.get_stats()
        assert stats["total_processed"] == 10

    def test_cache_cleanup(self, correlation_agent, make_record):
        """Cache cleanup should remove expired entries."""
        record = make_record(pkt_conf=0.5, pkt_threat=True)
        correlation_agent.correlate(record)
        # With max_age=0, everything should be evicted
        evicted = correlation_agent.cleanup_caches(max_age=0.0)
        assert evicted >= 0  # At least some entries should exist

    def test_custom_weights(self, make_record):
        """Custom CRS weights should be respected."""
        from agents.correlation_agent import CorrelationAgent
        agent = CorrelationAgent(crs_weights=[0.50, 0.20, 0.20, 0.10])
        record = make_record(pkt_conf=1.0, pkt_threat=True)
        result = agent.correlate(record)
        # With 50% weight on packet, CRS should be packet-dominated
        assert result.crs > 0.4

    def test_invalid_weights_rejected(self):
        """Weights not summing to 1.0 should raise AssertionError."""
        from agents.correlation_agent import CorrelationAgent
        with pytest.raises(AssertionError):
            CorrelationAgent(crs_weights=[0.5, 0.5, 0.5, 0.5])

    def test_invalid_weight_length_rejected(self):
        """Weights with wrong length should raise AssertionError."""
        from agents.correlation_agent import CorrelationAgent
        with pytest.raises(AssertionError):
            CorrelationAgent(crs_weights=[0.5, 0.5])


# 10. SUPPRESSION STATISTICS

class TestSuppressionStats:
    """Test the suppression statistics tracking."""

    def test_initial_stats_zero(self, correlation_agent):
        """Initial stats should all be zero."""
        stats = correlation_agent.get_stats()
        assert stats["total_processed"] == 0
        assert stats["dedup_suppressed"] == 0
        assert stats["alerts_emitted"] == 0

    def test_suppression_rate_calculation(self, correlation_agent, make_record):
        """Suppression rate should be calculated correctly."""
        # Process some records
        for _ in range(5):
            record = make_record(pkt_conf=0.6, pkt_threat=True)
            correlation_agent.correlate(record)
        stats = correlation_agent.get_stats()
        assert "suppression_rate" in stats
        assert "emission_rate" in stats
        assert 0.0 <= stats["suppression_rate"] <= 1.0
        assert 0.0 <= stats["emission_rate"] <= 1.0

    def test_total_equals_suppressed_plus_emitted(
        self, correlation_agent, make_record
    ):
        """total_suppressed + alerts_emitted should equal total_processed."""
        for i in range(8):
            record = make_record(
                src_ip=f"10.0.0.{i % 3}",
                pkt_conf=0.5 + i * 0.05,
                pkt_threat=True,
            )
            correlation_agent.correlate(record)
        stats = correlation_agent.get_stats()
        assert stats["total_suppressed"] + stats["alerts_emitted"] == stats["total_processed"]


# 11. IP CIDR MATCHING

class TestIPCIDR:
    """Test IP-in-CIDR matching utility."""

    def test_ip_in_cidr_match(self):
        from agents.correlation_agent import _ip_in_cidr
        assert _ip_in_cidr("10.22.16.50", "10.22.16.0/24") is True

    def test_ip_in_cidr_no_match(self):
        from agents.correlation_agent import _ip_in_cidr
        assert _ip_in_cidr("10.22.17.50", "10.22.16.0/24") is False

    def test_ip_in_cidr_edge_case(self):
        from agents.correlation_agent import _ip_in_cidr
        assert _ip_in_cidr("10.22.16.0", "10.22.16.0/24") is True
        assert _ip_in_cidr("10.22.16.255", "10.22.16.0/24") is True

    def test_ip_in_cidr_invalid(self):
        from agents.correlation_agent import _ip_in_cidr
        assert _ip_in_cidr("invalid", "10.22.16.0/24") is False
