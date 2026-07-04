"""
BankSentinel — Correlation Agent Endpoint
==========================================
Challenge C3: Alert Fatigue Suppression

POST /analyze/correlate — run all available agents on a flow, then
                          fuse results via BBN + CRS + 4 suppression layers.
"""

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import AgentRegistry, get_registry
from api.schemas import CorrelationResultResponse, FlowRecordRequest
from api.utils import build_flow_record

router = APIRouter(prefix="/analyze", tags=["Analysis"])


@router.post("/correlate", response_model=CorrelationResultResponse)
def analyze_correlate(
    req: FlowRecordRequest,
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Score a flow through **all available agents**, then fuse via the
    **Correlation Agent** (C3).

    Pipeline order:
      1. Packet Agent  (C4 encrypted traffic)
      2. Flow Agent    (C2 context-aware anomaly)
      3. Behavior Agent (C1 zero-day)
      4. Correlation Agent — BBN posterior + CRS weighted fusion
         + 4 suppression layers (dedup, causal chain, confidence gate,
           context filter)

    Agents that failed to load at startup are skipped — their
    contribution to the CRS is 0.0.

    Returns the unified ``CorrelationResult`` with CRS, BBN posterior,
    priority, suppression status, and per-agent scores.
    """
    if reg.correlation_agent is None:
        raise HTTPException(
            status_code=503,
            detail="CorrelationAgent not available.",
        )

    record = build_flow_record(req)

    # ── Score through each available analytical agent ──────────────────
    if reg.packet_agent is not None:
        reg.packet_agent.score(record)

    if reg.flow_agent is not None:
        reg.flow_agent.score(record)

    if reg.behavior_agent is not None:
        reg.behavior_agent.score(record)

    # ── Fuse via Correlation Agent ────────────────────────────────────
    result = reg.correlation_agent.correlate(record)

    return CorrelationResultResponse(
        record_id=result.record_id,
        src_ip=result.src_ip,
        dst_ip=result.dst_ip,
        crs=result.crs,
        bbn_posterior=result.bbn_posterior,
        priority=result.priority,
        is_suppressed=result.is_suppressed,
        suppression_reason=result.suppression_reason,
        agent_scores=result.agent_scores,
        agents_fired=result.agents_fired,
        campaign_ticket_id=result.campaign_ticket_id,
        dedup_count=result.dedup_count,
        explanation=result.explanation,
        timestamp=result.timestamp,
    )
