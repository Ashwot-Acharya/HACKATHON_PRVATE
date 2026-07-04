"""
BankSentinel — Flow Agent Endpoints
=====================================
Challenge C2: Legitimate High-Volume False Positive Reduction

POST /analyze/flow       — score a single flow
POST /analyze/flow/batch — score multiple flows (vectorized)
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import AgentRegistry, get_registry
from api.schemas import FlowAlertResponse, FlowRecordRequest
from api.utils import build_flow_record

router = APIRouter(prefix="/analyze", tags=["Analysis"])


def _alert_to_response(alert) -> FlowAlertResponse:
    """Convert a FlowAlert dataclass to its Pydantic response model."""
    return FlowAlertResponse(
        src_ip=alert.src_ip,
        dst_ip=alert.dst_ip,
        regime=alert.regime,
        anomaly_score=alert.anomaly_score,
        is_anomaly=alert.is_anomaly,
        confidence=alert.confidence,
        mitre_technique=alert.mitre_technique,
        explanation=alert.explanation,
        top_features=[list(t) for t in alert.top_features],
        timestamp=alert.timestamp,
        global_score=alert.global_score,
        context_fpr=alert.context_fpr,
        global_fpr=alert.global_fpr,
        fpr_reduction=alert.fpr_reduction,
    )


@router.post("/flow", response_model=FlowAlertResponse)
def analyze_flow(
    req: FlowRecordRequest,
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Score a single flow through the **Flow Agent** (C2).

    Uses six context-aware Isolation Forest models — one per Nepal
    banking traffic regime (month_end, atm_recon, rtgs, off_hours,
    weekend, normal).  The ``regime`` field on the request determines
    which model is used.
    """
    if reg.flow_agent is None:
        raise HTTPException(
            status_code=503,
            detail="FlowAgent not available — model files missing.",
        )

    record = build_flow_record(req)
    alert = reg.flow_agent.score(record)
    return _alert_to_response(alert)


@router.post("/flow/batch", response_model=List[FlowAlertResponse])
def analyze_flow_batch(
    requests: List[FlowRecordRequest],
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Score multiple flows at once using vectorized operations.

    Groups records by regime so each Isolation Forest model is called
    once per regime rather than once per record — much more efficient
    for bulk scoring.
    """
    if reg.flow_agent is None:
        raise HTTPException(
            status_code=503,
            detail="FlowAgent not available — model files missing.",
        )

    records = [build_flow_record(r) for r in requests]
    alerts = reg.flow_agent.score_batch(records)
    return [_alert_to_response(a) for a in alerts]
