"""
BankSentinel — Behavior Agent Endpoint
========================================
Challenge C1: Zero-Day Attack Detection

POST /analyze/behavior — score a single flow through the BiLSTM
                         autoencoder for behavioral anomaly detection.
"""

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import AgentRegistry, get_registry
from api.schemas import BehaviorAlertResponse, FlowRecordRequest
from api.utils import build_flow_record

router = APIRouter(prefix="/analyze", tags=["Analysis"])


@router.post("/behavior", response_model=BehaviorAlertResponse)
def analyze_behavior(
    req: FlowRecordRequest,
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Score a single flow through the **Behavior Agent** (C1).

    The BiLSTM autoencoder was trained exclusively on normal behavioral
    sequences. It detects zero-day attacks by measuring reconstruction
    error — any sequence that deviates from learned normal patterns
    spikes above the 95th-percentile threshold.

    If ``behavior_sequence`` (20×8 float matrix) is provided in the
    request, it is used directly. Otherwise, a sequence is synthesized
    from the flow features (``Flow Packets/s`` → query_rate, etc.).

    The ``account`` field is optional; defaults to ``"unknown_account"``.
    """
    if reg.behavior_agent is None:
        raise HTTPException(
            status_code=503,
            detail="BehaviorAgent not available — model files missing.",
        )

    try:
        record = build_flow_record(req)
        alert = reg.behavior_agent.score(record)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    return BehaviorAlertResponse(
        account=alert.account,
        src_ip=alert.src_ip,
        recon_error=alert.recon_error,
        threshold=alert.threshold,
        is_anomaly=alert.is_anomaly,
        confidence=alert.confidence,
        scenario_hint=alert.scenario_hint,
        mitre_technique=alert.mitre_technique,
        explanation=alert.explanation,
        top_dims=[list(t) for t in alert.top_dims],
        peer_z_score=alert.peer_z_score,
        timestamp=alert.timestamp,
    )
