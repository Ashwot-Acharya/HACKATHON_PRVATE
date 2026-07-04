"""
BankSentinel — Packet Agent Endpoint
======================================
Challenge C4: Encrypted TLS 1.3 Traffic Detection

POST /analyze/packet — score a single flow through the 3-layer
                       Packet Agent (JA3 + JA3S + Beacon RF).
"""

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import AgentRegistry, get_registry
from api.schemas import FlowRecordRequest, PacketAlertResponse
from api.utils import build_flow_record

router = APIRouter(prefix="/analyze", tags=["Analysis"])


@router.post("/packet", response_model=PacketAlertResponse)
def analyze_packet(
    req: FlowRecordRequest,
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Score a single flow through the **Packet Agent** (C4).

    Three independent detection layers — all operate without
    payload decryption:

    - **Layer 1** — JA3 client hash match against live abuse.ch feed
    - **Layer 2** — JA3S server-side cross-signal (catches Cobalt Strike)
    - **Layer 3** — CTU-13 Random Forest beacon timing classifier

    TLS fields (``ja3_hash``, ``tls_ciphers``, etc.) are optional.
    If omitted, only Layer 3 can fire.
    """
    if reg.packet_agent is None:
        raise HTTPException(
            status_code=503,
            detail="PacketAgent not available — model files missing.",
        )

    record = build_flow_record(req)
    alert = reg.packet_agent.score(record)

    return PacketAlertResponse(
        src_ip=alert.src_ip,
        dst_ip=alert.dst_ip,
        dst_port=alert.dst_port,
        ja3_hash=alert.ja3_hash,
        ja3s_hash=alert.ja3s_hash,
        confidence=alert.confidence,
        is_threat=alert.is_threat,
        active_layers=alert.active_layers,
        layer_scores=alert.layer_scores,
        malware_family=alert.malware_family,
        mitre_technique=alert.mitre_technique,
        explanation=alert.explanation,
        ja3_feed_age=alert.ja3_feed_age,
        timestamp=alert.timestamp,
    )
