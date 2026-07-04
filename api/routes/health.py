"""
BankSentinel — Health & Configuration Endpoints
=================================================
GET /health  — service readiness + loaded agents
GET /config  — non-secret system configuration
"""

from fastapi import APIRouter, Depends

from api.dependencies import AgentRegistry, get_registry
from api.schemas import ConfigResponse, HealthResponse
from config import (
    BEACON_IAT_CV_THRESHOLD,
    BBN_PRIOR_THREAT,
    CAUSAL_CHAIN_WINDOW_SEC,
    CONFIDENCE_GATE_HIGH,
    CONFIDENCE_GATE_LOW,
    DEDUP_WINDOW_SEC,
    MODELS_DIR,
    NEPAL_APT_GROUPS,
    NETWORK_SEGMENTS,
    REGIME_CONTEXTS,
)

router = APIRouter(tags=["System"])


@router.get("/health", response_model=HealthResponse)
def health_check(reg: AgentRegistry = Depends(get_registry)):
    """
    Service health check.

    Returns which agents are loaded, uptime, and threat feed age.
    """
    feed_age = None
    if reg.threat_engine is not None:
        feed_age = reg.threat_engine.stats.age_minutes

    return HealthResponse(
        status="ok",
        uptime_seconds=reg.uptime_seconds,
        agents_loaded={
            "packet_agent": reg.packet_agent is not None,
            "flow_agent": reg.flow_agent is not None,
            "behavior_agent": reg.behavior_agent is not None,
            "correlation_agent": reg.correlation_agent is not None,
            "response_agent": reg.response_agent is not None,
            "threat_intel": reg.threat_engine is not None,
        },
        threat_feed_age_minutes=feed_age,
        models_directory=str(MODELS_DIR),
    )


@router.get("/config", response_model=ConfigResponse)
def get_config():
    """
    Return non-secret system configuration.

    Useful for frontend dashboards to display regime names,
    CRS weights, thresholds, and network segments.
    """
    return ConfigResponse(
        regime_contexts={
            name: {
                "contamination": ctx["contamination"],
                "description": ctx["description"],
                "trigger": ctx["trigger"],
            }
            for name, ctx in REGIME_CONTEXTS.items()
        },
        confidence_gate_low=CONFIDENCE_GATE_LOW,
        confidence_gate_high=CONFIDENCE_GATE_HIGH,
        dedup_window_sec=DEDUP_WINDOW_SEC,
        causal_chain_window_sec=CAUSAL_CHAIN_WINDOW_SEC,
        bbn_prior_threat=BBN_PRIOR_THREAT,
        network_segments=NETWORK_SEGMENTS,
        nepal_apt_groups=NEPAL_APT_GROUPS,
        beacon_iat_cv_threshold=BEACON_IAT_CV_THRESHOLD,
    )
