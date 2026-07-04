"""
BankSentinel — Suppression Statistics Endpoint
================================================
GET /stats/suppression — Correlation Agent suppression counters
"""

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import AgentRegistry, get_registry
from api.schemas import SuppressionStatsResponse

router = APIRouter(prefix="/stats", tags=["Statistics"])


@router.get("/suppression", response_model=SuppressionStatsResponse)
def suppression_stats(
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Return Correlation Agent suppression statistics.

    Shows how many alerts were processed, how many were suppressed
    by each of the four mechanisms (deduplication, causal chaining,
    confidence gating, context filtering), and the overall
    suppression / emission rates.

    Target from the paper: 48,200 raw alerts → ~6,350 emitted (87% reduction).
    """
    if reg.correlation_agent is None:
        raise HTTPException(
            status_code=503,
            detail="CorrelationAgent not available.",
        )

    raw = reg.correlation_agent.get_stats()
    return SuppressionStatsResponse(
        total_processed=raw["total_processed"],
        dedup_suppressed=raw["dedup_suppressed"],
        chain_merged=raw["chain_merged"],
        confidence_suppressed=raw["confidence_suppressed"],
        context_suppressed=raw["context_suppressed"],
        alerts_emitted=raw["alerts_emitted"],
        total_suppressed=raw["total_suppressed"],
        suppression_rate=raw["suppression_rate"],
        emission_rate=raw["emission_rate"],
    )
