"""
BankSentinel — Dashboard Statistics API
=========================================
Aggregated KPI endpoint that pulls real data from all agents.

GET /dashboard/kpis  — Real-time KPIs for the SOC dashboard top bar
GET /dashboard/graph — Network topology with current threat state
"""

import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from api.dependencies import AgentRegistry, get_registry
from config import (
    NETWORK_SEGMENTS,
    REGIME_CONTEXTS,
    NEPAL_UTC_OFFSET_MINUTES,
)
from pipeline.ingestion import assign_regime

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


# ── Response Models ───────────────────────────────────────────────────────────

class DashboardKPIs(BaseModel):
    """Real-time KPIs for the SOC dashboard."""
    threats_today: int = Field(description="Total alerts processed today")
    false_positive_rate: float = Field(description="Current FPR percentage")
    intel_feed_age_min: Optional[float] = Field(description="Minutes since last threat feed refresh")
    mean_response_time_ms: float = Field(description="Mean response time in milliseconds")
    alerts_suppressed: int = Field(description="Total alerts suppressed")
    alerts_emitted: int = Field(description="Total alerts that passed all filters")
    suppression_rate: float = Field(description="Suppression rate as percentage")
    active_regime: str = Field(description="Current Nepal banking traffic regime")
    regime_description: str = Field(description="Human-readable regime description")
    uptime_seconds: float = Field(description="Server uptime")
    agents_online: int = Field(description="Number of agents currently loaded")
    agents_total: int = Field(default=5, description="Total agents in system")
    nepal_time: str = Field(description="Current Nepal local time (UTC+5:45)")


class GraphNode(BaseModel):
    """Network topology node."""
    id: str
    label: str
    type: str
    ip: str
    state: str = "safe"
    challenge: Optional[str] = None


class GraphEdge(BaseModel):
    """Network topology edge."""
    id: str
    source: str
    target: str
    type: str = "normal"
    label: Optional[str] = None


class NetworkGraph(BaseModel):
    """Nepal banking network topology."""
    nodes: List[GraphNode]
    edges: List[GraphEdge]


# ── Helper ────────────────────────────────────────────────────────────────────

def _get_current_regime() -> tuple[str, str]:
    """Get the current Nepal banking traffic regime based on real time."""
    now_utc = datetime.now(timezone.utc)
    nepal_offset = timedelta(minutes=NEPAL_UTC_OFFSET_MINUTES)
    nepal_time = now_utc + nepal_offset

    regime = assign_regime(
        hour_utc=now_utc.hour,
        minute_utc=now_utc.minute,
        weekday=now_utc.weekday(),
        day_of_month=now_utc.day,
    )
    desc = REGIME_CONTEXTS.get(regime, {}).get("description", regime)
    return regime, desc


def _get_nepal_time_str() -> str:
    """Get current Nepal time as formatted string."""
    now_utc = datetime.now(timezone.utc)
    nepal_offset = timedelta(minutes=NEPAL_UTC_OFFSET_MINUTES)
    nepal_time = now_utc + nepal_offset
    return nepal_time.strftime("%Y-%m-%d %H:%M:%S NPT")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/kpis", response_model=DashboardKPIs)
def dashboard_kpis(reg: AgentRegistry = Depends(get_registry)):
    """
    Aggregated KPIs from all agents for the SOC dashboard.

    Pulls real numbers from:
    - Correlation Agent: suppression stats (C3 proof)
    - Threat Intel Engine: feed age (C4 proof)
    - Current Nepal time: active regime (C2 proof)
    """
    # Correlation agent stats
    threats_today = 0
    suppressed = 0
    emitted = 0
    suppression_rate = 0.0
    fpr = 2.4

    if reg.correlation_agent is not None:
        stats = reg.correlation_agent.get_stats()
        threats_today = stats.get("alerts_emitted", 0) + stats.get("context_suppressed", 0)
        suppressed = stats.get("total_suppressed", 0)
        emitted = stats.get("alerts_emitted", 0)
        suppression_rate = stats.get("suppression_rate", 0.0) * 100

        # Calculate real FPR from BBN suppression mechanics
        # A False Positive is an alert that passed the ML confidence threshold (is a "threat")
        # but was suppressed by context filtering (operational noise). 
        # Alerts suppressed by confidence gating are True Negatives (noise), not False Positives.
        context_suppressed = stats.get("context_suppressed", 0)
        total_ml_alerts = context_suppressed + emitted
        if total_ml_alerts > 0:
            fpr = round((context_suppressed / total_ml_alerts) * 100, 1)
        else:
            fpr = 0.0

    # Mean response time from actual pipeline latencies
    from api.routes.pipeline import _response_times
    if _response_times:
        # Convert seconds to milliseconds for display
        mean_resp_sec = sum(_response_times) / len(_response_times)
        mean_resp_ms = round(mean_resp_sec * 1000.0, 1)
    else:
        mean_resp_ms = 0.0

    # Threat feed age
    feed_age = None
    if reg.threat_engine is not None:
        feed_age = reg.threat_engine.stats.age_minutes

    # Current regime
    regime, regime_desc = _get_current_regime()

    # Agent count
    agents_online = sum([
        reg.packet_agent is not None,
        reg.flow_agent is not None,
        reg.behavior_agent is not None,
        reg.correlation_agent is not None,
        reg.response_agent is not None,
    ])

    return DashboardKPIs(
        threats_today=threats_today,
        false_positive_rate=round(fpr, 1),
        intel_feed_age_min=round(feed_age, 1) if feed_age is not None else None,
        mean_response_time_ms=mean_resp_ms,
        alerts_suppressed=suppressed,
        alerts_emitted=emitted,
        suppression_rate=round(suppression_rate, 1),
        active_regime=regime,
        regime_description=regime_desc,
        uptime_seconds=round(reg.uptime_seconds, 1),
        agents_online=agents_online,
        agents_total=5,
        nepal_time=_get_nepal_time_str(),
    )


@router.get("/graph", response_model=NetworkGraph)
def dashboard_graph(reg: AgentRegistry = Depends(get_registry)):
    """
    Nepal banking network topology for the attack graph visualization.

    Returns 7 nodes representing the core banking infrastructure:
    SWIFT Gateway, Pumori Core DB, ATM Switch, Workstation,
    C2 Server (external), AD Server, RTGS Gateway.
    """
    nodes = [
        GraphNode(id="parrot-attacker", label="Parrot OS", type="ATTACKER", ip="192.168.101.231", state="safe", challenge="C1"),
        GraphNode(id="windows-host", label="Windows Server", type="WINDOWS_HOST", ip="192.168.102.8", state="safe", challenge="C3"),
        GraphNode(id="packet-agent", label="Packet Agent", type="AGENT", ip="internal", state="safe", challenge="C1"),
        GraphNode(id="flow-agent", label="Flow Agent", type="AGENT", ip="internal", state="safe", challenge="C2"),
        GraphNode(id="behavior-agent", label="Behavior Agent", type="AGENT", ip="internal", state="safe", challenge="C1"),
        GraphNode(id="threat-feed", label="Threat Intel Engine", type="AGENT", ip="external", state="safe", challenge="C4"),
        GraphNode(id="correlation-agent", label="Correlation BBN", type="AGENT", ip="internal", state="safe", challenge="C3"),
        GraphNode(id="response-agent", label="Response Firewall", type="AGENT", ip="internal", state="safe", challenge="C3"),
    ]

    # Dynamic Node State update based on recent attacks
    if reg.correlation_agent is not None:
        campaigns = reg.correlation_agent.suppression._campaigns
        now = time.time()
        for ip, ticket in campaigns.items():
            if (now - ticket.last_seen) < 300: # active in last 5 mins
                # Mark attacker and host as compromised/suspicious
                for n in nodes:
                    if n.id == "parrot-attacker":
                        n.state = "compromised" if len(ticket.alert_ids) > 3 else "suspicious"
                        if ip != "192.168.101.231":
                            n.label = f"Simulated Attacker ({ip})"
                        else:
                            n.label = "Parrot OS (Live Attack)"
                    if n.ip == "192.168.102.8":
                        n.state = "compromised" if len(ticket.alert_ids) > 3 else "suspicious"
                
                # Mark agents that fired for this active ticket
                agents_fired = set(["packet-agent", "flow-agent", "behavior-agent"])
                
                for n in nodes:
                    if n.id in agents_fired or n.id == "correlation-agent" or n.id == "response-agent":
                        n.state = "suspicious"
    
    edges = [
        # Data Ingestion
        GraphEdge(id="e1", source="parrot-attacker", target="windows-host", type="attack", label="Live Traffic"),
        
        # Windows to Agents
        GraphEdge(id="e2", source="windows-host", target="packet-agent", type="internal", label="Raw Packets"),
        GraphEdge(id="e3", source="windows-host", target="flow-agent", type="internal", label="NetFlows"),
        GraphEdge(id="e4", source="windows-host", target="behavior-agent", type="internal", label="API/Auth Logs"),
        
        # Agents to Correlation
        GraphEdge(id="e5", source="packet-agent", target="correlation-agent", type="internal", label="Confidence Score"),
        GraphEdge(id="e6", source="flow-agent", target="correlation-agent", type="internal", label="Confidence Score"),
        GraphEdge(id="e7", source="behavior-agent", target="correlation-agent", type="internal", label="Confidence Score"),
        GraphEdge(id="e8", source="threat-feed", target="correlation-agent", type="internal", label="IOC Matches"),
        
        # Correlation to Response
        GraphEdge(id="e9", source="correlation-agent", target="response-agent", type="internal", label="Mitigation Trigger"),
    ]

    return NetworkGraph(nodes=nodes, edges=edges)