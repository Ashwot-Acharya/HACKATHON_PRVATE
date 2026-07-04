"""
BankSentinel — API Schemas
===========================
Pydantic v2 request/response models for every endpoint.

Each response schema mirrors the corresponding agent dataclass
(PacketAlert, FlowAlert, BehaviorAlert, CorrelationResult) so the
frontend receives exactly the same field names the agents produce.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


# REQUEST MODELS

class FlowRecordRequest(BaseModel):
    """
    Input for all analysis endpoints.

    ``features`` must contain the 15 CICIDS flow feature columns
    (e.g. "Flow Duration", "Total Fwd Packets", …).  Missing keys
    default to 0.0 inside the pipeline.
    """
    src_ip: str = Field(..., examples=["10.22.14.45"])
    dst_ip: str = Field(..., examples=["185.220.101.32"])
    src_port: int = Field(0, ge=0, le=65535)
    dst_port: int = Field(0, ge=0, le=65535)
    protocol: int = Field(6, description="IP protocol number (6=TCP, 17=UDP)")
    features: Dict[str, Any] = Field(
        ...,
        description="Flow feature dict — keys match CICIDS column names",
    )
    label: str = Field("BENIGN", description="Ground-truth label (for testing)")
    regime: str = Field(
        "normal",
        description="Nepal banking traffic regime context",
    )

    # Optional TLS metadata (C4 encrypted traffic detection)
    tls_version: Optional[int] = None
    tls_ciphers: Optional[List[int]] = None
    tls_extensions: Optional[List[int]] = None
    tls_curves: Optional[List[int]] = None
    tls_point_formats: Optional[List[int]] = None
    ja3_hash: Optional[str] = None
    ja3s_hash: Optional[str] = None

    # Optional behavioral context (C1 zero-day detection)
    behavior_sequence: Optional[List[List[float]]] = Field(
        None,
        description="Pre-built behavioral sequence (seq_len × 8 floats). "
                    "If omitted, synthesized from flow features.",
        json_schema_extra={
            "example": None
        }
    )
    account: Optional[str] = Field(
        None,
        description="Windows account name or service principal.",
    )


class SuricataEveRequest(BaseModel):
    """
    Raw Suricata EVE JSON payload format for live ingestion.
    """
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    event_type: str = Field(..., description="Suricata event type (e.g. flow, tls, alert)")
    src_ip: str
    dest_ip: str
    src_port: Optional[int] = 0
    dest_port: Optional[int] = 0
    proto: str = Field("TCP", description="IP protocol string")
    flow: Optional[Dict[str, Any]] = None
    app_proto: Optional[str] = None
    tls: Optional[Dict[str, Any]] = None
    alert: Optional[Dict[str, Any]] = None
    label: Optional[str] = None

class JA3LookupRequest(BaseModel):
    """Input for direct JA3 hash lookup."""
    ja3_hash: str = Field(..., min_length=32, max_length=32)


class CorrelationResultInput(BaseModel):
    """
    Subset of CorrelationResult fields needed by the Response Agent.
    Allows triggering containment from a previously computed correlation.
    """
    record_id: int
    src_ip: str
    dst_ip: str
    crs: float = Field(..., ge=0.0, le=1.0)
    bbn_posterior: float = Field(..., ge=0.0, le=1.0)
    priority: str
    is_suppressed: bool
    suppression_reason: Optional[str] = None
    agent_scores: Dict[str, float]
    agents_fired: List[str]
    campaign_ticket_id: Optional[str] = None
    dedup_count: int = 1
    explanation: str = ""
    timestamp: Optional[datetime] = None


# RESPONSE MODELS — Agent Alerts

class PacketAlertResponse(BaseModel):
    """Mirrors ``agents.packet_agent.PacketAlert``."""
    src_ip: str
    dst_ip: str
    dst_port: int
    ja3_hash: Optional[str]
    ja3s_hash: Optional[str]
    confidence: float
    is_threat: bool
    active_layers: List[str]
    layer_scores: Dict[str, float]
    malware_family: Optional[str]
    mitre_technique: Optional[str]
    explanation: str
    ja3_feed_age: Optional[float] = None
    timestamp: datetime


class FlowAlertResponse(BaseModel):
    """Mirrors ``agents.flow_agent.FlowAlert``."""
    src_ip: str
    dst_ip: str
    regime: str
    anomaly_score: float
    is_anomaly: bool
    confidence: float
    mitre_technique: Optional[str]
    explanation: str
    top_features: List[List[Any]] = Field(default_factory=list)
    timestamp: datetime
    global_score: float = 0.0
    context_fpr: float = 0.0
    global_fpr: float = 0.0
    fpr_reduction: float = 0.0


class BehaviorAlertResponse(BaseModel):
    """Mirrors ``agents.behaviour_agent.BehaviorAlert``."""
    account: str
    src_ip: str
    recon_error: float
    threshold: float
    is_anomaly: bool
    confidence: float
    scenario_hint: Optional[str]
    mitre_technique: Optional[str]
    explanation: str
    top_dims: List[List[Any]] = Field(default_factory=list)
    peer_z_score: float = 0.0
    timestamp: datetime


class CorrelationResultResponse(BaseModel):
    """Mirrors ``agents.correlation_agent.CorrelationResult``."""
    record_id: int
    src_ip: str
    dst_ip: str
    crs: float
    bbn_posterior: float
    priority: str
    is_suppressed: bool
    suppression_reason: Optional[str]
    agent_scores: Dict[str, float]
    agents_fired: List[str]
    campaign_ticket_id: Optional[str] = None
    dedup_count: int = 1
    mitre_technique: Optional[str] = None
    explanation: str = ""
    timestamp: datetime


# RESPONSE MODELS — Composite / Utility

class PipelineResponse(BaseModel):
    """
    Full end-to-end pipeline result for a single flow.

    Contains detailed results from every agent that was available,
    plus the Response Agent actions if the alert was CRITICAL.
    """
    packet_alert: Optional[PacketAlertResponse] = None
    flow_alert: Optional[FlowAlertResponse] = None
    behavior_alert: Optional[BehaviorAlertResponse] = None
    correlation_result: Optional[CorrelationResultResponse] = None
    response_actions: Optional[ResponseActionResponse] = None


class ResponseActionResponse(BaseModel):
    """Result of Response Agent containment execution."""
    status: str
    actions: List[str]


# Fix forward reference — PipelineResponse references ResponseActionResponse
PipelineResponse.model_rebuild()


class HealthResponse(BaseModel):
    """Service health check result."""
    status: str = "ok"
    uptime_seconds: float
    agents_loaded: Dict[str, bool]
    threat_feed_age_minutes: Optional[float] = None
    models_directory: str


class ConfigResponse(BaseModel):
    """Non-secret system configuration."""
    regime_contexts: Dict[str, Any]
    confidence_gate_low: float
    confidence_gate_high: float
    dedup_window_sec: float
    causal_chain_window_sec: float
    bbn_prior_threat: float
    network_segments: Dict[str, str]
    nepal_apt_groups: List[str]
    beacon_iat_cv_threshold: float


class ThreatIntelStatusResponse(BaseModel):
    """Threat intelligence feed health snapshot."""
    ja3_entries: int
    ja3s_entries: int
    c2_ip_entries: int
    tor_entries: int
    last_updated: Optional[datetime] = None
    age_minutes: Optional[float] = None
    fetch_errors: int


class JA3LookupResponse(BaseModel):
    """Result of a JA3 hash lookup."""
    ja3_hash: str
    found: bool
    malware_family: Optional[str] = None
    is_server_side: bool = False


class SuppressionStatsResponse(BaseModel):
    """Correlation Agent suppression statistics."""
    total_processed: int
    dedup_suppressed: int
    chain_merged: int
    confidence_suppressed: int
    context_suppressed: int
    alerts_emitted: int
    total_suppressed: int
    suppression_rate: float
    emission_rate: float


class AuditVerifyResponse(BaseModel):
    """Hash chain verification result."""
    is_valid: bool
    tampered_at: Optional[str] = None


class AuditLogEntry(BaseModel):
    """Single audit log row."""
    timestamp: str
    action: str
    hash: str
    status: str
