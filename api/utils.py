"""
BankSentinel — API Utilities
==============================
Shared helper to convert Pydantic request models into internal
FlowRecord objects used by all agents.
"""

from __future__ import annotations

import numpy as np

from api.schemas import FlowRecordRequest
from pipeline.ingestion import FlowRecord


def build_flow_record(req: FlowRecordRequest) -> FlowRecord:
    """
    Convert a ``FlowRecordRequest`` into the internal ``FlowRecord``.

    Populates all standard fields, optional TLS metadata, and optional
    behavioral sequence so every downstream agent receives what it needs.

    Args:
        req: Validated Pydantic request body.

    Returns:
        Fully populated FlowRecord ready for agent scoring.
    """
    record = FlowRecord(
        src_ip=req.src_ip,
        dst_ip=req.dst_ip,
        features=req.features,
        label=req.label,
        regime=req.regime,
        src_port=req.src_port,
        dst_port=req.dst_port,
        protocol=req.protocol,
    )

    # ── TLS metadata (C4 Packet Agent) ─────────────────────────────────
    if req.tls_version is not None:
        record.tls_version = req.tls_version
    if req.tls_ciphers is not None:
        record.tls_ciphers = req.tls_ciphers
    if req.tls_extensions is not None:
        record.tls_extensions = req.tls_extensions
    if req.tls_curves is not None:
        record.tls_curves = req.tls_curves
    if req.tls_point_formats is not None:
        record.tls_point_formats = req.tls_point_formats
    if req.ja3_hash is not None:
        record.ja3_hash = req.ja3_hash
    if req.ja3s_hash is not None:
        record.ja3s_hash = req.ja3s_hash

    # ── Behavioral context (C1 Behavior Agent) ─────────────────────────
    if req.behavior_sequence is not None:
        seq_arr = np.array(req.behavior_sequence, dtype=np.float32)
        # Check if it's a valid 14-dimensional sequence. 
        # If it's the Swagger UI default [[0]] or [[0.0]], just ignore it 
        # so the Behavior Agent synthesizes a valid sequence automatically.
        if seq_arr.ndim >= 2 and seq_arr.shape[-1] == 14:
            record.behavior_sequence = seq_arr
            
    if req.account is not None:
        record.account = req.account

    return record
