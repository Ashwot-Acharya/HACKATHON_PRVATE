"""
BankSentinel — Federation Stub API Routes
===========================================
Concept + Stub API for federated IOC sharing across NRB member banks.
Privacy-preserving: only SHA-256 hashed signatures, never raw data.

POST /federation/share-ioc  — Share anonymized IOC hash
GET  /federation/threat-feed — Receive community intelligence
"""

import hashlib
import time
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from config import NETWORK_SEGMENTS

router = APIRouter(prefix="/federation", tags=["Federation (Concept)"])


# ── In-memory IOC store (stub) ────────────────────────────────────────────────
_shared_iocs: List[dict] = [
    {
        "ioc_hash": hashlib.sha256(f"{NETWORK_SEGMENTS['swift_subnet'].replace('0/24', '45')}|APT-C2|2024".encode()).hexdigest(),
        "ioc_type": "ip_hash",
        "contributing_bank": "NIC Asia (anonymized)",
        "shared_at": "2026-06-04T08:00:00Z",
        "confidence": 0.92,
        "attack_type": "C2 Beaconing",
    },
    {
        "ioc_hash": hashlib.sha256(b"ja3:0b32309a26951912be7dba376398abc3").hexdigest(),
        "ioc_type": "ja3_hash",
        "contributing_bank": "Everest Bank (anonymized)",
        "shared_at": "2026-06-04T07:30:00Z",
        "confidence": 0.88,
        "attack_type": "Cobalt Strike TLS",
    },
    {
        "ioc_hash": hashlib.sha256(b"behavior:novel_exfil_pattern_001").hexdigest(),
        "ioc_type": "behavior_hash",
        "contributing_bank": "NMB Bank (anonymized)",
        "shared_at": "2026-06-04T06:15:00Z",
        "confidence": 0.85,
        "attack_type": "Insider Exfiltration",
    },
]


# ── Request / Response Models ─────────────────────────────────────────────────

class ShareIOCRequest(BaseModel):
    """Request to share an anonymized IOC with the federation."""
    ioc_hash: str = Field(
        ..., min_length=64, max_length=64,
        description="SHA-256 hash of the IOC signature (never raw data)",
    )
    ioc_type: str = Field(
        ...,
        description="Type: ip_hash, ja3_hash, behavior_hash, domain_hash",
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Detection confidence [0, 1]",
    )
    attack_type: Optional[str] = Field(
        None, description="Attack classification (e.g., C2 Beaconing)",
    )


class SharedIOC(BaseModel):
    """A single shared IOC entry."""
    ioc_hash: str
    ioc_type: str
    contributing_bank: str
    shared_at: str
    confidence: float
    attack_type: Optional[str]


class ShareIOCResponse(BaseModel):
    """Confirmation of IOC sharing."""
    status: str
    ioc_hash: str
    message: str


class FederationFeedResponse(BaseModel):
    """Community threat feed from member banks."""
    member_banks: int
    total_iocs: int
    iocs: List[SharedIOC]
    last_sync: str
    privacy_note: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/share-ioc", response_model=ShareIOCResponse)
def share_ioc(req: ShareIOCRequest):
    """
    Share an anonymized IOC hash with the federation.

    **Privacy-preserving by design:**
    - Only SHA-256 hashed signatures are shared
    - Never raw traffic data
    - Never customer records
    - Contributing bank identity is anonymized

    When NIC Asia detects a new attack, the anonymized signature
    reaches Everest Bank and NMB Bank within seconds.
    """
    _shared_iocs.append({
        "ioc_hash": req.ioc_hash,
        "ioc_type": req.ioc_type,
        "contributing_bank": "BankSentinel Instance (anonymized)",
        "shared_at": datetime.now(timezone.utc).isoformat(),
        "confidence": req.confidence,
        "attack_type": req.attack_type,
    })

    return ShareIOCResponse(
        status="accepted",
        ioc_hash=req.ioc_hash,
        message=(
            "IOC hash shared with federation. "
            "Member banks will receive this in the next sync cycle."
        ),
    )


@router.get("/threat-feed", response_model=FederationFeedResponse)
def federation_feed():
    """
    Receive community threat intelligence from member banks.

    Returns anonymized IOC hashes contributed by NRB member banks.
    Each entry contains only the SHA-256 hash — never raw data
    or customer information.
    """
    return FederationFeedResponse(
        member_banks=12,
        total_iocs=len(_shared_iocs),
        iocs=[SharedIOC(**ioc) for ioc in _shared_iocs],
        last_sync=datetime.now(timezone.utc).isoformat(),
        privacy_note=(
            "All IOCs are SHA-256 hashed. No raw traffic, IP addresses, "
            "or customer data is shared. Contributing bank identity is anonymized."
        ),
    )
