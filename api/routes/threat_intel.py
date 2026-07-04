"""
BankSentinel — Threat Intelligence Endpoints
==============================================
GET  /intel/status     — feed health snapshot
POST /intel/refresh    — force immediate refresh
POST /intel/lookup/ja3 — lookup a JA3 hash
"""

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import AgentRegistry, get_registry
from api.schemas import (
    JA3LookupRequest,
    JA3LookupResponse,
    ThreatIntelStatusResponse,
)

router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])


@router.get("/status", response_model=ThreatIntelStatusResponse)
def intel_status(
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Current threat feed statistics.

    Shows the number of JA3/JA3S hashes, C2 IPs, and Tor exit nodes
    cached in memory, plus the last refresh time and age.
    """
    if reg.threat_engine is None:
        raise HTTPException(
            status_code=503,
            detail="ThreatIntelEngine not available.",
        )

    stats = reg.threat_engine.stats
    return ThreatIntelStatusResponse(
        ja3_entries=stats.ja3_entries,
        ja3s_entries=stats.ja3s_entries,
        c2_ip_entries=stats.c2_ip_entries,
        tor_entries=stats.tor_entries,
        last_updated=stats.last_updated,
        age_minutes=stats.age_minutes,
        fetch_errors=stats.fetch_errors,
    )


@router.post("/refresh", response_model=ThreatIntelStatusResponse)
def intel_refresh(
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Force an immediate synchronous refresh of all threat feeds.

    Pulls latest data from:
    - abuse.ch JA3 blacklist
    - Feodo Tracker C2 IP blocklist
    - Tor exit node list

    Returns updated feed statistics after refresh.
    """
    if reg.threat_engine is None:
        raise HTTPException(
            status_code=503,
            detail="ThreatIntelEngine not available.",
        )

    reg.threat_engine._refresh_all()

    stats = reg.threat_engine.stats
    return ThreatIntelStatusResponse(
        ja3_entries=stats.ja3_entries,
        ja3s_entries=stats.ja3s_entries,
        c2_ip_entries=stats.c2_ip_entries,
        tor_entries=stats.tor_entries,
        last_updated=stats.last_updated,
        age_minutes=stats.age_minutes,
        fetch_errors=stats.fetch_errors,
    )


@router.post("/lookup/ja3", response_model=JA3LookupResponse)
def intel_lookup_ja3(
    req: JA3LookupRequest,
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Lookup a JA3 client fingerprint hash against the live threat database.

    Returns whether the hash matches a known malware family.
    """
    if reg.threat_engine is None:
        raise HTTPException(
            status_code=503,
            detail="ThreatIntelEngine not available.",
        )

    hit = reg.threat_engine.lookup_ja3(req.ja3_hash)

    if hit:
        return JA3LookupResponse(
            ja3_hash=req.ja3_hash,
            found=True,
            malware_family=hit.malware_family,
            is_server_side=hit.is_server_side,
        )

    return JA3LookupResponse(
        ja3_hash=req.ja3_hash,
        found=False,
    )
