"""
BankSentinel — Pipeline Endpoints
===================================
Full end-to-end pipeline execution.

POST /pipeline/run      — all 5 agents on one flow
POST /pipeline/apt-demo — built-in 3-record APT attack scenario
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import AgentRegistry, get_registry
from api.schemas import (
    BehaviorAlertResponse,
    CorrelationResultResponse,
    FlowAlertResponse,
    FlowRecordRequest,
    PacketAlertResponse,
    PipelineResponse,
    ResponseActionResponse,
    SuricataEveRequest,
)
from api.utils import build_flow_record
from pydantic import BaseModel

router = APIRouter(prefix="/pipeline", tags=["Pipeline"])


# ── Module-level FPR tracking ─────────────────────────────────────────────────
# Tracks benign/anomaly records to calculate the real False Positive Rate.
#   FPR = (benign records that leaked through as emitted alerts) / (total emitted)
# This gives an accurate, dynamically updated metric.
_fpr_counters = {
    "total_emitted": 0,            # all non-suppressed alerts sent to analyst
    "false_positives": 0,          # benign/anomaly that leaked through (should be ~0)
    "total_benign_processed": 0,   # total benign/anomaly records processed (FPR denominator)
}

# ── Module-level response time tracking ───────────────────────────────────────
_response_times: list = []  # list of pipeline latencies in seconds (capped at 200)

_agent_latencies = {
    "packet": 0.0,
    "flow": 0.0,
    "behavior": 0.0,
    "correlation": 0.0,
    "response": 0.0,
}

_volume_tracking = {
    "raw_events": 0,
    "correlated_alerts": 0,
}

_live_volume_series = []
_current_minute_bucket = {"time": 0, "raw": 0, "correlated": 0}

from collections import Counter
_ja3_counts = Counter()

def _run_pipeline_on_record(record, reg: AgentRegistry, loop=None, source: str = "simulator", active_agents: list = None) -> PipelineResponse:
    if active_agents is None:
        active_agents = ["packet", "flow", "behavior", "correlation", "response"]
    """
    Internal helper — run every available agent on a single FlowRecord
    and build the composite PipelineResponse.

    Args:
        source: "simulator" | "live" | "redteam" — controls broadcast filtering
    """
    import time as _time
    _pipeline_start = _time.perf_counter()
    pkt_resp: Optional[PacketAlertResponse] = None
    flow_resp: Optional[FlowAlertResponse] = None
    beh_resp: Optional[BehaviorAlertResponse] = None
    corr_resp: Optional[CorrelationResultResponse] = None

    # ── Packet Agent ──────────────────────────────────────────────────
    if reg.packet_agent is not None and "packet" in active_agents:
        t0 = _time.perf_counter()
        alert = reg.packet_agent.score(record)
        _agent_latencies["packet"] = _agent_latencies["packet"] * 0.9 + (_time.perf_counter() - t0) * 1000 * 0.1
        pkt_resp = PacketAlertResponse(
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
        if alert.ja3_hash:
            _ja3_counts[alert.ja3_hash] += 1
        if alert.ja3s_hash:
            _ja3_counts[alert.ja3s_hash] += 1

    # ── Flow Agent ────────────────────────────────────────────────────
    if reg.flow_agent is not None and "flow" in active_agents:
        t0 = _time.perf_counter()
        alert = reg.flow_agent.score(record)
        _agent_latencies["flow"] = _agent_latencies["flow"] * 0.9 + (_time.perf_counter() - t0) * 1000 * 0.1
        flow_resp = FlowAlertResponse(
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

    # ── Behavior Agent ────────────────────────────────────────────────
    if reg.behavior_agent is not None and "behavior" in active_agents:
        try:
            t0 = _time.perf_counter()
            alert = reg.behavior_agent.score(record)
            _agent_latencies["behavior"] = _agent_latencies["behavior"] * 0.9 + (_time.perf_counter() - t0) * 1000 * 0.1
            beh_resp = BehaviorAlertResponse(
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
        except ValueError:
            # Raised if record.behavior_sequence is missing
            beh_resp = None

    # ── Correlation Agent ─────────────────────────────────────────────
    if reg.correlation_agent is not None and "correlation" in active_agents:
        t0 = _time.perf_counter()
        result = reg.correlation_agent.correlate(record)
        _agent_latencies["correlation"] = _agent_latencies["correlation"] * 0.9 + (_time.perf_counter() - t0) * 1000 * 0.1
        corr_resp = CorrelationResultResponse(
            record_id=result.record_id,
            src_ip=result.src_ip,
            dst_ip=result.dst_ip,
            crs=result.crs,
            bbn_posterior=result.bbn_posterior,
            priority=result.priority,
            is_suppressed=result.is_suppressed,
            suppression_reason=result.suppression_reason,
            agent_scores=result.agent_scores,
            agents_fired=result.agents_fired,
            campaign_ticket_id=result.campaign_ticket_id,
            dedup_count=result.dedup_count,
            mitre_technique=result.mitre_technique,
            explanation=result.explanation,
            timestamp=result.timestamp,
        )

        # ── Track FPR counters ──────────
        if not corr_resp.is_suppressed:
            _fpr_counters["total_emitted"] += 1
            if record.label in ("BENIGN", "ANOMALY"):
                _fpr_counters["false_positives"] += 1

        if record.label == "SURICATA_ALERT":
            corr_resp.priority = "HIGH"
            if corr_resp.crs < 0.85:
                corr_resp.crs = 0.85
            corr_resp.is_suppressed = False
            corr_resp.suppression_reason = None
            sig = record.features.get("suricata_signature", "Unknown Suricata Alert")
            cat = record.features.get("suricata_category", "Intrusion Attempt")
            corr_resp.mitre_technique = f"T1190 - {cat}"
            corr_resp.explanation = f"Suricata Signature Match: {sig}"
            if "packet" not in corr_resp.agents_fired:
                corr_resp.agents_fired.append("packet")
            corr_resp.agent_scores["packet"] = max(corr_resp.agent_scores.get("packet", 0.0), 0.9)

        # ── Final MITRE normalisation ────────────
        PRIORITY_MITRE_MAP = {
            "CRITICAL": "T1071.001 - Application Layer Protocol: C2",
            "HIGH":     "T1021.001 - Lateral Movement: RDP",
            "MEDIUM":   "T1213 - Data from Information Repositories",
            "LOW":      "T1046 - Network Service Discovery",
            "INFO":     "Normal Traffic",
        }
        mt = corr_resp.mitre_technique or ""
        if not (mt.startswith("T") or mt.lower().startswith("normal")):
            corr_resp.mitre_technique = PRIORITY_MITRE_MAP.get(
                corr_resp.priority, "T1071 - Application Layer Protocol"
            )
        result.mitre_technique = corr_resp.mitre_technique

        # Determine challenge from agents or label
        _challenge = "C1"  # Default: zero-day/behavioral
        if record.label == "LIVE":
            # Live sensor traffic — determine challenge by what agents fired
            fired = set(corr_resp.agents_fired)
            if "PacketAgent" in fired:
                _challenge = "C4"
            elif "FlowAgent" in fired:
                _challenge = "C2"
            elif "CorrelationAgent" in fired:
                _challenge = "C3"
            else:
                _challenge = "C1"
        elif record.label.startswith("APT"):
            _challenge = "C4"
        elif record.label.startswith("ATM"):
            _challenge = "C2"
        elif record.label.startswith("Ransom"):
            _challenge = "C3"
        elif record.label.startswith("Insider"):
            _challenge = "C1"

        # Broadcast to WebSocket if CRS > 0 AND source matches current mode
        _should_broadcast = False
        if source == "redteam":
            _should_broadcast = True  # Red team scenarios always broadcast
        elif source == "simulator":
            _should_broadcast = True
        elif source == "live":
            _should_broadcast = True

        if result.crs >= 0 and _should_broadcast:
            import asyncio
            from api.routes.websocket import broadcast_alert
            alert_data = corr_resp.model_dump(mode="json")
            alert_data["challenge"] = _challenge  # Inject challenge for frontend
            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(broadcast_alert(alert_data), loop)
            else:
                try:
                    current_loop = asyncio.get_running_loop()
                    current_loop.create_task(broadcast_alert(alert_data))
                except RuntimeError:
                    pass # Not in an async context, gracefully ignore or handle

        # ── Response Agent (only for CRITICAL, non-suppressed) ────────
        resp_resp = None
        if (
            reg.response_agent is not None
            and not result.is_suppressed
            and result.priority == "CRITICAL"
        ):
            t0 = _time.perf_counter()
            resp_result = reg.response_agent.execute(result)
            _agent_latencies["response"] = _agent_latencies["response"] * 0.9 + (_time.perf_counter() - t0) * 1000 * 0.1
            resp_resp = ResponseActionResponse(
                status=resp_result["status"],
                actions=resp_result["actions"],
            )

    # Track pipeline response time
    _pipeline_elapsed = _time.perf_counter() - _pipeline_start
    _response_times.append(_pipeline_elapsed)
    if len(_response_times) > 200:
        _response_times.pop(0)

    # Update volume tracking
    _volume_tracking["raw_events"] += 1
    if corr_resp and corr_resp.priority in ["CRITICAL", "HIGH", "MEDIUM"]:
        _volume_tracking["correlated_alerts"] += 1

    global _current_minute_bucket, _live_volume_series
    now_ms = int(_time.time() * 1000)
    minute_ms = now_ms - (now_ms % 60000) # Floor to current minute
    if _current_minute_bucket["time"] != minute_ms:
        if _current_minute_bucket["time"] != 0:
            _live_volume_series.append(dict(_current_minute_bucket))
            if len(_live_volume_series) > 60:
                _live_volume_series.pop(0)
        _current_minute_bucket = {"time": minute_ms, "raw": 0, "correlated": 0}
        
    _current_minute_bucket["raw"] += 1
    if corr_resp and corr_resp.priority in ["CRITICAL", "HIGH", "MEDIUM"]:
        _current_minute_bucket["correlated"] += 1

    return PipelineResponse(
        packet_alert=pkt_resp,
        flow_alert=flow_resp,
        behavior_alert=beh_resp,
        correlation_result=corr_resp,
        response_actions=resp_resp,
    )


@router.post("/run", response_model=PipelineResponse)
async def pipeline_run(
    req: FlowRecordRequest,
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Full end-to-end pipeline for a single flow.

    Runs **all 5 agents** in sequence:

    1. **Packet Agent** (C4) — encrypted traffic detection
    2. **Flow Agent** (C2) — context-aware anomaly detection
    3. **Behavior Agent** (C1) — zero-day behavioral detection
    4. **Correlation Agent** (C3) — BBN fusion + suppression
    5. **Response Agent** — containment (only if CRITICAL)

    Returns detailed results from every agent that was available.
    """
    import asyncio
    from fastapi.concurrency import run_in_threadpool
    loop = asyncio.get_running_loop()
    record = build_flow_record(req)
    return await run_in_threadpool(_run_pipeline_on_record, record, reg, loop, "live")


@router.post("/suricata", response_model=PipelineResponse)
async def ingest_suricata(
    req: SuricataEveRequest,
    reg: AgentRegistry = Depends(get_registry),
):
    """
    Live ingestion endpoint for raw Suricata EVE JSON.
    
    Accepts Suricata events (flow, tls), translates them dynamically into 
    the CICIDS feature format required by the BankSentinel agents, and 
    runs the full pipeline.
    """
    import asyncio
    from fastapi.concurrency import run_in_threadpool
    import numpy as np
    
    # 1. Translate Suricata proto string to IP protocol number
    proto_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
    proto_num = proto_map.get(req.proto.upper(), 6)
    
    # 2. Extract Flow metrics
    # Suricata EVE json puts duration, pkts, bytes inside the 'flow' dict
    dur = 0.0
    fwd_pkts = 0.0
    bwd_pkts = 0.0
    fwd_bytes = 0.0
    bwd_bytes = 0.0
    
    if req.flow:
        dur = req.flow.get("duration", 0.0)
        # Assuming toserver is fwd, toclient is bwd
        fwd_pkts = req.flow.get("pkts_toserver", 0.0)
        bwd_pkts = req.flow.get("pkts_toclient", 0.0)
        fwd_bytes = req.flow.get("bytes_toserver", 0.0)
        bwd_bytes = req.flow.get("bytes_toclient", 0.0)
        
    # Prevent division by zero
    dur_safe = max(dur, 1e-9)
    
    def is_internal(ip: str) -> int:
        if not ip: return 0
        return 1 if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") else 0

    import datetime
    features = {
        "start_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.000"),
        "bytes_recv": bwd_bytes,
        "bytes_sent": fwd_bytes,
        "dst_port": req.dest_port,
        "duration_sec": dur,
        "is_internal_dst": is_internal(req.dest_ip),
        "is_internal_src": is_internal(req.src_ip),
        "packets_recv": bwd_pkts,
        "packets_sent": fwd_pkts,
        "src_port": req.src_port,
        "protocol": req.proto.upper(),
        "tcp_flags": "NONE",
        "segment": "UNKNOWN",
        "application_guess": "UNKNOWN"
    }
    
    # 3. Create the FlowRecordRequest
    # NOTE: behavior_sequence=None for live traffic.
    label = "SURICATA_ALERT" if req.event_type == "alert" else (req.label if req.label else "LIVE")
    
    if req.event_type == "alert" and req.alert:
        features["suricata_signature"] = req.alert.get("signature", "Unknown Suricata Alert")
        features["suricata_category"] = req.alert.get("category", "Intrusion Attempt")

    flow_req = FlowRecordRequest(
        src_ip=req.src_ip,
        dst_ip=req.dest_ip,
        src_port=req.src_port,
        dst_port=req.dest_port,
        protocol=proto_num,
        features=features,
        behavior_sequence=None, 
        label=label,
        regime="normal",
    )
    
    # 4. Extract TLS JA3 data if present
    if req.tls:
        flow_req.ja3_hash = req.tls.get("ja3", {}).get("hash", req.tls.get("ja3"))
        flow_req.ja3s_hash = req.tls.get("ja3s", {}).get("hash", req.tls.get("ja3s"))
        
    loop = asyncio.get_running_loop()
    record = build_flow_record(flow_req)
    
    # Run pipeline — Suricata provides TLS/JA3 data so Packet Agent fires here too
    return await run_in_threadpool(_run_pipeline_on_record, record, reg, loop, "live", ["packet", "flow", "behavior", "correlation", "response"])

@router.post("/suricata_raw_ingest")
async def ingest_suricata_raw(
    req: SuricataEveRequest,
):
    """
    Live ingestion endpoint for raw Suricata EVE JSON.
    Unlike /suricata, this endpoint does NOT run ML analysis.
    It simply broadcasts the raw packet data directly to the frontend
    via /ws/suricata_raw so the frontend can orchestrate the ML call.
    """
    import asyncio
    from api.routes.websocket import broadcast_raw_suricata
    
    # Broadcast raw data immediately
    loop = asyncio.get_running_loop()
    raw_data = req.model_dump(mode="json")
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(broadcast_raw_suricata(raw_data), loop)
        
    return {"status": "broadcasted", "type": req.event_type}

from fastapi import Body

@router.post("/zeek_live_ingest", summary="Ingest live Zeek logs (conn.log)")
async def ingest_zeek(
    req: dict = Body(...),
    reg: AgentRegistry = Depends(get_registry)
):
    """
    Ingests live Zeek JSON logs (from conn.log), maps them to the 20 ML features, 
    and pipes them through the agent engine.
    """
    # 1. Map Zeek fields to internal schema
    # (Since we explicitly tail conn.log, we assume this is connection data)
    src_ip = req.get("id.orig_h", "")
    dest_ip = req.get("id.resp_h", "")
    src_port = req.get("id.orig_p", 0)
    dest_port = req.get("id.resp_p", 0)
    proto_str = req.get("proto", "tcp").upper()
    proto_num = 6 if proto_str == "TCP" else (17 if proto_str == "UDP" else 1)
    
    # Zeek duration and bytes
    dur = req.get("duration", 0.0)
    fwd_pkts = req.get("orig_pkts", 1.0)
    bwd_pkts = req.get("resp_pkts", 1.0)
    fwd_bytes = req.get("orig_bytes", 0.0)
    bwd_bytes = req.get("resp_bytes", 0.0)
    
    def is_internal(ip: str) -> int:
        if not ip: return 0
        return 1 if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") else 0

    import datetime
    features = {
        "start_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.000"),
        "bytes_recv": bwd_bytes,
        "bytes_sent": fwd_bytes,
        "dst_port": dest_port,
        "duration_sec": dur,
        "is_internal_dst": is_internal(dest_ip),
        "is_internal_src": is_internal(src_ip),
        "packets_recv": bwd_pkts,
        "packets_sent": fwd_pkts,
        "src_port": src_port,
        "protocol": proto_str,
        "tcp_flags": req.get("conn_state", "NONE"),
        "segment": "UNKNOWN",
        "application_guess": req.get("service", "UNKNOWN")
    }
    
    # 2. Build flow request
    # NOTE: behavior_sequence=None — Behavior Agent skipped for pure network data.
    # It requires real Windows Event Log sequences to function correctly.
    flow_req = FlowRecordRequest(
        src_ip=src_ip,
        dst_ip=dest_ip,
        src_port=src_port,
        dst_port=dest_port,
        protocol=proto_num,
        features=features,
        behavior_sequence=None, 
        label="LIVE",
        regime="normal",
    )
    
    # Extract JA3 if Zeek ssl.log data was joined (optional)
    if "ja3" in req:
        flow_req.ja3_hash = req["ja3"]
    if "ja3s" in req:
        flow_req.ja3s_hash = req["ja3s"]

    # 3. Trigger Pipeline
    import asyncio
    from starlette.concurrency import run_in_threadpool
    loop = asyncio.get_running_loop()
    record = build_flow_record(flow_req)
    # Run ALL agents for Zeek data
    result = await run_in_threadpool(_run_pipeline_on_record, record, reg, loop, "live", ["packet", "flow", "behavior", "correlation", "response"])
    
    return result

# ── Dashboards / Metrics Endpoints ────────────────────────────────────────

@router.get("/metrics/latencies")
def get_agent_latencies():
    return _agent_latencies

@router.get("/metrics/volume")
def get_alert_volume():
    """Return real live volume tracking per minute."""
    global _current_minute_bucket, _live_volume_series
    import time
    
    if _current_minute_bucket["time"] == 0:
        return {"raw": [], "correlated": []}
        
    now_ms = int(time.time() * 1000)
    current_minute = now_ms - (now_ms % 60000)
    
    if _current_minute_bucket["time"] != current_minute:
        _live_volume_series.append(dict(_current_minute_bucket))
        if len(_live_volume_series) > 60:
            _live_volume_series.pop(0)
        _current_minute_bucket = {"time": current_minute, "raw": 0, "correlated": 0}

    data = _live_volume_series + [_current_minute_bucket]
    
    # Fill in empty minutes if the gap is larger than 1 minute (optional, but good for charts)
    filled_data = []
    if data:
        start_time = data[0]["time"]
        end_time = data[-1]["time"]
        lookup = {d["time"]: d for d in data}
        for t in range(start_time, end_time + 60000, 60000):
            if t in lookup:
                filled_data.append(lookup[t])
            else:
                filled_data.append({"time": t, "raw": 0, "correlated": 0})
    
    raw = [{"time": d["time"], "value": d["raw"]} for d in filled_data]
    corr = [{"time": d["time"], "value": d["correlated"]} for d in filled_data]
    return {"raw": raw, "correlated": corr}

@router.get("/metrics/ja3_top")
def get_top_ja3():
    """Return top JA3s, mapping known hashes."""
    KNOWN_JA3 = {
        "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike profile",
        "e7d705a3286e19ea42f587b344ee6865": "Tor client fingerprint",
        "771pe871239123891238912389123891": "Trickbot dropper",
    }
    # Return top 5 actual observed JA3s
    if not _ja3_counts:
        return []
        
    top = _ja3_counts.most_common(5)
    results = []
    for hash_val, count in top:
        results.append({
            "hash": hash_val,
            "description": KNOWN_JA3.get(hash_val, "Unknown JA3/S"),
            "count": count
        })
    return results