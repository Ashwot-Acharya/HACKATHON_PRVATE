import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

"""
Behavior Agent Inference Example
==================================
BankSentinel Challenge C1: Zero-Day Attack Detection via UEBA

The Behavior Agent detects attacks that have NO known signature by
learning exclusively what NORMAL user behaviour looks like.  When it
encounters a sequence that deviates from the learned normal, the BiLSTM
autoencoder's reconstruction error spikes — regardless of whether the
attack has ever been seen before.

Input representation  (14 dimensions per event, sequence length = 20):
  [0] dataset_source          Source indicator (1=User, 2=Win)
  [1] hour_sin                sin(2π × hour/24)
  [2] hour_cos                cos(2π × hour/24)
  [3] event_id_norm           Normalised Event ID
  [4] ds1_bytes_transferred   Log bytes transferred
  [5] ds1_duration_sec        Duration in seconds
  [6] ds1_is_off_hours        Off-hours indicator
  [7] ds1_is_new_resource     New resource indicator
  [8] ds1_failed_attempts     Failed attempts prior 1h
  [9] ds1_peer_deviation      Peer group deviation score
  [10] ds2_logon_type_norm    Normalised logon type
  [11] is_sensitive_target    Sensitive target indicator
  [12] ip_cluster             Source IP cluster index
  [13] query_rate             Normalised query rate

Paper reference: Section V-C, Table IX
  Overall UEBA DR=94.9%, FPR=1.3%

Run:
    python behaviour_inference_example.py
"""

import sys
import io
import math
import time
from datetime import datetime, timezone

import numpy as np

# Fix Windows console encoding (cp1252 cannot handle Unicode symbols)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from agents.behaviour_agent import BehaviorAgent, BehaviorAlert
from pipeline.ingestion import FlowRecord


# HELPERS

_KNOWN_EVENT_IDS = {
    4624: 0,   # successful logon
    4625: 1,   # failed logon
    4648: 2,   # explicit credential logon
    4688: 3,   # process creation
    4698: 4,   # scheduled task creation
    4720: 5,   # user account creation
    4728: 6,   # group membership change
    4732: 7,   # group membership change
    4769: 8,   # kerberos ticket request
}
_N_EVENTS = max(_KNOWN_EVENT_IDS.values()) + 1

def _norm_event(eid: int) -> float:
    """Normalise event ID to [0, 1]."""
    return _KNOWN_EVENT_IDS.get(eid, 0) / max(_N_EVENTS - 1, 1)

def _time_enc(hour: float):
    """Cyclical time encoding → (sin, cos)."""
    rad = 2 * math.pi * hour / 24.0
    return math.sin(rad), math.cos(rad)

def _make_event(eid, hour, src_cluster=0, resource=0, priv=0,
                query_rate=0.1, peer_z=0.0):
    """Build one 14-dimensional event vector."""
    s, c = _time_enc(hour)
    return [
        0.0,                    # [0] dataset_source
        s,                      # [1] hour_sin
        c,                      # [2] hour_cos
        _norm_event(eid),       # [3] event_id_norm
        0.0,                    # [4] ds1_bytes_transferred_log
        0.5,                    # [5] ds1_duration_sec
        0.0,                    # [6] ds1_is_off_hours
        0.0,                    # [7] ds1_is_new_resource
        0.0,                    # [8] ds1_failed_attempts
        peer_z,                 # [9] ds1_peer_deviation
        0.2,                    # [10] ds2_logon_type_norm
        float(priv),            # [11] is_sensitive_target
        float(src_cluster),     # [12] ip_cluster
        query_rate              # [13] query_rate
    ]

def _seq_to_record(seq, account="user", src_ip="10.22.18.50"):
    """Wrap a sequence in a FlowRecord so BehaviorAgent.score() can consume it."""
    rec = FlowRecord(src_ip=src_ip, dst_ip="", features={})
    rec.behavior_sequence = np.array(seq, dtype=np.float32)
    rec.account = account
    return rec


# SCENARIO BUILDERS

def normal_office_hours_sequence():
    """
    20-event sequence: employee working 9 AM–5 PM.
    Regular logon → web/DB access → logoff cycle.  Low peer Z-score.
    Expected: NOT anomalous.
    """
    seq = []
    hour = 9.0
    for i in range(20):
        hour = min(hour + 0.4, 17.0)
        eid = [4624, 4769, 4688, 4769, 4688, 4624][i % 6]
        seq.append(_make_event(eid, hour,
                               src_cluster=0, resource=0, priv=0,
                               query_rate=0.15, peer_z=0.2))
    return seq


def normal_service_account_sequence():
    """
    20-event sequence: service account running scheduled batch jobs.
    Consistent timing, DB access only, no privilege escalation.
    Expected: NOT anomalous.
    """
    seq = []
    for i in range(20):
        hour = 2.0 + (i % 5) * 0.1   # nightly batch at ~02:00
        eid = [4624, 4769, 4688, 4624][i % 4]
        seq.append(_make_event(eid, hour,
                               src_cluster=0, resource=1, priv=0,
                               query_rate=0.3, peer_z=0.3))
    return seq


def credential_abuse_sequence():
    """
    C1 Zero-Day: compromised credential used from unexpected IP at off-hours.
    Event sequence shows normal work-hours pattern, then suddenly
    new source IP cluster + off-hours logon.
    Expected: ANOMALOUS — credential abuse / pass-the-hash indicator.
    Paper: Table IX row 1, DR=96.2%
    """
    seq = []
    # First 10 events: normal daytime pattern
    for i in range(10):
        hour = 10.0 + i * 0.3
        seq.append(_make_event(4624, hour,
                               src_cluster=0, resource=0, priv=0,
                               query_rate=0.12, peer_z=0.2))
    # Last 10 events: attacker using stolen credentials from new machine
    for i in range(10):
        hour = 3.0 + i * 0.1   # 03:00 — off-hours
        eid = [4648, 4769, 4688, 4769, 4624][i % 5]  # 4648 = explicit credential
        seq.append(_make_event(eid, hour,
                               src_cluster=1,   # NEW source IP cluster
                               resource=2,       # Domain controller access
                               priv=1,           # elevated
                               query_rate=0.8,   # rapid queries
                               peer_z=3.8))      # 3.8σ from peer group
    return seq


def privilege_escalation_sequence():
    """
    C1 Zero-Day: standard user account added to privileged group.
    Events: 4624 logon → 4728/4732 group membership change → 4769 Kerberos.
    Expected: ANOMALOUS — privilege escalation.
    Paper: Table IX row 2, DR=94.8%
    """
    seq = []
    # Normal logon sequence
    for i in range(8):
        seq.append(_make_event(4624, 9.0 + i * 0.2,
                               src_cluster=0, resource=0, priv=0,
                               query_rate=0.1, peer_z=0.1))
    # Escalation events
    seq.append(_make_event(4728, 11.0, src_cluster=0, resource=2, priv=1,
                           query_rate=0.5, peer_z=2.9))   # group change
    seq.append(_make_event(4732, 11.0, src_cluster=0, resource=2, priv=1,
                           query_rate=0.5, peer_z=2.9))   # group change
    # Post-escalation: suddenly accessing high-value resources
    for i in range(10):
        seq.append(_make_event(4769, 11.1 + i * 0.05,
                               src_cluster=0, resource=2, priv=1,
                               query_rate=1.2, peer_z=4.1))
    return seq


def data_staging_sequence():
    """
    C1 Zero-Day: massive burst of DB SELECT queries followed by file write.
    400+ queries in 2 minutes signals data staging before exfiltration.
    Expected: ANOMALOUS — data collection / staging.
    Paper: Table IX row 3, DR=91.3%
    """
    seq = []
    # Normal start
    for i in range(5):
        seq.append(_make_event(4624, 14.0, src_cluster=0, resource=1, priv=0,
                               query_rate=0.2, peer_z=0.3))
    # Burst of rapid DB access events — query_rate spikes to 8+
    for i in range(15):
        seq.append(_make_event(4769, 14.1 + i * 0.0083,  # 0.5 min window
                               src_cluster=0, resource=1, priv=0,
                               query_rate=8.5,    # 400+ queries / 2 min
                               peer_z=5.2))       # far from peer group
    return seq


def lateral_movement_sequence():
    """
    C1 Zero-Day: sequential RDP authentications across multiple servers
    within a 15-minute window — classic lateral movement pattern.
    Expected: ANOMALOUS — lateral movement.
    Paper: Table IX row 4, DR=97.1%
    """
    seq = []
    # Start: single normal logon
    seq.append(_make_event(4624, 15.0, src_cluster=0, resource=0, priv=0,
                           query_rate=0.1, peer_z=0.2))
    # Rapid sequential logons across different servers (resource changes)
    for i in range(19):
        resource_idx = (i % 3) + 1   # cycling through 3 different servers
        hour = 15.05 + i * 0.013     # every ~45 seconds
        eid  = [4624, 4769, 4624, 4648, 4624][i % 5]
        seq.append(_make_event(eid, hour,
                               src_cluster=0,
                               resource=resource_idx,
                               priv=int(i > 8),      # gains privilege halfway
                               query_rate=0.6 + i * 0.05,
                               peer_z=2.0 + i * 0.2))
    return seq


def insider_slow_exfiltration_sequence():
    """
    C1 Zero-Day: slow-drip exfiltration over 48 hours.
    Each event looks normal individually; the sequence reveals the pattern.
    Slightly elevated access to sensitive resources, always after hours.
    Expected: ANOMALOUS — insider threat / slow exfiltration.
    """
    seq = []
    for i in range(20):
        hour = 21.5 + (i % 3) * 0.3   # consistently late evening
        seq.append(_make_event(4769, hour,
                               src_cluster=0,
                               resource=2,        # consistently DC/sensitive
                               priv=0,
                               query_rate=0.4 + i * 0.02,   # slowly rising
                               peer_z=1.8 + i * 0.08))      # slowly drifting
    return seq


# RUNNER

def run_inference_example():
    print("\n" + "=" * 80)
    print("BEHAVIOR AGENT INFERENCE EXAMPLE")
    print("Challenge C1: Zero-Day Detection via BiLSTM UEBA")
    print("=" * 80)

    print("\n[1/3] Loading BehaviorAgent...")
    try:
        agent = BehaviorAgent.load()
        print(f"✓ BehaviorAgent loaded")
        print(f"  Threshold (95th pct) : {agent._threshold:.6f}")
        print(f"  Model                : BiLSTM autoencoder")
        print(f"  Sequence length      : 20 events")
        print(f"  Input dimensions     : 14")
    except FileNotFoundError as e:
        print(f"✗ {e}")
        print("\n  Train the Behavior Agent in Colab first:")
        print("  BankSentinel_BehaviourAgent_CERT.ipynb → run all cells → place")
        print("  behaviour_lstm.pt / behaviour_threshold.pkl in banksentinel/models/")
        return

    scenarios = [
        ("Normal office hours — employee 9AM–5PM",
         normal_office_hours_sequence(), "svc_user01", "10.22.18.50",
         False, None),

        ("Normal service account — nightly batch job",
         normal_service_account_sequence(), "svc_batch", "10.22.15.10",
         False, None),

        ("Credential abuse — new IP, off-hours, explicit credential (4648)",
         credential_abuse_sequence(), "user_finance03", "10.22.18.77",
         True, "credential_abuse"),

        ("Privilege escalation — 4728/4732 group membership change + Kerberos burst",
         privilege_escalation_sequence(), "user_devops11", "10.22.18.90",
         True, "privilege_escalation"),

        ("Data staging — 400+ DB queries in 2 minutes (collection before exfil)",
         data_staging_sequence(), "svc_corebanking", "10.22.15.25",
         True, "data_staging"),

        ("Lateral movement — sequential RDP across 3 servers in 15 minutes",
         lateral_movement_sequence(), "user_it_admin", "10.22.18.42",
         True, "lateral_movement"),

        ("Insider slow exfil — nightly DC access, slowly rising query rate",
         insider_slow_exfiltration_sequence(), "user_analyst07", "10.22.18.63",
         True, "insider_exfil"),
    ]

    # ── BENIGN ────────────────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("BENIGN SEQUENCES  (Expected: is_anomaly=False)")
    print("=" * 80)

    normal_pass = 0
    attack_pass = 0

    all_results = []
    for desc, seq, account, src_ip, expected_anom, scenario_hint in scenarios:
        rec = _seq_to_record(seq, account=account, src_ip=src_ip)
        alert = agent.score(rec)
        ok = alert.is_anomaly == expected_anom
        all_results.append(ok)

        if not expected_anom:
            normal_pass += ok
            print(f"\n{'✓ PASS' if ok else '✗ FAIL'}  {desc}")
            print(f"   Account       : {account}")
            print(f"   is_anomaly    : {alert.is_anomaly}  (expected: False)")
            print(f"   recon_error   : {alert.recon_error:.6f}")
            print(f"   threshold     : {alert.threshold:.6f}")
            print(f"   confidence    : {alert.confidence:.4f}")
            print(f"   Explanation   : {alert.explanation[:100]}")

    # ── ATTACKS ────────────────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("ATTACK SEQUENCES  (Expected: is_anomaly=True)")
    print("=" * 80)
    print("KEY: The model was trained on NORMAL sequences ONLY.")
    print("     It has never seen any of these attack patterns.")
    print("     Detection = pure reconstruction error spike (zero-day capable).")

    for desc, seq, account, src_ip, expected_anom, scenario_hint in scenarios:
        if not expected_anom:
            continue
        rec = _seq_to_record(seq, account=account, src_ip=src_ip)
        alert = agent.score(rec)
        ok = alert.is_anomaly
        attack_pass += ok

        status = "✓ PASS" if ok else "✗ FAIL"
        print(f"\n{status}  {desc}")
        print(f"   Account       : {account}")
        print(f"   Scenario hint : {scenario_hint}")
        print(f"   is_anomaly    : {alert.is_anomaly}  (expected: True)")
        print(f"   recon_error   : {alert.recon_error:.6f}  "
              f"(threshold: {alert.threshold:.6f}  "
              f"ratio: {alert.recon_error/max(alert.threshold,1e-9):.2f}×)")
        print(f"   confidence    : {alert.confidence:.4f}")
        print(f"   MITRE         : {alert.mitre_technique}")
        if alert.top_dims:
            print(f"   Top dims      : {alert.top_dims}")
        print(f"   Explanation   : {alert.explanation[:120]}")

    # ── BATCH ─────────────────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("BATCH SCORING")
    print("=" * 80)

    all_recs = [_seq_to_record(seq, account=acc, src_ip=ip)
                for _, seq, acc, ip, _, _ in scenarios]

    t0 = time.time()
    batch_alerts = agent.score_batch(all_recs)
    elapsed = time.time() - t0

    print(f"\n  Scored {len(batch_alerts)} sequences in {elapsed*1000:.1f} ms")
    print(f"  Anomalies detected : {sum(a.is_anomaly for a in batch_alerts)}")

    # ── SUMMARY ───────────────────────────────────────────────────────────────
    n_normal = sum(1 for _, _, _, _, ea, _ in scenarios if not ea)
    n_attack = sum(1 for _, _, _, _, ea, _ in scenarios if ea)

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"\n  Normal accuracy  : {100*normal_pass/max(n_normal,1):.1f}%  "
          f"({normal_pass}/{n_normal})")
    print(f"  Attack detection : {100*attack_pass/max(n_attack,1):.1f}%  "
          f"({attack_pass}/{n_attack})")
    print()
    print("  Scenarios targeted at paper Table IX:")
    print("    Credential abuse  (DR target: 96.2%)")
    print("    Privilege escal.  (DR target: 94.8%)")
    print("    Data staging      (DR target: 91.3%)")
    print("    Lateral movement  (DR target: 97.1%)")
    print()
    print("  Why this demonstrates Challenge C1 (Zero-Day):")
    print("    ✓ Model trained on NORMAL data only — zero attack examples")
    print("    ✓ Detection = reconstruction error > 95th-percentile threshold")
    print("    ✓ Any novel attack that deviates from normal is caught")
    print("    ✓ No signature database required — fires on unseen attack types")


if __name__ == "__main__":
    run_inference_example()
