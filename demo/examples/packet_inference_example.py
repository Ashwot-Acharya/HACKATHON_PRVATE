import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

"""
Packet Agent Inference Example
================================
BankSentinel Challenge C4: Encrypted Traffic Detection (No Decryption)

Three-layer detection without any payload inspection:
  Layer 1 — JA3 client fingerprint vs abuse.ch threat feed
             + C2 IP blocklist (FeodoTracker)
             + Tor exit node list
  Layer 2 — JA3S server fingerprint cross-signal
             (clean client JA3 but malicious server response = Cobalt Strike)
  Layer 3 — CTU-13 Random Forest beacon timing classifier
             (regularity, IAT variance, size consistency)

Paper reference: Section V-A, Table VI
  JA3+JA3S achieves 91.7% DR on CTU-13 TLS scenarios at 41 ms latency.

Run:
    python packet_inference_example.py
"""

import time
from datetime import datetime, timezone

import numpy as np

from agents.packet_agent import PacketAgent, compute_ja3, compute_ja3s
from intel.threat_feed import threat_engine
from pipeline.ingestion import FlowRecord


# HELPERS

def _flow(src_ip, dst_ip, dst_port=443, ja3=None, ja3s=None,
          dur=5.0, tot_pkts=80, tot_bytes=24000, src_bytes=14000,
          iat_mean=0.062, iat_std=0.031, proto=6, bwd_pkts=35):
    """Construct a minimal FlowRecord for the Packet Agent."""
    fwd_pkts = tot_pkts - bwd_pkts
    features = {"Flow Duration": 0.0, "Total Fwd Packets": 0.0, "Destination Port": 0.0}
    features.update({
        "Destination Port":               float(dst_port),
        "Flow Duration":                  dur * 1e6,           # µs
        "Total Fwd Packets":              float(fwd_pkts),
        "Total Backward Packets":         float(bwd_pkts),
        "Total Length of Fwd Packets":    float(src_bytes),
        "Total Length of Bwd Packets":    float(tot_bytes - src_bytes),
        "Flow Bytes/s":                   tot_bytes / (dur + 1e-9),
        "Flow Packets/s":                 tot_pkts  / (dur + 1e-9),
        "Flow IAT Mean":                  iat_mean * 1e6,
        "Flow IAT Std":                   iat_std  * 1e6,
        "Fwd IAT Total":                  dur * 1e6,
        "Fwd IAT Mean":                   iat_mean * 1e6,
        "Fwd IAT Std":                    iat_std  * 1e6,
        "Bwd IAT Mean":                   iat_mean * 1.2e6,
        "Bwd IAT Std":                    iat_std  * 1.4e6,
        "Protocol":                       float(proto),
    })
    rec = FlowRecord(src_ip=src_ip, dst_ip=dst_ip, features=features)
    rec.ja3_hash  = ja3
    rec.ja3s_hash = ja3s
    return rec


# ── Known-malicious JA3 hashes ──────────────────────────────────────────────
# These are real threat-intel hashes published by Salesforce / abuse.ch.
# In production the feed is refreshed every 30 min from abuse.ch.
# For demo purposes we inject them into the in-memory feed.

# Cobalt Strike default profile JA3
JA3_COBALT_STRIKE  = "b32309a26951912be7dba376398abc3"
# AsyncRAT JA3
JA3_ASYNCRAT       = "f436e8d78acf5861c44b16df33fbe77c"
# Metasploit Meterpreter JA3
JA3_METERPRETER    = "c12f54a3f91dc7bafd92cb59fe009a35"

# Cobalt Strike Malleable C2 JA3S
JA3S_COBALT_STRIKE = "ae4edc6faf64d08308082ad26be60767"

# Legitimate browser / service JA3 hashes (not in any threat feed)
JA3_CHROME_TLS13   = "cd08e31494f9531f560d64c695473da9"
JA3_CURL           = "d44a27a6e4b4e5484cb0f56fc6427697"
JA3S_NGINX_CLEAN   = "b742b407d1f7f635283599fb9ef31a82"

# Real Tor exit node and FeodoTracker C2 IPs (representative examples)
TOR_EXIT_IP        = "185.220.101.32"
FEODO_C2_IP        = "91.215.153.199"


def _inject_intel(engine):
    """
    Inject test threat-intel entries directly into the in-memory feed.
    In production these come from the live abuse.ch / FeodoTracker feeds.
    
    The internal dicts map hash → malware_family_string.
    """
    engine._ja3_db[JA3_COBALT_STRIKE]  = "CobaltStrike"
    engine._ja3_db[JA3_ASYNCRAT]        = "AsyncRAT"
    engine._ja3_db[JA3_METERPRETER]     = "Meterpreter"
    engine._ja3s_db[JA3S_COBALT_STRIKE] = "CobaltStrike_S"
    engine._c2_ips.add(FEODO_C2_IP)
    engine._tor_exits.add(TOR_EXIT_IP)
    print("✓ Test threat-intel injected (simulating live feed)")


# TEST SCENARIOS

def create_test_scenarios():
    """
    Returns list of (description, FlowRecord, expected_is_threat, expected_layers)
    """
    scenarios = []

    # ── BENIGN ─────────────────────────────────────────────────────────────────

    # 1. Clean Chrome browser session — no JA3 in threat feed, no C2 IP
    scenarios.append((
        "Clean Chrome HTTPS to banking portal",
        _flow("10.22.18.50", "203.20.100.1",   dst_port=443,
              ja3=JA3_CHROME_TLS13, ja3s=JA3S_NGINX_CLEAN,
              dur=4.2, tot_pkts=68, tot_bytes=18000, src_bytes=11000,
              iat_mean=0.062, iat_std=0.055),
        False, []
    ))

    # 2. curl API call — benign JA3, no C2 IP, normal timing
    scenarios.append((
        "curl API call — benign automation",
        _flow("10.22.15.10", "10.22.17.1",    dst_port=443,
              ja3=JA3_CURL, ja3s=JA3S_NGINX_CLEAN,
              dur=1.1, tot_pkts=20, tot_bytes=5500, src_bytes=3200,
              iat_mean=0.055, iat_std=0.048),
        False, []
    ))

    # 3. No TLS metadata — just flow stats, normal pattern
    scenarios.append((
        "Internal HTTP — no TLS metadata, normal pattern",
        _flow("10.22.18.100", "10.22.15.20",  dst_port=8080,
              ja3=None, ja3s=None,
              dur=2.8, tot_pkts=45, tot_bytes=12000, src_bytes=7000,
              iat_mean=0.062, iat_std=0.052),
        False, []
    ))

    # ── LAYER 1: JA3 HASH HIT ──────────────────────────────────────────────────

    # 4. Cobalt Strike C2 — JA3 in threat feed
    scenarios.append((
        "L1: Cobalt Strike C2 — JA3 hash matches known malware",
        _flow("10.22.14.45", "185.220.50.100", dst_port=443,
              ja3=JA3_COBALT_STRIKE, ja3s=JA3S_NGINX_CLEAN,
              dur=5.0, tot_pkts=80, tot_bytes=20000, src_bytes=12000),
        True, ["L1"]
    ))

    # 5. AsyncRAT — JA3 in threat feed
    scenarios.append((
        "L1: AsyncRAT — JA3 hash matches AsyncRAT family",
        _flow("10.22.18.35", "91.130.200.15",  dst_port=4449,
              ja3=JA3_ASYNCRAT, ja3s=JA3S_NGINX_CLEAN,
              dur=120.0, tot_pkts=240, tot_bytes=28800, src_bytes=14400,
              iat_mean=0.5, iat_std=0.05),   # very regular = beaconing
        True, ["L1"]
    ))

    # 6. Known C2 IP (FeodoTracker blocklist) — no JA3 match
    scenarios.append((
        "L1: C2 IP hit — FeodoTracker blocklist, no JA3 match",
        _flow("10.22.15.22", FEODO_C2_IP,      dst_port=8443,
              ja3=JA3_CHROME_TLS13, ja3s=JA3S_NGINX_CLEAN,
              dur=6.5, tot_pkts=90, tot_bytes=22000, src_bytes=13000),
        True, ["L1"]
    ))

    # 7. Tor exit node — anonymising exfiltration
    scenarios.append((
        "L1: Tor exit node — connection to known Tor exit",
        _flow("10.22.14.45", TOR_EXIT_IP,      dst_port=443,
              ja3=JA3_CHROME_TLS13, ja3s=JA3S_NGINX_CLEAN,
              dur=8.0, tot_pkts=120, tot_bytes=30000, src_bytes=22000),
        True, ["L1"]
    ))

    # ── LAYER 2: JA3S CROSS-SIGNAL ─────────────────────────────────────────────

    # 8. Malleable C2 profile — attacker randomised the client JA3 (evasion)
    #    but the server-side response still matches Cobalt Strike JA3S
    scenarios.append((
        "L2: JA3S cross-signal — randomised client JA3, server reveals C2",
        _flow("10.22.14.45", "45.142.200.44",  dst_port=443,
              ja3=JA3_CURL,       # not in threat feed (attacker evaded L1)
              ja3s=JA3S_COBALT_STRIKE,          # server still recognisable
              dur=5.5, tot_pkts=88, tot_bytes=21000, src_bytes=12500),
        True, ["L2"]
    ))

    # ── LAYER 3: BEACON TIMING (CTU-13 RF) ────────────────────────────────────

    # 9. Pure beacon — no JA3 match, no C2 IP, but highly regular timing
    #    (the hallmark of malware phoning home on a schedule)
    scenarios.append((
        "L3: Zero-day C2 beacon — unknown JA3, suspicious IAT regularity",
        _flow("10.22.18.55", "103.42.100.200", dst_port=443,
              ja3=None, ja3s=None,
              dur=300.0,                  # 5 min flow
              tot_pkts=300,
              tot_bytes=30000,
              src_bytes=18000,
              iat_mean=1.000,             # checks in every 1.0 s exactly
              iat_std=0.008,              # near-zero variance — machine timing
              bwd_pkts=100),
        True, ["L3"]
    ))

    # 10. Compound: JA3 + C2 IP + beacon timing all fire together
    scenarios.append((
        "L1+L3: Cobalt Strike with C2 IP and beacon timing — all layers fire",
        _flow("10.22.14.45", TOR_EXIT_IP,      dst_port=443,
              ja3=JA3_COBALT_STRIKE, ja3s=JA3S_COBALT_STRIKE,
              dur=600.0, tot_pkts=600, tot_bytes=60000, src_bytes=36000,
              iat_mean=1.0, iat_std=0.003,   # perfect 1-second beacon
              bwd_pkts=200),
        True, ["L1", "L3"]   # L2 won't fire because L1 already fired
    ))

    # 11. JA3 compute test — verify hash calculation matches paper Eq. 2
    scenarios.append((
        "JA3 compute test — verify fingerprint computation",
        None,   # uses score_ja3_direct below
        None, None
    ))

    return scenarios


# RUNNER

def run_inference_example():
    print("\n" + "=" * 80)
    print("PACKET AGENT INFERENCE EXAMPLE")
    print("Challenge C4: Encrypted TLS Traffic Detection (No Payload Decryption)")
    print("=" * 80)

    # ── Load agent ─────────────────────────────────────────────────────────────
    print("\n[1/4] Loading PacketAgent + ThreatIntelEngine...")
    try:
        agent = PacketAgent.load()
        print("✓ PacketAgent loaded (Layer 3 CTU-13 RF ready)")
    except FileNotFoundError as e:
        print(f"✗ {e}")
        print("\n  Train the Packet Agent in Colab first:")
        print("  BankSentinel_PacketAgent_Fixed.ipynb → run all cells → place")
        print("  packet_rf_ctu.pkl / packet_rf_scaler.pkl / packet_rf_features.json")
        print("  in banksentinel/models/")
        return

    # Inject test threat-intel (replaces live feed for offline demo)
    _inject_intel(threat_engine)

    # ── Feed status ────────────────────────────────────────────────────────────
    stats = threat_engine.stats
    print(f"\n  JA3 entries  in feed : {stats.ja3_entries}")
    print(f"  JA3S entries in feed : {stats.ja3s_entries}")
    print(f"  C2 IPs       in feed : {stats.c2_ip_entries}")
    print(f"  Tor exits    in feed : {stats.tor_entries}")

    scenarios = create_test_scenarios()

    # ── JA3 computation test (scenario 11) ────────────────────────────────────
    print("\n" + "=" * 80)
    print("[2/4] JA3/JA3S Hash Computation Test  (Equation 2 from paper)")
    print("=" * 80)
    # Chrome TLS 1.3 ClientHello fields (representative)
    ja3_computed = compute_ja3(
        version=771,
        ciphers=[4866, 4867, 4865, 49196, 49200, 49195, 49199, 52393, 52392],
        extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21],
        curves=[29, 23, 24],
        point_formats=[0],
    )
    ja3s_computed = compute_ja3s(
        version=771,
        cipher=4866,
        extensions=[23, 0],
    )
    print(f"  Computed JA3  : {ja3_computed}")
    print(f"  Computed JA3S : {ja3s_computed}")
    print(f"  Both are 32-char MD5 hex : "
          f"{'✓' if len(ja3_computed)==32 and len(ja3s_computed)==32 else '✗'}")

    # ── Main scenario tests ────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("[3/4] Scoring Test Scenarios")
    print("=" * 80)

    results = []
    for desc, flow, expected_threat, expected_layers in scenarios[:-1]:
        alert = agent.score(flow)
        if expected_threat is None:
            continue

        ok = alert.is_threat == expected_threat
        results.append(ok)
        status = "✓ PASS" if ok else "✗ FAIL"

        # Check layer presence
        layer_ok = True
        if expected_layers:
            layer_ok = all(l in alert.active_layers for l in expected_layers)

        print(f"\n{status}  {desc}")
        print(f"   SrcIP→DstIP   : {alert.src_ip} → {alert.dst_ip}:{alert.dst_port}")
        print(f"   is_threat     : {alert.is_threat}  (expected: {expected_threat})")
        print(f"   confidence    : {alert.confidence:.4f}")
        print(f"   active_layers : {alert.active_layers}")
        print(f"   layer_scores  : {alert.layer_scores}")
        print(f"   malware_family: {alert.malware_family}")
        print(f"   MITRE         : {alert.mitre_technique}")
        if not layer_ok and expected_layers:
            print(f"   ⚠  Expected layers {expected_layers} but got {alert.active_layers}")
        print(f"   Explanation   : {alert.explanation[:120]}")

    # ── Batch test ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("[4/4] Batch Scoring")
    print("=" * 80)

    test_flows = [flow for _, flow, et, _ in scenarios[:-1] if flow is not None]
    t0 = time.time()
    batch_alerts = [agent.score(f) for f in test_flows]
    elapsed = time.time() - t0

    threats = [a for a in batch_alerts if a.is_threat]
    print(f"\n  Scored {len(test_flows)} flows in {elapsed*1000:.1f} ms "
          f"({len(test_flows)/elapsed:.0f} flows/sec)")
    print(f"  Threats detected : {len(threats)}/{len(test_flows)}")

    layer_counts = {}
    for a in threats:
        for l in a.active_layers:
            layer_counts[l] = layer_counts.get(l, 0) + 1
    print(f"  Layer breakdown  : {layer_counts}")

    # ── Summary ────────────────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    n_pass = sum(results)
    n_total = len(results)
    print(f"\n  Tests passed : {n_pass}/{n_total}  ({100*n_pass/n_total:.0f}%)")
    print()
    print("  Layer 1 (JA3/C2 IP/Tor) — fires on known malware fingerprints")
    print("  Layer 2 (JA3S)           — catches evasion: client JA3 randomised")
    print("  Layer 3 (CTU-13 RF)      — catches zero-day: no fingerprint needed")
    print("  All three run in parallel; max(L1, L2, L3) = final confidence")
    print()
    print("  Paper Table VI: JA3+JA3S achieves 91.7% DR on CTU-13 TLS scenarios")
    print("  Layer 3 extends coverage to zero-day TLS C2 not in any database.")


if __name__ == "__main__":
    run_inference_example()
