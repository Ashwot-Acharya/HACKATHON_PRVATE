import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

"""
Response Agent Inference Example
================================
Demonstrates the BankSentinel containment, logging, STIX 2.1 generation, 
and NRB compliance PDF generation for a high-priority APT event.

Challenge C3: Alert Fatigue & Compliance (PCI-DSS 10.3 / NRB Guidelines)
"""

import sqlite3
import time
from datetime import datetime, timezone

from agents.correlation_agent import CorrelationResult
from agents.response_agent import ResponseAgent, FORENSICS_DIR

def _separator(title: str):
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}")

def main():
    _separator("RESPONSE AGENT — CONTAINMENT & FORENSICS DEMO")
    
    # 1. Initialize Response Agent
    # This automatically connects to forensics/audit.db (or creates it)
    agent = ResponseAgent()
    print(f"  Initialized Response Agent.")
    print(f"  Audit Database: {agent.db_path}")
    print(f"  Initial Hash  : {agent.prev_hash[:16]}...")
    
    # 2. Simulate a CRITICAL CorrelationResult (e.g. from APT Scenario)
    print("\n  Simulating incoming CRITICAL alert from Correlation Agent...")
    alert = CorrelationResult(
        record_id=999,
        src_ip="10.22.14.45",
        dst_ip="185.220.101.32",
        crs=0.9450,           # >= 0.85 triggers containment
        bbn_posterior=0.88,
        priority="CRITICAL",
        is_suppressed=False,
        suppression_reason=None,
        agent_scores={"packet": 0.8, "behavior": 1.0, "flow": 0.9},
        agents_fired=["packet", "flow", "behavior"],
        campaign_ticket_id="APT-CAMPAIGN-001",
        dedup_count=412,
        explanation="Simulated C2 Lateral Movement",
        timestamp=datetime.now(timezone.utc)
    )
    
    print(f"  Alert Received:")
    print(f"    Source IP : {alert.src_ip}")
    print(f"    Dest IP   : {alert.dst_ip}")
    print(f"    CRS       : {alert.crs:.4f}")
    print(f"    Priority  : {alert.priority}")
    
    # 3. Execute Response
    _separator("EXECUTING AUTOMATED RESPONSE")
    print(f"  Condition: CRS >= 0.85 -> TRIGGER CONTAINMENT")
    
    t_start = time.perf_counter()
    result = agent.execute(alert)
    t_total = (time.perf_counter() - t_start) * 1000
    
    print(f"\n  Actions Taken (Total Time: {t_total:.1f}ms):")
    for action in result["actions"]:
        print(f"    - {action}")
        
    print(f"\n  Check the '{FORENSICS_DIR}' folder for the generated STIX and PDF files.")
    
    # 4. Verify Immutable Audit Chain
    _separator("VERIFYING IMMUTABLE AUDIT CHAIN (PCI-DSS 10.3)")
    print("  Recalculating SHA-256 hashes from genesis block...")
    
    is_valid, _ = agent.verify_chain()
    print(f"  Chain Validity: {'PASS (Uncompromised)' if is_valid else 'FAIL (Tampered)'}")
    
    # 5. Tamper Simulation
    _separator("SIMULATING DATABASE TAMPERING")
    print("  An attacker gained access and altered the 'action' column in the SQLite DB...")
    
    with sqlite3.connect(agent.db_path) as db:
        db.execute("UPDATE audit_log SET action = 'TAMPERED_ACTION' WHERE action = 'CONTAINMENT_EXECUTED'")
        db.commit()
        
    is_valid, failed_ts = agent.verify_chain()
    print(f"  Chain Validity: {'PASS (Uncompromised)' if is_valid else 'FAIL (Tampered)'}")
    if not is_valid:
        print(f"  TAMPERING DETECTED at record timestamp: {failed_ts}")
        print("  The hash chain is broken because H_n != SHA256(H_n-1 || action || ts)")
        
    # Revert tampering for future runs
    with sqlite3.connect(agent.db_path) as db:
        db.execute("UPDATE audit_log SET action = 'CONTAINMENT_EXECUTED' WHERE action = 'TAMPERED_ACTION'")
        db.commit()
        
if __name__ == "__main__":
    main()
