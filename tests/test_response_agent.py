"""
BankSentinel — Response Agent Test Suite
========================================
Challenge Covered: C3 — Alert Fatigue & Compliance (PCI-DSS 10.3)

Run:  python -m pytest tests/test_response_agent.py -v
"""

import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from agents.correlation_agent import CorrelationResult
from agents.response_agent import ResponseAgent, FORENSICS_DIR


class TestResponseAgent(unittest.TestCase):
    def setUp(self):
        # Use a temporary database for testing
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.agent = ResponseAgent(db_path=self.temp_db_path)

    def tearDown(self):
        import os
        os.close(self.temp_db_fd)
        try:
            os.remove(self.temp_db_path)
        except OSError:
            pass

    def _make_alert(self, crs: float = 0.90, suppressed: bool = False) -> CorrelationResult:
        return CorrelationResult(
            record_id=101,
            src_ip="10.22.14.45",
            dst_ip="185.220.101.32",
            crs=crs,
            bbn_posterior=0.9,
            priority="CRITICAL" if crs >= 0.85 else "LOW",
            is_suppressed=suppressed,
            suppression_reason="Test",
            agent_scores={"packet": 0.9},
            agents_fired=["packet"],
            campaign_ticket_id="TEST_CAMPAIGN_01",
            dedup_count=1,
            timestamp=datetime.now(timezone.utc)
        )

    def test_init_creates_database(self):
        self.assertTrue(Path(self.temp_db_path).exists())
        with sqlite3.connect(self.temp_db_path) as db:
            tables = db.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
            self.assertIn(('audit_log',), tables)

    def test_execute_critical_alert_triggers_actions(self):
        alert = self._make_alert(crs=0.95, suppressed=False)
        result = self.agent.execute(alert)
        
        self.assertEqual(result["status"], "SUCCESS")
        actions_str = " ".join(result["actions"])
        
        # Verify all 4 actions are included
        self.assertIn("QUARANTINE_SRC", actions_str)
        self.assertIn("BLOCK_DST", actions_str)
        self.assertIn("STIX_EXPORT", actions_str)
        self.assertIn("PDF_REPORT", actions_str)
        
        # Check files were created
        stix_file = FORENSICS_DIR / f"STIX_{alert.campaign_ticket_id}.json"
        pdf_file = FORENSICS_DIR / f"NRB_Report_{alert.campaign_ticket_id}.pdf"
        self.assertTrue(stix_file.exists())
        self.assertTrue(pdf_file.exists())
        
        # Cleanup
        stix_file.unlink()
        pdf_file.unlink()

    def test_execute_low_crs_suppressed(self):
        alert = self._make_alert(crs=0.50, suppressed=False)
        result = self.agent.execute(alert)
        self.assertEqual(result["actions"], ["EVALUATED_NO_ACTION"])

    def test_execute_high_crs_but_suppressed(self):
        alert = self._make_alert(crs=0.95, suppressed=True)
        result = self.agent.execute(alert)
        self.assertEqual(result["actions"], ["EVALUATED_NO_ACTION"])

    def test_stix_format_valid(self):
        alert = self._make_alert()
        self.agent._export_stix(alert)
        stix_file = FORENSICS_DIR / f"STIX_{alert.campaign_ticket_id}.json"
        
        with open(stix_file, 'r') as f:
            data = json.load(f)
            
        self.assertEqual(data["type"], "bundle")
        self.assertIn("objects", data)
        self.assertEqual(data["objects"][0]["type"], "indicator")
        self.assertIn(alert.src_ip, data["objects"][0]["pattern"])
        
        stix_file.unlink()

    def test_audit_hash_chain_valid(self):
        alert1 = self._make_alert(crs=0.95)
        alert2 = self._make_alert(crs=0.30)
        
        self.agent.execute(alert1)
        self.agent.execute(alert2)
        
        is_valid, failing_ts = self.agent.verify_chain()
        self.assertTrue(is_valid)
        self.assertIsNone(failing_ts)

    def test_audit_hash_chain_detects_tampering(self):
        alert = self._make_alert(crs=0.95)
        self.agent.execute(alert)
        
        # Manually tamper with the database
        with sqlite3.connect(self.temp_db_path) as db:
            db.execute("UPDATE audit_log SET action = 'TAMPERED' WHERE action = 'CONTAINMENT_EXECUTED'")
            db.commit()
            
        is_valid, failing_ts = self.agent.verify_chain()
        self.assertFalse(is_valid)
        self.assertIsNotNone(failing_ts)


if __name__ == "__main__":
    unittest.main()
