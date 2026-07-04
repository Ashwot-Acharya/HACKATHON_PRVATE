import sys
import os
import unittest
import glob
from pathlib import Path
import pandas as pd
import numpy as np
from datetime import datetime, timezone

# Adjust path to find root packages
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import MODELS_DIR
from pipeline.ingestion import FlowRecord
from agents.packet_agent import PacketAgent
from agents.flow_agent import FlowAgent
from agents.behaviour_agent import BehaviorAgent

class TestAllModelsWorking(unittest.TestCase):
    """Centralized test suite to verify loading and runtime execution of all trained model checkpoints."""

    def setUp(self):
        # Create a mock/dummy FlowRecord for scoring
        self.flow_features = {
            "bytes_recv": 2000,
            "bytes_sent": 5000,
            "dst_port": 80,
            "duration_sec": 1.5,
            "is_internal_dst": 1,
            "is_internal_src": 1,
            "packets_recv": 8,
            "packets_sent": 10,
            "src_port": 12345
        }

        self.packet_features = {
            "dur": 1.5,
            "tot_pkts": 18,
            "tot_bytes": 7000,
            "src_bytes": 5000,
            "bytes_per_pkt": 388.8,
            "bytes_per_sec": 4666.6,
            "pkts_per_sec": 12.0,
            "iat_mean_proxy": 0.08,
            "iat_cv_proxy": 0.15,
            "regularity": 0.95,
            "size_consistency": 0.98,
            "flow_efficiency": 0.88,
            "beacon_score_raw": 0.05,
            "proto_tcp": 1,
            "proto_udp": 0,
            "dir_unidirectional": 0,
            "bwd_fwd_ratio": 0.8,
            "iat_mean": 0.08,
            "iat_std": 0.012,
            "dst_port": 80
        }

        self.packet_record = FlowRecord(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            features=self.packet_features,
            regime="normal"
        )
        self.packet_record.ja3_hash = "7c1b1a03e1e87834fc0c86ebf458db90"
        self.packet_record.ja3s_hash = "8f8bf25adcc6eb27a20c384dfa1ab891"
        self.packet_record.timestamp = datetime.now(timezone.utc)
        self.packet_record.behavior_sequence = np.zeros((20, 14), dtype=np.float32)

        self.flow_record = FlowRecord(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            features=self.flow_features,
            regime="normal"
        )
        self.flow_record.timestamp = datetime.now(timezone.utc)
        self.flow_record.behavior_sequence = np.zeros((20, 14), dtype=np.float32)

    def test_packet_agent_model_loading_and_inference(self):
        """Verify PacketAgent loaded RF model can execute Layer 3 inference."""
        try:
            agent = PacketAgent.load(models_dir=MODELS_DIR)
            self.assertIsNotNone(agent)
            
            # Run inference
            alert = agent.score(self.packet_record)
            self.assertEqual(alert.src_ip, "10.0.0.1")
            self.assertEqual(alert.dst_ip, "10.0.0.2")
            self.assertTrue(hasattr(alert, "confidence"))
            print(f"[PacketAgent verification] Fired successfully. Score={alert.confidence:.4f}")
        except Exception as e:
            self.fail(f"PacketAgent verification failed: {e}")

    def test_flow_agent_model_loading_and_inference(self):
        """Verify paper FlowAgent loaded context models can execute inference."""
        try:
            agent = FlowAgent.load(models_dir=MODELS_DIR)
            self.assertIsNotNone(agent)
            
            # Run inference
            alert = agent.score(self.flow_record)
            self.assertEqual(alert.src_ip, "10.0.0.1")
            self.assertEqual(alert.dst_ip, "10.0.0.2")
            self.assertTrue(hasattr(alert, "confidence"))
            print(f"[FlowAgent verification] Fired successfully. Regime={alert.regime}, Score={alert.anomaly_score:.4f}")
        except Exception as e:
            self.fail(f"FlowAgent verification failed: {e}")

    def test_behavior_agent_model_loading_and_inference(self):
        """Verify BehaviorAgent loaded BiLSTM Autoencoder works."""
        try:
            agent = BehaviorAgent.load(models_dir=MODELS_DIR)
            self.assertIsNotNone(agent)
            
            # Run inference (uses packet_record to satisfy behavior test logic)
            alert = agent.score(self.packet_record)
            self.assertEqual(alert.src_ip, "10.0.0.1")
            self.assertTrue(hasattr(alert, "confidence"))
            print(f"[BehaviorAgent verification] Fired successfully. Recon error={alert.recon_error:.6f}")
        except Exception as e:
            self.fail(f"BehaviorAgent verification failed: {e}")

    def test_track_d_flow_agent_loading_and_inference(self):
        """Verify standalone Track D Flow Agent XGB+IF bundle loads and executes."""
        try:
            import joblib
            model_files = glob.glob("agents/flow_agent_track_d/models/*.pkl")
            self.assertTrue(len(model_files) > 0, "No Track D models found")
            latest_model = max(model_files, key=os.path.getctime)
            
            bundle = joblib.load(latest_model)
            self.assertIn("xgb_model", bundle)
            self.assertIn("iso_forest", bundle)
            
            # Setup dummy hosts placeholder
            bundle["hosts_df_placeholder"] = pd.DataFrame({
                "ip_address": ["10.0.0.2"],
                "criticality": ["MEDIUM"],
                "host_type": ["SERVER"],
                "patch_level": ["CURRENT"],
                "is_honeypot": [False]
            })

            # Setup raw input row mapping expected raw netflow schema
            row = pd.DataFrame([{
                "start_time": "2026-07-03 12:00:00",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "protocol": "TCP",
                "tcp_flags": "PA",
                "segment": "USER",
                "application_guess": "HTTP",
                "duration_sec": 1.5,
                "bytes_sent": 5000,
                "bytes_recv": 2000,
                "packets_sent": 10,
                "packets_recv": 8,
                "is_internal_src": 1,
                "is_internal_dst": 1,
            }])

            from agents.flow_agent_track_d.inference import predict_final
            scores, criticality = predict_final(row, bundle)
            self.assertEqual(len(scores), 1)
            print(f"[Track D FlowAgent verification] Fired successfully. Score={scores[0]:.4f}")
        except Exception as e:
            self.fail(f"Track D FlowAgent verification failed: {e}")

if __name__ == "__main__":
    unittest.main()
