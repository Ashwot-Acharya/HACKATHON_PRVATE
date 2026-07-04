import sys
import os
import datetime
from pathlib import Path

# Adjust path to find root packages
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__))))

from agents.flow_agent import FlowAgent
from pipeline.ingestion import FlowRecord

def main():
    models_dir = Path("models")
    if not (models_dir / "flow_context_models.pkl").exists():
        print("Error: Models not found. Train the models first.")
        sys.exit(1)

    print("Loading FlowAgent with Global and Context Models...")
    agent = FlowAgent.load(models_dir=models_dir)

    # We will use an exact row from your dataset discovered during our search!
    # This flow transfers ~1MB over 23 seconds out to Port 8080.
    high_volume_features = {
        'bytes_recv': 39237,
        'bytes_sent': 1090187,
        'dst_port': 8080,
        'duration_sec': 23.456,
        'is_internal_dst': 0,
        'is_internal_src': 1,
        'packets_recv': 28,
        'packets_sent': 778,
        'src_port': 51831
    }

    # Scenario 1: This traffic occurs during peak business hours (12:00 PM)
    # This should be highly anomalous because backups don't happen at noon.
    ts_noon = datetime.datetime(2026, 7, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)
    record_noon = FlowRecord(
        src_ip="10.0.0.50",
        dst_ip="10.0.0.100",
        features=high_volume_features,
        regime="normal" # Regular business hours
    )
    record_noon.timestamp = ts_noon

    # Scenario 2: The exact same traffic occurs during the nightly maintenance window (2:00 AM)
    ts_night = datetime.datetime(2026, 7, 15, 2, 0, 0, tzinfo=datetime.timezone.utc)
    record_night = FlowRecord(
        src_ip="10.0.0.50",
        dst_ip="10.0.0.100",
        features=high_volume_features,
        regime="off_hours"
    )
    record_night.timestamp = ts_night

    print("\n--- Testing High Volume False Positives ---")
    
    print("\nScenario 1: 1MB Transfer out to Port 8080 at 12:00 PM (Peak Hours)")
    alert_noon = agent.score(record_noon)
    print(f"  Context Regime Applied : {alert_noon.regime}")
    print(f"  Global Model Score     : {alert_noon.global_score:.4f} " + 
          ("(FALSE POSITIVE)" if alert_noon.global_score > 0.5 else "(Normal)"))
    print(f"  Context Model Score    : {alert_noon.anomaly_score:.4f} " + 
          ("(TRUE ANOMALY - This traffic is suspicious at noon)" if alert_noon.is_anomaly else "(Normal)"))

    print("\nScenario 2: Exact same 1MB Transfer at 2:00 AM (Maintenance Window)")
    alert_night = agent.score(record_night)
    print(f"  Context Regime Applied : {alert_night.regime}")
    print(f"  Global Model Score     : {alert_night.global_score:.4f} " + 
          ("(FALSE POSITIVE)" if alert_night.global_score > 0.5 else "(Normal)"))
    print(f"  Context Model Score    : {alert_night.anomaly_score:.4f} " + 
          ("(Normal - Suppressed by Context!)" if not alert_night.is_anomaly else "(Anomaly)"))

    print("\nConclusion:")
    print("If the Global Score triggers on Scenario 2, but the Context Score stays low,")
    print("then the 6-regime approach successfully prevented a False Positive!")

if __name__ == "__main__":
    main()
