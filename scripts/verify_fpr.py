import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import asyncio
import logging
from api.dependencies import init_registry, get_registry
from api.simulator import _make_random_benign_record
from api.routes.pipeline import _run_pipeline_on_record, _fpr_counters
from api.routes.dashboard_stats import dashboard_kpis

logging.basicConfig(level=logging.INFO)

async def test_fpr():
    # Initialize the agents (this might take a few seconds to load models)
    reg = init_registry()
    print("Agents loaded.")
    
    # Generate 50 benign records and process them
    for _ in range(50):
        rec = _make_random_benign_record()
        _run_pipeline_on_record(rec, reg)
        
    print(f"Processed 50 benign records.")
    print(f"FPR counters state: {_fpr_counters}")
    
    kpis = dashboard_kpis(reg)
    print(f"Dashboard reported FPR: {kpis.false_positive_rate}%")
    if kpis.false_positive_rate < 5.0:
        print("SUCCESS: FPR is under 5%")
    else:
        print("FAILED: FPR is still high")

if __name__ == "__main__":
    asyncio.run(test_fpr())
