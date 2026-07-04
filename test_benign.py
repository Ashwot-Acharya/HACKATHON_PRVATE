import asyncio
from api.routes.pipeline import ingest_suricata
from api.schemas import SuricataEveRequest
from api.dependencies import init_registry, get_registry
import time

async def main():
    print("Initializing registry...")
    init_registry()
    reg = get_registry()
    req = SuricataEveRequest(
        timestamp="2026-07-03T12:00:00Z",
        event_type="flow",
        src_ip="10.0.0.1",
        dest_ip="10.0.0.2",
        proto="TCP",
        label="BENIGN"
    )
    try:
        await ingest_suricata(req, reg)
        print("Success")
    except Exception as e:
        import traceback
        traceback.print_exc()

asyncio.run(main())
