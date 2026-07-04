import asyncio
from api.routes.pipeline import ingest_zeek
from api.dependencies import init_registry, get_registry
import time

async def main():
    init_registry()
    reg = get_registry()
    req = {"id.orig_h":"10.0.0.1", "id.resp_h":"10.0.0.2", "id.orig_p":1234, "id.resp_p":80, "proto":"tcp", "orig_pkts":1, "resp_pkts":1}
    try:
        res = await ingest_zeek(req, reg)
        print(res)
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
