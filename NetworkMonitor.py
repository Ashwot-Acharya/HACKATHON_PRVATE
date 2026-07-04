import asyncio
import json
import os
import aiohttp

SENSORS = {
    "suricata": "logs/suricata_eve.json",
    "zeek": "logs/zeek/conn.log"
}

BACKEND_URL = "http://localhost:8000/pipeline/suricata_raw_ingest"

async def tail_sensor(sensor_name, filepath, session):
    print(f"[{sensor_name.upper()}] Waiting for {filepath} to exist...")
    while not os.path.exists(filepath):
        await asyncio.sleep(1)

    print(f"[{sensor_name.upper()}] Tailing {filepath}...")
    with open(filepath, "r") as logfile:
        logfile.seek(0, os.SEEK_END)
        while True:
            line = logfile.readline()
            if not line:
                await asyncio.sleep(0.1)
                continue
            
            try:
                if sensor_name == "suricata":
                    payload = json.loads(line.strip())
                    endpoint = "http://localhost:8000/pipeline/suricata" # Use /suricata for ML analysis instead of raw_ingest
                else:
                    # Zeek JSON format
                    payload = json.loads(line.strip())
                    endpoint = "http://localhost:8000/pipeline/zeek_live_ingest"

                async with session.post(endpoint, json=payload) as response:
                    if response.status != 200:
                        err = await response.text()
                        print(f"[{sensor_name.upper()}] Error {response.status}: {err}")
                    else:
                        data = await response.json()
                        corr = data.get("correlation_result", {})
                        resp = data.get("response_actions", {})
                        if corr and corr.get("priority") in ["CRITICAL", "HIGH"]:
                            print(f"  [!] {sensor_name.upper()} {corr.get('priority')} ALERT. CRS: {corr.get('crs')}")
                            if resp and resp.get("status") == "SUCCESS":
                                print(f"  [+] Response Agent executed: {resp.get('actions')}")
            except json.JSONDecodeError:
                pass
            except Exception as e:
                print(f"[{sensor_name.upper()}] Error processing payload: {e}")

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = []
        for name, path in SENSORS.items():
            # For now, Zeek is optional, it will wait for the file silently if it doesn't exist
            tasks.append(asyncio.create_task(tail_sensor(name, path, session)))
        await asyncio.gather(*tasks)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down network monitor.")

