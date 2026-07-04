import asyncio
import websockets
import json
import requests

async def frontend_sim():
    uri = "ws://localhost:8000/ws/suricata_raw"
    async with websockets.connect(uri) as websocket:
        print("Connected to raw suricata WS!")
        while True:
            response = await websocket.recv()
            msg = json.loads(response)
            if msg.get("type") == "suricata_raw":
                print(f"Frontend received raw data: {msg['data']['event_type']}")
                # Send to backend ML
                res = requests.post("http://localhost:8000/pipeline/suricata", json=msg["data"])
                print(f"Frontend sent to ML, response status: {res.status_code}")

asyncio.run(frontend_sim())
