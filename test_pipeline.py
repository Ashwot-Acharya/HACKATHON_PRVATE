import requests

payload = {
    "timestamp": "2026-07-04T12:00:00.000000+0000",
    "event_type": "alert",
    "src_ip": "1.2.3.4",
    "dest_ip": "5.6.7.8",
    "src_port": 1234,
    "dest_port": 80,
    "proto": "TCP",
    "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 2000000,
        "rev": 1,
        "signature": "ET SCAN Suspicious inbound to mySQL port 3306",
        "category": "Attempted Information Leak",
        "severity": 2
    }
}
resp = requests.post("http://localhost:8000/pipeline/suricata", json=payload)
print(resp.json())
