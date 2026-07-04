"""
BankSentinel Live Network Sensor
=================================
Captures real network traffic using cicflowmeter + scapy,
extracts True JA3 fingerprints, and forwards flow records
to the BankSentinel backend pipeline.

Works on both Linux and Windows (requires Npcap on Windows).

Usage:
  Linux:   sudo python3 sensor.py
  Windows: python sensor.py  (run as Administrator)
"""


import os
import sys
import csv
import time
import json
import platform
import queue
import logging
import threading
import subprocess
import requests
from scapy.all import sniff, TCP, IP, conf
import hashlib

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

API_URL = os.getenv("API_URL", "http://localhost:8000/pipeline/run")
BPF_FILTER = os.getenv("BPF_FILTER", "tcp or udp")

# Cache to store JA3 hashes by 4-tuple (src_ip, dst_ip, src_port, dst_port)
ja3_cache = {}
ja3_lock = threading.Lock()

# Standard CICIDS-2017 feature mapping (to match FlowRecordRequest)
FEATURE_MAPPING = {
    "flow duration": "Flow Duration",
    "total fwd packets": "Total Fwd Packets",
    "total backward packets": "Total Backward Packets",
    "total length of fwd packets": "Total Length of Fwd Packets",
    "total length of bwd packets": "Total Length of Bwd Packets",
    "flow bytes/s": "Flow Bytes/s",
    "flow packets/s": "Flow Packets/s",
    "flow iat mean": "Flow IAT Mean",
    "flow iat std": "Flow IAT Std",
    "fwd iat total": "Fwd IAT Total",
    "fwd iat mean": "Fwd IAT Mean",
    "fwd iat std": "Fwd IAT Std",
    "bwd iat mean": "Bwd IAT Mean",
    "bwd iat std": "Bwd IAT Std",
    "destination port": "Destination Port",
}


# ── Interface Selection (cross-platform) ──────────────────────────────────────

def select_interface():
    """
    Auto-detect or prompt the user to select a network interface.
    On Linux, uses the INTERFACE env var or defaults to the first available.
    On Windows, lists Npcap interfaces with friendly names and lets the
    user pick by number.
    """
    env_iface = os.getenv("INTERFACE")
    if env_iface:
        logging.info(f"Using interface from INTERFACE env var: {env_iface}")
        return env_iface

    is_windows = platform.system() == "Windows"

    if is_windows:
        try:
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list()
            if not ifaces:
                logging.error("No network interfaces found. Is Npcap installed?")
                sys.exit(1)

            print("\n╔══════════════════════════════════════════════╗")
            print("║  BankSentinel — Select Network Interface     ║")
            print("╠══════════════════════════════════════════════╣")
            for i, iface in enumerate(ifaces):
                name = iface.get("name", "Unknown")
                desc = iface.get("description", "")
                ips = ", ".join(iface.get("ips", []))
                print(f"║  [{i}] {name[:30]:<30}  ║")
                if desc:
                    print(f"║      {desc[:40]:<40}  ║")
                if ips:
                    print(f"║      IPs: {ips[:36]:<36}  ║")
            print("╚══════════════════════════════════════════════╝")

            while True:
                try:
                    choice = int(input("\nEnter interface number: "))
                    if 0 <= choice < len(ifaces):
                        selected = ifaces[choice]["name"]
                        logging.info(f"Selected interface: {selected}")
                        return selected
                    print(f"Please enter a number between 0 and {len(ifaces)-1}")
                except ValueError:
                    print("Please enter a valid number")

        except ImportError:
            logging.warning("Could not import Windows interface list. "
                            "Using Scapy default interface.")
            return str(conf.iface)
    else:
        # Linux: use first reasonable default
        defaults = ["wlp2s0", "eth0", "wlan0", "ens33", "enp0s3"]
        for d in defaults:
            if os.path.exists(f"/sys/class/net/{d}"):
                logging.info(f"Auto-detected Linux interface: {d}")
                return d
        # Fallback to scapy default
        iface = str(conf.iface)
        logging.info(f"Using Scapy default interface: {iface}")
        return iface


# ── True JA3 Extraction ───────────────────────────────────────────────────────

def extract_ja3(packet):
    """
    Scapy callback to parse TLS Client Hello and extract a True JA3 hash.
    JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    GREASE values are stripped as per the JA3 specification.
    """
    try:
        from scapy.layers.tls.all import TLSClientHello
        if packet.haslayer(TCP) and packet.haslayer(IP) and packet.haslayer(TLSClientHello):
            ch = packet[TLSClientHello]

            GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
                      0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
                      0xcaca, 0xdada, 0xeaea, 0xfafa}

            version = ch.version

            ciphers = getattr(ch, "ciphers", [])
            ciphers = [str(c) for c in ciphers if c not in GREASE]

            exts = getattr(ch, "ext", []) or []
            ext_types = [str(e.type) for e in exts
                         if getattr(e, "type", None) not in GREASE
                         and getattr(e, "type", None) is not None]

            curves = []
            points = []
            for e in exts:
                if getattr(e, "type", None) == 10:  # Supported Groups
                    groups = getattr(e, "groups", [])
                    curves = [str(g) for g in groups if g not in GREASE]
                elif getattr(e, "type", None) == 11:  # EC Point Formats
                    formats = getattr(e, "ecpl", [])
                    points = [str(f) for f in formats]

            ja3_str = (
                f"{version},"
                f"{'-'.join(ciphers)},"
                f"{'-'.join(ext_types)},"
                f"{'-'.join(curves)},"
                f"{'-'.join(points)}"
            )
            true_ja3 = hashlib.md5(ja3_str.encode()).hexdigest()

            src = packet[IP].src
            dst = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            logging.info(f"[JA3] {src}:{sport} -> {dst}:{dport} = {true_ja3}")

            with ja3_lock:
                ja3_cache[(src, dst, sport, dport)] = true_ja3
    except Exception:
        pass


def run_scapy_sniffer(interface):
    """Runs a background sniffer just for TLS JA3 extraction"""
    logging.info(f"Starting Scapy TLS JA3 sniffer on {interface}...")
    from scapy.all import load_layer
    load_layer("tls")
    sniff(iface=interface, filter="tcp port 443", prn=extract_ja3, store=0)


# ── Flow CSV Tailing & Forwarding ─────────────────────────────────────────────

def tail_csv_and_forward(csv_path):
    """Tails the cicflowmeter CSV output, merges with JA3, and forwards to API."""
    logging.info(f"Waiting for {csv_path} to be created by cicflowmeter...")
    while not os.path.exists(csv_path):
        time.sleep(1)

    logging.info(f"Found {csv_path}. Tailing flows...")

    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)

        while True:
            try:
                row = next(reader)

                if row:
                    # Parse basic flow info
                    src_ip = row.get("src_ip", "0.0.0.0")
                    dst_ip = row.get("dst_ip", "0.0.0.0")
                    src_port = int(row.get("src_port", 0))
                    dst_port = int(row.get("dst_port", 0))
                    protocol = int(row.get("protocol", 6))

                    # Map cicflowmeter features to BankSentinel features
                    features = {}
                    for cic_key, val in row.items():
                        cic_key_lower = cic_key.strip().lower()
                        if cic_key_lower in FEATURE_MAPPING:
                            bs_key = FEATURE_MAPPING[cic_key_lower]
                            try:
                                features[bs_key] = float(val)
                            except ValueError:
                                features[bs_key] = 0.0

                    # Try to attach JA3 if we caught the ClientHello
                    ja3_hash = None
                    with ja3_lock:
                        if (src_ip, dst_ip, src_port, dst_port) in ja3_cache:
                            ja3_hash = ja3_cache.pop((src_ip, dst_ip, src_port, dst_port))

                    # Construct Request
                    payload = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "features": features,
                        "label": "LIVE",  # Assume benign until proven anomaly
                        "regime": "normal",
                        "ja3_hash": ja3_hash
                    }

                    # Forward to BankSentinel
                    try:
                        resp = requests.post(API_URL, json=payload, timeout=2.0)
                        if resp.status_code == 200:
                            logging.info(
                                f"-> Forwarded flow {src_ip}:{src_port} -> "
                                f"{dst_ip}:{dst_port} (JA3: {bool(ja3_hash)})"
                            )
                        else:
                            logging.warning(f"API Error {resp.status_code}: {resp.text}")
                    except Exception as e:
                        logging.error(f"Failed to forward flow: {e}")

            except StopIteration:
                # EOF reached, wait for more data
                time.sleep(1)


# ── Dummy Listeners ───────────────────────────────────────────────────────────
def _handle_dummy(conn):
    try:
        conn.recv(2048)
    except:
        pass
    finally:
        try:
            conn.close()
        except:
            pass

def dummy_listener(port, is_udp=False):
    try:
        if is_udp:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(('0.0.0.0', port))
            while True:
                s.recvfrom(2048)
        else:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen(5)
            while True:
                conn, addr = s.accept()
                threading.Thread(target=_handle_dummy, args=(conn,), daemon=True).start()
    except Exception:
        pass

def start_dummy_listeners():
    ports = [80, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 9200]
    for p in ports:
        threading.Thread(target=dummy_listener, args=(p,), daemon=True).start()
    threading.Thread(target=dummy_listener, args=(8583, True), daemon=True).start()

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(r"""
    ╔══════════════════════════════════════════════════════╗
    ║   ____              _    ____             _   _      ║
    ║  | __ )  __ _ _ __ | | _/ ___|  ___ _ __ | |_(_)     ║
    ║  |  _ \ / _` | '_ \| |/ \___ \ / _ \ '_ \| __| |     ║
    ║  | |_) | (_| | | | |   < ___) |  __/ | | | |_| |     ║
    ║  |____/ \__,_|_| |_|_|\_\____/ \___|_| |_|\__|_|     ║
    ║                                                      ║
    ║          Live Network Sensor v2.0                     ║
    ║          True JA3 + CICFlowMeter                     ║
    ╚══════════════════════════════════════════════════════╝
    """)

    # Select interface (cross-platform)
    interface = select_interface()
    logging.info(f"Using interface: {interface}")
    logging.info(f"API endpoint: {API_URL}")

    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flows.csv")
    if not os.path.exists(csv_path):
        open(csv_path, "w").close()

    #0. start dummy listeners so connection complete
    start_dummy_listeners()
    logging.info("started dummy listeners on target ports.")

    # 1. Start JA3 Sniffer
    scapy_thread = threading.Thread(target=run_scapy_sniffer, args=(interface,), daemon=True)
    scapy_thread.start()

    # 2. Start Tailing Thread
    tail_thread = threading.Thread(target=tail_csv_and_forward, args=(csv_path,), daemon=True)
    tail_thread.start()

    # 3. Start cicflowmeter
    logging.info(f"Starting cicflowmeter on {interface}...")
    cmd = ["cicflowmeter", "-i", interface, "-c", csv_path]

    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        logging.error(
            "cicflowmeter not found! Install it with: pip install cicflowmeter\n"
            "On Windows, also ensure Npcap is installed: https://npcap.com/"
        )
    except KeyboardInterrupt:
        logging.info("Shutting down sensor...")


if __name__ == "__main__":
    main()
