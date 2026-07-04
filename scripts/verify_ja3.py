import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scapy.all import sniff, TCP, IP, load_layer
load_layer("tls")
from scapy.layers.tls.all import TLSClientHello

def check_ja3():
    print(hasattr(TLSClientHello, "ja3_hash"))

check_ja3()
