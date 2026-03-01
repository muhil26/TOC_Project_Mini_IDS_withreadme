"""
Network-layer IDS entry point.

Sniffs raw TCP packets on the loopback interface, URL-decodes payloads,
and passes HTTP request bodies through the DFA detection pipeline.

Requires: scapy (run as root / with CAP_NET_RAW capability)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from urllib.parse import unquote

from scapy.all import Raw, sniff

import app
from detectors.dfa_alerts import detect_attack


def packet_handler(packet):
    if not packet.haslayer(Raw):
        return

    raw_payload = packet[Raw].load.decode(errors="ignore")
    payload     = unquote(raw_payload)

    # Only inspect HTTP request lines
    if not payload.startswith(("GET", "POST", "PUT", "DELETE", "PATCH")):
        return
    # Skip socket.io noise
    if "/socket.io/" in payload:
        return

    print(f"\n[DEBUG] HTTP payload ({len(payload)} bytes):\n{payload[:200]}")

    results = detect_attack(payload, verbose=False)
    alerts  = [(name, v) for name, v in results if v > 0]

    if alerts:
        for name, v in alerts:
            label = "INTRUSION" if v == 2 else "SUSPICIOUS"
            print(f"[{label}] {name}")
            app.send_alert(name, payload)
    else:
        print("[INFO] Clean packet")


def start_sniffing(iface: str = "lo"):
    print(f"[*] Sniffing on interface '{iface}' — press Ctrl+C to stop")
    sniff(iface=iface, filter="tcp port 5000", prn=packet_handler, store=False)


if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "lo"
    start_sniffing(iface)
