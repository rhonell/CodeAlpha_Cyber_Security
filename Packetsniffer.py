from scapy.all import *
from scapy.layers.http import HTTPRequest
import argparse

def sniff_packets(interface, filter_protocol=None):
    """
    Sniffs network traffic on a given interface.
    Optional: Filter by protocol (e.g., 'tcp', 'http').
    """
    print(f"[+] Sniffing on {interface}... (Ctrl+C to stop)")
    try:
        sniff(
            iface=interface,
            prn=lambda pkt: process_packet(pkt, filter_protocol),
            store=False
        )
    except KeyboardInterrupt:
        print("\n[!] Sniffer stopped.")

def process_packet(packet, filter_protocol):
    """Processes each captured packet."""
    if filter_protocol and filter_protocol not in packet:
        return  # Skip if protocol filter is active

    # Basic packet info
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(f"\n[IP] {src_ip} → {dst_ip} | Proto: {proto}")

    # TCP/UDP details
    if packet.haslayer(TCP):
        print(f"[TCP] Port: {packet[TCP].sport} → {packet[TCP].dport}")
        if packet.haslayer(Raw):
            print(f"[Payload]\n{hexdump(packet[Raw].load)}")

    # HTTP traffic
    if packet.haslayer(HTTPRequest):
        host = packet[HTTPRequest].Host.decode()
        path = packet[HTTPRequest].Path.decode()
        print(f"[HTTP] {host}{path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Network interface (e.g., eth0, wlan0)", required=True)
    parser.add_argument("-f", "--filter", help="Filter by protocol (e.g., tcp, http)")
    args = parser.parse_args()

    sniff_packets(args.interface, args.filter)
