
from scapy.all import IP, TCP, Raw


def extract_packet_parts(packet_bytes):
    packet = IP(packet_bytes)

    if not packet.haslayer(TCP):
        raise ValueError("Not a TCP packet")

    ip_header = packet[IP].copy()
    tcp_header = packet[TCP].copy()

    payload = bytes(packet[TCP].payload)

    ip_header.remove_payload()
    tcp_header.remove_payload()

    return ip_header, tcp_header, payload


def rebuild_packet(ip_header, tcp_header, payload):
    packet = ip_header.copy() / tcp_header.copy() / Raw(load=payload)

    if hasattr(packet[IP], "len"):
        del packet[IP].len

    if hasattr(packet[IP], "chksum"):
        del packet[IP].chksum

    if hasattr(packet[TCP], "chksum"):
        del packet[TCP].chksum

    return bytes(packet)
