import hashlib
import hmac

from scapy.all import IP, TCP


def derive_packet_nonce(packet_bytes, key, direction):
    packet = IP(packet_bytes)
    tcp = packet[TCP]

    identity = (
        packet.src.encode() + b"|" +
        packet.dst.encode() + b"|" +
        tcp.sport.to_bytes(2, "big") +
        tcp.dport.to_bytes(2, "big") +
        tcp.seq.to_bytes(4, "big")
    )

    return hmac.new(
        key,
        b"SecureChannel-nonce-v2|" + direction.encode() + b"|" + identity,
        hashlib.sha256
    ).digest()[:12]
