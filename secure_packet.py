
from scapy.all import IP, TCP

from aes_gcm import encrypt_payload, decrypt_payload
from packet_handler import extract_packet_parts, rebuild_packet


def encrypt_tcp_packet(packet_bytes, key, nonce):
    ip_header, tcp_header, payload = extract_packet_parts(packet_bytes)

    if not payload:
        return packet_bytes

    ciphertext, tag = encrypt_payload(
        key, nonce, payload
    )

    return rebuild_packet(
        ip_header, tcp_header, ciphertext + tag
    )


def decrypt_tcp_packet(packet_bytes, key, nonce):
    ip_header, tcp_header, encrypted_payload = extract_packet_parts(
        packet_bytes
    )

    if not encrypted_payload:
        return packet_bytes

    if len(encrypted_payload) < 16:
        raise ValueError("Invalid encrypted payload")

    ciphertext = encrypted_payload[:-16]
    tag = encrypted_payload[-16:]

    plaintext = decrypt_payload(
        key, nonce, ciphertext, tag
    )

    return rebuild_packet(
        ip_header, tcp_header, plaintext
    )
