from secure_packet import encrypt_tcp_packet, decrypt_tcp_packet
from packet_nonce import derive_packet_nonce


def encrypt_packet(packet_bytes, key, direction):
    nonce = derive_packet_nonce(packet_bytes, key, direction)
    return encrypt_tcp_packet(packet_bytes, key, nonce)


def decrypt_packet(packet_bytes, key, direction):
    nonce = derive_packet_nonce(packet_bytes, key, direction)
    return decrypt_tcp_packet(packet_bytes, key, nonce)
