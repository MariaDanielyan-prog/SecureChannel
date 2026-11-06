from os import urandom
from scapy.all import IP, TCP, Raw

from bidirectional_crypto import encrypt_packet, decrypt_packet

key = urandom(32)

packet = bytes(
    IP(src="10.0.1.2", dst="10.0.3.2")
    / TCP(sport=12345, dport=8080, seq=1000)
    / Raw(b"SecureChannel protected message")
)

encrypted = encrypt_packet(packet, key, "pc1_to_pc2")

tampered = bytearray(encrypted)
tampered[-17] ^= 1

try:
    decrypt_packet(bytes(tampered), key, "pc1_to_pc2")
    print("FAIL: tampered packet accepted")
except Exception as error:
    if type(error).__name__ == "InvalidTag":
        print("PASS: tampered packet rejected")
    else:
        print(f"Unexpected error: {type(error).__name__}: {error}")