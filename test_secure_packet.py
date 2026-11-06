
import os

from scapy.all import IP, TCP, Raw

from secure_packet import encrypt_tcp_packet, decrypt_tcp_packet

key = os.urandom(32)
nonce = os.urandom(12)

original = (
    IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=12345, dport=8080, flags="PA", seq=100)
    / Raw(load=b"Hello from PC1 to PC2!")
)

original_bytes = bytes(original)

encrypted_bytes = encrypt_tcp_packet(
    original_bytes, key, nonce
)

encrypted = IP(encrypted_bytes)

print("Original payload:", bytes(IP(original_bytes)[TCP].payload))
print("Encrypted payload:", bytes(encrypted[TCP].payload).hex())
print("IP source preserved:", encrypted.src == original.src)
print("TCP source port preserved:", encrypted[TCP].sport == original[TCP].sport)

decrypted_bytes = decrypt_tcp_packet(
    encrypted_bytes, key, nonce
)

decrypted = IP(decrypted_bytes)

print("Decrypted payload:", bytes(decrypted[TCP].payload))

assert decrypted_bytes == original_bytes

print("SUCCESS: TCP packet encrypted and restored!")
