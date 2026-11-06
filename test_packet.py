
from scapy.all import IP, TCP, Raw

from packet_handler import (
    extract_packet_parts,
    rebuild_packet
)

original = (
    IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=12345, dport=8080, flags="PA", seq=100)
    / Raw(load=b"Hello from PC1!")
)

original_bytes = bytes(original)

ip_header, tcp_header, payload = extract_packet_parts(
    original_bytes
)

print("IP source:", ip_header.src)
print("IP destination:", ip_header.dst)
print("TCP source port:", tcp_header.sport)
print("TCP destination port:", tcp_header.dport)
print("Original payload:", payload)

rebuilt_bytes = rebuild_packet(
    ip_header,
    tcp_header,
    payload
)

rebuilt = IP(rebuilt_bytes)

assert bytes(rebuilt[TCP].payload) == payload
assert rebuilt[IP].src == original[IP].src
assert rebuilt[IP].dst == original[IP].dst
assert rebuilt[TCP].sport == original[TCP].sport
assert rebuilt[TCP].dport == original[TCP].dport

print("SUCCESS: TCP packet rebuilt correctly!")
