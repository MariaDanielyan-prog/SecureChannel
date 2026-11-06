from os import urandom
from unittest.mock import Mock

from scapy.all import IP, TCP, Raw

import device2
from bidirectional_crypto import encrypt_packet

key = urandom(32)
device2.KEYS = {"pc1_to_pc2": key}

original = bytes(
    IP(src="10.0.1.2", dst="10.0.3.2")
    / TCP(sport=12345, dport=8080, seq=1000)
    / Raw(b"Protected TCP message")
)

encrypted = encrypt_packet(original, key, "pc1_to_pc2")

tampered = bytearray(encrypted)
tampered[-17] ^= 1

packet = Mock()
packet.get_payload.return_value = bytes(tampered)

device2.process_packet(packet)

packet.drop.assert_called_once()
packet.accept.assert_not_called()

print("PASS: Device2 dropped tampered packet")