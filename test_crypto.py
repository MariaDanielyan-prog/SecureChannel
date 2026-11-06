
import os

from crypto_utils import (
    generate_keypair,
    public_key_to_bytes,
    derive_session_key
)

device1_private, device1_public = generate_keypair()
device2_private, device2_public = generate_keypair()

salt = os.urandom(32)

device1_key = derive_session_key(
    device1_private,
    public_key_to_bytes(device2_public),
    salt
)

device2_key = derive_session_key(
    device2_private,
    public_key_to_bytes(device1_public),
    salt
)

print("Device1 key:", device1_key.hex())
print("Device2 key:", device2_key.hex())
print("Keys match:", device1_key == device2_key)

assert device1_key == device2_key
assert len(device1_key) == 32

print("SUCCESS: Diffie-Hellman key exchange works!")
