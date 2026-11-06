
import os

from aes_gcm import encrypt_payload, decrypt_payload

key = AESGCM_KEY = os.urandom(32)
nonce = os.urandom(12)

original_payload = b"Hello from PC1 to PC2!"

ciphertext, tag = encrypt_payload(
    key,
    nonce,
    original_payload
)

decrypted_payload = decrypt_payload(
    key,
    nonce,
    ciphertext,
    tag
)

print("Original payload:", original_payload)
print("Encrypted payload:", ciphertext.hex())
print("Authentication tag:", tag.hex())
print("Decrypted payload:", decrypted_payload)

assert original_payload == decrypted_payload

print("SUCCESS: AES-GCM encryption and decryption work!")
