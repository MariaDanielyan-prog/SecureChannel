
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_payload(key, nonce, plaintext, aad=b""):
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, plaintext, aad)

    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]

    return ciphertext, tag


def decrypt_payload(key, nonce, ciphertext, tag, aad=b""):
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext + tag,
        aad
    )

    return plaintext
