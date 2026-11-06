from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_direction_keys(session_key):
    if len(session_key) != 32:
        raise ValueError("Session key must be 32 bytes")

    def derive(label):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"SecureChannel-v2|" + label
        ).derive(session_key)

    return {
        "pc1_to_pc2": derive(b"pc1-to-pc2"),
        "pc2_to_pc1": derive(b"pc2-to-pc1")
    }
