
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def generate_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def public_key_to_bytes(public_key):
    return public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )


def derive_session_key(private_key, peer_public_bytes, salt):
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(
        peer_public_bytes
    )

    shared_secret = private_key.exchange(peer_public_key)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"SecureChannel-v1"
    ).derive(shared_secret)
