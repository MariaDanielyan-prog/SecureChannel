import hashlib


class NonceReuseError(Exception):
    pass


class NonceGuard:
    def __init__(self):
        self.used = {}

    def check(self, nonce, plaintext):
        digest = hashlib.sha256(plaintext).digest()

        if nonce in self.used:
            if self.used[nonce] != digest:
                raise NonceReuseError(
                    "Nonce reuse with different plaintext"
                )
            return False

        self.used[nonce] = digest
        return True
