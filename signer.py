import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class Signer:
    def __init__(self, pki_manager):
        self.pki = pki_manager

    def compute_hash(self, filepath):
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            h.update(f.read())
        return h.digest()

    def sign_file(self, username, filepath):
        file_hash = self.compute_hash(filepath)
        private_key = self.pki.get_user_private_key(username)
        signature = private_key.sign(
            file_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return file_hash, signature

    def verify_signature(self, username, filepath, signature):
        if self.pki.is_revoked(username):
            print(f"ALERT: Certificate for {username} is revoked!")
            return False

        file_hash = self.compute_hash(filepath)
        cert = self.pki.get_user_cert(username)
        public_key = cert.public_key()
        try:
            public_key.verify(
                signature,
                file_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

