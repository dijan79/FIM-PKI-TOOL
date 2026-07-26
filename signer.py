"""
signer.py
---------
Provides file hashing and digital signature / verification helpers built
on top of a user's PKI key pair.

Author: Dijan Ghale
"""

import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


class Signer:
    """Compute file hashes and create/verify digital signatures."""

    def __init__(self, pki_manager):
        self.pki = pki_manager

    @staticmethod
    def compute_hash(filepath):
        """Return the SHA-256 digest of a file's contents."""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.digest()

    def sign_file(self, username, filepath):
        """Compute the hash of *filepath* and sign it with *username*'s key.

        Returns (file_hash, signature)
        """
        file_hash = self.compute_hash(filepath)
        private_key = self.pki.get_user_private_key(username)
        signature = private_key.sign(
            file_hash,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return file_hash, signature

    def verify_signature(self, username, filepath, signature):
        """Verify that *filepath* still matches the signed baseline.

        Returns True if the file is intact and the signing user's
        certificate has not been revoked, False otherwise.
        """
        if self.pki.is_revoked(username):
            return False

        file_hash = self.compute_hash(filepath)
        cert = self.pki.get_user_cert(username)
        public_key = cert.public_key()
        try:
            public_key.verify(
                signature,
                file_hash,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False
