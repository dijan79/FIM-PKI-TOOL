"""
pki_manager.py
--------------
Handles the PKI (Public Key Infrastructure) side of the tool:

    * generates an RSA key pair + self-signed X.509 certificate per user
    * stores the private key encrypted on disk
    * tracks certificate revocation in a simple JSON revocation list

Author: Dijan Ghale
"""

import os
import json
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509 import NameOID, CertificateBuilder, random_serial_number
from cryptography.x509 import Name, BasicConstraints

import config
class PKIManager:
    """Manage user certificates, private keys and revocation status."""

    def __init__(self):
        self.keys_dir = config.KEY_DIR
        self.certs_dir = config.CERT_DIR
        self.revoked_file = config.REVOKED_FILE

        if not os.path.exists(self.revoked_file):
            with open(self.revoked_file, "w") as f:
                json.dump([], f)

    def register_user(self, username):
        """Generate a new RSA key pair + self-signed certificate for a user."""
        username = username.strip()
        if not username:
            raise ValueError("Username cannot be empty.")

        priv_path = os.path.join(self.keys_dir, f"{username}_private.pem")
        cert_path = os.path.join(self.certs_dir, f"{username}_cert.pem")

        if os.path.exists(cert_path):
            raise FileExistsError(f"User '{username}' already has a certificate.")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # Save private key, encrypted at rest
        with open(priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(config.PRIVATE_KEY_PASSWORD),
            ))

        subject = issuer = Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])

        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=config.CERT_VALIDITY_DAYS))
            .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
        )

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return cert_path

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------
    def revoke_certificate(self, username):
        with open(self.revoked_file, "r+") as f:
            revoked = json.load(f)
            if username in revoked:
                f.seek(0)
                return False
            revoked.append(username)
            f.seek(0)
            f.truncate()
            json.dump(revoked, f, indent=2)
        return True

    def is_revoked(self, username):
        with open(self.revoked_file) as f:
            return username in json.load(f)

    def list_users(self):
        """Return a list of (username, status, expiry) tuples for all known users."""
        users = []
        revoked = set()
        if os.path.exists(self.revoked_file):
            with open(self.revoked_file) as f:
                revoked = set(json.load(f))

        if not os.path.isdir(self.certs_dir):
            return users

        for fname in sorted(os.listdir(self.certs_dir)):
            if not fname.endswith("_cert.pem"):
                continue
            username = fname[: -len("_cert.pem")]
            try:
                cert = self.get_user_cert(username)
                expiry = cert.not_valid_after.strftime("%Y-%m-%d")
            except Exception:
                expiry = "unknown"
            status = "REVOKED" if username in revoked else "ACTIVE"
            users.append((username, status, expiry))
        return users

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------
    def get_user_cert(self, username):
        cert_path = os.path.join(self.certs_dir, f"{username}_cert.pem")
        with open(cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    def get_user_private_key(self, username):
        priv_path = os.path.join(self.keys_dir, f"{username}_private.pem")
        with open(priv_path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(), password=config.PRIVATE_KEY_PASSWORD
            )

    def user_exists(self, username):
        return os.path.exists(os.path.join(self.certs_dir, f"{username}_cert.pem"))
