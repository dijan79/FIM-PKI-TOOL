from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID, CertificateBuilder, random_serial_number
from cryptography.x509 import Name, BasicConstraints
from cryptography import x509
from datetime import datetime, timedelta
import os
import json

class PKIManager:
    def __init__(self):
        self.keys_dir = "keys"
        self.certs_dir = "certs"
        self.revoked_file = "revoked.json"
        os.makedirs(self.keys_dir, exist_ok=True)
        os.makedirs(self.certs_dir, exist_ok=True)
        if not os.path.exists(self.revoked_file):
            with open(self.revoked_file, "w") as f:
                json.dump([], f)

    def register_user(self, username):
        print(f"Generating key pair and certificate for {username}...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        priv_path = os.path.join(self.keys_dir, f"{username}_private.pem")
        with open(priv_path, "wb") as f:
            encrypted_key = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"password")
            )
            f.write(encrypted_key)

        subject = issuer = Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username)
        ])

        cert = CertificateBuilder().subject_name(subject).issuer_name(issuer)
        cert = cert.public_key(public_key)
        cert = cert.serial_number(random_serial_number())
        cert = cert.not_valid_before(datetime.utcnow())
        cert = cert.not_valid_after(datetime.utcnow() + timedelta(days=365))
        cert = cert.add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        cert = cert.sign(private_key, hashes.SHA256())

        cert_path = os.path.join(self.certs_dir, f"{username}_cert.pem")
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"User {username} registered successfully.")

    def revoke_certificate(self, username):
        with open(self.revoked_file, "r+") as f:
            revoked = json.load(f)
            if username not in revoked:
                revoked.append(username)
                f.seek(0)
                json.dump(revoked, f, indent=4)
                print(f"Certificate for {username} revoked.")
            else:
                print("User already revoked.")

    def is_revoked(self, username):
        with open(self.revoked_file) as f:
            revoked = json.load(f)
            return username in revoked

    def get_user_cert(self, username):
        cert_path = os.path.join(self.certs_dir, f"{username}_cert.pem")
        with open(cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    def get_user_private_key(self, username):
        priv_path = os.path.join(self.keys_dir, f"{username}_private.pem")
        with open(priv_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=b"password")

