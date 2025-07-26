
# eternal_pulse/crypto.py
import os
import pathlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def load_rsa_private_key(path: str):
    path = os.path.abspath(path)
    pem = pathlib.Path(path).read_bytes()
    return serialization.load_pem_private_key(pem, password=None)

def load_rsa_public_key(path: str):
    path = os.path.abspath(path)
    pem = pathlib.Path(path).read_bytes()
    return serialization.load_pem_public_key(pem)

def sign_install_request(private_key, target: str, timestamp: str):
    payload = {"target": target, "timestamp": timestamp}
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(
        payload_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return payload_bytes, signature
