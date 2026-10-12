"""Legacy billing client (sample source file for the code scanner)."""
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa


def make_signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def invoice_fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()
