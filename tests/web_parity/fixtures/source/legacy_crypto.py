"""Legacy crypto helpers (web parity fixture: every call below is deliberate)."""
import hashlib
import ssl

from Crypto.Cipher import ARC4, DES3
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519


def make_keys():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    kex = x25519.X25519PrivateKey.generate()
    return rsa_key, ec_key, kex


def fingerprints(data: bytes) -> tuple[str, str]:
    return hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest()


def legacy_ciphers(key: bytes):
    return ARC4.new(key), DES3.new(key, DES3.MODE_CBC)


def legacy_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    ctx.set_ecdh_curve("prime256v1")
    return ctx


def pq_kem():
    import oqs  # liboqs: ML-KEM-768 key encapsulation
    return oqs.KeyEncapsulation("ML-KEM-768")
