"""Knowledge base of cryptographic algorithms and their quantum exposure.

Every algorithm QuantumShield discovers is normalised to an entry in this
catalog.  The catalog says what the algorithm does (primitive), how strong it
is against classical and quantum attackers, and what to migrate to.

References:
  * NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
  * NIST IR 8547 (transition to PQC: quantum-vulnerable algorithms are
    deprecated after 2030 and disallowed after 2035)
  * IETF draft-ietf-tls-ecdhe-mlkem (X25519MLKEM768 and friends)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class QuantumStatus(str, Enum):
    """How an algorithm fares against a cryptographically relevant quantum computer."""

    BROKEN = "quantum-broken"        # Shor's algorithm breaks it outright (RSA, ECC, DH)
    WEAKENED = "quantum-weakened"    # Grover halves effective strength (AES-128, SHA-256 preimage)
    RESISTANT = "quantum-resistant"  # PQC or large symmetric (ML-KEM, ML-DSA, AES-256)
    HYBRID = "hybrid"                # classical + PQC combined; safe while either holds
    INSECURE = "insecure"            # already broken classically (MD5, RC4, 3DES, SHA-1 sigs)


class Primitive(str, Enum):
    KEM = "kem"
    KEY_AGREE = "key-agree"
    SIGNATURE = "signature"
    PKE = "pke"
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    AE = "ae"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    OTHER = "other"


@dataclass(frozen=True)
class Algorithm:
    name: str
    primitive: Primitive
    status: QuantumStatus
    classical_bits: int            # approximate classical security level in bits
    quantum_bits: int              # approximate security vs. a quantum attacker
    nist_level: int = 0            # CycloneDX nistQuantumSecurityLevel (0 = none)
    oid: str | None = None
    replacement: str = ""
    aliases: tuple[str, ...] = field(default_factory=tuple)

    @property
    def quantum_safe(self) -> bool:
        return self.status in (QuantumStatus.RESISTANT, QuantumStatus.HYBRID)


def _a(*args, **kw) -> Algorithm:
    return Algorithm(*args, **kw)


KEX_REPLACEMENT = "X25519MLKEM768 (hybrid ML-KEM-768, FIPS 203)"
SIG_REPLACEMENT = "ML-DSA-65 (FIPS 204), or a hybrid/composite certificate during transition"

_ALGORITHMS: list[Algorithm] = [
    # --- Key establishment: post-quantum and hybrid (TLS 1.3 named groups) ---
    _a("X25519MLKEM768", Primitive.KEM, QuantumStatus.HYBRID, 128, 192, 3,
       aliases=("x25519_mlkem768", "mlkem768x25519", "mlkem768x25519-sha256")),
    _a("SecP256r1MLKEM768", Primitive.KEM, QuantumStatus.HYBRID, 128, 192, 3,
       aliases=("secp256r1mlkem768", "p256_mlkem768")),
    _a("SecP384r1MLKEM1024", Primitive.KEM, QuantumStatus.HYBRID, 192, 256, 5,
       aliases=("secp384r1mlkem1024", "p384_mlkem1024")),
    _a("X25519Kyber768Draft00", Primitive.KEM, QuantumStatus.HYBRID, 128, 192, 3,
       replacement="X25519MLKEM768 (the pre-standard Kyber draft is obsolete)",
       aliases=("x25519kyber768draft00", "x25519kyber768")),
    _a("sntrup761x25519-sha512", Primitive.KEM, QuantumStatus.HYBRID, 128, 128, 1,
       aliases=("sntrup761x25519-sha512@openssh.com",)),
    _a("ML-KEM-512", Primitive.KEM, QuantumStatus.RESISTANT, 128, 128, 1,
       oid="2.16.840.1.101.3.4.4.1", aliases=("mlkem512",)),
    _a("ML-KEM-768", Primitive.KEM, QuantumStatus.RESISTANT, 192, 192, 3,
       oid="2.16.840.1.101.3.4.4.2", aliases=("mlkem768",)),
    _a("ML-KEM-1024", Primitive.KEM, QuantumStatus.RESISTANT, 256, 256, 5,
       oid="2.16.840.1.101.3.4.4.3", aliases=("mlkem1024",)),

    # --- Key establishment: classical (harvest-now-decrypt-later exposure) ---
    _a("X25519", Primitive.KEY_AGREE, QuantumStatus.BROKEN, 128, 0, oid="1.3.101.110",
       replacement=KEX_REPLACEMENT, aliases=("curve25519", "curve25519-sha256",
                                              "curve25519-sha256@libssh.org")),
    _a("X448", Primitive.KEY_AGREE, QuantumStatus.BROKEN, 224, 0, oid="1.3.101.111",
       replacement=KEX_REPLACEMENT),
    _a("ECDH-P256", Primitive.KEY_AGREE, QuantumStatus.BROKEN, 128, 0,
       replacement=KEX_REPLACEMENT,
       aliases=("secp256r1", "prime256v1", "p-256", "ecdh-sha2-nistp256")),
    _a("ECDH-P384", Primitive.KEY_AGREE, QuantumStatus.BROKEN, 192, 0,
       replacement="SecP384r1MLKEM1024 or X25519MLKEM768",
       aliases=("secp384r1", "p-384", "ecdh-sha2-nistp384")),
    _a("ECDH-P521", Primitive.KEY_AGREE, QuantumStatus.BROKEN, 256, 0,
       replacement="SecP384r1MLKEM1024", aliases=("secp521r1", "p-521", "ecdh-sha2-nistp521")),
    _a("FFDHE", Primitive.KEY_AGREE, QuantumStatus.BROKEN, 112, 0, replacement=KEX_REPLACEMENT,
       aliases=("ffdhe2048", "ffdhe3072", "ffdhe4096", "dhe", "diffie-hellman-group14-sha256",
                "diffie-hellman-group16-sha512", "diffie-hellman-group-exchange-sha256")),
    _a("DH-1024", Primitive.KEY_AGREE, QuantumStatus.INSECURE, 80, 0, replacement=KEX_REPLACEMENT,
       aliases=("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1")),
    _a("RSA-KEX", Primitive.PKE, QuantumStatus.BROKEN, 112, 0,
       replacement=KEX_REPLACEMENT + " over TLS 1.3 (also restores forward secrecy)",
       aliases=("rsa key exchange", "kRSA")),

    # --- Signatures: post-quantum ---
    _a("ML-DSA-44", Primitive.SIGNATURE, QuantumStatus.RESISTANT, 128, 128, 2,
       oid="2.16.840.1.101.3.4.3.17", aliases=("mldsa44",)),
    _a("ML-DSA-65", Primitive.SIGNATURE, QuantumStatus.RESISTANT, 192, 192, 3,
       oid="2.16.840.1.101.3.4.3.18", aliases=("mldsa65",)),
    _a("ML-DSA-87", Primitive.SIGNATURE, QuantumStatus.RESISTANT, 256, 256, 5,
       oid="2.16.840.1.101.3.4.3.19", aliases=("mldsa87",)),
    _a("SLH-DSA-SHA2-128s", Primitive.SIGNATURE, QuantumStatus.RESISTANT, 128, 128, 1,
       oid="2.16.840.1.101.3.4.3.20", aliases=("slh-dsa-sha2-128s", "slhdsa")),

    # --- Signatures: classical ---
    _a("RSA", Primitive.SIGNATURE, QuantumStatus.BROKEN, 112, 0, oid="1.2.840.113549.1.1.1",
       replacement=SIG_REPLACEMENT,
       aliases=("rsaencryption", "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa", "rsassa-pss",
                "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "rsa-pss")),
    _a("ECDSA", Primitive.SIGNATURE, QuantumStatus.BROKEN, 128, 0, oid="1.2.840.10045.2.1",
       replacement=SIG_REPLACEMENT,
       aliases=("ec", "id-ecpublickey", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                "ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384")),
    _a("Ed25519", Primitive.SIGNATURE, QuantumStatus.BROKEN, 128, 0, oid="1.3.101.112",
       replacement=SIG_REPLACEMENT, aliases=("ssh-ed25519", "ed25519")),
    _a("Ed448", Primitive.SIGNATURE, QuantumStatus.BROKEN, 224, 0, oid="1.3.101.113",
       replacement=SIG_REPLACEMENT),
    _a("DSA", Primitive.SIGNATURE, QuantumStatus.INSECURE, 80, 0, oid="1.2.840.10040.4.1",
       replacement=SIG_REPLACEMENT, aliases=("ssh-dss",)),

    # --- Symmetric ciphers ---
    _a("AES-256-GCM", Primitive.AE, QuantumStatus.RESISTANT, 256, 128, 5,
       aliases=("aes256-gcm", "aes256-gcm@openssh.com", "tls_aes_256_gcm_sha384")),
    _a("AES-128-GCM", Primitive.AE, QuantumStatus.WEAKENED, 128, 64, 1,
       replacement="AES-256-GCM", aliases=("aes128-gcm", "aes128-gcm@openssh.com",
                                           "tls_aes_128_gcm_sha256")),
    _a("ChaCha20-Poly1305", Primitive.AE, QuantumStatus.RESISTANT, 256, 128, 5,
       aliases=("chacha20", "chacha20-poly1305@openssh.com", "tls_chacha20_poly1305_sha256")),
    _a("AES-256-CBC", Primitive.BLOCK_CIPHER, QuantumStatus.RESISTANT, 256, 128, 5,
       replacement="AES-256-GCM (AEAD)", aliases=("aes256-cbc", "aes256", "aes256-ctr")),
    _a("AES-128-CBC", Primitive.BLOCK_CIPHER, QuantumStatus.WEAKENED, 128, 64, 1,
       replacement="AES-256-GCM", aliases=("aes128-cbc", "aes128", "aes128-ctr")),
    _a("3DES", Primitive.BLOCK_CIPHER, QuantumStatus.INSECURE, 112, 56,
       replacement="AES-256-GCM", aliases=("des-cbc3", "des-ede3", "3des-cbc", "tripledes")),
    _a("DES", Primitive.BLOCK_CIPHER, QuantumStatus.INSECURE, 56, 28, replacement="AES-256-GCM"),
    _a("RC4", Primitive.STREAM_CIPHER, QuantumStatus.INSECURE, 0, 0,
       replacement="AES-256-GCM or ChaCha20-Poly1305", aliases=("arcfour",)),

    # --- Hashes / MACs ---
    _a("SHA-512", Primitive.HASH, QuantumStatus.RESISTANT, 256, 256, 5, aliases=("sha512",)),
    _a("SHA-384", Primitive.HASH, QuantumStatus.RESISTANT, 192, 192, 4, aliases=("sha384",)),
    _a("SHA-256", Primitive.HASH, QuantumStatus.RESISTANT, 128, 128, 2,
       aliases=("sha256", "hmac-sha2-256", "hmac-sha2-256-etm@openssh.com")),
    _a("SHA-1", Primitive.HASH, QuantumStatus.INSECURE, 63, 0, replacement="SHA-256 or SHA-384",
       aliases=("sha1", "hmac-sha1")),
    _a("MD5", Primitive.HASH, QuantumStatus.INSECURE, 18, 0, replacement="SHA-256 or SHA-384",
       aliases=("hmac-md5",)),
]

_INDEX: dict[str, Algorithm] = {}
for _alg in _ALGORITHMS:
    for _key in (_alg.name, *_alg.aliases, *([_alg.oid] if _alg.oid else [])):
        _INDEX[_key.lower()] = _alg


def lookup(name: str | None) -> Algorithm | None:
    """Find an algorithm by canonical name, alias or OID (case-insensitive)."""
    if not name:
        return None
    return _INDEX.get(name.strip().lower())


def all_algorithms() -> list[Algorithm]:
    return list(_ALGORITHMS)


# TLS 1.3 named groups QuantumShield probes, in preference order.
PQC_GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"]
PURE_PQC_GROUPS = ["MLKEM768", "MLKEM1024"]
CLASSICAL_GROUPS = ["X25519", "secp256r1", "secp384r1", "x448", "ffdhe2048"]


def classify_group(group: str | None) -> Algorithm | None:
    if not group:
        return None
    g = group.strip()
    alg = lookup(g)
    if alg:
        return alg
    if g.lower().startswith("mlkem"):
        return lookup("ML-KEM-" + g[5:])
    return None


@dataclass(frozen=True)
class CipherSuiteInfo:
    name: str
    kex: str          # "ECDHE", "DHE", "RSA", "TLS13" (negotiated separately)
    auth: str
    cipher: Algorithm | None
    mac: str
    forward_secrecy: bool


_CIPHER_PATTERNS = [
    (r"AES[_-]?256[_-]GCM", "AES-256-GCM"),
    (r"AES[_-]?128[_-]GCM", "AES-128-GCM"),
    (r"CHACHA20", "ChaCha20-Poly1305"),
    (r"AES[_-]?256", "AES-256-CBC"),
    (r"AES[_-]?128", "AES-128-CBC"),
    (r"(3DES|DES[_-]CBC3|DES-EDE3)", "3DES"),
    (r"RC4", "RC4"),
    (r"(^|[_-])DES([_-]|$)", "DES"),
]


def parse_cipher_suite(name: str) -> CipherSuiteInfo:
    """Decompose an OpenSSL or IANA cipher-suite name into its components."""
    n = name.upper()
    cipher = None
    for pat, alg in _CIPHER_PATTERNS:
        if re.search(pat, n):
            cipher = lookup(alg)
            break
    if n.startswith("TLS_") and "_WITH_" not in n:
        # TLS 1.3 suites only name the AEAD; key exchange is a separate group.
        return CipherSuiteInfo(name, "TLS13", "TLS13", cipher, "AEAD", True)
    if "ECDHE" in n:
        kex = "ECDHE"
    elif "DHE" in n or "EDH" in n:
        kex = "DHE"
    elif n.startswith(("PSK", "TLS_PSK")):
        kex = "PSK"
    else:
        kex = "RSA"
    if "ECDSA" in n:
        auth = "ECDSA"
    elif "PSK" in n:
        auth = "PSK"
    else:
        auth = "RSA"
    if "GCM" in n or "CHACHA" in n or "CCM" in n:
        mac = "AEAD"
    elif n.endswith("SHA384"):
        mac = "SHA-384"
    elif n.endswith("SHA256"):
        mac = "SHA-256"
    elif n.endswith("MD5"):
        mac = "MD5"
    else:
        mac = "SHA-1"
    return CipherSuiteInfo(name, kex, auth, cipher, mac, kex in ("ECDHE", "DHE"))


SIG_OIDS = {
    "1.2.840.113549.1.1.5": ("RSA", "SHA-1"),
    "1.2.840.113549.1.1.4": ("RSA", "MD5"),
    "1.2.840.113549.1.1.11": ("RSA", "SHA-256"),
    "1.2.840.113549.1.1.12": ("RSA", "SHA-384"),
    "1.2.840.113549.1.1.13": ("RSA", "SHA-512"),
    "1.2.840.113549.1.1.10": ("RSA", "SHA-256"),   # RSASSA-PSS (hash in params)
    "1.2.840.10045.4.1": ("ECDSA", "SHA-1"),
    "1.2.840.10045.4.3.2": ("ECDSA", "SHA-256"),
    "1.2.840.10045.4.3.3": ("ECDSA", "SHA-384"),
    "1.2.840.10045.4.3.4": ("ECDSA", "SHA-512"),
    "1.3.101.112": ("Ed25519", None),
    "1.3.101.113": ("Ed448", None),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", None),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", None),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", None),
}
