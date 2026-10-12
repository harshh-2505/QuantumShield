"""Certificate parsing and a small PKI for workload identities.

Parsing uses the `cryptography` package.  Key and certificate *generation* is
delegated to the `openssl` command-line tool, so post-quantum keys (ML-DSA)
come from OpenSSL 3.5's FIPS 204 implementation rather than anything written
here.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

from .catalog import SIG_OIDS, lookup
from .models import CertInfo

PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----", re.DOTALL)


def _name(n: x509.Name) -> str:
    return n.rfc4514_string()


def _key_info(cert: x509.Certificate) -> tuple[str, int | None, str | None]:
    try:
        key = cert.public_key()
    except Exception:  # noqa: BLE001 - unsupported (e.g. PQC) key types
        key = None
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ECDSA", key.curve.key_size, key.curve.name
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456, "Ed448"
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size, f"DSA-{key.key_size}"
    oid = None
    try:
        oid = cert.public_key_algorithm_oid.dotted_string
    except Exception:  # noqa: BLE001
        pass
    alg = lookup(oid) if oid else None
    if alg:
        return alg.name, None, alg.name
    name = type(key).__name__ if key is not None else "unknown"
    if "MLDSA" in name.upper():
        return "ML-DSA", None, name
    return oid or name, None, None


def _sig_info(cert: x509.Certificate) -> tuple[str, str | None]:
    oid = cert.signature_algorithm_oid.dotted_string
    if oid in SIG_OIDS:
        return SIG_OIDS[oid]
    alg = lookup(oid)
    if alg:
        return alg.name, None
    return cert.signature_algorithm_oid._name or oid, None  # noqa: SLF001


def cert_info(cert: x509.Certificate) -> CertInfo:
    from cryptography.hazmat.primitives.serialization import Encoding

    der = cert.public_bytes(Encoding.DER)
    alg, size, detail = _key_info(cert)
    sig_alg, sig_hash = _sig_info(cert)
    sans: list[str] = []
    is_ca = False
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = [f"DNS:{v}" for v in ext.get_values_for_type(x509.DNSName)]
        sans += [f"URI:{v}" for v in ext.get_values_for_type(x509.UniformResourceIdentifier)]
        sans += [f"IP:{v}" for v in ext.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    try:
        is_ca = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        pass
    return CertInfo(
        fingerprint_sha256=hashlib.sha256(der).hexdigest(),
        subject=_name(cert.subject),
        issuer=_name(cert.issuer),
        serial=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        public_key_algorithm=alg,
        public_key_size=size,
        public_key_detail=detail,
        signature_algorithm=sig_alg,
        signature_hash=sig_hash,
        subject_alt_names=sans,
        self_signed=cert.subject == cert.issuer,
        is_ca=is_ca,
    )


def parse_der(der: bytes) -> CertInfo:
    return cert_info(x509.load_der_x509_certificate(der))


def parse_pem_bundle(data: bytes) -> list[CertInfo]:
    out = []
    for m in PEM_CERT_RE.finditer(data):
        try:
            out.append(cert_info(x509.load_pem_x509_certificate(m.group(0))))
        except ValueError:
            continue
    return out


# --------------------------------------------------------------------------
# PKI: CA + workload certificates via the openssl CLI
# --------------------------------------------------------------------------

KEY_ALGS = {
    "rsa2048": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
    "rsa3072": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"],
    "ecdsa-p256": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
    "ecdsa-p384": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
    "ed25519": ["-algorithm", "ED25519"],
    "mldsa44": ["-algorithm", "ML-DSA-44"],
    "mldsa65": ["-algorithm", "ML-DSA-65"],
    "mldsa87": ["-algorithm", "ML-DSA-87"],
}


def openssl_bin() -> str:
    return os.environ.get("QS_OPENSSL", shutil.which("openssl") or "openssl")


def openssl_version() -> tuple[int, int]:
    try:
        out = subprocess.run([openssl_bin(), "version"], capture_output=True, text=True,
                             check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return (0, 0)
    m = re.search(r"OpenSSL (\d+)\.(\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def _run(args: list[str]) -> None:
    proc = subprocess.run([openssl_bin(), *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args[:2])} failed: {proc.stderr.strip()}")


def gen_key(alg: str, path: Path) -> None:
    if alg not in KEY_ALGS:
        raise ValueError(f"unknown key algorithm {alg!r}; choose from {', '.join(KEY_ALGS)}")
    if alg.startswith("mldsa") and openssl_version() < (3, 5):
        raise RuntimeError("ML-DSA keys need OpenSSL 3.5 or newer")
    _run(["genpkey", *KEY_ALGS[alg], "-out", str(path)])
    path.chmod(0o600)


def init_ca(pki_dir: Path, alg: str = "mldsa65", name: str = "QuantumShield Root CA",
            days: int = 3650) -> Path:
    pki_dir.mkdir(parents=True, exist_ok=True)
    key, crt = pki_dir / "ca.key", pki_dir / "ca.crt"
    gen_key(alg, key)
    _run(["req", "-new", "-x509", "-key", str(key), "-out", str(crt), "-days", str(days),
          "-subj", f"/O=QuantumShield/CN={name}",
          "-addext", "basicConstraints=critical,CA:TRUE",
          "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    (pki_dir / "revoked.json").write_text("[]\n")
    return crt


def issue(pki_dir: Path, name: str, alg: str = "mldsa65", dns: list[str] | None = None,
          trust_domain: str = "quantumshield.local", days: int = 30,
          out_dir: Path | None = None) -> tuple[Path, Path]:
    """Issue a short-lived workload certificate with a SPIFFE-style URI SAN.

    Short lifetimes make key rotation routine: re-run `issue` and the proxy
    picks up the new files without a restart.
    """
    out_dir = out_dir or pki_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    key, crt = out_dir / f"{name}.key", out_dir / f"{name}.crt"
    sans = [f"DNS:{d}" for d in (dns or [name, "localhost"])]
    sans.append(f"URI:spiffe://{trust_domain}/{name}")
    sans.append("IP:127.0.0.1")
    gen_key(alg, key)
    with tempfile.TemporaryDirectory() as td:
        csr = Path(td) / "req.csr"
        ext = Path(td) / "ext.cnf"
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=serverAuth,clientAuth\n"
            f"subjectAltName={','.join(sans)}\n")
        _run(["req", "-new", "-key", str(key), "-out", str(csr),
              "-subj", f"/O=QuantumShield/CN={name}"])
        _run(["x509", "-req", "-in", str(csr), "-CA", str(pki_dir / "ca.crt"),
              "-CAkey", str(pki_dir / "ca.key"), "-CAcreateserial", "-out", str(crt),
              "-days", str(days), "-extfile", str(ext)])
    return crt, key


def revoke(pki_dir: Path, cert_path: Path) -> str:
    """Add a certificate's serial to the CA's revocation list (read by the proxy)."""
    info = parse_pem_bundle(cert_path.read_bytes())[0]
    rl = pki_dir / "revoked.json"
    revoked = json.loads(rl.read_text()) if rl.exists() else []
    if info.serial not in revoked:
        revoked.append(info.serial)
    rl.write_text(json.dumps(revoked, indent=2) + "\n")
    return info.serial
