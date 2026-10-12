"""Static scanner for configuration files, key material and source code.

Supported inputs:
  nginx, Apache httpd, HAProxy, Envoy (YAML), OpenSSL config, OpenSSH
  (sshd_config / ssh_config), PEM certificates and private keys, and a
  pattern scan of Python / Go / Java / JavaScript / TypeScript source.
"""

from __future__ import annotations

import os
import re
import ssl
from pathlib import Path

from . import certs
from .catalog import classify_group, lookup, parse_cipher_suite
from .models import ConfigItem, ConfigScan, Inventory

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist", "build"}
MAX_FILE = 2 * 1024 * 1024


# ---------------------------------------------------------------- helpers

def _split_list(value: str) -> list[str]:
    return [v for v in re.split(r"[\s:,]+", value.strip().strip("\"';")) if v]


def groups_to_algs(value: str) -> list[str]:
    out = []
    for g in _split_list(value):
        g = g.lstrip("*?-")
        if g.lower() in ("auto", "default"):
            continue
        alg = classify_group(g)
        out.append(alg.name if alg else g)
    return list(dict.fromkeys(out))


def ciphers_to_algs(value: str) -> list[str]:
    """Expand an OpenSSL cipher string with the local library, then decompose suites."""
    names: list[str] = []
    v = value.strip().strip("\"';")
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers(v + ":@SECLEVEL=0")
        names = [c["name"] for c in ctx.get_ciphers() if c.get("protocol") != "TLSv1.3"]
    except ssl.SSLError:
        names = [c for c in _split_list(v) if not c.startswith(("!", "-", "+", "@"))]
    return list(dict.fromkeys(names))


def cipher_components(suites: list[str]) -> list[str]:
    algs = []
    for s in suites:
        info = parse_cipher_suite(s)
        if info.kex == "RSA":
            algs.append("RSA-KEX")
        if info.cipher:
            algs.append(info.cipher.name)
        if info.mac == "MD5":   # HMAC-SHA1 in TLS record protection is not broken
            algs.append(info.mac)
    return list(dict.fromkeys(algs))


def ssh_algs(value: str) -> list[str]:
    out = []
    for a in value.split(","):
        a = a.strip().lstrip("+-^")
        alg = lookup(a)
        if alg:
            out.append(alg.name)
        elif "mlkem" in a.lower():
            out.append("X25519MLKEM768")
        elif a:
            out.append(a)
    return list(dict.fromkeys(out))


def _item(directive, value, line, category, algorithms=None) -> ConfigItem:
    return ConfigItem(directive, value.strip(), line, category, algorithms or [])


def _resolve(base: Path, ref: str) -> Path:
    p = Path(ref.strip().strip("\"';"))
    if not p.is_absolute():
        p = base.parent / p
    return p


def _load_cert_refs(scan: ConfigScan, path: Path, ref: str, inventory: Inventory) -> None:
    p = _resolve(path, ref)
    if not p.exists():
        # Configs often reference container paths; try the file name next to the config.
        alt = path.parent / p.name
        if not alt.exists():
            alt = next(iter(path.parent.rglob(p.name)), None)
        p = alt if alt and alt.exists() else p
    if p.exists():
        for info in certs.parse_pem_bundle(p.read_bytes()):
            scan.certificates.append(inventory.add_cert(info, f"file://{p}"))


# ---------------------------------------------------------------- parsers

def parse_nginx(path: Path, text: str, inv: Inventory) -> ConfigScan:
    scan = ConfigScan(str(path), "nginx")
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"((?:proxy_|grpc_)?ssl_[a-z_]+)\s+(.+?);", line)
        if not m:
            m2 = re.match(r"server_name\s+(.+?);", line)
            if m2 and not scan.service:
                scan.service = m2.group(1).split()[0]
            continue
        d, v = m.groups()
        base = d.split("ssl_", 1)[1]
        if base == "protocols":
            scan.items.append(_item(d, v, n, "tls-protocol", v.split()))
        elif base == "ciphers":
            scan.items.append(_item(d, v, n, "tls-cipher", cipher_components(ciphers_to_algs(v))))
        elif base == "ecdh_curve":
            scan.items.append(_item(d, v, n, "tls-kex", groups_to_algs(v)))
        elif base == "conf_command":
            key, _, val = v.partition(" ")
            if key.lower() in ("groups", "curves"):
                scan.items.append(_item(d, v, n, "tls-kex", groups_to_algs(val)))
            elif key.lower() == "signaturealgorithms":
                scan.items.append(_item(d, v, n, "tls-sigalg", _split_list(val)))
        elif base in ("certificate", "trusted_certificate", "client_certificate"):
            scan.items.append(_item(d, v, n, "certificate"))
            _load_cert_refs(scan, path, v, inv)
        elif base == "verify_client":
            scan.items.append(_item(d, v, n, "mtls"))
    return scan


def parse_apache(path: Path, text: str, inv: Inventory) -> ConfigScan:
    scan = ConfigScan(str(path), "apache")
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"(SSL\w+|ServerName)\s+(.+)", line, re.I)
        if not m:
            continue
        d, v = m.groups()
        dl = d.lower()
        if dl == "servername" and not scan.service:
            scan.service = v.split()[0]
        elif dl in ("sslprotocol", "sslproxyprotocol"):
            scan.items.append(_item(d, v, n, "tls-protocol", v.split()))
        elif dl in ("sslciphersuite", "sslproxyciphersuite"):
            if v.strip().upper().startswith("TLSV1.3"):
                continue
            scan.items.append(_item(d, v, n, "tls-cipher", cipher_components(ciphers_to_algs(v))))
        elif dl == "sslopensslconfcmd":
            key, _, val = v.partition(" ")
            if key.lower() in ("curves", "groups"):
                scan.items.append(_item(d, v, n, "tls-kex", groups_to_algs(val)))
        elif dl in ("sslcertificatefile", "sslcacertificatefile"):
            scan.items.append(_item(d, v, n, "certificate"))
            _load_cert_refs(scan, path, v, inv)
    return scan


def parse_haproxy(path: Path, text: str, inv: Inventory) -> ConfigScan:
    scan = ConfigScan(str(path), "haproxy")
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"(ssl-default-(?:bind|server)-(?:ciphers|ciphersuites|options|curves))\s+(.+)",
                     line)
        if m:
            d, v = m.groups()
            if d.endswith("-ciphers"):
                scan.items.append(_item(d, v, n, "tls-cipher",
                                        cipher_components(ciphers_to_algs(v))))
            elif d.endswith("-curves"):
                scan.items.append(_item(d, v, n, "tls-kex", groups_to_algs(v)))
            elif d.endswith("-options"):
                protos = [o for o in v.split() if o.startswith(("ssl-min-ver", "no-tls", "no-ssl"))]
                scan.items.append(_item(d, v, n, "tls-protocol", protos))
            continue
        if line.startswith(("bind ", "server ")) and " ssl" in f" {line}":
            for key, cat in (("curves", "tls-kex"), ("ciphers", "tls-cipher"), ("crt", "certificate")):
                mm = re.search(rf"\b{key}\s+(\S+)", line)
                if not mm:
                    continue
                v = mm.group(1)
                if cat == "tls-kex":
                    scan.items.append(_item(key, v, n, cat, groups_to_algs(v)))
                elif cat == "tls-cipher":
                    scan.items.append(_item(key, v, n, cat, cipher_components(ciphers_to_algs(v))))
                else:
                    scan.items.append(_item(key, v, n, cat))
                    _load_cert_refs(scan, path, v, inv)
            mm = re.search(r"\bssl-min-ver\s+(\S+)", line)
            if mm:
                scan.items.append(_item("ssl-min-ver", mm.group(1), n, "tls-protocol",
                                        [mm.group(1)]))
    return scan


def parse_envoy(path: Path, text: str, inv: Inventory) -> ConfigScan:
    scan = ConfigScan(str(path), "envoy")
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"-?\s*(ecdh_curves|cipher_suites|tls_minimum_protocol_version|"
                     r"tls_maximum_protocol_version|filename)\s*:\s*(.*)", line)
        if not m:
            continue
        d, v = m.groups()
        v = v.strip().strip("[]\"'")
        if d == "ecdh_curves" and v:
            scan.items.append(_item(d, v, n, "tls-kex", groups_to_algs(v)))
        elif d == "cipher_suites" and v:
            scan.items.append(_item(d, v, n, "tls-cipher", cipher_components(ciphers_to_algs(v))))
        elif d.startswith("tls_m"):
            scan.items.append(_item(d, v, n, "tls-protocol", [v.replace("TLSv1_", "TLSv1.")]))
        elif d == "filename" and v.endswith((".crt", ".pem")):
            scan.items.append(_item(d, v, n, "certificate"))
            _load_cert_refs(scan, path, v, inv)
    return scan


def parse_openssl_cnf(path: Path, text: str, inv: Inventory) -> ConfigScan:
    scan = ConfigScan(str(path), "openssl")
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"(Groups|Curves|MinProtocol|MaxProtocol|CipherString|Ciphersuites|"
                     r"SignatureAlgorithms)\s*=\s*(.+)", line, re.I)
        if not m:
            continue
        d, v = m.groups()
        dl = d.lower()
        if dl in ("groups", "curves"):
            scan.items.append(_item(d, v, n, "tls-kex", groups_to_algs(v)))
        elif dl in ("minprotocol", "maxprotocol"):
            scan.items.append(_item(d, v, n, "tls-protocol", [v.strip()]))
        elif dl == "cipherstring":
            scan.items.append(_item(d, v, n, "tls-cipher", cipher_components(ciphers_to_algs(v))))
        elif dl == "signaturealgorithms":
            scan.items.append(_item(d, v, n, "tls-sigalg", _split_list(v)))
    return scan


def parse_ssh(path: Path, text: str, inv: Inventory) -> ConfigScan:
    scan = ConfigScan(str(path), "sshd" if "sshd" in path.name else "ssh")
    cats = {"kexalgorithms": "ssh-kex", "hostkeyalgorithms": "ssh-hostkey",
            "pubkeyacceptedalgorithms": "ssh-hostkey", "ciphers": "ssh-cipher",
            "macs": "ssh-mac"}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        d, v = parts
        dl = d.lower()
        if dl in cats:
            scan.items.append(_item(d, v, n, cats[dl], ssh_algs(v)))
        elif dl == "hostkey":
            alg = "RSA" if "rsa" in v else "ECDSA" if "ecdsa" in v else \
                "Ed25519" if "ed25519" in v else "DSA" if "dsa" in v else "unknown"
            scan.items.append(_item(d, v, n, "ssh-hostkey", [alg]))
    return scan


# Private-key headers and the DER-encoded OIDs of PQC algorithms inside PKCS#8.
_PQ_KEY_OIDS = {
    bytes.fromhex("0609608648016503040311"): "ML-DSA-44",
    bytes.fromhex("0609608648016503040312"): "ML-DSA-65",
    bytes.fromhex("0609608648016503040313"): "ML-DSA-87",
    bytes.fromhex("0609608648016503040401"): "ML-KEM-512",
    bytes.fromhex("0609608648016503040402"): "ML-KEM-768",
    bytes.fromhex("0609608648016503040403"): "ML-KEM-1024",
}


def _key_alg(pem: bytes) -> tuple[str, int | None]:
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    try:
        key = serialization.load_pem_private_key(pem, password=None)
        if isinstance(key, rsa.RSAPrivateKey):
            return "RSA", key.key_size
        if isinstance(key, ec.EllipticCurvePrivateKey):
            return "ECDSA", key.curve.key_size
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return "Ed25519", 256
    except Exception:  # noqa: BLE001 - encrypted, PQC or unsupported
        pass
    body = re.search(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----(.+?)-----END", pem, re.S)
    if body:
        try:
            der = base64.b64decode(re.sub(rb"\s+", b"", body.group(1)))
        except ValueError:
            der = b""
        for oid, name in _PQ_KEY_OIDS.items():
            if oid in der:
                return name, None
    if b"ENCRYPTED" in pem:
        return "encrypted", None
    return "unknown", None


def parse_pem(path: Path, data: bytes, inv: Inventory) -> ConfigScan:
    scan = ConfigScan(str(path), "pem")
    for info in certs.parse_pem_bundle(data):
        scan.certificates.append(inv.add_cert(info, f"file://{path}"))
    for n, m in enumerate(re.finditer(rb"-----BEGIN ([A-Z ]*PRIVATE KEY)-----.+?-----END \1-----",
                                      data, re.S), 1):
        alg, size = _key_alg(m.group(0))
        label = f"{alg}-{size}" if size and alg == "RSA" else alg
        scan.items.append(_item("private-key", label, n, "private-key", [alg]))
    return scan


SOURCE_PATTERNS: list[tuple[str, str, str]] = [
    # regex, algorithm, category
    (r"rsa\.generate_private_key|RSA\.generate\(|rsa\.GenerateKey|KeyPairGenerator\.getInstance\(\"RSA\"|"
     r"generateKeyPair(Sync)?\(\s*['\"]rsa", "RSA", "code-asymmetric"),
    (r"ec\.generate_private_key|ecdsa\.GenerateKey|KeyPairGenerator\.getInstance\(\"EC\"|"
     r"generateKeyPair(Sync)?\(\s*['\"]ec['\"]|ec\.SECP256R1|elliptic\.P256\(\)", "ECDSA",
     "code-asymmetric"),
    (r"ECDH|X25519PrivateKey|ecdh\.X25519\(\)|createECDH\(", "X25519", "code-kex"),
    (r"hashlib\.md5|createHash\(\s*['\"]md5|MessageDigest\.getInstance\(\"MD5\"|md5\.New\(\)", "MD5",
     "code-hash"),
    (r"hashlib\.sha1|createHash\(\s*['\"]sha1|MessageDigest\.getInstance\(\"SHA-?1\"|sha1\.New\(\)",
     "SHA-1", "code-hash"),
    (r"DES3|TripleDES|DESede|des\.NewTripleDESCipher", "3DES", "code-cipher"),
    (r"\bARC4\b|\bRC4\b|rc4\.NewCipher", "RC4", "code-cipher"),
    (r"PROTOCOL_TLSv1\b|TLSv1_METHOD|tls\.VersionTLS10|minVersion:\s*['\"]TLSv1['\"]", "TLSv1.0",
     "code-protocol"),
    (r"CurvePreferences|set_ecdh_curve|ecdhCurve", "configured-curves", "code-kex"),
    (r"ML-?KEM|MLKEM|X25519MLKEM768|mlkem768", "ML-KEM-768", "code-pqc"),
    (r"ML-?DSA|MLDSA|mldsa65", "ML-DSA-65", "code-pqc"),
]
SOURCE_EXT = {".py", ".go", ".java", ".js", ".ts", ".mjs", ".kt", ".rb", ".rs", ".cs"}


def parse_source(path: Path, text: str, inv: Inventory) -> ConfigScan | None:
    scan = ConfigScan(str(path), "source")
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 1000:
            continue
        for pat, alg, cat in SOURCE_PATTERNS:
            if re.search(pat, line):
                scan.items.append(_item("code", line.strip()[:160], n, cat, [alg]))
    return scan if scan.items else None


# ---------------------------------------------------------------- dispatch

def detect_kind(path: Path, head: str) -> str | None:
    name = path.name.lower()
    if name in ("sshd_config", "ssh_config") or name.endswith((".sshd_config", "sshd_config.conf")):
        return "ssh"
    if name == "openssl.cnf" or name.endswith(".cnf"):
        return "openssl"
    if name.startswith("haproxy") or name.endswith(".cfg") and "frontend" in head:
        return "haproxy"
    if name.endswith((".pem", ".crt", ".cer", ".key")) or "-----BEGIN " in head[:2000]:
        return "pem"
    if path.suffix in SOURCE_EXT:
        return "source"
    if name.endswith((".yaml", ".yml")) and ("ecdh_curves" in head or "tls_params" in head):
        return "envoy"
    if "nginx" in name or re.search(r"\bssl_(certificate|protocols|ciphers)\b", head):
        return "nginx"
    if re.search(r"^\s*SSL(Engine|Protocol|CertificateFile)\b", head, re.M) or \
            name in ("httpd.conf", "ssl.conf", "apache2.conf"):
        return "apache"
    return None


PARSERS = {"nginx": parse_nginx, "apache": parse_apache, "haproxy": parse_haproxy,
           "envoy": parse_envoy, "openssl": parse_openssl_cnf, "ssh": parse_ssh,
           "source": parse_source}


def scan_file(path: Path, inv: Inventory, service: str | None = None) -> ConfigScan | None:
    try:
        if path.stat().st_size > MAX_FILE:
            return None
        data = path.read_bytes()
    except OSError as e:
        return ConfigScan(str(path), "unknown", error=str(e))
    text = data.decode("utf-8", "replace")
    kind = detect_kind(path, text[:20000])
    if kind is None:
        return None
    if kind == "pem":
        scan = parse_pem(path, data, inv)
    else:
        scan = PARSERS[kind](path, text, inv)
    if scan is None or (not scan.items and not scan.certificates):
        return None
    scan.service = service or scan.service or path.parent.name
    return scan


def scan_paths(paths: list[str], inv: Inventory) -> None:
    for p in paths:
        service = None
        if "=" in p and not os.path.exists(p):
            service, p = p.split("=", 1)
        root = Path(p)
        files = [root] if root.is_file() else sorted(
            f for f in root.rglob("*")
            if f.is_file() and not any(part in SKIP_DIRS for part in f.parts))
        for f in files:
            res = scan_file(f, inv, service)
            if res:
                inv.configs.append(res)
