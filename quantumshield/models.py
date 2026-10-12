"""Plain data model shared by the scanners, analyzer, CBOM writer and dashboard."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CertInfo:
    fingerprint_sha256: str
    subject: str
    issuer: str
    serial: str
    not_before: str
    not_after: str
    public_key_algorithm: str          # catalog name: RSA, ECDSA, Ed25519, ML-DSA-65 ...
    public_key_size: int | None        # RSA modulus bits / EC curve bits
    public_key_detail: str | None      # curve name or parameter set
    signature_algorithm: str           # catalog name of the signing algorithm
    signature_hash: str | None
    subject_alt_names: list[str] = field(default_factory=list)
    self_signed: bool = False
    is_ca: bool = False
    sources: list[str] = field(default_factory=list)


@dataclass
class EndpointScan:
    target: str                        # host:port
    name: str                          # friendly service name
    reachable: bool = False
    error: str | None = None
    protocols: dict[str, bool] = field(default_factory=dict)
    negotiated_version: str | None = None
    negotiated_cipher: str | None = None
    negotiated_group: str | None = None
    negotiated_sigalg: str | None = None
    handshake_ms: float | None = None
    groups_supported: list[str] = field(default_factory=list)
    groups_probed: bool = False        # False when the local TLS stack cannot probe groups
    tls12_ciphers: list[str] = field(default_factory=list)
    certificate_chain: list[str] = field(default_factory=list)   # fingerprints, leaf first
    peer_requires_client_cert: bool = False

    @property
    def pqc_groups(self) -> list[str]:
        from .catalog import classify_group
        out = []
        for g in self.groups_supported:
            alg = classify_group(g)
            if alg and alg.quantum_safe:
                out.append(g)
        return out


@dataclass
class ConfigItem:
    directive: str
    value: str
    line: int
    category: str                      # tls-protocol, tls-kex, tls-cipher, certificate, ssh-kex ...
    algorithms: list[str] = field(default_factory=list)


@dataclass
class ConfigScan:
    path: str
    kind: str                          # nginx, apache, haproxy, sshd, openssl, pem, source
    service: str | None = None
    items: list[ConfigItem] = field(default_factory=list)
    certificates: list[str] = field(default_factory=list)       # fingerprints
    error: str | None = None


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str                      # critical, high, medium, low, info
    asset: str                         # endpoint target, config path, or cert fingerprint
    service: str | None
    evidence: str
    recommendation: str
    hndl: bool = False                 # exposed to harvest-now-decrypt-later
    migration: str | None = None       # machine-readable action id (see migrate.py)


@dataclass
class Inventory:
    generated_at: str
    endpoints: list[EndpointScan] = field(default_factory=list)
    configs: list[ConfigScan] = field(default_factory=list)
    certificates: dict[str, CertInfo] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    tls_library: str = ""

    def add_cert(self, cert: CertInfo, source: str) -> str:
        existing = self.certificates.get(cert.fingerprint_sha256)
        if existing:
            if source not in existing.sources:
                existing.sources.append(source)
        else:
            cert.sources = [source]
            self.certificates[cert.fingerprint_sha256] = cert
        return cert.fingerprint_sha256

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Inventory":
        inv = cls(generated_at=d["generated_at"], tls_library=d.get("tls_library", ""))
        inv.endpoints = [EndpointScan(**e) for e in d.get("endpoints", [])]
        inv.configs = []
        for c in d.get("configs", []):
            items = [ConfigItem(**i) for i in c.pop("items", [])]
            inv.configs.append(ConfigScan(items=items, **c))
        inv.certificates = {k: CertInfo(**v) for k, v in d.get("certificates", {}).items()}
        inv.findings = [Finding(**f) for f in d.get("findings", [])]
        return inv
