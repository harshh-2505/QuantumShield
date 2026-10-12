"""Turn an inventory into prioritised findings and a per-service readiness view."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from .catalog import QuantumStatus, classify_group, lookup, parse_cipher_suite
from .models import CertInfo, ConfigScan, EndpointScan, Finding, Inventory

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_POINTS = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}

QUANTUM_BROKEN_SIG = {"RSA", "ECDSA", "Ed25519", "Ed448", "DSA"}


def _status(name: str | None) -> QuantumStatus | None:
    alg = lookup(name) or classify_group(name)
    return alg.status if alg else None


# ---------------------------------------------------------------- endpoints

def _endpoint_findings(ep: EndpointScan) -> list[Finding]:
    f: list[Finding] = []
    svc, asset = ep.name, ep.target

    def add(rule, title, sev, evidence, rec, hndl=False, migration=None):
        f.append(Finding(rule, title, sev, asset, svc, evidence, rec, hndl, migration))

    if not ep.reachable:
        add("QS-NET-001", "Endpoint unreachable", "info", ep.error or "no response",
            "Check the address, or scan from inside the network.")
        return f

    pqc = ep.pqc_groups
    neg = classify_group(ep.negotiated_group)
    if neg is not None and not neg.quantum_safe:
        if pqc:
            add("QS-TLS-KEX-002", "Server prefers classical key exchange over its PQC groups",
                "medium", f"Negotiated {ep.negotiated_group} although {', '.join(pqc)} is accepted",
                "Put X25519MLKEM768 first in the server's group preference list.", True,
                "set-hybrid-groups")
        else:
            add("QS-TLS-KEX-001", "Key exchange is not quantum-safe (harvest-now-decrypt-later)",
                "high", f"Negotiated {ep.negotiated_group}; no hybrid ML-KEM group accepted"
                + ("" if ep.groups_probed or not ep.protocols.get("TLSv1.3")
                   else " (groups not probed)"),
                "Enable X25519MLKEM768 (OpenSSL 3.5+, BoringSSL, Go 1.24+) or front the service "
                "with the QuantumShield hybrid proxy.", True, "set-hybrid-groups")
    elif neg is None and ep.negotiated_version == "TLSv1.3" and not ep.groups_probed:
        add("QS-TLS-KEX-000", "Key-exchange group could not be determined", "low",
            "The local TLS runtime cannot report or select groups",
            "Re-run the scan with Python 3.15+ and OpenSSL 3.5+ (e.g. the QuantumShield image).")
    elif neg is None and ep.negotiated_version != "TLSv1.3" and not pqc:
        add("QS-TLS-KEX-001", "Key exchange is not quantum-safe (harvest-now-decrypt-later)",
            "high", f"{ep.negotiated_version} with {ep.negotiated_cipher}",
            "Enable TLS 1.3 with X25519MLKEM768, or front the service with the QuantumShield "
            "hybrid proxy.", True, "set-hybrid-groups")

    rsa_kex = [c for c in ep.tls12_ciphers if parse_cipher_suite(c).kex == "RSA"]
    if rsa_kex:
        add("QS-TLS-KEX-003", "Static RSA key exchange accepted (no forward secrecy)", "critical",
            "Accepts " + ", ".join(rsa_kex[:4]) + ("..." if len(rsa_kex) > 4 else ""),
            "Remove kRSA suites. Anyone who records traffic and later obtains or breaks the RSA "
            "key decrypts every session.", True, "remove-rsa-kex")

    if not ep.protocols.get("TLSv1.3", ep.negotiated_version == "TLSv1.3"):
        add("QS-TLS-PROTO-001", "TLS 1.3 not supported", "high",
            "Highest protocol: " + (ep.negotiated_version or "unknown"),
            "Hybrid ML-KEM key exchange is only defined for TLS 1.3. Upgrade the TLS stack or "
            "deploy the QuantumShield proxy.", True, "enable-tls13")
    legacy = [p for p in ("TLSv1.0", "TLSv1.1") if ep.protocols.get(p)]
    if legacy:
        add("QS-TLS-PROTO-002", "Legacy TLS versions accepted", "high", ", ".join(legacy),
            "Disable TLS 1.0 and 1.1.", False, "disable-legacy-tls")
    if ep.protocols.get("TLSv1.2") and ep.protocols.get("TLSv1.3") and pqc:
        add("QS-TLS-PROTO-003", "TLS 1.2 fallback bypasses post-quantum key exchange", "low",
            "TLS 1.2 is accepted; clients without TLS 1.3 negotiate classical ECDHE",
            "Once clients support it, require TLS 1.3 for internal traffic.", False,
            "disable-tls12")

    weak = set()
    for c in ep.tls12_ciphers + ([ep.negotiated_cipher] if ep.negotiated_cipher else []):
        info = parse_cipher_suite(c)
        if info.cipher and info.cipher.status == QuantumStatus.INSECURE:
            weak.add(c)
    if weak:
        add("QS-TLS-CIPH-001", "Insecure symmetric ciphers accepted", "high",
            ", ".join(sorted(weak)), "Allow only AEAD suites (AES-256-GCM, ChaCha20-Poly1305).",
            False, "remove-weak-ciphers")
    neg_cipher = parse_cipher_suite(ep.negotiated_cipher) if ep.negotiated_cipher else None
    if neg_cipher and neg_cipher.cipher and neg_cipher.cipher.status == QuantumStatus.WEAKENED:
        add("QS-TLS-CIPH-002", "128-bit symmetric cipher preferred", "low",
            f"Negotiated {ep.negotiated_cipher} (Grover's algorithm halves its strength)",
            "Prefer AES-256-GCM or ChaCha20-Poly1305 for long-lived secrets.", False,
            "prefer-aes256")

    if not ep.peer_requires_client_cert:
        add("QS-ZT-001", "No workload identity required (no mutual TLS)", "info",
            "The endpoint accepts anonymous clients",
            "For service-to-service traffic, require mTLS with short-lived workload "
            "certificates (the QuantumShield proxy does this).", False, "deploy-pqc-proxy")
    return f


# ---------------------------------------------------------------- certificates

def _cert_findings(cert: CertInfo, services: list[str], now: datetime) -> list[Finding]:
    f: list[Finding] = []
    asset = f"cert:{cert.fingerprint_sha256[:16]} ({cert.subject})"
    svc = ", ".join(sorted(set(services))) or None

    def add(rule, title, sev, evidence, rec, migration=None):
        f.append(Finding(rule, title, sev, asset, svc, evidence, rec, False, migration))

    key = cert.public_key_algorithm
    if key in QUANTUM_BROKEN_SIG:
        detail = cert.public_key_detail or key
        add("QS-CERT-SIG-001", "Certificate key is quantum-vulnerable", "medium",
            f"{detail} public key, signed with {cert.signature_algorithm}"
            + (f"/{cert.signature_hash}" if cert.signature_hash else ""),
            "Plan re-issuance with ML-DSA-65 (or a composite ML-DSA + ECDSA certificate). "
            "Authentication is not exposed to harvest-now-decrypt-later, so this follows key "
            "exchange in priority.", "reissue-mldsa")
    if key == "RSA" and cert.public_key_size and cert.public_key_size < 2048:
        add("QS-CERT-KEY-001", "RSA key shorter than 2048 bits", "high",
            f"RSA-{cert.public_key_size}", "Re-issue immediately.", "reissue-mldsa")
    if cert.signature_hash in ("SHA-1", "MD5"):
        add("QS-CERT-HASH-001", "Certificate signed with a broken hash", "high",
            f"{cert.signature_algorithm} with {cert.signature_hash}", "Re-issue with SHA-256+ "
            "or ML-DSA.", "reissue-mldsa")
    try:
        nb = datetime.fromisoformat(cert.not_before)
        na = datetime.fromisoformat(cert.not_after)
    except ValueError:
        return f
    if na < now:
        add("QS-CERT-EXP-001", "Certificate expired", "high", f"Expired {na:%Y-%m-%d}",
            "Rotate the certificate.", "rotate-cert")
    elif na - now < min(timedelta(days=30), (na - nb) / 3):
        add("QS-CERT-EXP-002", "Certificate expires within 30 days", "medium",
            f"Expires {na:%Y-%m-%d}", "Rotate the certificate.", "rotate-cert")
    if not cert.is_ca and (na - nb) > timedelta(days=398):
        add("QS-CERT-ROT-001", "Long-lived certificate", "low",
            f"Valid for {(na - nb).days} days",
            "Use short-lived workload certificates so rotation and algorithm changes are routine.",
            "rotate-cert")
    if cert.self_signed and not cert.is_ca:
        add("QS-CERT-TRUST-001", "Self-signed leaf certificate", "low", cert.subject,
            "Issue from an internal CA so certificates can be revoked and rotated centrally.",
            "rotate-cert")
    return f


# ---------------------------------------------------------------- configs

def _config_findings(cfg: ConfigScan) -> list[Finding]:
    f: list[Finding] = []
    svc = cfg.service

    def add(item, rule, title, sev, rec, hndl=False, migration=None):
        f.append(Finding(rule, title, sev, f"{cfg.path}:{item.line}", svc,
                         f"{item.directive} {item.value}", rec, hndl, migration))

    has_kex = False
    has_tls = False
    for it in cfg.items:
        algs = it.algorithms
        if it.category == "tls-kex":
            has_kex = True
            if algs and not any(_status(a) in (QuantumStatus.HYBRID, QuantumStatus.RESISTANT)
                                for a in algs):
                add(it, "QS-CFG-KEX-001", "Only classical key-exchange groups configured", "high",
                    "Add X25519MLKEM768 first, keeping X25519 for older clients.", True,
                    "set-hybrid-groups")
        elif it.category == "tls-protocol":
            has_tls = True
            joined = " ".join(algs).lower()
            tokens = {t.lstrip("+") for t in joined.replace("_", ".").split()}
            legacy = bool(tokens & {"tlsv1", "tlsv1.0", "tlsv1.1", "sslv3", "sslv2"})
            if "all" in tokens and not {"-tlsv1", "-tlsv1.1"} <= tokens:
                legacy = True
            if legacy and it.directive.lower() != "maxprotocol":
                add(it, "QS-CFG-PROTO-002", "Legacy TLS versions enabled", "high",
                    "Allow only TLS 1.2 and 1.3.", False, "disable-legacy-tls")
            if it.directive.lower() in ("ssl_protocols", "proxy_ssl_protocols", "sslprotocol") \
                    and "tlsv1.3" not in joined and "all" not in joined:
                add(it, "QS-CFG-PROTO-001", "TLS 1.3 not enabled", "high",
                    "Enable TLSv1.3; hybrid ML-KEM requires it.", True, "enable-tls13")
            if it.directive.lower() == "maxprotocol" and "1.3" not in joined:
                add(it, "QS-CFG-PROTO-001", "TLS 1.3 not enabled", "high",
                    "Raise MaxProtocol to TLSv1.3.", True, "enable-tls13")
        elif it.category == "tls-cipher":
            has_tls = True
            if "RSA-KEX" in algs:
                add(it, "QS-CFG-CIPH-003", "Static RSA key-exchange suites allowed", "critical",
                    "Restrict to ECDHE suites, e.g. ECDHE+AESGCM:ECDHE+CHACHA20.", True,
                    "remove-rsa-kex")
            bad = [a for a in algs if _status(a) == QuantumStatus.INSECURE]
            if bad:
                add(it, "QS-CFG-CIPH-001", "Insecure ciphers allowed", "high",
                    f"Remove {', '.join(bad)}.", False, "remove-weak-ciphers")
        elif it.category == "certificate":
            has_tls = True
        elif it.category == "ssh-kex":
            if not any(_status(a) == QuantumStatus.HYBRID for a in algs):
                add(it, "QS-SSH-KEX-001", "SSH key exchange is not quantum-safe", "high",
                    "Put mlkem768x25519-sha256 (OpenSSH 9.9+) and sntrup761x25519-sha512 first.",
                    True, "ssh-hybrid-kex")
            if any(_status(a) == QuantumStatus.INSECURE for a in algs):
                add(it, "QS-SSH-KEX-002", "SSH allows broken key exchange", "high",
                    "Remove SHA-1 / 1024-bit Diffie-Hellman groups.", False, "ssh-hybrid-kex")
        elif it.category == "ssh-hostkey":
            if "DSA" in algs:
                add(it, "QS-SSH-HK-002", "DSA host key", "high", "Remove DSA host keys.",
                    False, "ssh-hostkey")
            elif any(a in QUANTUM_BROKEN_SIG for a in algs):
                add(it, "QS-SSH-HK-001", "SSH host key is quantum-vulnerable", "low",
                    "Track OpenSSH's ML-DSA host-key support; keep keys rotatable.", False,
                    "ssh-hostkey")
        elif it.category == "ssh-cipher":
            if any(_status(a) == QuantumStatus.INSECURE for a in algs):
                add(it, "QS-SSH-CIPH-001", "SSH allows insecure ciphers", "high",
                    "Use chacha20-poly1305 and aes256-gcm.", False, "remove-weak-ciphers")
        elif it.category == "private-key":
            if any(a in QUANTUM_BROKEN_SIG for a in algs):
                add(it, "QS-KEY-001", "Quantum-vulnerable private key on disk", "low",
                    "Replace with ML-DSA keys when the certificate is re-issued; keep keys out of "
                    "source trees.", False, "reissue-mldsa")
        elif it.category in ("code-asymmetric", "code-kex"):
            add(it, "QS-CODE-001", "Hard-coded quantum-vulnerable algorithm in source", "medium",
                f"Route {', '.join(algs)} through a crypto-agility layer (config-selected "
                "algorithm) so it can be swapped for ML-KEM / ML-DSA.", False, "refactor-code")
        elif it.category == "code-hash":
            add(it, "QS-CODE-002", "Broken hash function used in source", "medium",
                "Use SHA-256 or stronger (fine for non-security checksums, but verify).", False,
                "refactor-code")
        elif it.category in ("code-cipher", "code-protocol"):
            add(it, "QS-CODE-003", "Insecure cipher or protocol in source", "high",
                "Replace with AES-256-GCM / TLS 1.3.", False, "refactor-code")
        elif it.category == "code-pqc":
            add(it, "QS-CODE-PQC", "Post-quantum algorithm in use", "info",
                "Good: confirm it comes from a validated library.", False, None)
    if cfg.kind in ("nginx", "apache", "haproxy") and has_tls and not has_kex:
        f.append(Finding("QS-CFG-KEX-000", "Key-exchange groups left to library defaults", "info",
                         cfg.path, svc, "No ssl_ecdh_curve / Groups directive",
                         "Defaults are hybrid only with OpenSSL 3.5+. Pin "
                         "X25519MLKEM768:X25519 explicitly.", False, "set-hybrid-groups"))
    return f


# ---------------------------------------------------------------- entry points

def analyze(inv: Inventory, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []
    cert_services: dict[str, list[str]] = defaultdict(list)
    for ep in inv.endpoints:
        findings += _endpoint_findings(ep)
        for fp in ep.certificate_chain[:1]:
            cert_services[fp].append(ep.name)
    for cfg in inv.configs:
        findings += _config_findings(cfg)
        for fp in cfg.certificates:
            cert_services[fp].append(cfg.service or cfg.path)
    for fp, cert in inv.certificates.items():
        if cert.is_ca and fp not in cert_services:
            continue
        findings += _cert_findings(cert, cert_services.get(fp, []), now)
    findings.sort(key=lambda x: (SEVERITY_ORDER[x.severity], x.service or "", x.rule_id))
    inv.findings = findings
    return findings


def service_summary(inv: Inventory) -> list[dict]:
    """Per-service readiness: quantum-safe, partial or vulnerable, with a risk score."""
    services: dict[str, dict] = {}

    def entry(name):
        return services.setdefault(name, {
            "service": name, "endpoints": [], "kex": set(), "cert_keys": set(),
            "findings": defaultdict(int), "score": 0, "hndl": False})

    for ep in inv.endpoints:
        e = entry(ep.name)
        e["endpoints"].append(ep.target)
        if ep.negotiated_group:
            e["kex"].add(ep.negotiated_group)
        if ep.certificate_chain and ep.certificate_chain[0] in inv.certificates:
            c = inv.certificates[ep.certificate_chain[0]]
            e["cert_keys"].add(c.public_key_detail or c.public_key_algorithm)
    for fnd in inv.findings:
        name = fnd.service or "(unassigned)"
        if fnd.rule_id.startswith("QS-CERT") and name not in services:
            # certificate findings carry a comma-joined list of services
            for n in name.split(", "):
                if n in services:
                    name = n
                    break
        e = entry(name)
        e["findings"][fnd.severity] += 1
        e["score"] += SEVERITY_POINTS[fnd.severity]
        e["hndl"] = e["hndl"] or fnd.hndl
    out = []
    for e in services.values():
        kex_safe = bool(e["kex"]) and all(
            (classify_group(k) and classify_group(k).quantum_safe) for k in e["kex"])
        if e["hndl"]:
            status = "vulnerable"
        elif kex_safe and e["findings"].get("medium", 0) == 0:
            status = "quantum-safe"
        elif kex_safe:
            status = "partial"
        else:
            status = "review"
        out.append({**e, "kex": sorted(e["kex"]), "cert_keys": sorted(e["cert_keys"]),
                    "findings": dict(e["findings"]), "status": status,
                    "needs_migration": status in ("vulnerable", "review")})
    out.sort(key=lambda x: -x["score"])
    return out
