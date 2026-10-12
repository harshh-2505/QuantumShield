"""CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) export.

Each discovered algorithm, certificate, protocol instance and key becomes a
`cryptographic-asset` component; services are `service` entries whose
dependencies point at the crypto they use.
"""

from __future__ import annotations

import uuid
from typing import Any

from . import __version__
from .catalog import Primitive, classify_group, lookup, parse_cipher_suite
from .models import Inventory

_FUNCS = {
    Primitive.KEM: ["encapsulate", "decapsulate", "keygen"],
    Primitive.KEY_AGREE: ["keygen"],
    Primitive.SIGNATURE: ["sign", "verify", "keygen"],
    Primitive.PKE: ["encrypt", "decrypt"],
    Primitive.AE: ["encrypt", "decrypt"],
    Primitive.BLOCK_CIPHER: ["encrypt", "decrypt"],
    Primitive.STREAM_CIPHER: ["encrypt", "decrypt"],
    Primitive.HASH: ["digest"],
}


class _Builder:
    def __init__(self) -> None:
        self.components: dict[str, dict[str, Any]] = {}
        self.deps: dict[str, set[str]] = {}

    def algorithm(self, name: str) -> str | None:
        alg = lookup(name) or classify_group(name)
        cname = alg.name if alg else name
        ref = f"crypto/algorithm/{cname}"
        if ref in self.components:
            return ref
        props: dict[str, Any] = {"assetType": "algorithm"}
        if alg:
            prim = alg.primitive.value
            props["algorithmProperties"] = {
                "primitive": "combiner" if alg.status.value == "hybrid" else prim,
                "parameterSetIdentifier": cname,
                "executionEnvironment": "software-plain-ram",
                "cryptoFunctions": _FUNCS.get(alg.primitive, []),
                "classicalSecurityLevel": alg.classical_bits,
                "nistQuantumSecurityLevel": alg.nist_level,
            }
            if alg.oid:
                props["oid"] = alg.oid
        comp = {
            "type": "cryptographic-asset", "bom-ref": ref, "name": cname,
            "cryptoProperties": props,
            "properties": [
                {"name": "quantumshield:quantum-status",
                 "value": alg.status.value if alg else "unknown"},
            ],
        }
        if alg and alg.replacement:
            comp["properties"].append({"name": "quantumshield:recommended-replacement",
                                       "value": alg.replacement})
        self.components[ref] = comp
        return ref

    def add(self, comp: dict[str, Any]) -> str:
        self.components[comp["bom-ref"]] = comp
        return comp["bom-ref"]

    def dep(self, src: str, *dst: str | None) -> None:
        self.deps.setdefault(src, set()).update(d for d in dst if d)


def build_cbom(inv: Inventory) -> dict[str, Any]:
    b = _Builder()
    services: dict[str, dict[str, Any]] = {}

    def service(name: str) -> str:
        ref = f"service/{name}"
        services.setdefault(ref, {"bom-ref": ref, "name": name, "endpoints": []})
        return ref

    # Certificates
    for fp, c in inv.certificates.items():
        key_ref = b.algorithm(c.public_key_algorithm)
        sig_ref = b.algorithm(c.signature_algorithm)
        if c.signature_hash:
            b.dep(sig_ref, b.algorithm(c.signature_hash))
        ref = b.add({
            "type": "cryptographic-asset", "bom-ref": f"crypto/certificate/{fp[:16]}",
            "name": c.subject,
            "cryptoProperties": {
                "assetType": "certificate",
                "certificateProperties": {
                    "subjectName": c.subject, "issuerName": c.issuer,
                    "notValidBefore": c.not_before, "notValidAfter": c.not_after,
                    "signatureAlgorithmRef": sig_ref, "subjectPublicKeyRef": key_ref,
                    "certificateFormat": "X.509", "certificateExtension": "crt",
                },
            },
            "properties": [
                {"name": "quantumshield:fingerprint-sha256", "value": fp},
                {"name": "quantumshield:public-key", "value": c.public_key_detail or
                 c.public_key_algorithm},
                *({"name": "quantumshield:san", "value": s} for s in c.subject_alt_names),
                *({"name": "quantumshield:source", "value": s} for s in c.sources),
            ],
        })
        b.dep(ref, key_ref, sig_ref)

    # TLS endpoints
    for ep in inv.endpoints:
        sref = service(ep.name)
        services[sref]["endpoints"].append(f"tls://{ep.target}")
        if not ep.reachable:
            continue
        suites = []
        algo_refs = []
        for cs in dict.fromkeys(([ep.negotiated_cipher] if ep.negotiated_cipher else [])
                                + ep.tls12_ciphers):
            info = parse_cipher_suite(cs)
            refs = []
            if info.cipher:
                refs.append(b.algorithm(info.cipher.name))
            if info.kex == "RSA":
                refs.append(b.algorithm("RSA-KEX"))
            elif info.kex == "ECDHE" and ep.negotiated_group and ep.negotiated_version != "TLSv1.3":
                refs.append(b.algorithm(ep.negotiated_group))
            elif info.kex == "DHE":
                refs.append(b.algorithm("FFDHE"))
            if info.auth in ("RSA", "ECDSA"):
                refs.append(b.algorithm(info.auth))
            suites.append({"name": cs, "algorithms": refs})
            algo_refs += refs
        group_refs = [b.algorithm(g) for g in (ep.groups_supported or
                                              ([ep.negotiated_group] if ep.negotiated_group else []))]
        versions = [v.replace("TLSv", "") for v, ok in ep.protocols.items() if ok] or \
            ([ep.negotiated_version.replace("TLSv", "")] if ep.negotiated_version else [])
        pref = b.add({
            "type": "cryptographic-asset", "bom-ref": f"crypto/protocol/tls/{ep.target}",
            "name": f"TLS @ {ep.target}",
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "tls", "version": ", ".join(versions), "cipherSuites": suites,
                },
            },
            "properties": [
                {"name": "quantumshield:negotiated-version", "value": str(ep.negotiated_version)},
                {"name": "quantumshield:negotiated-group", "value": str(ep.negotiated_group)},
                {"name": "quantumshield:negotiated-cipher", "value": str(ep.negotiated_cipher)},
                {"name": "quantumshield:pqc-groups", "value": ", ".join(ep.pqc_groups) or "none"},
                {"name": "quantumshield:mtls-required",
                 "value": str(ep.peer_requires_client_cert).lower()},
            ],
        })
        cert_refs = [f"crypto/certificate/{fp[:16]}" for fp in ep.certificate_chain]
        b.dep(pref, *group_refs, *algo_refs, *cert_refs)
        b.dep(sref, pref)

    # Configuration files
    for cfg in inv.configs:
        sref = service(cfg.service or cfg.path)
        refs = []
        for it in cfg.items:
            if it.category == "private-key":
                kref = b.add({
                    "type": "cryptographic-asset",
                    "bom-ref": f"crypto/key/{cfg.path}#{it.line}",
                    "name": f"private key ({it.value})",
                    "cryptoProperties": {
                        "assetType": "related-crypto-material",
                        "relatedCryptoMaterialProperties": {
                            "type": "private-key",
                            "algorithmRef": b.algorithm(it.algorithms[0]) if it.algorithms
                            else None,
                        },
                    },
                    "evidence": {"occurrences": [{"location": cfg.path, "line": it.line}]},
                })
                refs.append(kref)
                continue
            if it.category in ("tls-protocol", "certificate", "mtls"):
                continue
            for a in it.algorithms:
                if a.startswith("configured-"):
                    continue
                r = b.algorithm(a)
                comp = b.components[r]
                occ = comp.setdefault("evidence", {}).setdefault("occurrences", [])
                if len(occ) < 50:
                    occ.append({"location": cfg.path, "line": it.line,
                                "additionalContext": f"{it.directive} {it.value}"[:200]})
                refs.append(r)
        refs += [f"crypto/certificate/{fp[:16]}" for fp in cfg.certificates]
        b.dep(sref, *refs)

    deps = [{"ref": k, "dependsOn": sorted(v)} for k, v in sorted(b.deps.items())]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": inv.generated_at,
            "tools": {"components": [{"type": "application", "name": "quantumshield",
                                      "version": __version__}]},
            "properties": [{"name": "quantumshield:tls-library", "value": inv.tls_library}],
        },
        "components": sorted(b.components.values(), key=lambda c: c["bom-ref"]),
        "services": [{"bom-ref": s["bom-ref"], "name": s["name"],
                      "endpoints": s["endpoints"]} for s in services.values()],
        "dependencies": deps,
    }
