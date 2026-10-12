"""Human-readable renderings of an inventory: terminal summary and Markdown report."""

from __future__ import annotations

from collections import Counter

from .analyzer import service_summary
from .catalog import classify_group, lookup
from .models import Inventory

STATUS_ICON = {"quantum-safe": "SAFE", "partial": "PARTIAL", "vulnerable": "MIGRATE",
               "review": "REVIEW"}


def _table(rows: list[list[str]], header: list[str]) -> str:
    widths = [max(len(str(x)) for x in col) for col in zip(header, *rows)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    out = [fmt.format(*header), fmt.format(*["-" * w for w in widths])]
    out += [fmt.format(*[str(c) for c in r]) for r in rows]
    return "\n".join(out)


def _kex_label(group: str | None) -> str:
    if not group:
        return "-"
    alg = classify_group(group)
    tag = alg.status.value if alg else "unknown"
    return f"{group} ({tag})"


def text_summary(inv: Inventory) -> str:
    parts = []
    if inv.endpoints:
        rows = []
        for ep in inv.endpoints:
            if not ep.reachable:
                rows.append([ep.name, ep.target, "unreachable", "-", "-", "-", "-"])
                continue
            leaf = inv.certificates.get(ep.certificate_chain[0]) if ep.certificate_chain else None
            protos = ",".join(p.replace("TLSv", "") for p, ok in ep.protocols.items() if ok)
            rows.append([ep.name, ep.target, protos or ep.negotiated_version or "-",
                         _kex_label(ep.negotiated_group),
                         ", ".join(ep.pqc_groups) or "none",
                         (leaf.public_key_detail or leaf.public_key_algorithm) if leaf else "-",
                         "yes" if ep.peer_requires_client_cert else "no"])
        parts.append("TLS ENDPOINTS\n" + _table(
            rows, ["service", "endpoint", "TLS", "key exchange", "PQC groups", "cert key", "mTLS"]))
    if inv.configs:
        c = Counter(cfg.kind for cfg in inv.configs)
        parts.append("CONFIG FILES  " + ", ".join(f"{k}: {v}" for k, v in sorted(c.items())))
    if inv.certificates:
        rows = [[c.subject[:48], c.public_key_detail or c.public_key_algorithm,
                 f"{c.signature_algorithm}{'/' + c.signature_hash if c.signature_hash else ''}",
                 c.not_after[:10]] for c in inv.certificates.values()]
        parts.append("CERTIFICATES\n" + _table(rows, ["subject", "key", "signature", "expires"]))
    summ = service_summary(inv)
    if summ:
        rows = [[s["service"], STATUS_ICON.get(s["status"], s["status"]), s["score"],
                 " ".join(f"{k}:{v}" for k, v in sorted(s["findings"].items(),
                                                       key=lambda kv: kv[0]))]
                for s in summ]
        parts.append("MIGRATION READINESS\n" + _table(rows, ["service", "status", "risk",
                                                             "findings"]))
    sev = Counter(f.severity for f in inv.findings)
    parts.append("FINDINGS  " + ", ".join(f"{k}: {sev[k]}" for k in
                                          ("critical", "high", "medium", "low", "info") if sev[k]))
    return "\n\n".join(parts)


def markdown_report(inv: Inventory) -> str:
    L = ["# QuantumShield cryptographic inventory", "",
         f"Generated: {inv.generated_at}  ", f"Scanner TLS runtime: {inv.tls_library}", ""]
    summ = service_summary(inv)
    if summ:
        L += ["## Migration readiness", "", "| Service | Status | Risk score | Key exchange | "
              "Certificate key | Findings |", "|---|---|---:|---|---|---|"]
        for s in summ:
            L.append(f"| {s['service']} | **{s['status']}** | {s['score']} | "
                     f"{', '.join(s['kex']) or '-'} | {', '.join(s['cert_keys']) or '-'} | "
                     + ", ".join(f"{v} {k}" for k, v in s["findings"].items()) + " |")
        L.append("")
    if inv.endpoints:
        L += ["## TLS endpoints", "", "| Service | Endpoint | Protocols | Negotiated | Group | "
              "PQC groups accepted | TLS 1.2 suites | mTLS |", "|---|---|---|---|---|---|---|---|"]
        for ep in inv.endpoints:
            protos = ", ".join(p for p, ok in ep.protocols.items() if ok)
            L.append(f"| {ep.name} | {ep.target} | {protos or '-'} | "
                     f"{ep.negotiated_version or '-'} {ep.negotiated_cipher or ''} | "
                     f"{ep.negotiated_group or '-'} | {', '.join(ep.pqc_groups) or 'none'} | "
                     f"{len(ep.tls12_ciphers)} | {'required' if ep.peer_requires_client_cert else 'no'} |")
        L.append("")
    if inv.certificates:
        L += ["## Certificates", "", "| Subject | Key | Signature | Expires | Seen at |",
              "|---|---|---|---|---|"]
        for c in inv.certificates.values():
            L.append(f"| {c.subject} | {c.public_key_detail or c.public_key_algorithm} | "
                     f"{c.signature_algorithm}{'/' + c.signature_hash if c.signature_hash else ''}"
                     f" | {c.not_after[:10]} | {'<br>'.join(c.sources[:3])} |")
        L.append("")
    algs: Counter[str] = Counter()
    for cfg in inv.configs:
        for it in cfg.items:
            for a in it.algorithms:
                if lookup(a) or classify_group(a):
                    algs[a] += 1
    if inv.configs:
        L += ["## Configuration and source files", "",
              "| File | Kind | Service | Crypto settings |", "|---|---|---|---|"]
        for cfg in inv.configs:
            L.append(f"| {cfg.path} | {cfg.kind} | {cfg.service or '-'} | {len(cfg.items)} |")
        L.append("")
    if algs:
        L += ["## Algorithms referenced in configuration", "",
              "| Algorithm | Quantum status | Occurrences | Replace with |", "|---|---|---:|---|"]
        for a, n in algs.most_common():
            alg = lookup(a) or classify_group(a)
            L.append(f"| {a} | {alg.status.value} | {n} | {alg.replacement or '-'} |")
        L.append("")
    if inv.findings:
        L += ["## Findings", "", "| Severity | Rule | Service | Asset | Finding | Evidence | "
              "Recommendation |", "|---|---|---|---|---|---|---|"]
        for f in inv.findings:
            hndl = " (HNDL)" if f.hndl else ""
            L.append(f"| {f.severity}{hndl} | {f.rule_id} | {f.service or '-'} | {f.asset} | "
                     f"{f.title} | {f.evidence} | {f.recommendation} |")
        L.append("")
    return "\n".join(L)
