#!/usr/bin/env python3
"""Build the static website in web/ from the demo results in docs/sample-output.

    python3 scripts/build_web.py            # uses docs/sample-output
    python3 scripts/build_web.py demo/out   # uses a fresh demo run (demo/run-demo.sh)

Writes web/assets/demo-data.js, web/dashboard.html and the Content-Security-Policy
in web/vercel.json (the dashboard's inline script is allowed by hash, nothing else is).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from quantumshield import dashboard  # noqa: E402
from quantumshield.analyzer import service_summary  # noqa: E402
from quantumshield.models import Inventory  # noqa: E402

WEB = ROOT / "web"
DEMO_SERVICES = ("orders", "payments", "inventory")
SAMPLES = [
    ("nginx.conf", "demo/services/inventory/nginx.conf", "inventory service (nginx)"),
    ("apache-ssl.conf", "demo/legacy-configs/apache-ssl.conf", "Apache httpd"),
    ("haproxy.cfg", "demo/legacy-configs/haproxy.cfg", "HAProxy"),
    ("sshd_config", "demo/legacy-configs/sshd_config", "OpenSSH server"),
    ("openssl.cnf", "demo/legacy-configs/openssl.cnf", "OpenSSL"),
    ("billing_client.py", "demo/legacy-configs/billing_client.py", "Python source"),
]


def _sources(base: Path) -> dict[str, Path]:
    if (base / "before" / "inventory.json").exists():          # demo/out layout
        return {"before": base / "before/inventory.json", "after": base / "after/inventory.json",
                "bench": base / "bench.json", "plan": base / "migration/plan.json",
                "cbom": base / "before/cbom.json", "transcript": None}
    return {"before": base / "inventory-before.json", "after": base / "inventory-after.json",
            "bench": base / "bench.json", "plan": base / "migration-plan.json",
            "cbom": base / "cbom-before.json", "transcript": base / "demo-transcript.txt"}


def _service_view(inv: Inventory) -> list[dict]:
    eps = {e.name: e for e in inv.endpoints}
    out = []
    for s in service_summary(inv):
        if s["service"] not in DEMO_SERVICES:
            continue
        ep = eps.get(s["service"])
        out.append({**s, "endpoint": ep and {
            "target": ep.target, "negotiated_group": ep.negotiated_group,
            "negotiated_cipher": ep.negotiated_cipher,
            "protocols": [p for p, ok in ep.protocols.items() if ok],
            "pqc_groups": ep.pqc_groups, "mtls": ep.peer_requires_client_cert,
            "cert_key": (inv.certificates[ep.certificate_chain[0]].public_key_algorithm
                         if ep.certificate_chain and ep.certificate_chain[0] in inv.certificates
                         else None)}})
    out.sort(key=lambda s: DEMO_SERVICES.index(s["service"]))
    return out


def _zero_trust(transcript: str) -> list[dict]:
    """Pull the zero-trust check outcomes (and their proxy log lines) out of the demo run."""
    def grab(pattern):
        m = re.search(pattern, transcript)
        return m.group(0).strip() if m else None
    return [
        {"check": "Classical-only client", "outcome": "refused",
         "detail": "A client that offers only X25519 cannot complete a handshake with the strict "
                   "payments sidecar.",
         "log": grab(r"connection failed: \[SSL[^\n]*")},
        {"check": "Valid certificate, unknown identity", "outcome": "rejected",
         "detail": "The certificate chains to the trusted ML-DSA CA, but its SPIFFE ID is not on "
                   "the payments allow-list.",
         "log": grab(r'\{"event": "rejected"[^\n]*intruder[^\n]*\}')},
        {"check": "Key rotation", "outcome": "reloaded",
         "detail": "payments gets a new 30-day ML-DSA-65 certificate; the sidecar picks it up "
                   "on the next connection without a restart.",
         "log": grab(r'\{"event": "context-reloaded"[^\n]*\}')},
        {"check": "Revocation", "outcome": "revoked",
         "detail": "The scanner's certificate is revoked; its next connection is refused.",
         "log": grab(r'\{"event": "rejected"[^\n]*revoked"\}')},
    ]


def build(base: Path) -> dict:
    src = _sources(base)
    before = Inventory.from_dict(json.loads(src["before"].read_text()))
    after = Inventory.from_dict(json.loads(src["after"].read_text()))
    bench = json.loads(src["bench"].read_text())
    plan = json.loads(src["plan"].read_text())
    cbom = json.loads(src["cbom"].read_text())
    transcript = src["transcript"].read_text() if src["transcript"] else ""

    algs = []
    for c in cbom["components"]:
        if c["cryptoProperties"]["assetType"] != "algorithm":
            continue
        props = {p["name"].rsplit(":", 1)[-1]: p["value"] for p in c.get("properties", [])}
        algs.append({"name": c["name"], "status": props.get("quantum-status"),
                     "primitive": c["cryptoProperties"].get("algorithmProperties", {})
                                  .get("primitive")})
    kinds = Counter(c["cryptoProperties"]["assetType"] for c in cbom["components"])

    def sev(inv, services=None):
        return dict(Counter(f.severity for f in inv.findings
                            if services is None or f.service in services))

    data = {
        "generated_at": after.generated_at,
        "runtime": bench.get("runtime"),
        "before": {"services": _service_view(before), "severity": sev(before),
                   "severity_demo": sev(before, DEMO_SERVICES),
                   "certificates": len(before.certificates), "configs": len(before.configs),
                   "findings": len(before.findings)},
        "after": {"services": _service_view(after), "severity": sev(after),
                  "severity_demo": sev(after, DEMO_SERVICES),
                  "certificates": len(after.certificates), "findings": len(after.findings)},
        "cbom": {"components": len(cbom["components"]), "kinds": dict(kinds), "algorithms": algs,
                 "spec": cbom.get("specVersion")},
        "plan": [{"service": s["service"], "status": s["status"], "score": s["score"],
                  "steps": [{"phase": st["phase"], "severity": st["severity"],
                             "description": st["description"]} for st in s["steps"]]}
                 for s in plan["services"]],
        "bench": bench,
        "zero_trust": _zero_trust(transcript) if transcript else [],
        "samples": [{"name": n, "label": label, "text": (ROOT / p).read_text()}
                    for n, p, label in SAMPLES],
    }
    return data, before, after, bench, plan


def main() -> None:
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs/sample-output"
    data, before, after, bench, plan = build(base)
    blob = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    (WEB / "assets/demo-data.js").write_text(
        "// Generated by scripts/build_web.py from the demo results. Do not edit.\n"
        f"window.QS_DEMO = {blob};\n")

    html = dashboard.render(before, after, bench, plan, title="QuantumShield demo dashboard",
                            web=True)
    (WEB / "dashboard.html").write_text(html)
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    hashes = " ".join(f"'sha256-{base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()}'"
                      for s in scripts)

    vercel_path = WEB / "vercel.json"
    vercel = json.loads(vercel_path.read_text())
    csp_site = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; "
                "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    csp_dash = csp_site.replace("script-src 'self'", f"script-src 'self' {hashes}")
    for h in vercel["headers"]:
        for kv in h["headers"]:
            if kv["key"] == "Content-Security-Policy":
                kv["value"] = csp_dash if h["source"].startswith("/dashboard") else csp_site
    vercel_path.write_text(json.dumps(vercel, indent=2) + "\n")
    print(f"web/assets/demo-data.js ({len(blob):,} bytes), web/dashboard.html, web/vercel.json")


if __name__ == "__main__":
    main()
