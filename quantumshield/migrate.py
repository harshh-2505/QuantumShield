"""Migration planner: turns findings into ordered steps, patched configs and proxy configs.

Two migration paths are produced for every service that needs one:

1. In-place: patch the server's own TLS config to offer hybrid ML-KEM groups
   (works when the server links OpenSSL 3.5+, BoringSSL, Go 1.24+, ...).
2. Sidecar: put a QuantumShield proxy in front of the service.  Nothing in the
   service changes; the proxy terminates hybrid-PQC mutual TLS and forwards to
   the service locally.  This is the crypto-agility path for legacy stacks.
"""

from __future__ import annotations

import difflib
import json
import re
import shutil
from collections import defaultdict
from pathlib import Path

from .analyzer import SEVERITY_ORDER, service_summary
from .models import ConfigScan, Inventory

GROUPS_OPENSSL = "X25519MLKEM768:X25519:prime256v1"
GROUPS_HAPROXY = "X25519MLKEM768:X25519:P-256"
SAFE_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20"
SSH_KEX = ("mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,"
           "curve25519-sha256")
SSH_CIPHERS = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"

ACTIONS = {
    "set-hybrid-groups": (1, "Offer hybrid ML-KEM key exchange (X25519MLKEM768) first"),
    "remove-rsa-kex": (1, "Remove static-RSA key-exchange cipher suites"),
    "enable-tls13": (1, "Enable TLS 1.3 (required for hybrid ML-KEM)"),
    "ssh-hybrid-kex": (1, "Use mlkem768x25519-sha256 / sntrup761x25519 SSH key exchange"),
    "deploy-pqc-proxy": (2, "Front the service with a QuantumShield hybrid-PQC mTLS proxy"),
    "disable-legacy-tls": (2, "Disable TLS 1.0 / 1.1"),
    "remove-weak-ciphers": (2, "Remove insecure ciphers"),
    "reissue-mldsa": (3, "Re-issue certificates with ML-DSA-65 (or composite) keys"),
    "rotate-cert": (3, "Move to short-lived, centrally issued certificates"),
    "refactor-code": (3, "Route hard-coded crypto through a configurable (agile) layer"),
    "prefer-aes256": (4, "Prefer 256-bit symmetric ciphers"),
    "disable-tls12": (4, "Require TLS 1.3 for internal traffic once clients allow it"),
    "ssh-hostkey": (4, "Plan SSH host-key migration"),
}
PHASES = {1: "Phase 1: stop harvest-now-decrypt-later (key exchange)",
          2: "Phase 2: harden transport and add workload identity",
          3: "Phase 3: post-quantum authentication and agility",
          4: "Phase 4: clean-up"}


# ---------------------------------------------------------------- config patchers

def _patch_nginx(text: str) -> str:
    out, seen_curve = [], "ssl_ecdh_curve" in text
    for line in text.splitlines(keepends=True):
        indent = re.match(r"\s*", line).group(0)
        s = line.strip()
        if s.startswith("ssl_ecdh_curve"):
            line = f"{indent}ssl_ecdh_curve {GROUPS_OPENSSL};  # quantumshield: hybrid ML-KEM\n"
        elif s.startswith("ssl_protocols"):
            line = f"{indent}ssl_protocols TLSv1.2 TLSv1.3;\n"
        elif s.startswith("ssl_ciphers"):
            line = f"{indent}ssl_ciphers {SAFE_CIPHERS};\n"
        elif s.startswith("proxy_ssl_protocols"):
            line = f"{indent}proxy_ssl_protocols TLSv1.2 TLSv1.3;\n"
        out.append(line)
        if s.startswith("ssl_certificate_key") and not seen_curve:
            out.append(f"{indent}ssl_ecdh_curve {GROUPS_OPENSSL};  # quantumshield: hybrid ML-KEM\n")
    return "".join(out)


def _patch_apache(text: str) -> str:
    out, has = [], re.search(r"SSLOpenSSLConfCmd\s+(Curves|Groups)", text, re.I)
    for line in text.splitlines(keepends=True):
        indent = re.match(r"\s*", line).group(0)
        s = line.strip().lower()
        if s.startswith("sslprotocol"):
            line = f"{indent}SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
        elif s.startswith("sslciphersuite") and "tlsv1.3" not in s:
            line = f"{indent}SSLCipherSuite {SAFE_CIPHERS}\n"
        elif re.match(r"sslopensslconfcmd\s+(curves|groups)", s):
            line = f"{indent}SSLOpenSSLConfCmd Groups {GROUPS_OPENSSL}\n"
        out.append(line)
        if s.startswith("sslcertificatekeyfile") and not has:
            out.append(f"{indent}SSLOpenSSLConfCmd Groups {GROUPS_OPENSSL}\n")
    return "".join(out)


def _patch_haproxy(text: str) -> str:
    text = re.sub(r"(ssl-default-bind-curves\s+)\S+", rf"\g<1>{GROUPS_HAPROXY}", text)
    text = re.sub(r"(ssl-default-bind-ciphers\s+)\S+", rf"\g<1>{SAFE_CIPHERS}", text)
    text = re.sub(r"(\bcurves\s+)\S+", rf"\g<1>{GROUPS_HAPROXY}", text)
    text = re.sub(r"(\bssl-min-ver\s+)TLSv1\.[01]\b", r"\g<1>TLSv1.2", text)
    if "ssl-default-bind-curves" not in text and re.search(r"^global", text, re.M):
        text = re.sub(r"^(global[^\n]*\n)", rf"\1    ssl-default-bind-curves {GROUPS_HAPROXY}\n",
                      text, count=1, flags=re.M)
    return text


def _patch_openssl(text: str) -> str:
    text = re.sub(r"^(\s*(?:Groups|Curves)\s*=\s*).*$", rf"\g<1>{GROUPS_OPENSSL}", text,
                  flags=re.M | re.I)
    text = re.sub(r"^(\s*MinProtocol\s*=\s*)TLSv1(\.[01])?\s*$", r"\g<1>TLSv1.2", text,
                  flags=re.M | re.I)
    text = re.sub(r"^(\s*MaxProtocol\s*=\s*)TLSv1\.[0-2]\s*$", r"\g<1>TLSv1.3", text,
                  flags=re.M | re.I)
    return text


def _patch_ssh(text: str) -> str:
    if re.search(r"^\s*KexAlgorithms", text, re.M | re.I):
        text = re.sub(r"^(\s*KexAlgorithms\s+).*$", rf"\g<1>{SSH_KEX}", text, flags=re.M | re.I)
    else:
        text += f"\nKexAlgorithms {SSH_KEX}\n"
    text = re.sub(r"^(\s*Ciphers\s+).*$", rf"\g<1>{SSH_CIPHERS}", text, flags=re.M | re.I)
    return text


PATCHERS = {"nginx": _patch_nginx, "apache": _patch_apache, "haproxy": _patch_haproxy,
            "openssl": _patch_openssl, "sshd": _patch_ssh, "ssh": _patch_ssh}


def patch_config(cfg: ConfigScan) -> tuple[str, str] | None:
    fn = PATCHERS.get(cfg.kind)
    if not fn:
        return None
    original = Path(cfg.path).read_text()
    patched = fn(original)
    return (original, patched) if patched != original else None


# ---------------------------------------------------------------- plan

def build_plan(inv: Inventory) -> dict:
    by_service: dict[str, dict] = defaultdict(lambda: {"actions": {}, "findings": []})
    for f in inv.findings:
        if not f.migration or f.severity == "info" and f.migration != "deploy-pqc-proxy":
            continue
        for svc in (f.service or "(unassigned)").split(", "):
            s = by_service[svc]
            s["findings"].append(f.rule_id)
            a = s["actions"].setdefault(f.migration, {"action": f.migration, "evidence": [],
                                                      "severity": f.severity})
            if SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[a["severity"]]:
                a["severity"] = f.severity
            ev = f"{f.asset}: {f.evidence}"
            if len(a["evidence"]) < 5 and ev not in a["evidence"]:
                a["evidence"].append(ev)
    summary = {s["service"]: s for s in service_summary(inv)}
    services = []
    for svc, data in by_service.items():
        steps = sorted(data["actions"].values(),
                       key=lambda a: (ACTIONS.get(a["action"], (9, ""))[0],
                                      SEVERITY_ORDER[a["severity"]]))
        for st in steps:
            phase, desc = ACTIONS.get(st["action"], (9, st["action"]))
            st["phase"], st["description"] = phase, desc
        services.append({"service": svc, "status": summary.get(svc, {}).get("status", "review"),
                         "score": summary.get(svc, {}).get("score", 0), "steps": steps})
    services.sort(key=lambda s: -s["score"])
    return {"generated_at": inv.generated_at, "services": services}


def proxy_config_for(inv: Inventory, port_base: int = 8443) -> list[dict]:
    """A sidecar ingress-proxy definition for each endpoint that is not yet quantum-safe."""
    out = []
    summary = {s["service"]: s for s in service_summary(inv)}
    for i, ep in enumerate(inv.endpoints):
        if not ep.reachable or not summary.get(ep.name, {}).get("needs_migration"):
            continue
        host, port = ep.target.rsplit(":", 1)
        out.append({
            "name": f"{ep.name}-pqc", "mode": "ingress", "listen": f"0.0.0.0:{port_base + i}",
            "upstream": f"{host}:{port}", "upstream_tls": True, "policy": "strict",
            "cert": f"pki/{ep.name}.crt", "key": f"pki/{ep.name}.key", "ca": "pki/ca.crt",
            "require_client_cert": True,
        })
    return out


def write_migration(inv: Inventory, out_dir: Path, in_place: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    plan = build_plan(inv)
    patched_dir = out_dir / "patched"
    patches = []
    for cfg in inv.configs:
        res = patch_config(cfg)
        if not res:
            continue
        original, patched = res
        diff = "".join(difflib.unified_diff(original.splitlines(True), patched.splitlines(True),
                                            fromfile=cfg.path, tofile=cfg.path + " (migrated)"))
        if in_place:
            shutil.copy2(cfg.path, cfg.path + ".qs-bak")
            Path(cfg.path).write_text(patched)
            target = cfg.path
        else:
            prefix = re.sub(r"[^A-Za-z0-9_.-]", "_", cfg.service or "config")
            target = patched_dir / f"{prefix}-{Path(cfg.path).name}"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(patched)
        patches.append({"service": cfg.service, "file": cfg.path, "written_to": str(target),
                        "diff": diff})
    proxies = proxy_config_for(inv)
    plan["patches"] = [{k: v for k, v in p.items() if k != "diff"} for p in patches]
    plan["proxies"] = proxies
    (out_dir / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    (out_dir / "proxies.json").write_text(json.dumps({"proxies": proxies}, indent=2) + "\n")
    (out_dir / "plan.md").write_text(render_plan_md(plan, patches))
    return plan


def render_plan_md(plan: dict, patches: list[dict]) -> str:
    lines = ["# QuantumShield migration plan", "", f"Generated {plan['generated_at']}", ""]
    for s in plan["services"]:
        lines += [f"## {s['service']}  ({s['status']}, risk score {s['score']})", ""]
        phase = None
        for st in s["steps"]:
            if st["phase"] != phase:
                if phase is not None:
                    lines.append("")
                phase = st["phase"]
                lines.append(f"**{PHASES.get(phase, 'Other')}**")
                lines.append("")
            lines.append(f"- [{st['severity']}] {st['description']}")
            for ev in st["evidence"][:3]:
                lines.append(f"  - {ev}")
        lines.append("")
    if patches:
        lines += ["## Config patches", ""]
        for p in patches:
            lines += [f"### {p['file']}", "", "```diff", p["diff"].rstrip(), "```", ""]
    if plan.get("proxies"):
        lines += ["## Sidecar proxies (no change to the service)", "", "```json",
                  json.dumps({"proxies": plan["proxies"]}, indent=2), "```", ""]
    return "\n".join(lines) + "\n"
