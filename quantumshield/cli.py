"""Command-line interface: `quantumshield <command>` (alias `qs`)."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, analyzer, bench, cbom, certs, config_scanner, dashboard, migrate, \
    report, tls_scanner, tlsutil
from .models import Inventory


def _load_inv(path: str) -> Inventory:
    return Inventory.from_dict(json.loads(Path(path).read_text()))


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str) + "\n")


# ---------------------------------------------------------------- scan

def cmd_scan(a) -> int:
    inv = Inventory(generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    tls_library=tlsutil.runtime_description())
    targets = list(a.endpoint or [])
    if a.targets_file:
        targets += [line.strip() for line in Path(a.targets_file).read_text().splitlines()
                    if line.strip() and not line.startswith("#")]
    if targets:
        ident = tls_scanner.ClientIdentity(a.client_cert, a.client_key)
        tls_scanner.scan_endpoints(targets, inv, ident)
    if a.config:
        config_scanner.scan_paths(a.config, inv)
    if not targets and not a.config:
        print("nothing to scan: pass --endpoint and/or --config", file=sys.stderr)
        return 2
    analyzer.analyze(inv)
    out = Path(a.output)
    out.mkdir(parents=True, exist_ok=True)
    _write_json(out / "inventory.json", inv.to_dict())
    _write_json(out / "cbom.json", cbom.build_cbom(inv))
    _write_json(out / "findings.json", [f.__dict__ for f in inv.findings])
    (out / "report.md").write_text(report.markdown_report(inv))
    dashboard.write(out / "dashboard.html", before=inv)
    print(report.text_summary(inv))
    print(f"\nWrote {out}/inventory.json, cbom.json (CycloneDX 1.6), findings.json, report.md, "
          "dashboard.html")
    if a.fail_on:
        order = analyzer.SEVERITY_ORDER
        if any(order[f.severity] <= order[a.fail_on] for f in inv.findings):
            return 1
    return 0


def cmd_report(a) -> int:
    inv = _load_inv(a.inventory)
    if a.format == "md":
        print(report.markdown_report(inv))
    elif a.format == "cbom":
        print(json.dumps(cbom.build_cbom(inv), indent=2))
    else:
        print(report.text_summary(inv))
    return 0


def cmd_migrate(a) -> int:
    inv = _load_inv(a.inventory)
    plan = migrate.write_migration(inv, Path(a.output), in_place=a.in_place)
    for s in plan["services"]:
        print(f"{s['service']}: {s['status']} (risk {s['score']})")
        for st in s["steps"]:
            print(f"  [{st['severity']:>8}] phase {st['phase']}: {st['description']}")
    print(f"\n{len(plan['patches'])} config patch(es), {len(plan['proxies'])} sidecar proxy "
          f"definition(s). Plan: {a.output}/plan.md")
    return 0


def cmd_compare(a) -> int:
    before, after = _load_inv(a.before), _load_inv(a.after)
    b = {s["service"]: s for s in analyzer.service_summary(before)}
    rows = []
    for s in analyzer.service_summary(after):
        prev = b.get(s["service"], {})
        rows.append([s["service"], prev.get("status", "-"), s["status"], prev.get("score", "-"),
                     s["score"], ", ".join(prev.get("kex", [])) or "-", ", ".join(s["kex"]) or "-"])
    print(report._table(rows, ["service", "before", "after", "risk before", "risk after",
                               "kex before", "kex after"]))
    return 0


# ---------------------------------------------------------------- pki

def cmd_pki(a) -> int:
    d = Path(a.dir)
    if a.pki_cmd == "init":
        crt = certs.init_ca(d, a.alg, a.name)
        print(f"CA ({a.alg}) written to {crt}")
    elif a.pki_cmd == "issue":
        for name in a.names:
            crt, key = certs.issue(d, name, a.alg, dns=a.dns or [name, "localhost"],
                                   trust_domain=a.trust_domain, days=a.days)
            print(f"{name}: {crt} ({a.alg}, {a.days} days, spiffe://{a.trust_domain}/{name})")
    elif a.pki_cmd == "revoke":
        serial = certs.revoke(d, Path(a.cert))
        print(f"revoked serial {serial}; proxies pick this up on the next connection")
    return 0


# ---------------------------------------------------------------- proxy

def cmd_proxy(a) -> int:
    from . import proxy
    proxy.setup_logging(a.log_level)
    if a.config:
        cfgs = proxy.load_configs(a.config)
    else:
        if not (a.mode and a.listen and a.upstream):
            print("pass --config, or --mode/--listen/--upstream", file=sys.stderr)
            return 2
        cfgs = [proxy.ProxyConfig(
            name=a.name or f"{a.mode}-{a.listen}", mode=a.mode, listen=a.listen,
            upstream=a.upstream, policy=a.policy, cert=a.cert, key=a.key, ca=a.ca,
            require_client_cert=not a.no_client_auth, allowed_ids=a.allow_id or [],
            server_name=a.server_name, upstream_tls=a.upstream_tls, groups=a.groups)]
    try:
        asyncio.run(proxy.run(cfgs, a.admin))
    except KeyboardInterrupt:
        pass
    return 0


# ---------------------------------------------------------------- bench

def _parse_net_target(spec: str) -> bench.NetTarget:
    # name=host:port[,group=X][,cert=..][,key=..][,admin=http://..]
    name, _, rest = spec.partition("=")
    parts = rest.split(",")
    t = bench.NetTarget(name=name, address=parts[0])
    for p in parts[1:]:
        k, _, v = p.partition("=")
        if k == "group":
            t.group = v
        elif k == "cert":
            t.client_cert = v
        elif k == "key":
            t.client_key = v
        elif k == "admin":
            t.admin_url = v
    return t


def cmd_bench(a) -> int:
    local = net = None
    if a.bench_cmd == "local":
        scen = bench.DEFAULT_SCENARIOS
        if a.scenarios:
            want = set(a.scenarios.split(","))
            scen = [s for s in scen if s.name in want]
        local = bench.bench_local(scen, a.iterations, mutual=not a.no_mtls)
    else:
        net = bench.bench_network([_parse_net_target(t) for t in a.target], a.iterations)
    md = bench.to_markdown(local, net)
    print(md)
    if a.output:
        out = Path(a.output)
        existing = json.loads(out.read_text()) if out.exists() and a.merge else {}
        data = bench.to_json(local, net)
        if a.merge:
            # Keep earlier results; new runs replace entries with the same name.
            for k, key in (("local", "scenario"), ("network", "name")):
                fresh = {r[key] for r in data[k]}
                data[k] = [r for r in existing.get(k, []) if r[key] not in fresh] + data[k]
        _write_json(out, data)
        out.with_suffix(".md").write_text(bench.to_markdown(
            [bench.Result(**r) for r in data["local"]] or None,
            [bench.NetResult(**r) for r in data["network"]] or None))
    return 0


def cmd_dashboard(a) -> int:
    before = _load_inv(a.before) if a.before else None
    after = _load_inv(a.after) if a.after else None
    bench_data = json.loads(Path(a.bench).read_text()) if a.bench else None
    plan = json.loads(Path(a.plan).read_text()) if a.plan else None
    out = dashboard.write(Path(a.output), before=before or after, after=after if before else None,
                          bench=bench_data, plan=plan)
    print(f"dashboard written to {out}")
    if a.serve:
        import functools
        import http.server
        handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                    directory=str(out.parent))
        print(f"serving on http://0.0.0.0:{a.serve}/{out.name}")
        http.server.ThreadingHTTPServer(("0.0.0.0", a.serve), handler).serve_forever()
    return 0


def cmd_get(a) -> int:
    """HTTPS GET that reports the negotiated key exchange (a PQC-aware curl)."""
    import socket
    import ssl
    from urllib.parse import urlsplit

    u = urlsplit(a.url)
    host, port = u.hostname, u.port or 443
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if a.ca:
        ctx.load_verify_locations(a.ca)
        ctx.check_hostname = not a.insecure
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if a.insecure:
        ctx.verify_mode = ssl.CERT_NONE
    if a.cert:
        ctx.load_cert_chain(a.cert, a.key)
    if a.groups and not tlsutil.set_groups(ctx, a.groups):
        print("this runtime cannot select groups", file=sys.stderr)
    try:
        with socket.create_connection((host, port), timeout=10) as raw, \
                ctx.wrap_socket(raw, server_hostname=host) as s:
            leaf = s.getpeercert(binary_form=True)
            info = certs.parse_der(leaf) if leaf else None
            print(f"* {s.version()} {s.cipher()[0]}  group={tlsutil.negotiated_group(s)}  "
                  f"server-sig={tlsutil.negotiated_sigalg(s)}")
            if info:
                key = info.public_key_detail or info.public_key_algorithm
                print(f"* server cert: {info.subject}  key={key}  "
                      f"ids={','.join(info.subject_alt_names)}")
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
                      f"User-Agent: quantumshield/{__version__}\r\n\r\n".encode())
            chunks = []
            try:
                while data := s.recv(65536):
                    chunks.append(data)
            except (ssl.SSLEOFError, ConnectionResetError):
                pass
    except (OSError, ssl.SSLError) as e:
        print(f"* connection failed: {e}", file=sys.stderr)
        return 1
    resp = b"".join(chunks).decode("utf-8", "replace")
    head, _, body = resp.partition("\r\n\r\n")
    if not head:
        print("* server closed the connection after the handshake (rejected by its policy)")
        return 1
    print("* " + head.splitlines()[0])
    print(body.strip())
    return 0


def cmd_info(a) -> int:
    print(f"quantumshield {__version__}")
    print(f"TLS runtime: {tlsutil.runtime_description()}")
    print(f"openssl CLI: {'.'.join(map(str, certs.openssl_version()))}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="quantumshield", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan TLS endpoints and config files; write inventory + CBOM")
    s.add_argument("-e", "--endpoint", action="append",
                   help="[name=]host:port (repeatable)")
    s.add_argument("--targets-file", help="file with one [name=]host:port per line")
    s.add_argument("-c", "--config", action="append",
                   help="[service=]path to a config file or directory (repeatable)")
    s.add_argument("--client-cert"), s.add_argument("--client-key")
    s.add_argument("-o", "--output", default="qs-out")
    s.add_argument("--fail-on", choices=list(analyzer.SEVERITY_ORDER),
                   help="exit 1 if a finding at this severity or worse exists (CI gate)")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("report", help="render an inventory")
    r.add_argument("inventory")
    r.add_argument("-f", "--format", choices=["text", "md", "cbom"], default="text")
    r.set_defaults(func=cmd_report)

    m = sub.add_parser("migrate", help="build a migration plan, patched configs, proxy configs")
    m.add_argument("inventory")
    m.add_argument("-o", "--output", default="qs-migration")
    m.add_argument("--in-place", action="store_true",
                   help="patch config files in place (keeps a .qs-bak copy)")
    m.set_defaults(func=cmd_migrate)

    c = sub.add_parser("compare", help="compare two inventories (before/after migration)")
    c.add_argument("before"), c.add_argument("after")
    c.set_defaults(func=cmd_compare)

    k = sub.add_parser("pki", help="workload-identity PKI (ML-DSA by default)")
    ksub = k.add_subparsers(dest="pki_cmd", required=True)
    ki = ksub.add_parser("init")
    ki.add_argument("--dir", default="pki")
    ki.add_argument("--alg", default="mldsa65", choices=list(certs.KEY_ALGS))
    ki.add_argument("--name", default="QuantumShield Root CA")
    kis = ksub.add_parser("issue")
    kis.add_argument("names", nargs="+")
    kis.add_argument("--dir", default="pki")
    kis.add_argument("--alg", default="mldsa65", choices=list(certs.KEY_ALGS))
    kis.add_argument("--dns", action="append")
    kis.add_argument("--trust-domain", default="quantumshield.local")
    kis.add_argument("--days", type=int, default=30)
    kr = ksub.add_parser("revoke")
    kr.add_argument("cert")
    kr.add_argument("--dir", default="pki")
    k.set_defaults(func=cmd_pki)

    x = sub.add_parser("proxy", help="run the hybrid post-quantum mTLS proxy")
    x.add_argument("--config", help="JSON file with one or more proxy definitions")
    x.add_argument("--name"), x.add_argument("--mode", choices=["ingress", "egress"])
    x.add_argument("--listen"), x.add_argument("--upstream")
    x.add_argument("--policy", choices=list(tlsutil.POLICIES), default="strict")
    x.add_argument("--groups", help="explicit OpenSSL group list (overrides --policy)")
    x.add_argument("--cert"), x.add_argument("--key"), x.add_argument("--ca")
    x.add_argument("--no-client-auth", action="store_true")
    x.add_argument("--allow-id", action="append", help="allowed peer SPIFFE ID (repeatable)")
    x.add_argument("--server-name"), x.add_argument("--upstream-tls", action="store_true")
    x.add_argument("--admin", help="host:port for /stats and /healthz")
    x.add_argument("--log-level", default="INFO")
    x.set_defaults(func=cmd_proxy)

    b = sub.add_parser("bench", help="benchmark classical vs hybrid PQC TLS")
    bsub = b.add_subparsers(dest="bench_cmd", required=True)
    bl = bsub.add_parser("local", help="in-process handshake benchmark")
    bl.add_argument("-n", "--iterations", type=int, default=200)
    bl.add_argument("--no-mtls", action="store_true")
    bl.add_argument("--scenarios", help="comma-separated subset of: " +
                    ", ".join(s.name for s in bench.DEFAULT_SCENARIOS))
    bn = bsub.add_parser("net", help="live-connection benchmark")
    bn.add_argument("-t", "--target", action="append", required=True,
                    help="name=host:port[,group=G][,cert=F,key=F][,admin=URL]")
    bn.add_argument("-n", "--iterations", type=int, default=100)
    for bp in (bl, bn):
        bp.add_argument("-o", "--output", help="write JSON (and .md) results here")
        bp.add_argument("--merge", action="store_true",
                        help="keep the other benchmark section already in --output")
    b.set_defaults(func=cmd_bench)

    d = sub.add_parser("dashboard", help="render an HTML dashboard")
    d.add_argument("--before"), d.add_argument("--after")
    d.add_argument("--bench"), d.add_argument("--plan")
    d.add_argument("-o", "--output", default="dashboard.html")
    d.add_argument("--serve", type=int, help="also serve it on this port")
    d.set_defaults(func=cmd_dashboard)

    g = sub.add_parser("get", help="HTTPS GET showing the negotiated (PQC) key exchange")
    g.add_argument("url")
    g.add_argument("--groups", help="offer only these groups, e.g. X25519 to act as a legacy client")
    g.add_argument("--cert"), g.add_argument("--key"), g.add_argument("--ca")
    g.add_argument("-k", "--insecure", action="store_true")
    g.set_defaults(func=cmd_get)

    i = sub.add_parser("info",help="show the TLS runtime's post-quantum capabilities")
    i.set_defaults(func=cmd_info)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
