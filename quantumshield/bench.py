"""Classical vs. hybrid post-quantum TLS benchmarks.

`bench_local` runs complete TLS 1.3 handshakes in-process over memory BIOs,
so it measures exactly:
  * handshake CPU time on the client and on the server
  * bytes on the wire in each direction (handshake only; tickets disabled)
  * handshake wall time without network latency

`bench_network` performs real TCP + TLS connections against live endpoints
(e.g. the demo services directly vs. through QuantumShield proxies) and
reports connection time, client CPU, bytes and, when an admin URL is given,
the proxy's server-side CPU per connection.
"""

from __future__ import annotations

import json
import socket
import ssl
import statistics
import tempfile
import time
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

from . import certs, tlsutil


@dataclass
class Scenario:
    name: str
    group: str
    cert_alg: str        # key algorithm for CA and leaf certificates
    label: str


DEFAULT_SCENARIOS = [
    Scenario("classical-rsa", "secp256r1", "rsa2048", "ECDHE P-256 + RSA-2048 (legacy)"),
    Scenario("classical-ecdsa", "X25519", "ecdsa-p256", "X25519 + ECDSA P-256"),
    Scenario("hybrid-ecdsa", "X25519MLKEM768", "ecdsa-p256", "X25519MLKEM768 + ECDSA P-256"),
    Scenario("hybrid-mldsa", "X25519MLKEM768", "mldsa65", "X25519MLKEM768 + ML-DSA-65"),
    Scenario("pqc-only", "MLKEM768", "mldsa65", "ML-KEM-768 + ML-DSA-65 (pure PQC)"),
    Scenario("hybrid-high", "SecP384r1MLKEM1024", "mldsa87",
             "SecP384r1MLKEM1024 + ML-DSA-87 (CNSA 2.0 level)"),
]


@dataclass
class Result:
    scenario: str
    label: str
    group: str
    cert_alg: str
    iterations: int
    mutual_tls: bool
    negotiated_group: str | None
    wall_ms_median: float
    wall_ms_p95: float
    client_cpu_ms: float
    server_cpu_ms: float
    bytes_client_to_server: int
    bytes_server_to_client: int
    bytes_total: int
    round_trips: int


def _pctl(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))]


def _make_pki(root: Path, alg: str) -> dict[str, str]:
    d = root / alg
    certs.init_ca(d, alg, name=f"Bench CA {alg}")
    s_crt, s_key = certs.issue(d, "server", alg, dns=["bench.local"])
    c_crt, c_key = certs.issue(d, "client", alg, dns=["client.local"])
    return {"ca": str(d / "ca.crt"), "server_crt": str(s_crt), "server_key": str(s_key),
            "client_crt": str(c_crt), "client_key": str(c_key)}


def _contexts(pki: dict[str, str], group: str, mutual: bool):
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.minimum_version = ssl.TLSVersion.TLSv1_3
    sctx.num_tickets = 0
    sctx.load_cert_chain(pki["server_crt"], pki["server_key"])
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.minimum_version = ssl.TLSVersion.TLSv1_3
    cctx.load_verify_locations(pki["ca"])
    if mutual:
        sctx.verify_mode = ssl.CERT_REQUIRED
        sctx.load_verify_locations(pki["ca"])
        cctx.load_cert_chain(pki["client_crt"], pki["client_key"])
    for ctx in (sctx, cctx):
        if not tlsutil.set_groups(ctx, group):
            raise RuntimeError(f"cannot select group {group}: {tlsutil.runtime_description()}")
    return sctx, cctx


def handshake_once(sctx: ssl.SSLContext, cctx: ssl.SSLContext) -> dict:
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = cctx.wrap_bio(c_in, c_out, server_hostname="bench.local")
    server = sctx.wrap_bio(s_in, s_out, server_side=True)
    c_cpu = s_cpu = 0.0
    c2s = s2c = 0
    flights = 0
    c_done = s_done = False
    t0 = time.perf_counter()
    for _ in range(20):
        if not c_done:
            t = time.thread_time()
            try:
                client.do_handshake()
                c_done = True
            except ssl.SSLWantReadError:
                pass
            c_cpu += time.thread_time() - t
        data = c_out.read()
        if data:
            c2s += len(data)
            flights += 1
            s_in.write(data)
        if not s_done:
            t = time.thread_time()
            try:
                server.do_handshake()
                s_done = True
            except ssl.SSLWantReadError:
                pass
            s_cpu += time.thread_time() - t
        data = s_out.read()
        if data:
            s2c += len(data)
            flights += 1
            c_in.write(data)
        if c_done and s_done and not data:
            break
    wall = time.perf_counter() - t0
    if not (c_done and s_done):
        raise RuntimeError("handshake did not complete")
    return {"wall": wall, "c_cpu": c_cpu, "s_cpu": s_cpu, "c2s": c2s, "s2c": s2c,
            "flights": flights, "group": tlsutil.negotiated_group(client)}


def bench_local(scenarios: list[Scenario] | None = None, iterations: int = 200,
                mutual: bool = True, warmup: int = 10) -> list[Result]:
    scenarios = scenarios or DEFAULT_SCENARIOS
    results = []
    with tempfile.TemporaryDirectory() as td:
        pkis: dict[str, dict[str, str]] = {}
        for sc in scenarios:
            if sc.cert_alg not in pkis:
                pkis[sc.cert_alg] = _make_pki(Path(td), sc.cert_alg)
            sctx, cctx = _contexts(pkis[sc.cert_alg], sc.group, mutual)
            for _ in range(warmup):
                handshake_once(sctx, cctx)
            runs = [handshake_once(sctx, cctx) for _ in range(iterations)]
            walls = [r["wall"] * 1000 for r in runs]
            results.append(Result(
                scenario=sc.name, label=sc.label, group=sc.group, cert_alg=sc.cert_alg,
                iterations=iterations, mutual_tls=mutual, negotiated_group=runs[-1]["group"],
                wall_ms_median=round(statistics.median(walls), 3),
                wall_ms_p95=round(_pctl(walls, 0.95), 3),
                client_cpu_ms=round(statistics.median(r["c_cpu"] for r in runs) * 1000, 3),
                server_cpu_ms=round(statistics.median(r["s_cpu"] for r in runs) * 1000, 3),
                bytes_client_to_server=runs[-1]["c2s"], bytes_server_to_client=runs[-1]["s2c"],
                bytes_total=runs[-1]["c2s"] + runs[-1]["s2c"],
                round_trips=(runs[-1]["flights"] + 1) // 2,
            ))
    return results


# ---------------------------------------------------------------- network benchmark

@dataclass
class NetTarget:
    name: str
    address: str              # host:port
    group: str | None = None  # None = library default / prefer list
    client_cert: str | None = None
    client_key: str | None = None
    admin_url: str | None = None   # QuantumShield proxy /stats URL for server CPU


@dataclass
class NetResult:
    name: str
    address: str
    iterations: int
    negotiated_group: str | None
    connect_ms_median: float
    connect_ms_p95: float
    tcp_ms_median: float
    tls_ms_median: float
    client_cpu_ms: float
    server_cpu_ms_per_conn: float | None
    bytes_client_to_server: int
    bytes_server_to_client: int
    bytes_total: int
    errors: int


def _client_ctx(t: NetTarget) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # measuring cost, not trust
    if t.group:
        tlsutil.set_groups(ctx, t.group)
    if t.client_cert:
        ctx.load_cert_chain(t.client_cert, t.client_key)
    return ctx


def _net_once(t: NetTarget, ctx: ssl.SSLContext) -> dict:
    host, _, port = t.address.rpartition(":")
    cpu0 = time.thread_time()
    t0 = time.perf_counter()
    sock = socket.create_connection((host, int(port)), timeout=10)
    t_tcp = time.perf_counter()
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=host)
    c2s = s2c = 0
    try:
        while True:
            try:
                obj.do_handshake()
                done = True
            except ssl.SSLWantReadError:
                done = False
            data = out.read()
            if data:
                c2s += len(data)
                sock.sendall(data)
            if done:
                break
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("peer closed during handshake")
            s2c += len(chunk)
            inc.write(chunk)
        t_end = time.perf_counter()
        cpu = time.thread_time() - cpu0
        group = tlsutil.negotiated_group(obj)
    finally:
        sock.close()
    return {"total": t_end - t0, "tcp": t_tcp - t0, "tls": t_end - t_tcp, "cpu": cpu,
            "c2s": c2s, "s2c": s2c, "group": group}


def _admin_cpu(url: str | None) -> tuple[float, int] | None:
    if not url:
        return None
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            data = json.loads(r.read())
    except (OSError, ValueError):
        return None
    snap = next(iter(data.values()))
    return snap["cpu_s"], snap["connections"]


def bench_network(targets: list[NetTarget], iterations: int = 100) -> list[NetResult]:
    out = []
    for t in targets:
        ctx = _client_ctx(t)
        runs, errors = [], 0
        for _ in range(3):
            try:
                _net_once(t, ctx)
            except (OSError, ssl.SSLError):
                pass
        before = _admin_cpu(t.admin_url)
        for _ in range(iterations):
            try:
                runs.append(_net_once(t, ctx))
            except (OSError, ssl.SSLError, ConnectionError):
                errors += 1
        after = _admin_cpu(t.admin_url)
        server_cpu = None
        if before and after and after[1] > before[1]:
            server_cpu = round((after[0] - before[0]) / (after[1] - before[1]) * 1000, 3)
        if not runs:
            out.append(NetResult(t.name, t.address, iterations, None, 0, 0, 0, 0, 0, None,
                                 0, 0, 0, errors))
            continue
        tot = [r["total"] * 1000 for r in runs]
        out.append(NetResult(
            name=t.name, address=t.address, iterations=len(runs),
            negotiated_group=runs[-1]["group"],
            connect_ms_median=round(statistics.median(tot), 3),
            connect_ms_p95=round(_pctl(tot, 0.95), 3),
            tcp_ms_median=round(statistics.median(r["tcp"] for r in runs) * 1000, 3),
            tls_ms_median=round(statistics.median(r["tls"] for r in runs) * 1000, 3),
            client_cpu_ms=round(statistics.median(r["cpu"] for r in runs) * 1000, 3),
            server_cpu_ms_per_conn=server_cpu,
            bytes_client_to_server=runs[-1]["c2s"], bytes_server_to_client=runs[-1]["s2c"],
            bytes_total=runs[-1]["c2s"] + runs[-1]["s2c"], errors=errors))
    return out


# ---------------------------------------------------------------- rendering

def to_markdown(local: list[Result] | None, net: list[NetResult] | None) -> str:
    lines = []
    if local:
        base = local[0]
        lines += ["### Handshake cost (in-process, TLS 1.3"
                  + (", mutual TLS" if base.mutual_tls else "") + f", n={base.iterations})", "",
                  "| Scenario | Group | Certs | Wall ms (p50) | Client CPU ms | Server CPU ms "
                  "| Client→Server B | Server→Client B | Total B | vs. baseline |",
                  "|---|---|---|---:|---:|---:|---:|---:|---:|---:|"]
        for r in local:
            ratio = r.bytes_total / base.bytes_total if base.bytes_total else 0
            lines.append(f"| {r.label} | {r.negotiated_group or r.group} | {r.cert_alg} | "
                         f"{r.wall_ms_median:.3f} | {r.client_cpu_ms:.3f} | {r.server_cpu_ms:.3f}"
                         f" | {r.bytes_client_to_server:,} | {r.bytes_server_to_client:,} | "
                         f"{r.bytes_total:,} | {ratio:.2f}x bytes |")
        lines.append("")
    if net:
        lines += ["### Live connections (TCP + TLS)", "",
                  "| Path | Group | Connect ms (p50) | p95 | TLS ms | Client CPU ms | "
                  "Proxy CPU ms/conn | Total bytes | Errors |",
                  "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
        for r in net:
            sc = f"{r.server_cpu_ms_per_conn:.3f}" if r.server_cpu_ms_per_conn is not None else "-"
            lines.append(f"| {r.name} | {r.negotiated_group or '-'} | {r.connect_ms_median:.3f} |"
                         f" {r.connect_ms_p95:.3f} | {r.tls_ms_median:.3f} | {r.client_cpu_ms:.3f}"
                         f" | {sc} | {r.bytes_total:,} | {r.errors} |")
        lines.append("")
    return "\n".join(lines)


def to_json(local, net) -> dict:
    return {"runtime": tlsutil.runtime_description(),
            "local": [asdict(r) for r in local or []],
            "network": [asdict(r) for r in net or []]}
