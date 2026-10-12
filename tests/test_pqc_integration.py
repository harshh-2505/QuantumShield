"""End-to-end tests of the hybrid proxy, scanner and benchmark against real OpenSSL 3.5.

Skipped unless the runtime has ML-KEM (OpenSSL 3.5+) and group control
(Python 3.15+); run them in the QuantumShield image:
    docker run --rm --entrypoint pytest quantumshield -q
"""

import asyncio
import json
import shutil
import socket
import ssl
import threading
import time

import pytest

from quantumshield import bench, certs, tls_scanner, tlsutil
from quantumshield.models import Inventory
from quantumshield.proxy import Proxy, ProxyConfig

pytestmark = pytest.mark.skipif(
    not (tlsutil.HAS_GROUP_API and tlsutil.OPENSSL_HAS_MLKEM and certs.openssl_version() >= (3, 5)),
    reason="needs Python 3.15+ and OpenSSL 3.5+")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Harness:
    """Runs an echo upstream plus proxies on a background event loop."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.proxies = []

    def call(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(10)

    def echo(self) -> int:
        port = _free_port()

        async def handle(r, w):
            while data := await r.read(65536):
                w.write(b"echo:" + data)
                await w.drain()
            w.close()

        self.call(asyncio.start_server(handle, "127.0.0.1", port))
        return port

    def proxy(self, cfg: ProxyConfig) -> Proxy:
        p = Proxy(cfg)
        self.call(p.start())
        self.proxies.append(p)
        return p

    def close(self):
        async def shutdown():
            for p in self.proxies:
                if p.server:
                    p.server.close()
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        self.call(shutdown())
        self.loop.call_soon_threadsafe(self.loop.stop)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    certs.init_ca(d, "mldsa65")
    for name in ("server", "client", "intruder", "revoked"):
        certs.issue(d, name, "mldsa65")
    return d


@pytest.fixture
def harness():
    h = Harness()
    yield h
    h.close()


def _client(pki, name="client", groups=tlsutil.HYBRID_ONLY):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(pki / "ca.crt")
    ctx.load_cert_chain(pki / f"{name}.crt", pki / f"{name}.key")
    tlsutil.set_groups(ctx, groups)
    return ctx


def _roundtrip(ctx, port, payload=b"hello"):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, \
            ctx.wrap_socket(raw, server_hostname="server") as s:
        s.sendall(payload)
        s.settimeout(3)
        data = s.recv(1024)
        return tlsutil.negotiated_group(s), tlsutil.negotiated_sigalg(s), data


def _ingress(pki, port, upstream, **kw):
    return ProxyConfig(name="t-ingress", mode="ingress", listen=f"127.0.0.1:{port}",
                       upstream=f"127.0.0.1:{upstream}", cert=str(pki / "server.crt"),
                       key=str(pki / "server.key"), ca=str(pki / "ca.crt"), **kw)


def test_ingress_hybrid_mtls(pki, harness):
    up = harness.echo()
    port = _free_port()
    p = harness.proxy(_ingress(pki, port, up,
                               allowed_ids=["spiffe://quantumshield.local/client"]))
    group, sigalg, data = _roundtrip(_client(pki), port)
    assert group == "X25519MLKEM768"
    assert sigalg == "mldsa65"
    assert data == b"echo:hello"
    assert p.stats.groups["X25519MLKEM768"] == 1


def test_strict_policy_refuses_classical_client(pki, harness):
    up = harness.echo()
    port = _free_port()
    harness.proxy(_ingress(pki, port, up))
    with pytest.raises((ssl.SSLError, ConnectionError)):
        _roundtrip(_client(pki, groups="X25519:secp256r1"), port)


def test_prefer_policy_falls_back(pki, harness):
    up = harness.echo()
    port = _free_port()
    harness.proxy(_ingress(pki, port, up, policy="prefer"))
    group, _, data = _roundtrip(_client(pki, groups="X25519"), port)
    assert group == "x25519" and data == b"echo:hello"


def test_identity_allow_list_and_revocation(pki, harness):
    up = harness.echo()
    port = _free_port()
    p = harness.proxy(_ingress(pki, port, up, allowed_ids=[
        "spiffe://quantumshield.local/client", "spiffe://quantumshield.local/revoked"]))
    assert _roundtrip(_client(pki, "intruder"), port)[2] == b""
    assert p.stats.rejected_identity == 1
    assert _roundtrip(_client(pki, "revoked"), port)[2] == b"echo:hello"
    certs.revoke(pki, pki / "revoked.crt")
    time.sleep(1.1)   # proxy re-checks rotated/revocation files once per second
    assert _roundtrip(_client(pki, "revoked"), port)[2] == b""
    assert p.stats.rejected_revoked == 1


def test_egress_to_ingress_chain(pki, harness):
    up = harness.echo()
    in_port, out_port = _free_port(), _free_port()
    harness.proxy(_ingress(pki, in_port, up,
                           allowed_ids=["spiffe://quantumshield.local/client"]))
    eg = harness.proxy(ProxyConfig(
        name="t-egress", mode="egress", listen=f"127.0.0.1:{out_port}",
        upstream=f"127.0.0.1:{in_port}", server_name="server",
        cert=str(pki / "client.crt"), key=str(pki / "client.key"), ca=str(pki / "ca.crt"),
        allowed_ids=["spiffe://quantumshield.local/server"]))
    with socket.create_connection(("127.0.0.1", out_port), timeout=5) as s:
        s.sendall(b"plain")
        s.settimeout(3)
        assert s.recv(1024) == b"echo:plain"
    assert eg.stats.groups["X25519MLKEM768"] == 1


def test_scanner_sees_pqc_endpoint(pki, harness):
    up = harness.echo()
    port = _free_port()
    harness.proxy(_ingress(pki, port, up))
    inv = Inventory(generated_at="now")
    ident = tls_scanner.ClientIdentity(str(pki / "client.crt"), str(pki / "client.key"))
    ep = tls_scanner.scan_endpoint(f"svc=127.0.0.1:{port}", ident, inv)
    assert ep.negotiated_group == "X25519MLKEM768"
    assert "X25519MLKEM768" in ep.pqc_groups and "X25519" not in ep.groups_supported
    assert ep.protocols["TLSv1.3"] and not ep.protocols["TLSv1.2"]
    assert ep.peer_requires_client_cert
    leaf = inv.certificates[ep.certificate_chain[0]]
    assert leaf.public_key_algorithm == "ML-DSA-65"
    assert "URI:spiffe://quantumshield.local/server" in leaf.subject_alt_names


def test_bench_local_smoke():
    res = bench.bench_local([s for s in bench.DEFAULT_SCENARIOS
                             if s.name in ("classical-ecdsa", "hybrid-mldsa")], iterations=5,
                            warmup=1)
    classical, hybrid = res
    assert hybrid.negotiated_group == "X25519MLKEM768"
    assert hybrid.bytes_total > classical.bytes_total
    json.dumps(bench.to_json(res, None))


# --------------------------------------------------------------------------- hardening

def _refused(ctx, port) -> bool:
    try:
        return _roundtrip(ctx, port)[2] == b""
    except (ssl.SSLError, ConnectionError, socket.timeout):
        return True


def _wait(pred, timeout=5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.05)
    return pred()


@pytest.fixture
def own_pki(pki, tmp_path):
    """A private copy of the PKI for tests that corrupt or rotate files."""
    d = tmp_path / "pki"
    shutil.copytree(pki, d)
    (d / "revoked.json").unlink(missing_ok=True)
    return d


def test_pq_only_sigalgs_refuse_classical_client_cert(pki, harness):
    certs.issue(pki, "ecclient", "ecdsa-p256")
    up = harness.echo()
    port = _free_port()
    harness.proxy(_ingress(pki, port, up, sigalgs="mldsa65:mldsa87"))
    assert _roundtrip(_client(pki), port)[2] == b"echo:hello"
    assert _refused(_client(pki, "ecclient"), port)
    # Without the restriction the same ECDSA certificate (same CA) is accepted.
    port2 = _free_port()
    harness.proxy(_ingress(pki, port2, up))
    assert _roundtrip(_client(pki, "ecclient"), port2)[2] == b"echo:hello"


def test_unreadable_revocation_list_fails_closed(own_pki, harness):
    up = harness.echo()
    port = _free_port()
    p = harness.proxy(_ingress(own_pki, port, up))
    assert _roundtrip(_client(own_pki), port)[2] == b"echo:hello"
    (own_pki / "revoked.json").write_text("{not json")
    time.sleep(1.1)
    assert _refused(_client(own_pki), port)
    assert p.stats.rejected_revoked == 1
    (own_pki / "revoked.json").write_text("[]")
    time.sleep(1.1)
    assert _roundtrip(_client(own_pki), port)[2] == b"echo:hello"


def test_broken_rotation_keeps_serving_old_certificate(own_pki, harness):
    up = harness.echo()
    port = _free_port()
    p = harness.proxy(_ingress(own_pki, port, up))
    good = (own_pki / "server.crt").read_bytes()
    # Half-finished rotation: the certificate no longer matches the key.
    (own_pki / "server.crt").write_bytes((own_pki / "client.crt").read_bytes())
    time.sleep(1.1)
    assert _roundtrip(_client(own_pki), port)[2] == b"echo:hello"
    assert p.stats.reload_failures >= 1
    (own_pki / "server.crt").write_bytes(good)
    time.sleep(1.1)
    assert _roundtrip(_client(own_pki), port)[2] == b"echo:hello"


def test_connection_cap_and_idle_timeout(pki, harness):
    up = harness.echo()
    port = _free_port()
    p = harness.proxy(_ingress(pki, port, up, max_connections=1, idle_timeout=1))
    ctx = _client(pki)
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    held = ctx.wrap_socket(raw, server_hostname="server")
    held.sendall(b"hold")
    held.settimeout(3)
    assert held.recv(1024) == b"echo:hold"
    assert _refused(ctx, port)
    assert p.stats.rejected_overload == 1
    # The held connection goes quiet and is closed by the idle timeout, freeing the slot.
    assert _wait(lambda: p.stats.idle_timeouts == 1 and p.stats.active == 0)
    held.close()
    assert _roundtrip(ctx, port)[2] == b"echo:hello"


def test_start_rejects_unsafe_config(pki, harness):
    from quantumshield.proxy import ConfigError
    with pytest.raises(ConfigError):
        harness.proxy(ProxyConfig(
            name="t-bad-egress", mode="egress", listen=f"127.0.0.1:{_free_port()}",
            upstream="127.0.0.1:1", cert=str(pki / "client.crt"),
            key=str(pki / "client.key")))
