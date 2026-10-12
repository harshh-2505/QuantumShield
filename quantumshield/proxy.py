"""Hybrid post-quantum mutual-TLS proxy (sidecar).

Modes
-----
ingress   TLS 1.3 + hybrid ML-KEM listener  ->  local upstream (plain TCP or legacy TLS)
egress    local plain-TCP listener          ->  remote ingress over TLS 1.3 + hybrid ML-KEM

An egress proxy next to service A and an ingress proxy next to service B give
A->B traffic hybrid post-quantum protection and mutual workload
authentication without touching either service.

Key exchange, signatures and certificate validation are all performed by
OpenSSL (3.5+ for ML-KEM / ML-DSA) through Python's `ssl` module.

Operational features
--------------------
* policy: strict (hybrid groups only), prefer (hybrid first, classical
  fallback) or classical (for baseline benchmarks)
* mutual TLS with SPIFFE-style URI SANs and an optional allow-list
* revocation list (serials in <ca dir>/revoked.json), checked per connection
* hot key rotation: cert/key/CA files are re-read when they change
* /stats and /healthz on an admin port (JSON), JSON-lines handshake log

Hardening
---------
* configs are validated before anything listens: egress must verify the
  remote (CA + hostname), ingress demanding client certs must have a CA,
  unverified legacy-TLS upstreams are only allowed on loopback
* optional post-quantum-only authentication (`sigalgs`, e.g. "mldsa65:mldsa87")
* fail-closed revocation: an unreadable revocation list rejects every peer
* a bad rotation (half-written cert/key) keeps serving the previous material
* connection cap, handshake / connect / idle timeouts
* private keys readable by group/other are refused
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import ipaddress
import re
import signal
import ssl
import stat
import sys
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path

from . import tlsutil

log = logging.getLogger("quantumshield.proxy")


@dataclass
class ProxyConfig:
    name: str
    mode: str                       # ingress | egress
    listen: str                     # host:port
    upstream: str                   # host:port
    policy: str = "strict"          # strict | prefer | classical
    cert: str | None = None
    key: str | None = None
    ca: str | None = None
    require_client_cert: bool = True
    allowed_ids: list[str] = field(default_factory=list)   # e.g. spiffe://qs.local/orders
    server_name: str | None = None  # egress: expected name of the remote service
    upstream_tls: bool = False      # ingress: upstream itself speaks (legacy) TLS
    upstream_ca: str | None = None  # ingress: verify legacy upstream with this CA
    revocation_list: str | None = None
    groups: str | None = None       # explicit OpenSSL group list overrides policy
    sigalgs: str | None = None      # e.g. "mldsa65:mldsa87" = post-quantum authentication only
    max_connections: int = 1024
    handshake_timeout: float = 10.0
    connect_timeout: float = 10.0
    idle_timeout: float = 300.0     # close a relayed connection idle this long (0 = never)
    insecure_skip_verify: bool = False   # egress only; for lab use, never production

    @staticmethod
    def from_dict(d: dict) -> "ProxyConfig":
        known = ProxyConfig.__dataclass_fields__
        unknown = set(d) - set(known)
        if unknown:
            raise ConfigError(f"unknown proxy setting(s): {', '.join(sorted(unknown))}")
        return ProxyConfig(**d)

    def validate(self) -> list[str]:
        """Raise ConfigError for unsafe or broken settings; return warnings."""
        errors, warnings = [], []
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", self.name or ""):
            errors.append("name must be 1-64 characters of letters, digits, _ . : -")
        if self.mode not in ("ingress", "egress"):
            errors.append("mode must be 'ingress' or 'egress'")
        if self.policy not in tlsutil.POLICIES:
            errors.append(f"policy must be one of {', '.join(tlsutil.POLICIES)}")
        for label, addr in (("listen", self.listen), ("upstream", self.upstream)):
            try:
                _hostport(addr)
            except (ValueError, AttributeError):
                errors.append(f"{label} must be host:port")
        if bool(self.cert) != bool(self.key):
            errors.append("cert and key must be given together")
        if self.max_connections < 1:
            errors.append("max_connections must be at least 1")
        if self.mode == "ingress":
            if not self.cert:
                errors.append("ingress needs a server certificate (cert/key)")
            if self.require_client_cert and not self.ca:
                errors.append("require_client_cert needs a CA to verify clients (ca)")
            if self.require_client_cert and not self.allowed_ids:
                warnings.append("no allowed_ids: any certificate from the CA is accepted")
            if self.upstream_tls and not self.upstream_ca and not _is_loopback(self.upstream):
                errors.append("unverified upstream TLS is only allowed to a loopback upstream; "
                              "set upstream_ca")
            if self.insecure_skip_verify:
                errors.append("insecure_skip_verify applies to egress only")
        else:
            if not self.ca and not self.insecure_skip_verify:
                errors.append("egress must verify the remote: set ca (or insecure_skip_verify "
                              "for lab use)")
            if self.insecure_skip_verify:
                warnings.append("insecure_skip_verify: the remote is NOT authenticated")
            if not self.allowed_ids:
                warnings.append("no allowed_ids: any certificate from the CA is accepted as "
                                "the remote service")
            if not _is_loopback(self.listen):
                warnings.append("egress listener is not on loopback; other hosts can use "
                                "this workload's identity")
        if self.policy == "classical":
            warnings.append("classical policy: traffic is NOT protected against "
                            "harvest-now-decrypt-later")
        if self.key:
            try:
                mode = os.stat(self.key).st_mode
                if mode & (stat.S_IRWXG | stat.S_IRWXO) and os.name == "posix" and \
                        not os.environ.get("QS_ALLOW_SHARED_KEYS"):
                    errors.append(f"private key {self.key} is readable by group/other; "
                                  "chmod 600 it")
            except FileNotFoundError:
                errors.append(f"private key {self.key} not found")
        if errors:
            raise ConfigError(f"proxy {self.name!r}: " + "; ".join(errors))
        return warnings


class ConfigError(ValueError):
    pass


def _is_loopback(addr: str) -> bool:
    host = addr.rpartition(":")[0].strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _hostport(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    p = int(port)
    if not 0 < p < 65536:
        raise ValueError(f"bad port in {s!r}")
    return host.strip("[]") or "0.0.0.0", p


class Stats:
    def __init__(self) -> None:
        self.started = time.time()
        self.cpu_start = time.process_time()
        self.connections = 0
        self.active = 0
        self.handshake_failures = 0
        self.rejected_revoked = 0
        self.rejected_identity = 0
        self.rejected_overload = 0
        self.idle_timeouts = 0
        self.reload_failures = 0
        self.bytes_up = 0
        self.bytes_down = 0
        self.groups: Counter[str] = Counter()
        self.sigalgs: Counter[str] = Counter()
        self.handshake_ms: deque[float] = deque(maxlen=2000)

    def snapshot(self) -> dict:
        hs = sorted(self.handshake_ms)
        med = hs[len(hs) // 2] if hs else None
        return {
            "uptime_s": round(time.time() - self.started, 1),
            "cpu_s": round(time.process_time() - self.cpu_start, 4),
            "connections": self.connections, "active": self.active,
            "handshake_failures": self.handshake_failures,
            "rejected_revoked": self.rejected_revoked,
            "rejected_identity": self.rejected_identity,
            "rejected_overload": self.rejected_overload,
            "idle_timeouts": self.idle_timeouts,
            "reload_failures": self.reload_failures,
            "bytes_up": self.bytes_up, "bytes_down": self.bytes_down,
            "groups": dict(self.groups), "sigalgs": dict(self.sigalgs),
            "handshake_ms_median": round(med, 3) if med is not None else None,
            "tls_runtime": tlsutil.runtime_description(),
        }


class ContextManager:
    """Builds SSL contexts and rebuilds them when cert/key/CA files change (rotation)."""

    CHECK_INTERVAL = 1.0   # seconds between checks for rotated files

    def __init__(self, cfg: ProxyConfig, stats: "Stats | None" = None) -> None:
        self.cfg = cfg
        self.stats = stats
        self.revocation_error: str | None = None
        self._stamp: str | None = None
        self._checked = 0.0
        self._ctx: ssl.SSLContext | None = None
        self._upstream_ctx: ssl.SSLContext | None = None
        self.revoked: set[str] = set()
        rl = cfg.revocation_list or (str(Path(cfg.ca).parent / "revoked.json") if cfg.ca else None)
        self.revocation_path = Path(rl) if rl else None

    def _files(self) -> list[Path]:
        files = [Path(p) for p in (self.cfg.cert, self.cfg.key, self.cfg.ca) if p]
        if self.revocation_path:
            files.append(self.revocation_path)
        return files

    def _current_stamp(self) -> str:
        # Content hash rather than mtime: robust on network/synced filesystems.
        h = hashlib.sha256()
        for f in self._files():
            h.update(str(f).encode())
            try:
                h.update(f.read_bytes())
            except FileNotFoundError:
                h.update(b"<missing>")
        return h.hexdigest()

    def context(self) -> ssl.SSLContext:
        now = time.monotonic()
        if self._ctx is not None and now - self._checked < self.CHECK_INTERVAL:
            return self._ctx
        self._checked = now
        stamp = self._current_stamp()
        if stamp != self._stamp or self._ctx is None:
            reloaded = self._ctx is not None
            try:
                ctx = self._build()
            except (OSError, ssl.SSLError, ValueError) as e:
                if not reloaded:
                    raise
                # Mid-rotation (e.g. new cert written, key not yet): keep serving the old
                # material and retry on the next check.
                if self.stats:
                    self.stats.reload_failures += 1
                log.warning(json.dumps({"event": "context-reload-failed", "proxy": self.cfg.name,
                                        "error": str(e)[:200]}))
                return self._ctx
            self._ctx = ctx
            self._stamp = stamp
            self._load_revoked()
            log.info(json.dumps({"event": "context-reloaded" if reloaded else "context-loaded",
                                 "proxy": self.cfg.name, "cert": self.cfg.cert}))
        return self._ctx

    def _load_revoked(self) -> None:
        """Fail closed: a revocation list that exists but cannot be read blocks all peers."""
        self.revocation_error = None
        if not (self.revocation_path and self.revocation_path.exists()):
            self.revoked = set()
            return
        try:
            data = json.loads(self.revocation_path.read_text())
            if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
                raise ValueError("expected a JSON list of hex serial strings")
            self.revoked = {x.lower().lstrip("0") for x in data}
        except (ValueError, OSError) as e:
            self.revocation_error = f"revocation list unreadable: {e}"
            log.error(json.dumps({"event": "revocation-list-error", "proxy": self.cfg.name,
                                  "path": str(self.revocation_path), "error": str(e)[:200]}))

    def _groups(self) -> str:
        return self.cfg.groups or tlsutil.POLICIES[self.cfg.policy]

    def _build(self) -> ssl.SSLContext:
        cfg = self.cfg
        server = cfg.mode == "ingress"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if not tlsutil.set_groups(ctx, self._groups()):
            if cfg.policy == "strict" and not tlsutil.OPENSSL_HAS_MLKEM:
                raise RuntimeError("strict policy needs OpenSSL 3.5+ with ML-KEM")
            log.warning("runtime cannot pin groups; using OpenSSL defaults (%s)",
                        tlsutil.runtime_description())
        if cfg.sigalgs and not tlsutil.set_sigalgs(ctx, cfg.sigalgs):
            raise RuntimeError("this runtime cannot restrict signature algorithms "
                               "(needs Python 3.15+)")
        if cfg.cert:
            ctx.load_cert_chain(cfg.cert, cfg.key)
        if cfg.ca:
            ctx.load_verify_locations(cfg.ca)
        # Session tickets/resumption would skip the per-connection identity, revocation and
        # policy checks, so every connection does a full handshake.
        ctx.options |= ssl.OP_NO_TICKET
        if server:
            ctx.verify_mode = ssl.CERT_REQUIRED if cfg.require_client_cert else ssl.CERT_NONE
            ctx.num_tickets = 0
        elif cfg.insecure_skip_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def upstream_context(self) -> ssl.SSLContext | None:
        if not self.cfg.upstream_tls:
            return None
        if self._upstream_ctx is None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if self.cfg.upstream_ca:
                ctx.load_verify_locations(self.cfg.upstream_ca)
            else:
                # Legacy service on the same host/pod: link is loopback-only.
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._upstream_ctx = ctx
        return self._upstream_ctx


def _peer_identity(cert: dict | None) -> tuple[list[str], str | None]:
    if not cert:
        return [], None
    ids = [v for k, v in cert.get("subjectAltName", ()) if k == "URI"]
    serial = cert.get("serialNumber")
    return ids, serial.lower().lstrip("0") if serial else None


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, count) -> None:
    try:
        while data := await reader.read(65536):
            count(len(data))
            writer.write(data)
            await writer.drain()
    except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError, OSError):
        pass
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
            else:
                writer.close()
        except (OSError, RuntimeError):
            pass


class Proxy:
    def __init__(self, cfg: ProxyConfig, stats: Stats | None = None) -> None:
        self.cfg = cfg
        self.stats = stats or Stats()
        self.ctxm = ContextManager(cfg, self.stats)
        self.server: asyncio.base_events.Server | None = None
        self._slots = asyncio.Semaphore(cfg.max_connections)

    def _authorize(self, ssl_obj) -> str | None:
        """Returns a rejection reason, or None if the peer is acceptable."""
        cert = ssl_obj.getpeercert()
        ids, serial = _peer_identity(cert)
        if self.ctxm.revocation_error and cert is not None:
            self.stats.rejected_revoked += 1
            return self.ctxm.revocation_error
        if serial and serial in self.ctxm.revoked:
            self.stats.rejected_revoked += 1
            return f"certificate serial {serial} is revoked"
        if self.cfg.allowed_ids and cert is not None and not set(ids) & set(self.cfg.allowed_ids):
            self.stats.rejected_identity += 1
            return f"identity {ids or 'none'} not in allow-list"
        return None

    def _record(self, ssl_obj, ms: float, peer) -> dict:
        group = tlsutil.negotiated_group(ssl_obj) or "unknown"
        sigalg = tlsutil.negotiated_sigalg(ssl_obj, server_side=False) or "unknown"
        ids, _ = _peer_identity(ssl_obj.getpeercert())
        self.stats.groups[group] += 1
        self.stats.sigalgs[sigalg] += 1
        self.stats.handshake_ms.append(ms)
        rec = {"event": "handshake", "proxy": self.cfg.name, "peer": str(peer),
               "version": ssl_obj.version(), "cipher": ssl_obj.cipher()[0], "group": group,
               "server_sigalg": sigalg, "peer_ids": ids, "ms": round(ms, 3)}
        log.info(json.dumps(rec))
        return rec

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        if self._slots.locked():
            self.stats.rejected_overload += 1
            log.warning(json.dumps({"event": "rejected", "proxy": self.cfg.name,
                                    "peer": str(peer), "reason": "max_connections reached"}))
            writer.close()
            return
        async with self._slots:
            await self._serve(reader, writer, peer)

    async def _serve(self, reader, writer, peer) -> None:
        cfg = self.cfg
        self.stats.connections += 1
        self.stats.active += 1
        up_writer = None
        try:
            if self.cfg.mode == "ingress":
                ctx = self.ctxm.context()
                t0 = time.perf_counter()
                try:
                    await writer.start_tls(ctx, ssl_handshake_timeout=cfg.handshake_timeout)
                except (ssl.SSLError, ConnectionError, OSError, asyncio.TimeoutError) as e:
                    self.stats.handshake_failures += 1
                    log.info(json.dumps({"event": "handshake-failed", "proxy": self.cfg.name,
                                         "peer": str(peer), "error": str(e)[:200]}))
                    return
                ms = (time.perf_counter() - t0) * 1000
                ssl_obj = writer.get_extra_info("ssl_object")
                self._record(ssl_obj, ms, peer)
                if reason := self._authorize(ssl_obj):
                    log.info(json.dumps({"event": "rejected", "proxy": self.cfg.name,
                                         "peer": str(peer), "reason": reason}))
                    return
                host, port = _hostport(self.cfg.upstream)
                up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(
                    host, port, ssl=self.ctxm.upstream_context(),
                    server_hostname=host if cfg.upstream_tls else None), cfg.connect_timeout)
            else:
                ctx = self.ctxm.context()
                host, port = _hostport(self.cfg.upstream)
                t0 = time.perf_counter()
                try:
                    up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(
                        host, port, ssl=ctx, server_hostname=cfg.server_name or host,
                        ssl_handshake_timeout=cfg.handshake_timeout),
                        cfg.connect_timeout + cfg.handshake_timeout)
                except (ssl.SSLError, ConnectionError, OSError, asyncio.TimeoutError) as e:
                    self.stats.handshake_failures += 1
                    log.info(json.dumps({"event": "handshake-failed", "proxy": self.cfg.name,
                                         "upstream": self.cfg.upstream, "error": str(e)[:200]}))
                    return
                ms = (time.perf_counter() - t0) * 1000
                ssl_obj = up_writer.get_extra_info("ssl_object")
                self._record(ssl_obj, ms, self.cfg.upstream)
                if reason := self._authorize(ssl_obj):
                    log.info(json.dumps({"event": "rejected", "proxy": self.cfg.name,
                                         "upstream": self.cfg.upstream, "reason": reason}))
                    return

            def up(n):
                self.stats.bytes_up += n

            def down(n):
                self.stats.bytes_down += n

            activity = [time.monotonic()]

            def touch_up(n):
                activity[0] = time.monotonic()
                up(n)

            def touch_down(n):
                activity[0] = time.monotonic()
                down(n)

            pipes = asyncio.gather(_pipe(reader, up_writer, touch_up),
                                   _pipe(up_reader, writer, touch_down))
            if cfg.idle_timeout > 0:
                while not pipes.done():
                    await asyncio.wait({pipes}, timeout=min(cfg.idle_timeout, 5.0))
                    if not pipes.done() and \
                            time.monotonic() - activity[0] > cfg.idle_timeout:
                        self.stats.idle_timeouts += 1
                        pipes.cancel()
                        break
                try:
                    await pipes
                except asyncio.CancelledError:
                    if not pipes.cancelled():
                        raise
            else:
                await pipes
        except asyncio.TimeoutError:
            log.info(json.dumps({"event": "upstream-timeout", "proxy": self.cfg.name,
                                 "upstream": self.cfg.upstream}))
        except (ConnectionError, OSError) as e:
            log.info(json.dumps({"event": "upstream-error", "proxy": self.cfg.name,
                                 "error": str(e)[:200]}))
        finally:
            self.stats.active -= 1
            for w in (writer, up_writer):
                if w is not None:
                    try:
                        w.close()
                    except (OSError, RuntimeError):
                        pass

    async def start(self) -> None:
        for w in self.cfg.validate():
            log.warning(json.dumps({"event": "config-warning", "proxy": self.cfg.name,
                                    "warning": w}))
        self.ctxm.context()   # fail fast on bad certificates
        host, port = _hostport(self.cfg.listen)
        self.server = await asyncio.start_server(self._handle, host, port)
        log.info(json.dumps({"event": "listening", "proxy": self.cfg.name, "mode": self.cfg.mode,
                             "listen": self.cfg.listen, "upstream": self.cfg.upstream,
                             "policy": self.cfg.policy,
                             "runtime": tlsutil.runtime_description()}))


async def _admin_server(listen: str, proxies: list[Proxy]) -> asyncio.base_events.Server:
    async def handle(reader, writer):
        try:
            async def read_head():
                first = await reader.readline()
                for _ in range(100):   # bounded header count
                    if (await reader.readline()) in (b"\r\n", b"\n", b""):
                        break
                return first

            req = await asyncio.wait_for(read_head(), 5)
            if len(req) > 2048 or not req.startswith(b"GET "):
                req = b"GET /404 HTTP/1.1"
            path = req.split()[1].decode() if len(req.split()) > 1 else "/"
            if path.startswith("/healthz"):
                body, code = b"ok\n", "200 OK"
            elif path.startswith("/stats"):
                body = json.dumps({p.cfg.name: p.stats.snapshot() for p in proxies},
                                  indent=2).encode()
                code = "200 OK"
            else:
                body, code = b"not found\n", "404 Not Found"
            writer.write(f"HTTP/1.1 {code}\r\nContent-Type: application/json\r\n"
                         f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                         + body)
            await writer.drain()
        except (OSError, asyncio.TimeoutError, IndexError, ValueError):
            pass
        finally:
            writer.close()

    host, port = _hostport(listen)
    if not _is_loopback(listen):
        log.warning(json.dumps({"event": "config-warning", "warning":
                                f"admin endpoint {listen} is reachable from the network"}))
    return await asyncio.start_server(handle, host, port)


async def run(configs: list[ProxyConfig], admin: str | None = None) -> None:
    stats = Stats()   # one process: CPU accounting is shared across listeners
    proxies = [Proxy(c, stats) for c in configs]
    for p in proxies:
        await p.start()
    if admin:
        await _admin_server(admin, proxies)
        log.info(json.dumps({"event": "admin-listening", "listen": admin}))
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()


def load_configs(path: str) -> list[ProxyConfig]:
    data = json.loads(Path(path).read_text())
    items = data["proxies"] if isinstance(data, dict) and "proxies" in data else data
    if isinstance(items, dict):
        items = [items]
    base = Path(path).parent
    out = []
    for d in items:
        for k in ("cert", "key", "ca", "upstream_ca", "revocation_list"):
            if d.get(k) and not os.path.isabs(d[k]):
                d[k] = str(base / d[k])
        out.append(ProxyConfig.from_dict(d))
    listens = [c.listen for c in out]
    dupes = {x for x in listens if listens.count(x) > 1}
    if dupes:
        raise ConfigError(f"several proxies listen on {', '.join(sorted(dupes))}")
    return out


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(stream=sys.stdout, level=level, format="%(message)s")
