"""Active TLS endpoint scanner.

For each endpoint it records:
  * which protocol versions are accepted (TLS 1.0 - 1.3)
  * the default negotiated version, cipher, key-exchange group and signature
  * which TLS 1.3 key-exchange groups the server accepts, including the
    hybrid post-quantum groups (X25519MLKEM768, ...)
  * the TLS 1.2 cipher suites the server accepts
  * the certificate chain
"""

from __future__ import annotations

import re
import shutil
import socket
import ssl
import subprocess
import time
import warnings
from concurrent.futures import ThreadPoolExecutor

from . import certs, tlsutil
from .catalog import CLASSICAL_GROUPS, PQC_GROUPS, PURE_PQC_GROUPS
from .models import EndpointScan, Inventory

TIMEOUT = 5.0

PROTOCOLS = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def parse_target(target: str) -> tuple[str, int, str]:
    """Accept 'name=host:port', 'host:port', 'https://host[:port]' or 'host'."""
    name = None
    if "=" in target:
        name, target = target.split("=", 1)
    target = re.sub(r"^[a-z]+://", "", target).rstrip("/")
    if target.startswith("["):
        host, _, port = target[1:].partition("]:")
    elif target.count(":") == 1:
        host, port = target.split(":")
    else:
        host, port = target, "443"
    return host, int(port or 443), name or host


class ClientIdentity:
    def __init__(self, cert: str | None = None, key: str | None = None):
        self.cert, self.key = cert, key


warnings.filterwarnings("ignore", "ssl.TLSVersion.TLSv1", DeprecationWarning)


def _ctx(min_v=None, max_v=None, groups: str | None = None, ciphers: str | None = None,
         identity: ClientIdentity | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE        # inventory, not trust decisions
    if min_v is not None and min_v < ssl.TLSVersion.TLSv1_2:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    if min_v is not None:
        ctx.minimum_version = min_v
    if max_v is not None:
        ctx.maximum_version = max_v
    if ciphers:
        ctx.set_ciphers(ciphers)
    if groups:
        if not tlsutil.set_groups(ctx, groups):
            raise NotImplementedError("group selection unsupported")
    if identity and identity.cert:
        ctx.load_cert_chain(identity.cert, identity.key)
    return ctx


def _handshake(host: str, port: int, ctx: ssl.SSLContext, sni: str | None = None):
    raw = socket.create_connection((host, port), timeout=TIMEOUT)
    try:
        t0 = time.perf_counter()
        s = ctx.wrap_socket(raw, server_hostname=sni or host)
        return s, (time.perf_counter() - t0) * 1000
    except Exception:
        raw.close()
        raise


def _cert_required_alert(s: ssl.SSLSocket) -> bool:
    """A TLS 1.3 server demanding mTLS only says so after the client's handshake ends.

    Servers send a certificate_required alert, or (some async stacks) just close
    the connection; an idle server that is waiting for a request does neither.
    """
    try:
        s.settimeout(0.5)
        return s.recv(1) == b""
    except (ssl.SSLEOFError, ConnectionResetError):
        return True
    except ssl.SSLError as e:
        return "CERTIFICATE_REQUIRED" in str(e).upper()
    except (OSError, ValueError):   # timeout: server is waiting for us to speak
        return False


def _try(host, port, ctx, sni=None):
    try:
        s, _ = _handshake(host, port, ctx, sni)
    except (OSError, ssl.SSLError, ValueError):
        return None
    try:
        return {"version": s.version(), "cipher": s.cipher()[0],
                "group": tlsutil.negotiated_group(s)}
    finally:
        s.close()


def _openssl_group_probe(host: str, port: int, group: str) -> bool | None:
    """Fallback group probe using an OpenSSL >= 3.5 CLI when Python can't select groups."""
    if certs.openssl_version() < (3, 5) or not shutil.which(certs.openssl_bin()):
        return None
    try:
        p = subprocess.run(
            [certs.openssl_bin(), "s_client", "-connect", f"{host}:{port}", "-tls1_3",
             "-groups", group, "-servername", host],
            input="", capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return False
    return p.returncode == 0 and "Cipher is (NONE)" not in p.stdout


TLS12_CIPHERS = [
    "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-SHA384", "ECDHE-RSA-AES128-SHA256", "ECDHE-RSA-AES256-SHA",
    "ECDHE-RSA-AES128-SHA", "ECDHE-ECDSA-AES256-SHA", "ECDHE-ECDSA-AES128-SHA",
    "DHE-RSA-AES256-GCM-SHA384", "DHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-SHA",
    "AES256-GCM-SHA384", "AES128-GCM-SHA256", "AES256-SHA256", "AES128-SHA256",
    "AES256-SHA", "AES128-SHA", "DES-CBC3-SHA", "ECDHE-RSA-DES-CBC3-SHA",
]


def _enumerate_tls12(host, port, sni) -> list[str]:
    """Server-preference enumeration: offer everything, drop what was chosen, repeat."""
    remaining = list(TLS12_CIPHERS)
    accepted: list[str] = []
    while remaining:
        try:
            ctx = _ctx(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2,
                       ciphers=":".join(remaining) + ":@SECLEVEL=0")
        except ssl.SSLError:
            break
        r = _try(host, port, ctx, sni)
        if not r or r["cipher"] not in remaining:
            break
        accepted.append(r["cipher"])
        remaining.remove(r["cipher"])
    return accepted


def scan_endpoint(target: str, identity: ClientIdentity | None = None,
                  inventory: Inventory | None = None, deep: bool = True) -> EndpointScan:
    host, port, name = parse_target(target)
    res = EndpointScan(target=f"{host}:{port}", name=name)

    # 1. Default handshake, with QuantumShield's preferred group list.
    try:
        ctx = _ctx(identity=identity)
        try:
            tlsutil.set_groups(ctx, tlsutil.HYBRID_PREFERRED)
        except (ssl.SSLError, ValueError):
            pass
        s, ms = _handshake(host, port, ctx)
    except (OSError, ssl.SSLError) as e:
        res.error = f"{type(e).__name__}: {e}"
        return res
    with s:
        res.reachable = True
        res.handshake_ms = round(ms, 2)
        res.negotiated_version = s.version()
        res.negotiated_cipher = s.cipher()[0]
        res.negotiated_group = tlsutil.negotiated_group(s)
        res.negotiated_sigalg = tlsutil.negotiated_sigalg(s)
        chain = tlsutil.peer_chain_der(s)
        if not (identity and identity.cert):
            res.peer_requires_client_cert = _cert_required_alert(s)
    if identity and identity.cert:
        # We authenticated; check whether an anonymous client would be refused.
        try:
            anon, _ = _handshake(host, port, _ctx())
            with anon:
                res.peer_requires_client_cert = _cert_required_alert(anon)
        except ssl.SSLError as e:
            res.peer_requires_client_cert = "CERTIFICATE_REQUIRED" in str(e).upper()
        except OSError:
            pass
    for der in chain:
        try:
            info = certs.parse_der(der)
        except Exception:  # noqa: BLE001
            continue
        fp = inventory.add_cert(info, f"tls://{res.target}") if inventory else \
            info.fingerprint_sha256
        res.certificate_chain.append(fp)

    if not deep:
        return res

    # 2. Protocol versions.
    for label, ver in PROTOCOLS.items():
        try:
            ok = _try(host, port, _ctx(ver, ver, identity=identity)) is not None
        except (ssl.SSLError, ValueError):
            ok = False
        res.protocols[label] = ok

    # 3. TLS 1.3 key-exchange groups (classical, hybrid PQC, pure PQC).
    if res.protocols.get("TLSv1.3"):
        for group in PQC_GROUPS + PURE_PQC_GROUPS + CLASSICAL_GROUPS:
            ok = None
            try:
                ctx = _ctx(ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3, groups=group,
                           identity=identity)
                ok = _try(host, port, ctx) is not None
                res.groups_probed = True
            except NotImplementedError:
                ok = _openssl_group_probe(host, port, group)
                if ok is not None:
                    res.groups_probed = True
            except (ssl.SSLError, ValueError):
                ok = False   # group unknown to the local library
            if ok:
                res.groups_supported.append(group)

    # 4. TLS 1.2 cipher suites.
    if res.protocols.get("TLSv1.2"):
        res.tls12_ciphers = _enumerate_tls12(host, port, host)
    return res


def scan_endpoints(targets: list[str], inventory: Inventory,
                   identity: ClientIdentity | None = None, workers: int = 8) -> None:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda t: scan_endpoint(t, identity, inventory), targets))
    inventory.endpoints.extend(results)
