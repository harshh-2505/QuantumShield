"""Thin helpers over Python's `ssl` module for TLS 1.3 named-group control.

Post-quantum and hybrid key exchange (ML-KEM) comes from OpenSSL 3.5+.  Python
3.15 exposes `SSLContext.set_groups()` and `SSLSocket.group()`; on older
Pythons QuantumShield falls back to OpenSSL's defaults (which in 3.5 already
prefer X25519MLKEM768) and reports the group as unknown.
"""

from __future__ import annotations

import ssl

HAS_GROUP_API = hasattr(ssl.SSLContext, "set_groups")
OPENSSL_HAS_MLKEM = ssl.OPENSSL_VERSION_INFO >= (3, 5)

# Offered by QuantumShield clients/proxies in "prefer" mode.  The leading '*'
# asks OpenSSL to send a key share for that group up front, so classical-only
# peers still complete in one round trip instead of a HelloRetryRequest.
HYBRID_PREFERRED = "*X25519MLKEM768:*X25519:SecP256r1MLKEM768:secp256r1:SecP384r1MLKEM1024:secp384r1"
HYBRID_ONLY = "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024"
CLASSICAL_ONLY = "X25519:secp256r1:secp384r1"

POLICIES = {"strict": HYBRID_ONLY, "prefer": HYBRID_PREFERRED, "classical": CLASSICAL_ONLY}


def set_groups(ctx: ssl.SSLContext, groups: str) -> bool:
    """Restrict the key-exchange groups. Returns False if the runtime cannot."""
    if HAS_GROUP_API:
        ctx.set_groups(groups)
        return True
    first = groups.split(":")[0].lstrip("*?")
    if ":" not in groups and not any(k in first.upper() for k in ("MLKEM", "KYBER")):
        try:
            ctx.set_ecdh_curve(first)
            return True
        except (ValueError, ssl.SSLError):
            return False
    return False


def set_sigalgs(ctx: ssl.SSLContext, sigalgs: str) -> bool:
    """Restrict signature algorithms for both server and client authentication.

    With "mldsa65:mldsa87" a peer holding only an RSA/ECDSA certificate cannot
    authenticate at all, so authentication is post-quantum end to end.
    """
    if not (hasattr(ctx, "set_server_sigalgs") and hasattr(ctx, "set_client_sigalgs")):
        return False
    ctx.set_server_sigalgs(sigalgs)
    ctx.set_client_sigalgs(sigalgs)
    return True


PQ_SIGALGS = "mldsa65:mldsa87:mldsa44"


def negotiated_group(sock) -> str | None:
    fn = getattr(sock, "group", None)
    try:
        return fn() if fn else None
    except (ssl.SSLError, ValueError):
        return None


def negotiated_sigalg(sock, server_side: bool = False) -> str | None:
    fn = getattr(sock, "client_sigalg" if server_side else "server_sigalg", None)
    try:
        return fn() if fn else None
    except (ssl.SSLError, ValueError):
        return None


def peer_chain_der(sock) -> list[bytes]:
    """DER certificates presented by the peer, leaf first."""
    chain = []
    getter = getattr(sock, "get_unverified_chain", None)
    if getter:
        try:
            for c in getter() or []:
                if isinstance(c, bytes):
                    chain.append(c)
                else:
                    chain.append(c.public_bytes(ssl._ssl.ENCODING_DER))  # noqa: SLF001
        except (ssl.SSLError, ValueError, AttributeError):
            chain = []
    if not chain:
        leaf = sock.getpeercert(binary_form=True)
        if leaf:
            chain = [leaf]
    return chain


def runtime_description() -> str:
    api = "group control" if HAS_GROUP_API else "no group control (needs Python 3.15+)"
    pqc = "ML-KEM available" if OPENSSL_HAS_MLKEM else "no ML-KEM (needs OpenSSL 3.5+)"
    return f"{ssl.OPENSSL_VERSION}; {pqc}; {api}"
