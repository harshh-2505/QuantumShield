from quantumshield.analyzer import analyze, service_summary
from quantumshield.models import EndpointScan, Inventory


def _inv(*eps):
    inv = Inventory(generated_at="2026-01-01T00:00:00+00:00")
    inv.endpoints = list(eps)
    analyze(inv)
    return inv


def rules(inv):
    return {f.rule_id for f in inv.findings}


def test_classical_endpoint_is_hndl_exposed():
    ep = EndpointScan("a:443", "a", reachable=True, negotiated_version="TLSv1.3",
                      negotiated_cipher="TLS_AES_128_GCM_SHA256", negotiated_group="x25519",
                      protocols={"TLSv1.2": True, "TLSv1.3": True},
                      groups_supported=["X25519", "secp256r1"], groups_probed=True)
    inv = _inv(ep)
    assert "QS-TLS-KEX-001" in rules(inv)
    assert any(f.hndl for f in inv.findings)
    assert service_summary(inv)[0]["status"] == "vulnerable"


def test_static_rsa_and_legacy_protocols():
    ep = EndpointScan("b:443", "b", reachable=True, negotiated_version="TLSv1.2",
                      negotiated_cipher="AES128-GCM-SHA256",
                      protocols={"TLSv1.0": True, "TLSv1.1": True, "TLSv1.2": True,
                                 "TLSv1.3": False},
                      tls12_ciphers=["AES128-GCM-SHA256", "DES-CBC3-SHA"])
    r = rules(_inv(ep))
    assert {"QS-TLS-KEX-003", "QS-TLS-PROTO-001", "QS-TLS-PROTO-002", "QS-TLS-CIPH-001"} <= r


def test_hybrid_endpoint_is_quantum_safe():
    ep = EndpointScan("c:8443", "c", reachable=True, negotiated_version="TLSv1.3",
                      negotiated_cipher="TLS_AES_256_GCM_SHA384",
                      negotiated_group="X25519MLKEM768", protocols={"TLSv1.3": True},
                      groups_supported=["X25519MLKEM768"], groups_probed=True,
                      peer_requires_client_cert=True)
    inv = _inv(ep)
    assert not [f for f in inv.findings if f.severity != "info"]
    assert service_summary(inv)[0]["status"] == "quantum-safe"


def test_prefers_classical_despite_pqc_support():
    ep = EndpointScan("d:443", "d", reachable=True, negotiated_version="TLSv1.3",
                      negotiated_cipher="TLS_AES_256_GCM_SHA384", negotiated_group="x25519",
                      protocols={"TLSv1.3": True}, groups_supported=["X25519MLKEM768", "X25519"],
                      groups_probed=True)
    assert "QS-TLS-KEX-002" in rules(_inv(ep))
