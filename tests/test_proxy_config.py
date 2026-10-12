"""Proxy configuration validation (runs on any Python)."""

import os

import pytest

from quantumshield.proxy import ConfigError, ProxyConfig, load_configs


@pytest.fixture
def keyfile(tmp_path):
    k = tmp_path / "w.key"
    k.write_text("x")
    k.chmod(0o600)
    return str(k)


def cfg(**kw):
    base = dict(name="t", mode="ingress", listen="127.0.0.1:8443", upstream="127.0.0.1:8080")
    base.update(kw)
    return ProxyConfig(**base)


def test_valid_ingress(keyfile):
    warnings = cfg(cert="c", key=keyfile, ca="ca", allowed_ids=["spiffe://x/y"]).validate()
    assert warnings == []


@pytest.mark.parametrize("kw,msg", [
    (dict(cert=None, key=None), "server certificate"),
    (dict(key=None), "cert and key"),
    (dict(require_client_cert=True, ca=None), "needs a CA"),
    (dict(upstream="10.0.0.5:443", upstream_tls=True), "loopback upstream"),
    (dict(listen="nonsense"), "host:port"),
    (dict(listen="127.0.0.1:70000"), "host:port"),
    (dict(policy="bogus"), "policy"),
    (dict(name="bad name/../x"), "name"),
    (dict(max_connections=0), "max_connections"),
    (dict(insecure_skip_verify=True), "egress only"),
])
def test_ingress_errors(kw, msg, keyfile):
    base = dict(cert="c", key=keyfile, ca="ca")
    base.update(kw)
    with pytest.raises(ConfigError, match=msg):
        cfg(**base).validate()


def test_egress_must_verify(keyfile):
    with pytest.raises(ConfigError, match="must verify"):
        cfg(mode="egress", cert="c", key=keyfile).validate()
    w = cfg(mode="egress", cert="c", key=keyfile, insecure_skip_verify=True).validate()
    assert any("NOT authenticated" in x for x in w)
    w = cfg(mode="egress", cert="c", key=keyfile, ca="ca", listen="0.0.0.0:9001").validate()
    assert any("not on loopback" in x for x in w)


def test_world_readable_key_refused(keyfile):
    os.chmod(keyfile, 0o644)
    with pytest.raises(ConfigError, match="chmod 600"):
        cfg(cert="c", key=keyfile, ca="ca").validate()


def test_unknown_and_duplicate_settings(tmp_path):
    p = tmp_path / "p.json"
    p.write_text('{"proxies":[{"name":"a","mode":"ingress","listen":"127.0.0.1:1",'
                 '"upstream":"127.0.0.1:2","requre_client_cert":false}]}')
    with pytest.raises(ConfigError, match="unknown"):
        load_configs(str(p))
    p.write_text('{"proxies":[{"name":"a","mode":"ingress","listen":"127.0.0.1:1",'
                 '"upstream":"127.0.0.1:2"},{"name":"b","mode":"ingress",'
                 '"listen":"127.0.0.1:1","upstream":"127.0.0.1:3"}]}')
    with pytest.raises(ConfigError, match="several proxies"):
        load_configs(str(p))


def test_classical_policy_warns(keyfile):
    w = cfg(cert="c", key=keyfile, ca="ca", allowed_ids=["x"], policy="classical").validate()
    assert any("harvest-now" in x for x in w)
