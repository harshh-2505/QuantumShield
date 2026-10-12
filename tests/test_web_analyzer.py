"""Parity between the browser analyzer (web/assets/analyzer.js) and the Python one.

web/assets/analyzer.js is a port of config_scanner, certs, the config / certificate /
key / source rules of analyzer and of cbom, so the static site can analyze a pasted
file without uploading it.  This test runs both implementations on the same fixtures
(the demo configs plus tests/web_parity/fixtures) through tests/web_parity/run_node.js
and requires the same kind, items, certificates and findings for every file, the same
algorithm catalog, and a CBOM that equals build_cbom() and validates against the
CycloneDX 1.6 schema.

What the browser cannot do, and so is not ported:
  * the endpoint rules (QS-NET-001, QS-TLS-*, QS-ZT-001) need a live TLS scan;
  * certificate files referenced from a config (ssl_certificate, crt ...) are listed
    as items but not opened, since a web page has no file system.  The config
    fixtures reference files that do not exist, and the test checks that Python did
    not load any either.

OpenSSL versions.  config_scanner.ciphers_to_algs() expands cipher strings with the
host's OpenSSL; the JavaScript engine replays a table that scripts/gen_cipher_table.py
probed from OpenSSL 3.5 (tests/web_parity/cipher_vectors.json holds that OpenSSL's
own answers, replayed exactly below).  Hosts with OpenSSL 3.0 (Ubuntu 24.04, i.e. CI)
differ from 3.5 in three ways: 3.5 rates the ten AES-CCM8 suites MEDIUM instead of
HIGH (which also moves them in the default order), and only 3.5 knows the MEDIUM alias
and IANA suite names.  The fixtures avoid MEDIUM and IANA names and either do not
select CCM8 suites or remove them with !AESCCM8, so their expansions are identical on
both versions and are compared suite for suite.  The one fixture string that does
depend on the version is listed in VERSION_SENSITIVE.  Algorithm sets and findings
are the same either way, since every CCM8 suite has a CCM twin with the same
components, and are compared exactly for every fixture.
"""

from __future__ import annotations

import json
import re
import shutil
import ssl
import subprocess
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import pytest

from quantumshield import __version__, analyzer, cbom, config_scanner
from quantumshield.catalog import all_algorithms, classify_group, lookup
from quantumshield.models import Inventory

ROOT = Path(__file__).resolve().parent.parent
ANALYZER_JS = ROOT / "web" / "assets" / "analyzer.js"
DRIVER = ROOT / "tests" / "web_parity" / "run_node.js"
FIXTURES = ROOT / "tests" / "web_parity" / "fixtures"
VECTORS = ROOT / "tests" / "web_parity" / "cipher_vectors.json"
NODE = shutil.which("node")

# The PEM fixtures have fixed validity dates; evaluate the expiry rules at this instant.
NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)
NOW_ISO = "2026-10-12T00:00:00Z"

pytestmark = [
    pytest.mark.skipif(NODE is None, reason="node is not installed; the web analyzer "
                       "parity test needs Node.js 18+ on PATH"),
    pytest.mark.skipif(not ANALYZER_JS.exists(), reason="web/assets/analyzer.js is not "
                       "part of this checkout (the Docker image ships without web/)"),
]

# Every rule of analyzer._config_findings() and analyzer._cert_findings().  At least one
# fixture triggers each; test_rule_list_is_complete keeps this list in step with
# analyzer.py, so a new rule fails here until it is ported and covered.
PORTED_RULES = {
    "QS-CFG-KEX-000", "QS-CFG-KEX-001", "QS-CFG-PROTO-001", "QS-CFG-PROTO-002",
    "QS-CFG-CIPH-001", "QS-CFG-CIPH-003",
    "QS-SSH-KEX-001", "QS-SSH-KEX-002", "QS-SSH-HK-001", "QS-SSH-HK-002", "QS-SSH-CIPH-001",
    "QS-KEY-001", "QS-CODE-001", "QS-CODE-002", "QS-CODE-003", "QS-CODE-PQC",
    "QS-CERT-SIG-001", "QS-CERT-KEY-001", "QS-CERT-HASH-001", "QS-CERT-EXP-001",
    "QS-CERT-EXP-002", "QS-CERT-ROT-001", "QS-CERT-TRUST-001",
}

# Cipher strings whose expansion differs between OpenSSL 3.0 and 3.5, with the reason.
# On a host older than 3.5 they are compared with the AES-CCM8 suites removed.
CCM8 = re.compile(r"CCM8")
VERSION_SENSITIVE = {
    # demo/legacy-configs/apache-ssl.conf: HIGH includes the CCM8 suites on 3.0 only.
    "HIGH:!aNULL:!MD5": "OpenSSL 3.5 moved the AES-CCM8 suites from HIGH to MEDIUM",
}
HOST_IS_35 = ssl.OPENSSL_VERSION_INFO[:2] >= (3, 5)


def fixture_files() -> list[str]:
    files = sorted((ROOT / "demo" / "legacy-configs").iterdir())
    files += sorted((ROOT / "demo" / "services").glob("*/nginx.conf"))
    files += sorted(p for p in FIXTURES.rglob("*") if p.is_file())
    return [p.relative_to(ROOT).as_posix() for p in files if p.is_file()]


FILES = fixture_files()


def host_expand(cipher_string: str) -> list[str] | None:
    """The suites ciphers_to_algs() gets from the host OpenSSL, or None on SSLError."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        ctx.set_ciphers(cipher_string)
    except ssl.SSLError:
        return None
    return [c["name"] for c in ctx.get_ciphers() if c.get("protocol") != "TLSv1.3"]


def cipher_input(value: str) -> str:
    """What ciphers_to_algs() hands to set_ciphers() for a directive value."""
    return value.strip().strip("\"';") + ":@SECLEVEL=0"


@pytest.fixture(scope="module")
def parity():
    """Scan every fixture with Python and with analyzer.js (one Node run)."""
    py: dict[str, dict] = {}
    combined = Inventory(generated_at="2026-10-12T00:00:00+00:00", tls_library="test")
    with pytest.MonkeyPatch.context() as mp:
        mp.chdir(ROOT)  # relative paths, as a user running `quantumshield scan` would see
        for rel in FILES:
            text = (ROOT / rel).read_bytes().decode("utf-8", "replace")
            inv = Inventory(generated_at="2026-10-12T00:00:00+00:00", tls_library="test")
            scan = config_scanner.scan_file(Path(rel), inv)
            if scan:
                inv.configs.append(scan)
            findings = analyzer.analyze(inv, now=NOW)
            py[rel] = {"text": text, "kind": config_scanner.detect_kind(Path(rel), text[:20000]),
                       "scan": scan, "inv": inv, "findings": findings}
            combined_scan = config_scanner.scan_file(Path(rel), combined)
            if combined_scan:
                combined.configs.append(combined_scan)
    analyzer.analyze(combined, now=NOW)

    ciphers = sorted({cipher_input(it.value) for p in py.values() if p["scan"]
                      for it in p["scan"].items if it.category == "tls-cipher"})
    vectors = json.loads(VECTORS.read_text())
    request = {
        "analyzer": str(ANALYZER_JS), "now": NOW_ISO,
        "files": [{"path": rel, "text": py[rel]["text"]} for rel in FILES],
        "ciphers": ciphers + [v[0] for v in vectors["vectors"]],
        "cbom": {"timestamp": combined.generated_at,
                 "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000"},
    }
    proc = subprocess.run([NODE, str(DRIVER)], input=json.dumps(request), cwd=ROOT,
                          capture_output=True, text=True, encoding="utf-8", timeout=300)
    assert proc.returncode == 0, proc.stderr
    js = json.loads(proc.stdout)
    js["results"] = dict(zip(FILES, js["results"]))
    js["async"] = dict(zip(FILES, js["async"]))
    js["ciphers"] = dict((s, out) for s, out in js["ciphers"])
    return {"py": py, "js": js, "ciphers": ciphers, "vectors": vectors, "combined": combined}


def _line(asset: str, path: str) -> int | None:
    return int(asset.rsplit(":", 1)[1]) if asset.startswith(path + ":") else None


@pytest.mark.parametrize("rel", FILES)
def test_same_results(parity, rel):
    p, js = parity["py"][rel], parity["js"]["results"][rel]
    scan = p["scan"]
    assert js["kind"] == p["kind"]
    assert js["scan_kind"] == (scan.kind if scan else None)
    assert js["service"] == (scan.service if scan else None)

    # Items: directive, value, line, category and the set of algorithm names.
    py_items = [(it.directive, it.value, it.line, it.category, sorted(set(it.algorithms)))
                for it in (scan.items if scan else [])]
    js_items = [(it["directive"], it["value"], it["line"], it["category"],
                 sorted({a["name"] for a in it["algorithms"]})) for it in js["items"]]
    assert js_items == py_items
    for it in js["items"]:
        for a in it["algorithms"]:
            alg = lookup(a["name"]) or classify_group(a["name"])
            assert (a["status"], a["primitive"]) == \
                ((alg.status.value, alg.primitive.value) if alg else (None, None))

    # Certificates: every CertInfo field.  Configs never pull in referenced files here.
    if scan and scan.kind != "pem":
        assert not scan.certificates, f"{rel} loaded a referenced certificate from disk"
    assert js["certificates"] == [asdict(c) for c in p["inv"].certificates.values()]

    # Findings: the (rule, severity, line) multiset, then every field in order.
    def triples(fs):
        return Counter((f["rule_id"], f["severity"], _line(f["asset"], rel)) for f in fs)
    py_findings = [asdict(f) for f in p["findings"]]
    assert triples(js["findings"]) == triples(py_findings)
    assert js["findings"] == py_findings


def test_async_matches_sync(parity):
    """analyzeAsync() (WebCrypto fingerprints, as in the browser) gives the same answer."""
    for rel in FILES:
        assert parity["js"]["async"][rel] == parity["js"]["results"][rel], rel


def test_every_rule_fires(parity):
    fired = {f["rule_id"] for r in parity["js"]["results"].values() for f in r["findings"]}
    assert PORTED_RULES - fired == set(), "no fixture triggers these rules"
    assert fired <= PORTED_RULES


def test_rule_list_is_complete():
    src = (ROOT / "quantumshield" / "analyzer.py").read_text()
    body = src[src.index("def _cert_findings"):src.index("def analyze(")]
    assert set(re.findall(r'"(QS-[A-Z0-9-]+)"', body)) == PORTED_RULES


def test_unsupported_input(parity):
    r = parity["js"]["results"]["tests/web_parity/fixtures/misc/README.txt"]
    assert (r["kind"], r["items"], r["findings"]) == (None, [], [])


def test_cipher_strings_match_host_openssl(parity):
    """Every cipher string in the fixtures expands to the same suites as on the host."""
    js = parity["js"]["ciphers"]
    for s in parity["ciphers"]:
        host, mine = host_expand(s), js[s]
        base = s[:-len(":@SECLEVEL=0")]
        if base in VERSION_SENSITIVE and not HOST_IS_35:
            assert host != mine, f"{base!r} no longer differs on {ssl.OPENSSL_VERSION}"
            host = [c for c in host or [] if not CCM8.search(c)]
            mine = [c for c in mine or [] if not CCM8.search(c)]
        assert mine == host, f"{base!r}: analyzer.js and {ssl.OPENSSL_VERSION} disagree"
    used = {s[:-len(":@SECLEVEL=0")] for s in parity["ciphers"]}
    assert set(VERSION_SENSITIVE) <= used, "VERSION_SENSITIVE lists a string no fixture uses"


def test_cipher_vectors_match_openssl_35(parity):
    """The engine reproduces OpenSSL 3.5 itself on the generator's recorded strings."""
    vec = parity["vectors"]
    js = parity["js"]["ciphers"]
    assert parity["js"]["cipherTable"]["openssl"] == vec["openssl"]
    bad = []
    for s, idx in vec["vectors"]:
        want = None if idx is None else [vec["suites"][int(i)] for i in idx.split()]
        if js[s] != want:
            bad.append(s)
        if HOST_IS_35 and host_expand(s) != want:
            bad.append(f"host: {s}")
    assert not bad, f"{len(bad)} of {len(vec['vectors'])} differ, e.g. {bad[:5]}"


def test_catalog_and_version(parity):
    assert parity["js"]["version"] == __version__
    py = [{"name": a.name, "primitive": a.primitive.value, "status": a.status.value,
           "classical_bits": a.classical_bits, "quantum_bits": a.quantum_bits,
           "nist_level": a.nist_level, "oid": a.oid, "replacement": a.replacement,
           "aliases": list(a.aliases), "quantum_safe": a.quantum_safe}
          for a in all_algorithms()]
    assert parity["js"]["catalog"] == py


def _comparable(bom: dict) -> dict:
    bom = json.loads(json.dumps(bom))
    bom.pop("serialNumber")
    bom["metadata"].pop("timestamp")
    bom["metadata"]["properties"] = [p for p in bom["metadata"]["properties"]
                                     if p["name"] != "quantumshield:tls-library"]
    return bom


def test_cbom_matches_python(parity):
    js_bom = parity["js"]["cbom"]
    assert js_bom["serialNumber"] == "urn:uuid:00000000-0000-4000-8000-000000000000"
    assert js_bom["metadata"]["timestamp"] == parity["combined"].generated_at
    assert _comparable(js_bom) == _comparable(cbom.build_cbom(parity["combined"]))


def test_cbom_validates(parity):
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    schemas = ROOT / "tests" / "schemas"
    reg = referencing.Registry()
    for name in ("spdx.schema.json", "jsf-0.82.schema.json"):
        sch = json.loads((schemas / name).read_text())
        res = referencing.Resource.from_contents(sch)
        reg = reg.with_resource(sch["$id"], res).with_resource(name, res)
    schema = json.loads((schemas / "bom-1.6.schema.json").read_text())
    validator = jsonschema.Draft7Validator(schema, registry=reg)
    errors = [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(parity["js"]["cbom"])]
    assert not errors, errors[:5]
