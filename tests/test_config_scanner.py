import json
import shutil
from pathlib import Path

from quantumshield import analyzer, cbom, config_scanner, migrate
from quantumshield.models import Inventory


def _scan(paths):
    inv = Inventory(generated_at="2026-01-01T00:00:00+00:00")
    config_scanner.scan_paths([str(p) for p in paths], inv)
    analyzer.analyze(inv)
    return inv


def test_detects_kinds(demo_dir):
    inv = _scan([demo_dir / "legacy-configs", demo_dir / "services"])
    kinds = {c.kind for c in inv.configs}
    assert {"nginx", "apache", "haproxy", "openssl", "sshd", "source"} <= kinds


def test_findings_from_configs(demo_dir):
    inv = _scan([demo_dir / "legacy-configs", demo_dir / "services"])
    r = {f.rule_id for f in inv.findings}
    assert {"QS-CFG-KEX-001", "QS-CFG-PROTO-002", "QS-SSH-KEX-001", "QS-SSH-KEX-002",
            "QS-SSH-CIPH-001", "QS-CODE-001", "QS-CODE-002"} <= r
    inventory_nginx = [c for c in inv.configs if c.path.endswith("inventory/nginx.conf")][0]
    kex = [i for i in inventory_nginx.items if i.category == "tls-kex"][0]
    assert kex.algorithms == ["ECDH-P256", "ECDH-P384"]


def test_pqc_config_is_not_flagged(tmp_path):
    conf = tmp_path / "nginx.conf"
    conf.write_text("server {\n  ssl_certificate a.crt;\n  ssl_protocols TLSv1.3;\n"
                    "  ssl_ecdh_curve X25519MLKEM768:X25519;\n}\n")
    inv = _scan([conf])
    assert not [f for f in inv.findings if f.rule_id.startswith("QS-CFG-KEX")]


def test_migration_patches(demo_dir, tmp_path):
    src = tmp_path / "cfg"
    shutil.copytree(demo_dir / "legacy-configs", src)
    shutil.copy(demo_dir / "services" / "inventory" / "nginx.conf", src / "nginx.conf")
    inv = _scan([src])
    plan = migrate.write_migration(inv, tmp_path / "out")
    patched = {Path(p["written_to"]).name: Path(p["written_to"]).read_text()
               for p in plan["patches"]}
    nginx = next(v for k, v in patched.items() if k.endswith("nginx.conf"))
    assert "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1" in nginx
    assert "ssl_protocols TLSv1.2 TLSv1.3" in nginx
    sshd = next(v for k, v in patched.items() if k.endswith("sshd_config"))
    assert "mlkem768x25519-sha256" in sshd
    cnf = next(v for k, v in patched.items() if k.endswith("openssl.cnf"))
    assert "Groups = X25519MLKEM768" in cnf
    # Re-scanning the patched files clears the key-exchange findings.
    after = _scan([tmp_path / "out" / "patched"])
    assert not {"QS-CFG-KEX-001", "QS-SSH-KEX-001"} & {f.rule_id for f in after.findings}


def test_cbom_structure(demo_dir):
    inv = _scan([demo_dir / "legacy-configs", demo_dir / "services"])
    bom = cbom.build_cbom(inv)
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    refs = {c["bom-ref"] for c in bom["components"]} | {s["bom-ref"] for s in bom["services"]}
    for d in bom["dependencies"]:
        assert d["ref"] in refs
        assert set(d["dependsOn"]) <= refs
    for c in bom["components"]:
        assert c["type"] == "cryptographic-asset"
        assert c["cryptoProperties"]["assetType"] in (
            "algorithm", "certificate", "protocol", "related-crypto-material")
    json.dumps(bom)
