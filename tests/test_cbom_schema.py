"""Validate generated CBOMs against the official CycloneDX 1.6 JSON schema."""

import json
from pathlib import Path

import pytest

from quantumshield import analyzer, cbom, config_scanner
from quantumshield.models import EndpointScan, Inventory

jsonschema = pytest.importorskip("jsonschema")
referencing = pytest.importorskip("referencing")

SCHEMAS = Path(__file__).parent / "schemas"


@pytest.fixture(scope="module")
def validator():
    reg = referencing.Registry()
    for name in ("spdx.schema.json", "jsf-0.82.schema.json"):
        sch = json.loads((SCHEMAS / name).read_text())
        res = referencing.Resource.from_contents(sch)
        reg = reg.with_resource(sch["$id"], res).with_resource(name, res)
    schema = json.loads((SCHEMAS / "bom-1.6.schema.json").read_text())
    return jsonschema.Draft7Validator(schema, registry=reg)


def test_cbom_validates(validator, demo_dir):
    inv = Inventory(generated_at="2026-01-01T00:00:00+00:00", tls_library="test")
    config_scanner.scan_paths([str(demo_dir / "legacy-configs"), str(demo_dir / "services")], inv)
    inv.endpoints.append(EndpointScan(
        "a:443", "a", reachable=True, negotiated_version="TLSv1.2",
        negotiated_cipher="ECDHE-RSA-AES128-GCM-SHA256", negotiated_group="secp256r1",
        protocols={"TLSv1.2": True}, tls12_ciphers=["ECDHE-RSA-AES128-GCM-SHA256", "AES256-SHA"]))
    analyzer.analyze(inv)
    errors = [f"{list(e.path)}: {e.message}" for e in validator.iter_errors(cbom.build_cbom(inv))]
    assert not errors, errors[:5]


def test_validator_rejects_garbage(validator):
    assert list(validator.iter_errors({"bomFormat": "CycloneDX", "specVersion": "1.6",
                                       "components": [{"type": "nonsense"}]}))
