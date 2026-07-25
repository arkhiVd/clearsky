import json
from pathlib import Path

from clearsky.detectors.unused_eip import parse_addresses

FIXTURES = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIXTURES / name).read_text())


def test_only_unassociated_eip_flagged():
    findings = parse_addresses(load("describe_addresses.json"), "us-east-1")
    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == "eipalloc-unused111"
    assert f.detector == "ec2.unused_eip"
    assert f.severity == "LOW"
    assert f.estimated_monthly_cost > 3
    assert "release-address" in f.detail


def test_empty_response():
    assert parse_addresses({"Addresses": []}, "us-east-1") == []


def test_finding_key_stable():
    findings = parse_addresses(load("describe_addresses.json"), "us-east-1")
    assert findings[0].key == "ec2.unused_eip#us-east-1#eipalloc-unused111"
