"""Pure tests: region resolution, AI finding item builder, store exemption."""

from clearsky import regions
from clearsky.chat import build_ai_finding
from clearsky.models import Finding
from clearsky.store import FindingStore


def test_resolve_regions_explicit_list_used_verbatim():
    out = regions.resolve_regions(None, "us-east-1, ap-northeast-1")
    assert out == ["us-east-1", "ap-northeast-1"]


def test_resolve_regions_unset_falls_back():
    assert regions.resolve_regions(None, "") == ["us-east-1"]


def test_build_ai_finding_validates_and_shapes_item():
    item = build_ai_finding({
        "severity": "high", "title": "t", "detail": "d",
        "resource_id": "vol-1", "region": "ap-northeast-1",
        "estimated_monthly_cost": "1.5",
    }, now="2026-07-06T00:00:00+00:00")
    assert item["pk"] == "ai#ap-northeast-1#vol-1"
    assert item["source"] == "ai" and item["severity"] == "HIGH"
    assert item["estimated_monthly_cost"] == 1.5
    assert item["status"] == "new"

    assert build_ai_finding({"severity": "NOPE"}, "x").startswith("ERROR")
    assert build_ai_finding({"severity": "LOW", "title": "t",
                             "resource_id": "", "region": "r"}, "x").startswith("ERROR")


class _FakeTable:
    def __init__(self, items):
        self.items = {i["pk"]: dict(i) for i in items}
        self.puts = []

    def scan(self, **kw):
        return {"Items": list(self.items.values())}

    def put_item(self, Item):
        self.puts.append(Item)
        self.items[Item["pk"]] = Item


def test_reconcile_never_auto_resolves_ai_findings():
    ai_item = {"pk": "ai#r#x", "source": "ai", "status": "open"}
    det_item = {"pk": "d#r#y", "status": "open"}
    store = FindingStore.__new__(FindingStore)
    store.table = _FakeTable([ai_item, det_item])
    result = store.reconcile([])  # detectors emit nothing this run
    resolved = {i["pk"] for i in result["resolved"]}
    assert "d#r#y" in resolved          # detector finding auto-resolves
    assert "ai#r#x" not in resolved     # AI finding untouched
    assert store.table.items["ai#r#x"]["status"] == "open"


def test_reconcile_scoped_to_scanned_accounts():
    # single-account scan must not resolve other accounts' findings
    home_item = {"pk": "d#r#h", "status": "open", "account": ""}
    member_item = {"pk": "111122223333#d#r#m", "status": "open",
                   "account": "111122223333"}
    legacy_item = {"pk": "d#r#old", "status": "open"}  # pre-account schema
    store = FindingStore.__new__(FindingStore)
    store.table = _FakeTable([home_item, member_item, legacy_item])

    # member-only scan: home + legacy (account "") findings untouched
    result = store.reconcile([], scanned_accounts={"111122223333"})
    resolved = {i["pk"] for i in result["resolved"]}
    assert resolved == {"111122223333#d#r#m"}
    assert store.table.items["d#r#h"]["status"] == "open"
    assert store.table.items["d#r#old"]["status"] == "open"

    # home-only scan on fresh state: member finding untouched
    store2 = FindingStore.__new__(FindingStore)
    store2.table = _FakeTable([dict(home_item), dict(member_item)])
    result2 = store2.reconcile([], scanned_accounts={""})
    assert {i["pk"] for i in result2["resolved"]} == {"d#r#h"}
    assert store2.table.items["111122223333#d#r#m"]["status"] == "open"
