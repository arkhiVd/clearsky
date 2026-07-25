import json as _json_mod

from clearsky.api import ROUTES, lambda_handler


def test_unauthenticated_request_gets_401(monkeypatch):
    resp = lambda_handler({"rawPath": "/api/summary", "headers": {}}, None)
    assert resp["statusCode"] == 401
    assert "unauthorized" in _json_mod.loads(resp["body"])["error"]


def test_authenticated_unknown_path_404(monkeypatch):
    from clearsky import api as api_mod
    monkeypatch.setattr(api_mod.authn, "authenticate",
                        lambda event: {"sub": "u"})
    resp = lambda_handler({"rawPath": "/nope", "headers": {}}, None)
    assert resp["statusCode"] == 404


def test_api_route_table():
    assert set(ROUTES) == {
        "/api/summary", "/api/findings", "/api/costwatch", "/api/inventory"
    }


def test_accounts_post_rejects_bad_arn(monkeypatch):
    import json
    from clearsky.api import _accounts_post
    monkeypatch.setenv("ACCOUNTS_PARAM", "/cd/accounts")
    resp = _accounts_post({"body": json.dumps({"role_arn": "not-an-arn"})})
    assert resp["statusCode"] == 400
    assert "role_arn" in json.loads(resp["body"])["error"]


def test_accounts_post_validates_assume_before_saving(monkeypatch):
    import json
    from clearsky import api as api_mod
    monkeypatch.setenv("ACCOUNTS_PARAM", "/cd/accounts")
    monkeypatch.setattr(api_mod, "_load_accounts", lambda: [])
    saved = {}
    monkeypatch.setattr(api_mod, "_save_accounts",
                        lambda entries: saved.update(entries=entries))

    from clearsky import accounts as accounts_mod

    def deny(arn):
        raise RuntimeError("AccessDenied")

    monkeypatch.setattr(accounts_mod, "assume_session", deny)
    resp = api_mod._accounts_post({"body": json.dumps(
        {"role_arn": "arn:aws:iam::111122223333:role/clearsky-readonly"})})
    assert resp["statusCode"] == 400
    assert "could not assume" in json.loads(resp["body"])["error"]
    assert not saved  # nothing persisted on failed validation

    class _FakeSession:
        def client(self, svc):
            class _Sts:
                def get_caller_identity(self):
                    return {"Account": "111122223333"}
            return _Sts()

    monkeypatch.setattr(accounts_mod, "assume_session", lambda arn: _FakeSession())
    resp = api_mod._accounts_post({"body": json.dumps(
        {"role_arn": "arn:aws:iam::111122223333:role/clearsky-readonly",
         "label": "second"})})
    assert resp["statusCode"] == 200
    assert json.loads(resp["body"])["account_id"] == "111122223333"
    assert saved["entries"][0]["label"] == "second"


def test_accounts_post_remove(monkeypatch):
    import json
    from clearsky import api as api_mod
    monkeypatch.setenv("ACCOUNTS_PARAM", "/cd/accounts")
    monkeypatch.setattr(api_mod, "_load_accounts", lambda: [
        {"account_id": "111122223333", "role_arn": "arn:x", "label": ""}])
    saved = {}
    monkeypatch.setattr(api_mod, "_save_accounts",
                        lambda entries: saved.update(entries=entries))
    resp = api_mod._accounts_post({"body": json.dumps({"remove": "111122223333"})})
    assert resp["statusCode"] == 200
    assert saved["entries"] == []


def test_cost_periods_presets():
    from datetime import date
    from clearsky.api import _cost_periods

    today = date(2026, 7, 10)

    cs, ce, ps, pe, g = _cost_periods("daily-14", today)
    assert (ce - cs).days == 14 and (pe - ps).days == 14
    assert ce == today and pe == cs and g == "DAILY"

    cs, ce, ps, pe, g = _cost_periods("mtd", today)
    assert cs == date(2026, 7, 1) and ce == today
    assert ps == date(2026, 6, 1) and pe == date(2026, 6, 10) and g == "DAILY"

    cs, ce, ps, pe, g = _cost_periods("monthly-6", today)
    assert cs == date(2026, 1, 1) and ce == date(2026, 7, 1)
    assert ps == date(2025, 7, 1) and pe == cs and g == "MONTHLY"

    cs, ce, ps, pe, g = _cost_periods("yearly", today)
    assert cs == date(2026, 1, 1) and ce == today
    assert ps == date(2025, 1, 1) and pe == cs and g == "MONTHLY"


def test_eks_node_split_in_inventory():
    from clearsky.inventory import summarize_instances
    res = [{"Instances": [
        {"State": {"Name": "running"}, "InstanceType": "t3.large",
         "Tags": [{"Key": "eks:cluster-name", "Value": "prod"}]},
        {"State": {"Name": "stopped"}, "InstanceType": "t3.micro",
         "Tags": [{"Key": "kubernetes.io/cluster/prod", "Value": "owned"}]},
        {"State": {"Name": "running"}, "InstanceType": "t3.micro", "Tags": []},
    ]}]
    m = summarize_instances(res)
    assert m["eks.nodes.running"] == 1 and m["eks.nodes.stopped"] == 1
    assert m["ec2.running"] == 2 and m["ec2.stopped"] == 1
