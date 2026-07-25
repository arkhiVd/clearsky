from clearsky.accounts import account_id_from_arn, tag_account
from clearsky.models import Finding


def _finding(**kw):
    defaults = dict(
        detector="ec2.unused_eip", resource_id="eip-1", severity="LOW",
        title="Unused EIP", detail="release", region="us-east-1",
    )
    defaults.update(kw)
    return Finding(**defaults)


def test_account_id_from_arn():
    arn = "arn:aws:iam::111122223333:role/clearsky-readonly"
    assert account_id_from_arn(arn) == "111122223333"


def test_home_account_key_unchanged():
    f = _finding()
    assert f.key == "ec2.unused_eip#us-east-1#eip-1"
    assert tag_account([f], "") == [f]


def test_member_findings_tagged_and_key_prefixed():
    tagged = tag_account([_finding()], "111122223333")
    f = tagged[0]
    assert f.account == "111122223333"
    assert f.key == "111122223333#ec2.unused_eip#us-east-1#eip-1"
    assert f.title.startswith("[111122223333] ")


def test_configured_accounts_from_ssm_and_env(monkeypatch):
    from clearsky import accounts as mod
    monkeypatch.setenv("ACCOUNTS_PARAM", "/cd/accounts")
    monkeypatch.setenv(
        "MEMBER_ROLE_ARNS",
        "arn:aws:iam::999900001111:role/legacy,"
        "arn:aws:iam::111122223333:role/dup-should-be-ignored")

    class FakeSSM:
        def get_parameter(self, Name):
            assert Name == "/cd/accounts"
            return {"Parameter": {"Value": (
                '[{"account_id": "111122223333", '
                '"role_arn": "arn:aws:iam::111122223333:role/clearsky-readonly", '
                '"label": "second"}]')}}

    monkeypatch.setattr(mod.boto3, "client", lambda svc: FakeSSM())
    got = mod.configured_accounts()
    ids = [a["account_id"] for a in got]
    # SSM entry wins over the duplicate env ARN; legacy env ARN still merged
    assert ids == ["111122223333", "999900001111"]
    assert got[0]["label"] == "second"
    assert mod.role_arn_for("999900001111") == "arn:aws:iam::999900001111:role/legacy"
    assert mod.role_arn_for("000000000000") is None


def test_configured_accounts_survives_ssm_failure(monkeypatch):
    from clearsky import accounts as mod
    monkeypatch.setenv("ACCOUNTS_PARAM", "/cd/accounts")
    monkeypatch.setenv("MEMBER_ROLE_ARNS", "arn:aws:iam::999900001111:role/legacy")

    def boom(svc):
        raise RuntimeError("no ssm access")

    monkeypatch.setattr(mod.boto3, "client", boom)
    assert [a["account_id"] for a in mod.configured_accounts()] == ["999900001111"]


def test_scan_targets_only_filters(monkeypatch):
    from clearsky import accounts as mod
    entries = [
        {"account_id": "111122223333", "role_arn": "arn:1", "label": ""},
        {"account_id": "444455556666", "role_arn": "arn:2", "label": ""},
    ]
    monkeypatch.setattr(mod, "configured_accounts", lambda: entries)
    monkeypatch.setattr(mod, "assume_session", lambda arn: f"session-{arn}")
    home = object()

    all_targets = list(mod.scan_targets(home))
    assert [t[0] for t in all_targets] == ["", "111122223333", "444455556666"]

    one = list(mod.scan_targets(home, only=["444455556666"]))
    assert [t[0] for t in one] == ["444455556666"]
    assert one[0][1] == "session-arn:2"

    home_only = list(mod.scan_targets(home, only=["home"]))
    assert [t[0] for t in home_only] == [""]
    assert home_only[0][1] is home
