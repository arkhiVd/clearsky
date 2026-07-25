from clearsky.detectors.s3_hygiene import check_bucket


def base(**overrides):
    cfg = {
        "name": "bucket-a",
        "versioning": None,
        "has_lifecycle": False,
        "has_noncurrent_expiry": False,
        "has_mpu_abort_rule": False,
        "is_logging_target": False,
        "pending_mpus": 0,
    }
    cfg.update(overrides)
    return cfg


def test_clean_bucket_no_findings():
    assert check_bucket(base(), "us-east-1") == []


def test_versioning_without_noncurrent_expiry():
    findings = check_bucket(base(versioning="Enabled"), "us-east-1")
    assert [f.detector for f in findings] == ["s3.versioning_no_lifecycle"]


def test_versioning_with_noncurrent_expiry_clean():
    cfg = base(versioning="Enabled", has_noncurrent_expiry=True)
    assert check_bucket(cfg, "us-east-1") == []


def test_logging_target_without_lifecycle():
    findings = check_bucket(base(is_logging_target=True), "us-east-1")
    assert [f.detector for f in findings] == ["s3.log_bucket_no_lifecycle"]


def test_pending_mpus_without_abort_rule():
    findings = check_bucket(base(pending_mpus=3), "us-east-1")
    assert [f.detector for f in findings] == ["s3.incomplete_mpu"]
    assert "3 incomplete" in findings[0].title


def test_pending_mpus_with_abort_rule_clean():
    cfg = base(pending_mpus=3, has_mpu_abort_rule=True)
    assert check_bucket(cfg, "us-east-1") == []
