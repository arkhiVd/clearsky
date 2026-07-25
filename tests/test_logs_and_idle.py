from clearsky.detectors.ec2_idle import evaluate_idle
from clearsky.detectors.logs_retention import parse_log_groups


def test_log_group_without_retention_flagged():
    groups = [
        {"logGroupName": "/aws/lambda/x", "storedBytes": 5_000_000_000},
        {"logGroupName": "/aws/lambda/y", "retentionInDays": 14,
         "storedBytes": 9e12},
    ]
    findings = parse_log_groups(groups, "us-east-1")
    assert [f.resource_id for f in findings] == ["/aws/lambda/x"]
    assert findings[0].severity == "MEDIUM"  # 5 GB stored
    assert "put-retention-policy" in findings[0].detail


def test_idle_instance_flagged():
    instances = [{
        "id": "i-idle", "type": "t3.micro", "name": "dev-box",
        "daily_p95": [1.2, 0.8, 2.0, 1.1, 0.5, 3.9, 1.0, 2.2],
    }]
    findings = evaluate_idle(instances, "us-east-1")
    assert len(findings) == 1
    assert findings[0].resource_id == "i-idle"
    assert findings[0].estimated_monthly_cost == 7.6


def test_busy_or_young_instances_not_flagged():
    instances = [
        {"id": "i-busy", "type": "t3.micro",
         "daily_p95": [1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 80.0]},
        {"id": "i-young", "type": "t3.micro", "daily_p95": [0.5, 0.5]},
    ]
    assert evaluate_idle(instances, "us-east-1") == []
