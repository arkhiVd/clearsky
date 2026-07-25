from datetime import datetime, timezone

from clearsky.detectors.ebs import parse_snapshots, parse_volumes

NOW = datetime(2026, 7, 6, tzinfo=timezone.utc)


def test_unattached_gp2_volume_gets_two_findings():
    volumes = [{
        "VolumeId": "vol-1", "Size": 100, "VolumeType": "gp2",
        "Attachments": [],
    }]
    findings = parse_volumes(volumes, "us-east-1")
    detectors = sorted(f.detector for f in findings)
    assert detectors == ["ebs.gp2", "ebs.unattached"]
    unattached = next(f for f in findings if f.detector == "ebs.unattached")
    assert unattached.estimated_monthly_cost == 10.0  # 100 GiB * $0.10
    gp2 = next(f for f in findings if f.detector == "ebs.gp2")
    assert gp2.estimated_monthly_cost == 2.0  # 20% of gp2 price


def test_attached_gp3_volume_clean():
    volumes = [{
        "VolumeId": "vol-2", "Size": 50, "VolumeType": "gp3",
        "Attachments": [{"InstanceId": "i-1"}],
    }]
    assert parse_volumes(volumes, "us-east-1") == []


def test_stale_snapshot_flagged_fresh_kept():
    snapshots = [
        {"SnapshotId": "snap-old", "VolumeSize": 40,
         "StartTime": datetime(2026, 1, 1, tzinfo=timezone.utc)},
        {"SnapshotId": "snap-new", "VolumeSize": 40,
         "StartTime": datetime(2026, 7, 1, tzinfo=timezone.utc)},
    ]
    findings = parse_snapshots(snapshots, "us-east-1", now=NOW)
    assert [f.resource_id for f in findings] == ["snap-old"]
    assert findings[0].estimated_monthly_cost == 2.0  # 40 GiB * $0.05
