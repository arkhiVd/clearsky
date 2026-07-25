from clearsky.detectors.security_data import (
    check_bucket_public,
    parse_db_instances,
    parse_trails,
    parse_unencrypted_volumes,
)
from clearsky.detectors.security_iam import evaluate_users
from clearsky.detectors.security_net import parse_security_groups, parse_vpcs
from clearsky.posture import compute_score, render_section

FULL_PAB = {
    "BlockPublicAcls": True, "IgnorePublicAcls": True,
    "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
}


def test_console_user_without_mfa_high():
    users = [{"name": "alice", "has_console": True, "mfa_count": 0}]
    findings = evaluate_users(users)
    assert [f.detector for f in findings] == ["sec.iam_no_mfa"]
    assert findings[0].severity == "HIGH"


def test_service_user_old_key_and_admin():
    users = [{
        "name": "ci-bot", "has_console": False, "mfa_count": 0,
        "key_ages_days": [120, 200],
        "attached_policies": ["AdministratorAccess"],
    }]
    detectors = sorted(f.detector for f in evaluate_users(users))
    assert detectors == ["sec.iam_admin_user", "sec.iam_old_key"]
    # no MFA finding for console-less user, one key finding despite two old keys


def test_sg_open_world_sensitive_ports():
    groups = [{
        "GroupId": "sg-1", "GroupName": "bad",
        "IpPermissions": [{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],
        }],
    }]
    findings = parse_security_groups(groups, "us-east-1")
    assert len(findings) == 1
    assert "22 (SSH)" in findings[0].title


def test_sg_restricted_or_http_not_flagged():
    groups = [
        {"GroupId": "sg-2", "IpPermissions": [{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}], "Ipv6Ranges": [],
        }]},
        {"GroupId": "sg-3", "IpPermissions": [{
            "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],
        }]},
    ]
    assert parse_security_groups(groups, "us-east-1") == []


def test_sg_all_traffic_flagged():
    groups = [{"GroupId": "sg-4", "IpPermissions": [{
        "IpProtocol": "-1",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],
    }]}]
    findings = parse_security_groups(groups, "us-east-1")
    assert "ALL traffic" in findings[0].title


def test_default_vpc_flagged():
    vpcs = [{"VpcId": "vpc-1", "IsDefault": True},
            {"VpcId": "vpc-2", "IsDefault": False}]
    findings = parse_vpcs(vpcs, "us-east-1")
    assert [f.resource_id for f in findings] == ["vpc-1"]


def test_bucket_public_policy_high_no_pab_medium():
    assert check_bucket_public(
        {"name": "b", "pab": FULL_PAB, "policy_public": True}, "g"
    )[0].detector == "sec.s3_public"
    assert check_bucket_public(
        {"name": "b", "pab": None, "policy_public": False}, "g"
    )[0].detector == "sec.s3_no_pab"
    assert check_bucket_public(
        {"name": "b", "pab": FULL_PAB, "policy_public": False}, "g"
    ) == []


def test_unencrypted_volume_and_rds():
    assert parse_unencrypted_volumes(
        [{"VolumeId": "vol-1", "Encrypted": False},
         {"VolumeId": "vol-2", "Encrypted": True}], "r"
    )[0].resource_id == "vol-1"
    findings = parse_db_instances(
        [{"DBInstanceIdentifier": "db1", "StorageEncrypted": False,
          "PubliclyAccessible": True}], "r"
    )
    assert sorted(f.detector for f in findings) == [
        "sec.rds_public", "sec.rds_unencrypted"
    ]


def test_cloudtrail_missing_vs_present():
    assert parse_trails([])[0].detector == "sec.no_cloudtrail"
    assert parse_trails([{"IsMultiRegionTrail": True}]) == []


def test_posture_score_and_render():
    findings = [
        {"detector": "sec.iam_no_mfa", "severity": "HIGH", "title": "no mfa"},
        {"detector": "sec.s3_no_pab", "severity": "MEDIUM", "title": "no pab"},
    ]
    score = compute_score(findings)
    assert score == 80  # 100 - 15 - 5
    section = render_section(score, 95, findings)
    assert "80/100" in section and "DROPPED from 95" in section
    assert "no mfa" in section
    assert compute_score([]) == 100
