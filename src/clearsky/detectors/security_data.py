"""Data protection: public S3 buckets, unencrypted EBS/RDS, missing
CloudTrail."""

from botocore.exceptions import ClientError

from clearsky.models import Finding
from clearsky.registry import register


def check_bucket_public(cfg: dict, region: str) -> list[Finding]:
    """cfg: {name, pab: {four block flags} | None, policy_public: bool}"""
    name = cfg["name"]
    pab = cfg.get("pab") or {}
    fully_blocked = all(pab.get(flag) for flag in (
        "BlockPublicAcls", "IgnorePublicAcls",
        "BlockPublicPolicy", "RestrictPublicBuckets",
    ))
    findings = []
    if cfg.get("policy_public"):
        findings.append(Finding(
            detector="sec.s3_public",
            resource_id=name,
            severity="HIGH",
            title=f"Bucket {name} has a public bucket policy",
            detail=(
                "Bucket policy grants public access. Remove the public "
                "statement and enable the public access block."
            ),
            region=region,
        ))
    elif not fully_blocked:
        findings.append(Finding(
            detector="sec.s3_no_pab",
            resource_id=name,
            severity="MEDIUM",
            title=f"Bucket {name} lacks a full public access block",
            detail=(
                "Enable all four public access block settings: "
                f"aws s3api put-public-access-block --bucket {name} "
                "--public-access-block-configuration BlockPublicAcls=true,"
                "IgnorePublicAcls=true,BlockPublicPolicy=true,"
                "RestrictPublicBuckets=true"
            ),
            region=region,
        ))
    return findings


def parse_unencrypted_volumes(volumes: list, region: str) -> list[Finding]:
    return [
        Finding(
            detector="sec.ebs_unencrypted",
            resource_id=vol["VolumeId"],
            severity="MEDIUM",
            title=f"EBS volume {vol['VolumeId']} is not encrypted",
            detail=(
                "Existing volumes cannot be encrypted in place: snapshot, "
                "copy the snapshot with encryption, recreate the volume. "
                "Also enable EBS encryption-by-default for the account."
            ),
            region=region,
        )
        for vol in volumes if not vol.get("Encrypted")
    ]


def parse_db_instances(instances: list, region: str) -> list[Finding]:
    findings = []
    for db in instances:
        db_id = db["DBInstanceIdentifier"]
        if not db.get("StorageEncrypted"):
            findings.append(Finding(
                detector="sec.rds_unencrypted",
                resource_id=db_id,
                severity="MEDIUM",
                title=f"RDS instance {db_id} storage is not encrypted",
                detail=(
                    "Encryption can only be set at creation: snapshot, copy "
                    "with encryption, restore."
                ),
                region=region,
            ))
        if db.get("PubliclyAccessible"):
            findings.append(Finding(
                detector="sec.rds_public",
                resource_id=db_id,
                severity="HIGH",
                title=f"RDS instance {db_id} is publicly accessible",
                detail=(
                    "Database reachable from the internet. Disable public "
                    "accessibility and reach it through the VPC."
                ),
                region=region,
            ))
    return findings


def parse_trails(trails: list, region: str = "global") -> list[Finding]:
    if any(t.get("IsMultiRegionTrail") for t in trails):
        return []
    return [Finding(
        detector="sec.no_cloudtrail",
        resource_id="account",
        severity="HIGH",
        title="No multi-region CloudTrail trail configured",
        detail=(
            "API activity is not being recorded. Create one multi-region "
            "trail to S3 (first management-event trail is free; S3 storage "
            "pennies)."
        ),
        region=region,
    )]


@register
class S3PublicDetector:
    id = "sec.s3_public"
    title = "Publicly accessible S3 buckets"
    scope = "global"

    def run(self, session, region: str) -> list[Finding]:
        s3 = session.client("s3")
        findings = []
        for bucket in s3.list_buckets()["Buckets"]:
            name = bucket["Name"]
            try:
                pab = s3.get_public_access_block(Bucket=name)[
                    "PublicAccessBlockConfiguration"
                ]
            except ClientError as err:
                code = err.response["Error"]["Code"]
                if code != "NoSuchPublicAccessBlockConfiguration":
                    raise
                pab = None
            try:
                policy_public = s3.get_bucket_policy_status(Bucket=name)[
                    "PolicyStatus"
                ]["IsPublic"]
            except ClientError as err:
                if err.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    raise
                policy_public = False
            findings.extend(check_bucket_public(
                {"name": name, "pab": pab, "policy_public": policy_public},
                region,
            ))
        return findings


@register
class UnencryptedEbsDetector:
    id = "sec.ebs_unencrypted"
    title = "Unencrypted EBS volumes"

    def run(self, session, region: str) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        volumes = []
        for page in ec2.get_paginator("describe_volumes").paginate():
            volumes.extend(page["Volumes"])
        return parse_unencrypted_volumes(volumes, region)


@register
class RdsSecurityDetector:
    id = "sec.rds"
    title = "RDS encryption and exposure"

    def run(self, session, region: str) -> list[Finding]:
        rds = session.client("rds", region_name=region)
        instances = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            instances.extend(page["DBInstances"])
        return parse_db_instances(instances, region)


@register
class CloudTrailDetector:
    id = "sec.no_cloudtrail"
    title = "CloudTrail coverage"
    scope = "global"

    def run(self, session, region: str) -> list[Finding]:
        ct = session.client("cloudtrail", region_name=region)
        return parse_trails(ct.describe_trails()["trailList"])
