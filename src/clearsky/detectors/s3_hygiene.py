"""S3 hygiene: versioning without lifecycle, unbounded log buckets,
incomplete multipart uploads.

One runner collects per-bucket config once, then pure check functions
evaluate it. Only buckets homed in the scanned region are evaluated so
multi-region scans do not duplicate findings.
"""

from botocore.exceptions import ClientError

from clearsky.models import Finding
from clearsky.registry import register


def check_bucket(cfg: dict, region: str) -> list[Finding]:
    """cfg: {name, versioning, has_lifecycle, has_noncurrent_expiry,
             has_mpu_abort_rule, is_logging_target, pending_mpus}"""
    name = cfg["name"]
    findings = []

    if cfg.get("versioning") == "Enabled" and not cfg.get("has_noncurrent_expiry"):
        findings.append(Finding(
            detector="s3.versioning_no_lifecycle",
            resource_id=name,
            severity="MEDIUM",
            title=f"Bucket {name}: versioning on, no noncurrent-version expiry",
            detail=(
                "Every overwrite/delete keeps the old version forever and "
                "bills as storage. Add a lifecycle rule with "
                "NoncurrentVersionExpiration (e.g. expire noncurrent versions "
                "after 30-90 days)."
            ),
            region=region,
        ))

    if cfg.get("is_logging_target") and not cfg.get("has_lifecycle"):
        findings.append(Finding(
            detector="s3.log_bucket_no_lifecycle",
            resource_id=name,
            severity="MEDIUM",
            title=f"Bucket {name} receives access logs but has no lifecycle",
            detail=(
                "Server access log buckets grow without bound. Add a "
                "lifecycle rule expiring log objects (e.g. after 90 days) "
                "or transitioning them to Glacier."
            ),
            region=region,
        ))

    if cfg.get("pending_mpus", 0) > 0 and not cfg.get("has_mpu_abort_rule"):
        findings.append(Finding(
            detector="s3.incomplete_mpu",
            resource_id=name,
            severity="LOW",
            title=(
                f"Bucket {name}: {cfg['pending_mpus']} incomplete multipart "
                "uploads, no abort rule"
            ),
            detail=(
                "Incomplete multipart uploads bill as storage but are "
                "invisible in object listings. Add a lifecycle rule with "
                "AbortIncompleteMultipartUpload (e.g. 7 days)."
            ),
            region=region,
        ))

    return findings


@register
class S3HygieneDetector:
    id = "s3.hygiene"
    title = "S3 bucket hygiene"

    def run(self, session, region: str) -> list[Finding]:
        s3 = session.client("s3", region_name=region)
        buckets = [b["Name"] for b in s3.list_buckets()["Buckets"]]

        logging_targets = set()
        configs = []
        for name in buckets:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            bucket_region = loc or "us-east-1"
            if bucket_region != region:
                continue

            cfg = {"name": name}
            cfg["versioning"] = s3.get_bucket_versioning(Bucket=name).get("Status")

            try:
                rules = s3.get_bucket_lifecycle_configuration(
                    Bucket=name
                ).get("Rules", [])
            except ClientError as err:
                if err.response["Error"]["Code"] != "NoSuchLifecycleConfiguration":
                    raise
                rules = []
            enabled = [r for r in rules if r.get("Status") == "Enabled"]
            cfg["has_lifecycle"] = bool(enabled)
            cfg["has_noncurrent_expiry"] = any(
                "NoncurrentVersionExpiration" in r for r in enabled
            )
            cfg["has_mpu_abort_rule"] = any(
                "AbortIncompleteMultipartUpload" in r for r in enabled
            )

            target = s3.get_bucket_logging(Bucket=name).get(
                "LoggingEnabled", {}
            ).get("TargetBucket")
            if target:
                logging_targets.add(target)

            cfg["pending_mpus"] = len(
                s3.list_multipart_uploads(Bucket=name).get("Uploads", []) or []
            )
            configs.append(cfg)

        findings = []
        for cfg in configs:
            cfg["is_logging_target"] = cfg["name"] in logging_targets
            findings.extend(check_bucket(cfg, region))
        return findings
