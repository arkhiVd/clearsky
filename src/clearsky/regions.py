"""Region resolution: explicit list, or auto-discovery of regions that
actually hold infrastructure.

SCAN_REGIONS="auto" probes every enabled region with three cheap reads
(EC2 instances, Lambda functions, DynamoDB tables) in parallel and keeps
the regions where anything exists. The result is cached in the reports
bucket (meta/regions.json, refreshed after CACHE_HOURS) so the API and
diagram workers never pay the probe cost on an interactive path.
"""

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

logger = logging.getLogger()

CACHE_KEY = "meta/regions.json"
CACHE_HOURS = 24
FALLBACK = ["us-east-1"]


def _region_has_infra(session, region: str) -> bool:
    try:
        ec2 = session.client("ec2", region_name=region)
        if ec2.describe_instances(MaxResults=5).get("Reservations"):
            return True
        lam = session.client("lambda", region_name=region)
        if lam.list_functions(MaxItems=1).get("Functions"):
            return True
        ddb = session.client("dynamodb", region_name=region)
        if ddb.list_tables(Limit=1).get("TableNames"):
            return True
    except Exception:  # noqa: BLE001 - opt-in region without access etc.
        logger.info("region probe failed for %s", region)
    return False


def discover_active_regions(session) -> list[str]:
    """All enabled regions that contain EC2/Lambda/DynamoDB resources."""
    ec2 = session.client("ec2", region_name="us-east-1")
    enabled = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
    with ThreadPoolExecutor(max_workers=8) as pool:
        flags = list(pool.map(lambda r: _region_has_infra(session, r), enabled))
    active = sorted(r for r, hit in zip(enabled, flags) if hit)
    return active or FALLBACK


def _load_cache(s3, bucket: str) -> list[str] | None:
    try:
        obj = s3.get_object(Bucket=bucket, Key=CACHE_KEY)
        data = json.loads(obj["Body"].read())
        at = datetime.fromisoformat(data["at"])
        if datetime.now(timezone.utc) - at < timedelta(hours=CACHE_HOURS):
            return data["regions"] or None
    except Exception:  # noqa: BLE001 - no cache yet
        pass
    return None


def _save_cache(s3, bucket: str, regions: list[str]) -> None:
    try:
        s3.put_object(
            Bucket=bucket, Key=CACHE_KEY, ContentType="application/json",
            Body=json.dumps({
                "regions": regions,
                "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }).encode())
    except Exception:  # noqa: BLE001 - cache is best-effort
        logger.info("could not cache region list")


def resolve_regions(session, env_value: str, bucket: str | None = None,
                    allow_discovery: bool = True) -> list[str]:
    """Turn the SCAN_REGIONS setting into a concrete region list.

    Explicit comma list -> as given. "auto" -> cached discovery result,
    or a fresh probe (cached afterwards) when allowed; interactive callers
    pass allow_discovery=False and fall back rather than block."""
    explicit = [r.strip() for r in (env_value or "").split(",")
                if r.strip() and r.strip() != "auto"]
    if explicit:
        return explicit
    if (env_value or "").strip() != "auto":
        return FALLBACK
    s3 = session.client("s3") if bucket else None
    if s3 and bucket:
        cached = _load_cache(s3, bucket)
        if cached:
            return cached
    if not allow_discovery:
        return FALLBACK
    regions = discover_active_regions(session)
    if s3 and bucket:
        _save_cache(s3, bucket, regions)
    return regions
