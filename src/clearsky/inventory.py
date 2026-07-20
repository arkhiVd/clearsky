"""Daily inventory sheet: resource counts, backup job outcomes, deltas.

Deterministic describe/list calls only — no AI, no metrics math. Each
collector returns a flat {metric_name: count} dict; summarize functions
are pure so they fixture-test without AWS. Snapshots persist to S3 as
JSON (machine, dashboard) and CSV (humans, Excel), and the digest shows
today's counts with deltas vs the previous snapshot.
"""

import csv
import io
import json
import os
from datetime import datetime, timedelta, timezone


# ---------- pure summarizers ----------

def summarize_instances(reservations: list) -> dict[str, int]:
    counts: dict[str, int] = {"ec2.total": 0}
    for res in reservations:
        for inst in res.get("Instances", []):
            state = inst["State"]["Name"]
            if state == "terminated":
                continue
            counts["ec2.total"] += 1
            counts[f"ec2.{state}"] = counts.get(f"ec2.{state}", 0) + 1
            itype = inst.get("InstanceType", "unknown")
            counts[f"ec2.type.{itype}"] = counts.get(f"ec2.type.{itype}", 0) + 1
            # EKS worker nodes carry cluster tags — split them out so the
            # dashboard's server-state ring can show nodes separately
            tags = {t.get("Key", "") for t in inst.get("Tags", [])}
            if any(k == "eks:cluster-name" or k.startswith("kubernetes.io/cluster/")
                   for k in tags):
                counts[f"eks.nodes.{state}"] = counts.get(f"eks.nodes.{state}", 0) + 1
    return counts


def summarize_volumes(volumes: list) -> dict[str, int]:
    return {
        "ebs.volumes": len(volumes),
        "ebs.unattached": sum(1 for v in volumes if not v.get("Attachments")),
    }


def summarize_db_instances(instances: list) -> dict[str, int]:
    counts = {"rds.instances": len(instances)}
    for db in instances:
        engine = db.get("Engine", "unknown")
        counts[f"rds.engine.{engine}"] = counts.get(f"rds.engine.{engine}", 0) + 1
    return counts


def summarize_backup_jobs(jobs: list) -> dict[str, int]:
    counts = {"backup.jobs_24h": len(jobs), "backup.failed_24h": 0}
    for job in jobs:
        state = job.get("State", "")
        if state in ("FAILED", "ABORTED", "EXPIRED"):
            counts["backup.failed_24h"] += 1
    return counts


def diff(current: dict[str, int], previous: dict[str, int] | None) -> dict[str, int]:
    """Per-metric change vs previous snapshot. Empty when no previous."""
    if not previous:
        return {}
    keys = set(current) | set(previous)
    return {
        k: current.get(k, 0) - previous.get(k, 0)
        for k in sorted(keys)
        if current.get(k, 0) != previous.get(k, 0)
    }


# ---------- collection ----------

def collect(session, regions: list[str]) -> dict[str, int]:
    metrics: dict[str, int] = {}

    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        reservations = []
        for page in ec2.get_paginator("describe_instances").paginate():
            reservations.extend(page["Reservations"])
        _merge(metrics, summarize_instances(reservations))

        volumes = []
        for page in ec2.get_paginator("describe_volumes").paginate():
            volumes.extend(page["Volumes"])
        _merge(metrics, summarize_volumes(volumes))

        snaps = ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]
        _merge(metrics, {"ebs.snapshots": len(snaps)})

        eips = ec2.describe_addresses()["Addresses"]
        _merge(metrics, {"ec2.eips": len(eips)})

        rds = session.client("rds", region_name=region)
        dbs = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            dbs.extend(page["DBInstances"])
        _merge(metrics, summarize_db_instances(dbs))

        lam = session.client("lambda", region_name=region)
        fn_count = 0
        for page in lam.get_paginator("list_functions").paginate():
            fn_count += len(page["Functions"])
        _merge(metrics, {"lambda.functions": fn_count})

        eks = session.client("eks", region_name=region)
        _merge(metrics, {"eks.clusters": len(eks.list_clusters()["clusters"])})

        backup = session.client("backup", region_name=region)
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        jobs = []
        for page in backup.get_paginator("list_backup_jobs").paginate(
            ByCreatedAfter=since
        ):
            jobs.extend(page["BackupJobs"])
        _merge(metrics, summarize_backup_jobs(jobs))

    # global services, once
    s3 = session.client("s3")
    metrics["s3.buckets"] = len(s3.list_buckets()["Buckets"])
    ddb = session.client("dynamodb", region_name=regions[0])
    tables = []
    for page in ddb.get_paginator("list_tables").paginate():
        tables.extend(page["TableNames"])
    metrics["dynamodb.tables"] = len(tables)

    return metrics


def _merge(into: dict[str, int], new: dict[str, int]) -> None:
    for key, value in new.items():
        into[key] = into.get(key, 0) + value


# ---------- persistence ----------

def _key(day: str, ext: str) -> str:
    y, m, d = day.split("-")
    return f"inventory/{y}/{m}/{d}.{ext}"


def load_previous(s3, bucket: str, today: str) -> dict[str, int] | None:
    """Most recent snapshot in the 7 days before today, if any."""
    day = datetime.fromisoformat(today).date()
    for back in range(1, 8):
        key = _key((day - timedelta(days=back)).isoformat(), "json")
        try:
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            return json.loads(body)["metrics"]
        except s3.exceptions.NoSuchKey:
            continue
    return None


def save(s3, bucket: str, day: str, metrics: dict[str, int]) -> None:
    s3.put_object(
        Bucket=bucket,
        Key=_key(day, "json"),
        Body=json.dumps({"day": day, "metrics": metrics}).encode(),
        ContentType="application/json",
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["date", "metric", "value"])
    for name in sorted(metrics):
        writer.writerow([day, name, metrics[name]])
    s3.put_object(
        Bucket=bucket,
        Key=_key(day, "csv"),
        Body=buf.getvalue().encode(),
        ContentType="text/csv",
    )


# ---------- rendering ----------

HEADLINE = [
    ("ec2.running", "EC2 running"),
    ("ec2.stopped", "EC2 stopped"),
    ("ec2.eips", "Elastic IPs"),
    ("ebs.volumes", "EBS volumes"),
    ("ebs.unattached", "EBS unattached"),
    ("ebs.snapshots", "EBS snapshots"),
    ("rds.instances", "RDS instances"),
    ("lambda.functions", "Lambda functions"),
    ("eks.clusters", "EKS clusters"),
    ("dynamodb.tables", "DynamoDB tables"),
    ("s3.buckets", "S3 buckets"),
    ("backup.jobs_24h", "Backup jobs 24h"),
    ("backup.failed_24h", "Backup FAILED 24h"),
]


def render_section(metrics: dict[str, int], deltas: dict[str, int]) -> str:
    lines = ["INVENTORY"]
    for key, label in HEADLINE:
        value = metrics.get(key, 0)
        if key == "backup.failed_24h" and value == 0 and metrics.get("backup.jobs_24h", 0) == 0:
            continue
        delta = deltas.get(key)
        delta_part = f"  ({delta:+d} vs prev)" if delta else ""
        alert = "  <-- ATTENTION" if key == "backup.failed_24h" and value > 0 else ""
        lines.append(f"  {label}: {value}{delta_part}{alert}")
    other_changes = {
        k: v for k, v in deltas.items() if k not in dict(HEADLINE)
    }
    if other_changes:
        lines.append("  Other changes:")
        lines.extend(f"    {k}: {v:+d}" for k, v in sorted(other_changes.items()))
    return "\n".join(lines)


def run(session, regions: list[str], bucket: str | None = None) -> str:
    """Collect, persist, and render today's inventory section."""
    import boto3

    bucket = bucket or os.environ["REPORTS_BUCKET"]
    s3 = session.client("s3") if session else boto3.client("s3")
    today = datetime.now(timezone.utc).date().isoformat()

    metrics = collect(session, regions)
    previous = load_previous(s3, bucket, today)
    deltas = diff(metrics, previous)
    save(s3, bucket, today, metrics)
    return render_section(metrics, deltas)
