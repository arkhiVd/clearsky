"""EBS waste: unattached volumes, gp2 volumes, stale snapshots."""

from datetime import datetime, timedelta, timezone

from clearsky.models import Finding
from clearsky.registry import register

GB_MONTH_PRICE = {
    "gp2": 0.10, "gp3": 0.08, "io1": 0.125, "io2": 0.125,
    "st1": 0.045, "sc1": 0.015, "standard": 0.05,
}
SNAPSHOT_GB_MONTH = 0.05
GP2_TO_GP3_SAVING_PER_GB = 0.02
STALE_SNAPSHOT_DAYS = 90


def parse_volumes(volumes: list, region: str) -> list[Finding]:
    findings = []
    for vol in volumes:
        vol_id = vol["VolumeId"]
        size = vol.get("Size", 0)
        vtype = vol.get("VolumeType", "gp2")
        if not vol.get("Attachments"):
            monthly = round(size * GB_MONTH_PRICE.get(vtype, 0.08), 2)
            findings.append(Finding(
                detector="ebs.unattached",
                resource_id=vol_id,
                severity="MEDIUM",
                title=f"Unattached {size} GiB {vtype} volume {vol_id}",
                detail=(
                    "Volume is not attached to any instance but still billed. "
                    "Snapshot it if the data matters, then delete: "
                    f"aws ec2 delete-volume --volume-id {vol_id}"
                ),
                region=region,
                estimated_monthly_cost=monthly,
            ))
        if vtype == "gp2":
            saving = round(size * GP2_TO_GP3_SAVING_PER_GB, 2)
            findings.append(Finding(
                detector="ebs.gp2",
                resource_id=vol_id,
                severity="LOW",
                title=f"gp2 volume {vol_id} ({size} GiB) can migrate to gp3",
                detail=(
                    "gp3 is ~20% cheaper than gp2 at the same baseline "
                    "performance; migration is online and non-disruptive: "
                    f"aws ec2 modify-volume --volume-id {vol_id} --volume-type gp3"
                ),
                region=region,
                estimated_monthly_cost=saving,
            ))
    return findings


def parse_snapshots(snapshots: list, region: str,
                    now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=STALE_SNAPSHOT_DAYS)
    findings = []
    for snap in snapshots:
        start = snap["StartTime"]
        if isinstance(start, str):
            start = datetime.fromisoformat(start)
        if start > cutoff:
            continue
        snap_id = snap["SnapshotId"]
        size = snap.get("VolumeSize", 0)
        age_days = (now - start).days
        findings.append(Finding(
            detector="ebs.stale_snapshot",
            resource_id=snap_id,
            severity="LOW",
            title=f"Snapshot {snap_id} is {age_days} days old ({size} GiB)",
            detail=(
                f"Snapshot older than {STALE_SNAPSHOT_DAYS} days. If it is not "
                "a retained backup, delete it: "
                f"aws ec2 delete-snapshot --snapshot-id {snap_id}"
            ),
            region=region,
            estimated_monthly_cost=round(size * SNAPSHOT_GB_MONTH, 2),
        ))
    return findings


@register
class EbsVolumeDetector:
    id = "ebs.volumes"
    title = "EBS volume waste (unattached, gp2)"

    def run(self, session, region: str) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        volumes = []
        for page in ec2.get_paginator("describe_volumes").paginate():
            volumes.extend(page["Volumes"])
        return parse_volumes(volumes, region)


@register
class StaleSnapshotDetector:
    id = "ebs.stale_snapshot"
    title = "Stale EBS snapshots"

    def run(self, session, region: str) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        snapshots = []
        for page in ec2.get_paginator("describe_snapshots").paginate(
            OwnerIds=["self"]
        ):
            snapshots.extend(page["Snapshots"])
        return parse_snapshots(snapshots, region)
