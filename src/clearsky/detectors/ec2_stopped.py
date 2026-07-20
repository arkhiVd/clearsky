"""Stopped EC2 instances that keep billing through their attached EBS.

A stopped instance costs nothing for compute, but every attached volume
is billed in full. If a box has been stopped for a while, the cheaper
durable options are an AMI (image + snapshots, then terminate) or
per-volume snapshots — snapshot storage is ~half the gp3 GB price and
only stores used blocks.

The stop timestamp comes from StateTransitionReason, e.g.
"User initiated (2026-07-01 07:05:20 GMT)"; instances without a
parseable timestamp are skipped rather than guessed at.
"""

import re
from datetime import datetime, timedelta, timezone

from clearsky.models import Finding
from clearsky.registry import register

STOPPED_DAYS = 3
GB_MONTH_PRICE = 0.096   # gp3, most regions incl. ap-northeast-1
SNAPSHOT_GB_MONTH = 0.05

_STOP_TS = re.compile(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)")


def _stopped_at(reason: str) -> datetime | None:
    m = _STOP_TS.search(reason or "")
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(
        tzinfo=timezone.utc)


def parse_stopped(instances: list, gb_by_instance: dict, region: str,
                  now: datetime | None = None) -> list[Finding]:
    """instances: raw describe_instances Instances (stopped state);
    gb_by_instance: {instance_id: attached EBS GiB}."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=STOPPED_DAYS)
    findings = []
    for inst in instances:
        if inst.get("State", {}).get("Name") != "stopped":
            continue
        stopped_at = _stopped_at(inst.get("StateTransitionReason", ""))
        if stopped_at is None or stopped_at > cutoff:
            continue
        iid = inst["InstanceId"]
        days = (now - stopped_at).days
        gb = gb_by_instance.get(iid, 0)
        ebs_month = round(gb * GB_MONTH_PRICE, 2)
        saving = round(gb * (GB_MONTH_PRICE - SNAPSHOT_GB_MONTH), 2)
        name = next((t["Value"] for t in inst.get("Tags", [])
                     if t["Key"] == "Name"), iid)
        findings.append(Finding(
            detector="ec2.stopped",
            resource_id=iid,
            severity="MEDIUM",
            title=(f"Instance {name} stopped {days} days — "
                   f"{gb} GiB EBS still billing"),
            detail=(
                f"Stopped since {stopped_at.date()}; compute is free but the "
                f"attached volumes cost ~${ebs_month}/mo. If it won't be "
                "needed soon, keep a restorable image and terminate: "
                f"aws ec2 create-image --instance-id {iid} "
                f"--name {name}-archive --region {region} "
                f"(then terminate-instances). Snapshots cost ~half the "
                "volume price and only store used blocks."
            ),
            region=region,
            estimated_monthly_cost=saving,
        ))
    return findings


@register
class Ec2StoppedDetector:
    id = "ec2.stopped"
    title = "Long-stopped EC2 instances with billed EBS"

    def run(self, session, region: str) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        instances = []
        for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        ):
            for res in page["Reservations"]:
                instances.extend(res["Instances"])
        if not instances:
            return []
        gb_by_instance: dict[str, int] = {}
        for page in ec2.get_paginator("describe_volumes").paginate():
            for vol in page["Volumes"]:
                for att in vol.get("Attachments", []):
                    iid = att.get("InstanceId", "")
                    gb_by_instance[iid] = (gb_by_instance.get(iid, 0)
                                           + vol.get("Size", 0))
        return parse_stopped(instances, gb_by_instance, region)
