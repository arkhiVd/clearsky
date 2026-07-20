"""Running EC2 instances whose CPU never rises above the idle threshold.

Daily p95 CPUUtilization over the lookback window; every observed day
must be below IDLE_CPU_PCT and at least MIN_DAYS of data must exist, so
freshly launched instances are not flagged.
"""

from datetime import datetime, timedelta, timezone

from clearsky.models import Finding
from clearsky.registry import register

IDLE_CPU_PCT = 5.0
LOOKBACK_DAYS = 14
MIN_DAYS = 7

# rough on-demand $/month for common lab types; unknown types report 0
MONTHLY_PRICE = {
    "t2.micro": 8.5, "t3.micro": 7.6, "t3.small": 15.2, "t3.medium": 30.4,
    "t3.large": 60.7, "m5.large": 70.1, "m5.xlarge": 140.2, "c5.large": 62.1,
}


def evaluate_idle(instances: list[dict], region: str) -> list[Finding]:
    """instances: [{id, type, name, daily_p95: [floats]}] -> findings."""
    findings = []
    for inst in instances:
        series = inst.get("daily_p95", [])
        if len(series) < MIN_DAYS:
            continue
        peak = max(series)
        if peak >= IDLE_CPU_PCT:
            continue
        label = inst.get("name") or inst["id"]
        findings.append(Finding(
            detector="ec2.idle",
            resource_id=inst["id"],
            severity="MEDIUM",
            title=(
                f"Idle instance {label} ({inst.get('type', '?')}): "
                f"CPU p95 peaked at {peak:.1f}% over {len(series)} days"
            ),
            detail=(
                "CPU has stayed below "
                f"{IDLE_CPU_PCT:.0f}% for the whole window. Stop it, "
                "downsize it, or schedule it off out of hours: "
                f"aws ec2 stop-instances --instance-ids {inst['id']}"
            ),
            region=region,
            estimated_monthly_cost=MONTHLY_PRICE.get(inst.get("type", ""), 0.0),
        ))
    return findings


@register
class Ec2IdleDetector:
    id = "ec2.idle"
    title = "Idle EC2 instances"

    def run(self, session, region: str) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        running = []
        for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ):
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    running.append({
                        "id": inst["InstanceId"],
                        "type": inst.get("InstanceType"),
                        "name": tags.get("Name"),
                    })
        if not running:
            return []

        cw = session.client("cloudwatch", region_name=region)
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=LOOKBACK_DAYS)
        # one GetMetricData call per 100 instances (500-query API limit margin)
        for chunk_start in range(0, len(running), 100):
            chunk = running[chunk_start:chunk_start + 100]
            queries = [{
                "Id": f"cpu{i}",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/EC2",
                        "MetricName": "CPUUtilization",
                        "Dimensions": [
                            {"Name": "InstanceId", "Value": inst["id"]}
                        ],
                    },
                    "Period": 86400,
                    "Stat": "p95",
                },
            } for i, inst in enumerate(chunk)]
            resp = cw.get_metric_data(
                MetricDataQueries=queries, StartTime=start, EndTime=end
            )
            by_id = {r["Id"]: r.get("Values", []) for r in resp["MetricDataResults"]}
            for i, inst in enumerate(chunk):
                inst["daily_p95"] = by_id.get(f"cpu{i}", [])

        return evaluate_idle(running, region)
