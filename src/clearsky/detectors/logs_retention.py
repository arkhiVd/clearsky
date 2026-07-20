"""CloudWatch log groups without a retention policy grow forever."""

from clearsky.models import Finding
from clearsky.registry import register

INGEST_ONLY = 0.03  # storage $/GB-month; used for the estimate


def parse_log_groups(groups: list, region: str) -> list[Finding]:
    findings = []
    for group in groups:
        if group.get("retentionInDays"):
            continue
        name = group["logGroupName"]
        stored_gb = group.get("storedBytes", 0) / 1e9
        findings.append(Finding(
            detector="logs.no_retention",
            resource_id=name,
            severity="LOW" if stored_gb < 1 else "MEDIUM",
            title=f"Log group {name} has no retention policy",
            detail=(
                f"Currently storing {stored_gb:.2f} GB forever. Set retention: "
                f'aws logs put-retention-policy --log-group-name "{name}" '
                "--retention-in-days 14"
            ),
            region=region,
            estimated_monthly_cost=round(stored_gb * INGEST_ONLY, 2),
        ))
    return findings


@register
class LogRetentionDetector:
    id = "logs.no_retention"
    title = "CloudWatch log groups without retention"

    def run(self, session, region: str) -> list[Finding]:
        logs = session.client("logs", region_name=region)
        groups = []
        for page in logs.get_paginator("describe_log_groups").paginate():
            groups.extend(page["logGroups"])
        return parse_log_groups(groups, region)
