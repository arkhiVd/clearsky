"""EKS cost: clusters in extended support, underutilized worker nodes.

Extended support bills $0.60/cluster-hour vs $0.10 standard — an extra
~$365/month per cluster just for running an old Kubernetes version.

Standard support end dates from the published EKS release calendar;
maintain this map as new versions ship (verify against
https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html).
"""

from datetime import date, datetime, timedelta, timezone

from clearsky.models import Finding
from clearsky.registry import register

STANDARD_SUPPORT_END = {
    "1.26": date(2024, 6, 11),
    "1.27": date(2024, 7, 24),
    "1.28": date(2024, 11, 26),
    "1.29": date(2025, 3, 23),
    "1.30": date(2025, 7, 23),
    "1.31": date(2025, 11, 26),
    "1.32": date(2026, 3, 23),
    "1.33": date(2026, 7, 29),
}
EXTENDED_SUPPORT_EXTRA_MONTHLY = 365.0  # ($0.60 - $0.10) * 730
WARN_DAYS_BEFORE = 60

NODE_IDLE_CPU_PCT = 20.0
MIN_DAYS = 7


def evaluate_cluster_versions(clusters: list[dict], region: str,
                              today: date | None = None) -> list[Finding]:
    """clusters: [{name, version}]"""
    today = today or date.today()
    findings = []
    for cluster in clusters:
        version = cluster.get("version", "")
        name = cluster["name"]
        end = STANDARD_SUPPORT_END.get(version)
        if end is None:
            if version and version < min(STANDARD_SUPPORT_END):
                end = date(2000, 1, 1)  # ancient: definitely extended/EOL
            else:
                continue  # newer than our map: assume standard support
        if today > end:
            findings.append(Finding(
                detector="eks.extended_support",
                resource_id=name,
                severity="HIGH",
                title=(
                    f"EKS cluster {name} on {version} is in extended "
                    f"support (standard ended {end.isoformat()})"
                ),
                detail=(
                    "Extended support bills $0.60/hr vs $0.10/hr — an extra "
                    f"~${EXTENDED_SUPPORT_EXTRA_MONTHLY:.0f}/month. Upgrade "
                    "the control plane and node groups to a supported "
                    "version."
                ),
                region=region,
                estimated_monthly_cost=EXTENDED_SUPPORT_EXTRA_MONTHLY,
            ))
        elif today > end - timedelta(days=WARN_DAYS_BEFORE):
            findings.append(Finding(
                detector="eks.support_ending",
                resource_id=name,
                severity="MEDIUM",
                title=(
                    f"EKS cluster {name} on {version}: standard support "
                    f"ends {end.isoformat()}"
                ),
                detail=(
                    "Plan the upgrade now; after that date the cluster "
                    "auto-enrolls in extended support at 6x the control "
                    "plane price."
                ),
                region=region,
            ))
    return findings


def evaluate_node_utilization(clusters: list[dict], region: str) -> list[Finding]:
    """clusters: [{name, nodes: [{id, type, daily_p95: [floats]}]}]

    Flags a cluster when every node's p95 CPU stayed under the threshold
    — the node group is oversized or workloads need consolidation
    (Karpenter / smaller instance types).
    """
    findings = []
    for cluster in clusters:
        nodes = [
            n for n in cluster.get("nodes", [])
            if len(n.get("daily_p95", [])) >= MIN_DAYS
        ]
        if not nodes:
            continue
        peaks = [max(n["daily_p95"]) for n in nodes]
        if max(peaks) >= NODE_IDLE_CPU_PCT:
            continue
        findings.append(Finding(
            detector="eks.nodes_underutilized",
            resource_id=cluster["name"],
            severity="MEDIUM",
            title=(
                f"EKS cluster {cluster['name']}: all {len(nodes)} nodes "
                f"peaked below {NODE_IDLE_CPU_PCT:.0f}% CPU (max p95 "
                f"{max(peaks):.1f}%)"
            ),
            detail=(
                "Worker nodes are oversized for the workload. Consolidate "
                "onto fewer/smaller nodes, enable Karpenter or the cluster "
                "autoscaler, or move steady small workloads to Fargate."
            ),
            region=region,
        ))
    return findings


@register
class EksVersionDetector:
    id = "eks.extended_support"
    title = "EKS clusters in or nearing extended support"

    def run(self, session, region: str) -> list[Finding]:
        eks = session.client("eks", region_name=region)
        clusters = []
        for name in eks.list_clusters()["clusters"]:
            info = eks.describe_cluster(name=name)["cluster"]
            clusters.append({"name": name, "version": info.get("version", "")})
        return evaluate_cluster_versions(clusters, region)


@register
class EksNodeUtilizationDetector:
    id = "eks.nodes_underutilized"
    title = "Underutilized EKS worker nodes"

    def run(self, session, region: str) -> list[Finding]:
        eks = session.client("eks", region_name=region)
        names = eks.list_clusters()["clusters"]
        if not names:
            return []

        ec2 = session.client("ec2", region_name=region)
        cw = session.client("cloudwatch", region_name=region)
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=14)

        clusters = []
        for name in names:
            nodes = []
            for page in ec2.get_paginator("describe_instances").paginate(
                Filters=[
                    {"Name": f"tag:kubernetes.io/cluster/{name}",
                     "Values": ["owned", "shared"]},
                    {"Name": "instance-state-name", "Values": ["running"]},
                ]
            ):
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        nodes.append({
                            "id": inst["InstanceId"],
                            "type": inst.get("InstanceType"),
                        })
            if not nodes:
                clusters.append({"name": name, "nodes": []})
                continue
            queries = [{
                "Id": f"n{i}",
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/EC2",
                        "MetricName": "CPUUtilization",
                        "Dimensions": [
                            {"Name": "InstanceId", "Value": n["id"]}
                        ],
                    },
                    "Period": 86400,
                    "Stat": "p95",
                },
            } for i, n in enumerate(nodes[:100])]
            resp = cw.get_metric_data(
                MetricDataQueries=queries, StartTime=start, EndTime=end
            )
            by_id = {r["Id"]: r.get("Values", []) for r in resp["MetricDataResults"]}
            for i, n in enumerate(nodes[:100]):
                n["daily_p95"] = by_id.get(f"n{i}", [])
            clusters.append({"name": name, "nodes": nodes})
        return evaluate_node_utilization(clusters, region)
