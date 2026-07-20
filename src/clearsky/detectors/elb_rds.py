"""Orphaned load balancers and idle RDS instances."""

from clearsky.models import Finding
from clearsky.registry import register

ALB_MONTHLY = 19.0   # ~$0.0225/hr + minimum LCUs
NLB_MONTHLY = 16.4


def evaluate_load_balancers(lbs: list[dict], region: str) -> list[Finding]:
    """lbs: [{arn, name, type, healthy_targets, total_targets}]"""
    findings = []
    for lb in lbs:
        if lb.get("total_targets", 0) > 0 and lb.get("healthy_targets", 0) > 0:
            continue
        reason = (
            "no registered targets" if lb.get("total_targets", 0) == 0
            else "no healthy targets"
        )
        monthly = NLB_MONTHLY if lb.get("type") == "network" else ALB_MONTHLY
        findings.append(Finding(
            detector="elb.orphaned",
            resource_id=lb["name"],
            severity="MEDIUM",
            title=f"Load balancer {lb['name']} has {reason}",
            detail=(
                "Load balancer bills hourly whether or not it serves "
                "traffic. Delete it if the backend is gone, or fix target "
                "health if this is an outage."
            ),
            region=region,
            estimated_monthly_cost=monthly,
        ))
    return findings


def evaluate_rds_connections(instances: list[dict], region: str) -> list[Finding]:
    """instances: [{id, engine, instance_class, daily_max_connections: [floats]}]"""
    findings = []
    for db in instances:
        series = db.get("daily_max_connections", [])
        if len(series) < 7 or max(series) > 0:
            continue
        db_id = db["id"]
        findings.append(Finding(
            detector="rds.idle",
            resource_id=db_id,
            severity="MEDIUM",
            title=(
                f"RDS instance {db_id} ({db.get('instance_class', '?')}): "
                f"zero connections for {len(series)} days"
            ),
            detail=(
                "Nothing has connected in the whole window. Snapshot and "
                f"delete, or stop it (7-day max): aws rds stop-db-instance "
                f"--db-instance-identifier {db_id}"
            ),
            region=region,
        ))
    return findings


@register
class OrphanedElbDetector:
    id = "elb.orphaned"
    title = "Load balancers without healthy targets"

    def run(self, session, region: str) -> list[Finding]:
        elb = session.client("elbv2", region_name=region)
        lbs = []
        for page in elb.get_paginator("describe_load_balancers").paginate():
            lbs.extend(page["LoadBalancers"])
        if not lbs:
            return []

        health_by_lb: dict[str, dict] = {
            lb["LoadBalancerArn"]: {"healthy": 0, "total": 0} for lb in lbs
        }
        for page in elb.get_paginator("describe_target_groups").paginate():
            for tg in page["TargetGroups"]:
                targets = elb.describe_target_health(
                    TargetGroupArn=tg["TargetGroupArn"]
                )["TargetHealthDescriptions"]
                for lb_arn in tg.get("LoadBalancerArns", []):
                    if lb_arn in health_by_lb:
                        health_by_lb[lb_arn]["total"] += len(targets)
                        health_by_lb[lb_arn]["healthy"] += sum(
                            1 for t in targets
                            if t["TargetHealth"]["State"] == "healthy"
                        )

        summary = [{
            "arn": lb["LoadBalancerArn"],
            "name": lb["LoadBalancerName"],
            "type": lb.get("Type", "application"),
            "healthy_targets": health_by_lb[lb["LoadBalancerArn"]]["healthy"],
            "total_targets": health_by_lb[lb["LoadBalancerArn"]]["total"],
        } for lb in lbs]
        return evaluate_load_balancers(summary, region)


@register
class RdsIdleDetector:
    id = "rds.idle"
    title = "Idle RDS instances"

    def run(self, session, region: str) -> list[Finding]:
        from datetime import datetime, timedelta, timezone

        rds = session.client("rds", region_name=region)
        instances = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page["DBInstances"]:
                if db.get("DBInstanceStatus") == "available":
                    instances.append({
                        "id": db["DBInstanceIdentifier"],
                        "engine": db.get("Engine"),
                        "instance_class": db.get("DBInstanceClass"),
                    })
        if not instances:
            return []

        cw = session.client("cloudwatch", region_name=region)
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=14)
        queries = [{
            "Id": f"c{i}",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/RDS",
                    "MetricName": "DatabaseConnections",
                    "Dimensions": [{
                        "Name": "DBInstanceIdentifier", "Value": db["id"],
                    }],
                },
                "Period": 86400,
                "Stat": "Maximum",
            },
        } for i, db in enumerate(instances[:100])]
        resp = cw.get_metric_data(
            MetricDataQueries=queries, StartTime=start, EndTime=end
        )
        by_id = {r["Id"]: r.get("Values", []) for r in resp["MetricDataResults"]}
        for i, db in enumerate(instances[:100]):
            db["daily_max_connections"] = by_id.get(f"c{i}", [])
        return evaluate_rds_connections(instances, region)
