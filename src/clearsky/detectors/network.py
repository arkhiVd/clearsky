"""VPC networking waste: NAT gateways without S3/DynamoDB gateway
endpoints, and NAT gateways with barely any traffic.

Gateway endpoints are free and route S3/DynamoDB traffic past the NAT
($0.045/GB data processing), so any VPC that pays for a NAT should have
both endpoints. Heuristic on config only — no flow logs required.
"""

from clearsky.models import Finding
from clearsky.registry import register

NAT_MONTHLY_BASE = 32.85  # $0.045/hr * 730
NAT_IDLE_GB_THRESHOLD = 1.0  # total GB over the lookback window


def evaluate_gateway_endpoints(nat_gateways: list, endpoints: list,
                               region: str) -> list[Finding]:
    """Flag VPCs paying for NAT but missing S3/DynamoDB gateway endpoints."""
    nat_vpcs = {
        nat["VpcId"] for nat in nat_gateways
        if nat.get("State") in ("available", "pending")
    }
    have: dict[str, set] = {}
    for ep in endpoints:
        if ep.get("VpcEndpointType") == "Gateway" and ep.get("State") in (
            "Available", "available"
        ):
            service = ep.get("ServiceName", "")
            for suffix in ("s3", "dynamodb"):
                if service.endswith(f".{suffix}"):
                    have.setdefault(ep["VpcId"], set()).add(suffix)

    findings = []
    for vpc_id in sorted(nat_vpcs):
        missing = {"s3", "dynamodb"} - have.get(vpc_id, set())
        if not missing:
            continue
        names = " and ".join(sorted(missing))
        findings.append(Finding(
            detector="net.missing_gateway_endpoint",
            resource_id=vpc_id,
            severity="MEDIUM",
            title=f"VPC {vpc_id} has a NAT gateway but no {names} gateway endpoint",
            detail=(
                "S3/DynamoDB traffic from private subnets is billed through "
                "the NAT at $0.045/GB. Gateway endpoints are free and remove "
                "that charge: aws ec2 create-vpc-endpoint --vpc-id "
                f"{vpc_id} --service-name com.amazonaws.{region}.s3 "
                "--vpc-endpoint-type Gateway --route-table-ids <rtb-...>"
            ),
            region=region,
        ))
    return findings


def evaluate_nat_traffic(nat_stats: list[dict], region: str) -> list[Finding]:
    """nat_stats: [{id, vpc_id, total_gb, days}] -> idle NAT findings."""
    findings = []
    for nat in nat_stats:
        if nat.get("days", 0) < 7 or nat["total_gb"] >= NAT_IDLE_GB_THRESHOLD:
            continue
        findings.append(Finding(
            detector="net.nat_idle",
            resource_id=nat["id"],
            severity="MEDIUM",
            title=(
                f"NAT gateway {nat['id']} processed only "
                f"{nat['total_gb']:.2f} GB in {nat['days']} days"
            ),
            detail=(
                f"Base price ~${NAT_MONTHLY_BASE}/month regardless of "
                "traffic. If the VPC's private workloads are gone or can "
                "use VPC endpoints, delete it: aws ec2 delete-nat-gateway "
                f"--nat-gateway-id {nat['id']}"
            ),
            region=region,
            estimated_monthly_cost=NAT_MONTHLY_BASE,
        ))
    return findings


@register
class GatewayEndpointDetector:
    id = "net.missing_gateway_endpoint"
    title = "NAT without S3/DynamoDB gateway endpoints"

    def run(self, session, region: str) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        nats = ec2.describe_nat_gateways()["NatGateways"]
        if not nats:
            return []
        endpoints = ec2.describe_vpc_endpoints()["VpcEndpoints"]
        return evaluate_gateway_endpoints(nats, endpoints, region)


@register
class NatIdleDetector:
    id = "net.nat_idle"
    title = "Idle NAT gateways"

    def run(self, session, region: str) -> list[Finding]:
        from datetime import datetime, timedelta, timezone

        ec2 = session.client("ec2", region_name=region)
        nats = [
            n for n in ec2.describe_nat_gateways()["NatGateways"]
            if n.get("State") == "available"
        ]
        if not nats:
            return []

        cw = session.client("cloudwatch", region_name=region)
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=14)
        stats = []
        for i, nat in enumerate(nats):
            resp = cw.get_metric_data(
                MetricDataQueries=[{
                    "Id": f"b{i}",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/NATGateway",
                            "MetricName": "BytesOutToDestination",
                            "Dimensions": [{
                                "Name": "NatGatewayId",
                                "Value": nat["NatGatewayId"],
                            }],
                        },
                        "Period": 86400,
                        "Stat": "Sum",
                    },
                }],
                StartTime=start, EndTime=end,
            )
            values = resp["MetricDataResults"][0].get("Values", [])
            stats.append({
                "id": nat["NatGatewayId"],
                "vpc_id": nat["VpcId"],
                "total_gb": sum(values) / 1e9,
                "days": len(values),
            })
        return evaluate_nat_traffic(stats, region)
