"""Network exposure: security groups open to the world on sensitive
ports, lingering default VPCs."""

from clearsky.models import Finding
from clearsky.registry import register

SENSITIVE_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 9200: "OpenSearch",
}
WORLD = {"0.0.0.0/0", "::/0"}


def _world_open(perm: dict) -> bool:
    v4 = any(r.get("CidrIp") in WORLD for r in perm.get("IpRanges", []))
    v6 = any(r.get("CidrIpv6") in WORLD for r in perm.get("Ipv6Ranges", []))
    return v4 or v6


def _exposed_ports(perm: dict) -> list[str]:
    proto = perm.get("IpProtocol")
    if proto == "-1":
        return ["ALL traffic"]
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort", from_port)
    if from_port is None:
        return []
    return [
        f"{port} ({label})"
        for port, label in SENSITIVE_PORTS.items()
        if from_port <= port <= to_port
    ]


def parse_security_groups(groups: list, region: str) -> list[Finding]:
    findings = []
    for sg in groups:
        exposed: list[str] = []
        for perm in sg.get("IpPermissions", []):
            if _world_open(perm):
                exposed.extend(_exposed_ports(perm))
        if not exposed:
            continue
        sg_id = sg["GroupId"]
        findings.append(Finding(
            detector="sec.sg_open",
            resource_id=sg_id,
            severity="HIGH",
            title=(
                f"Security group {sg_id} ({sg.get('GroupName', '')}) open "
                f"to the world: {', '.join(sorted(set(exposed)))}"
            ),
            detail=(
                "Ingress from 0.0.0.0/0 on sensitive ports. Restrict to "
                "known CIDRs or use SSM Session Manager instead of SSH: "
                f"aws ec2 revoke-security-group-ingress --group-id {sg_id} ..."
            ),
            region=region,
        ))
    return findings


def parse_vpcs(vpcs: list, region: str) -> list[Finding]:
    return [
        Finding(
            detector="sec.default_vpc",
            resource_id=vpc["VpcId"],
            severity="LOW",
            title=f"Default VPC {vpc['VpcId']} still present",
            detail=(
                "Unused default VPCs invite accidental public deployments. "
                "Delete it if nothing runs there."
            ),
            region=region,
        )
        for vpc in vpcs if vpc.get("IsDefault")
    ]


@register
class OpenSecurityGroupDetector:
    id = "sec.sg_open"
    title = "Security groups open to the world"

    def run(self, session, region: str) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        groups = []
        for page in ec2.get_paginator("describe_security_groups").paginate():
            groups.extend(page["SecurityGroups"])
        return parse_security_groups(groups, region)


@register
class DefaultVpcDetector:
    id = "sec.default_vpc"
    title = "Default VPC present"

    def run(self, session, region: str) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        return parse_vpcs(ec2.describe_vpcs()["Vpcs"], region)
