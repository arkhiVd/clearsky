"""Detect Elastic IPs that are allocated but not attached to anything.

An unassociated EIP costs ~$0.005/hr (~$3.60/month) and provides no value.
Remediation: release it, or associate it with the instance that needs it.
"""

from clearsky.models import Finding
from clearsky.registry import register

HOURLY_EIP_PRICE = 0.005
MONTHLY_EIP_PRICE = round(HOURLY_EIP_PRICE * 730, 2)


def parse_addresses(response: dict, region: str) -> list[Finding]:
    """Pure function: DescribeAddresses response -> findings.

    Unit-testable without AWS. An EIP is unused when it has neither an
    AssociationId nor an attached network interface.
    """
    findings = []
    for addr in response.get("Addresses", []):
        if addr.get("AssociationId") or addr.get("NetworkInterfaceId"):
            continue
        allocation_id = addr.get("AllocationId", addr.get("PublicIp", "unknown"))
        findings.append(
            Finding(
                detector="ec2.unused_eip",
                resource_id=allocation_id,
                severity="LOW",
                title=f"Unassociated Elastic IP {addr.get('PublicIp', '')}".strip(),
                detail=(
                    "Elastic IP is allocated but not associated with any instance "
                    "or network interface. Release it if unneeded: "
                    f"aws ec2 release-address --allocation-id {allocation_id}"
                ),
                region=region,
                estimated_monthly_cost=MONTHLY_EIP_PRICE,
                extra={"public_ip": addr.get("PublicIp", "")},
            )
        )
    return findings


@register
class UnusedEipDetector:
    id = "ec2.unused_eip"
    title = "Unassociated Elastic IPs"

    def run(self, session, region: str) -> list[Finding]:
        ec2 = session.client("ec2", region_name=region)
        return parse_addresses(ec2.describe_addresses(), region)
