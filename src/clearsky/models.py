"""Core data model shared by all detectors."""

from dataclasses import dataclass, field, asdict


@dataclass(frozen=True)
class Finding:
    """One detected issue on one resource.

    detector:   registry id of the detector that produced this finding
    resource_id: unique resource identifier (ARN or id) within the account
    severity:   LOW | MEDIUM | HIGH
    title:      one-line human summary
    detail:     longer explanation with remediation hint
    estimated_monthly_cost: rough USD/month waste, 0.0 if not costable
    region:     region the resource lives in
    """

    detector: str
    resource_id: str
    severity: str
    title: str
    detail: str
    region: str
    estimated_monthly_cost: float = 0.0
    extra: dict = field(default_factory=dict)
    # empty for the home account (keeps existing single-account pks
    # stable); set to the 12-digit id for findings from member accounts
    account: str = ""

    @property
    def key(self) -> str:
        """Stable identity used for lifecycle tracking in DynamoDB."""
        base = f"{self.detector}#{self.region}#{self.resource_id}"
        return f"{self.account}#{base}" if self.account else base

    def to_dict(self) -> dict:
        return asdict(self)
