"""Commitment advisor: Savings Plans and Reserved Instance purchase
recommendations for steady workloads.

Cost Explorer computes the recommendations; this module packages them
into a readable digest section. Runs weekly (Monday) because each CE
recommendation call costs $0.01 and the numbers move slowly.

Recommendations need spend history — a quiet account legitimately
returns none, and the section says so rather than disappearing.
"""

from datetime import datetime, timezone

SP_TERM = "ONE_YEAR"
SP_PAYMENT = "NO_UPFRONT"
LOOKBACK = "THIRTY_DAYS"
RI_SERVICES = ["Amazon Elastic Compute Cloud - Compute",
               "Amazon Relational Database Service"]


def is_commitments_day(now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    return now.weekday() == 0  # Monday


def summarize_sp(response: dict) -> dict | None:
    """GetSavingsPlansPurchaseRecommendation response -> summary or None."""
    rec = response.get("SavingsPlansPurchaseRecommendation", {})
    summary = rec.get("SavingsPlansPurchaseRecommendationSummary", {})
    details = rec.get("SavingsPlansPurchaseRecommendationDetails", [])
    if not details:
        return None
    return {
        "hourly_commitment": float(
            summary.get("HourlyCommitmentToPurchase", 0)
        ),
        "monthly_savings": float(
            summary.get("EstimatedMonthlySavingsAmount", 0)
        ),
        "savings_pct": float(summary.get("EstimatedSavingsPercentage", 0)),
        "term": SP_TERM,
        "payment": SP_PAYMENT,
    }


def summarize_ri(response: dict, service: str) -> list[dict]:
    """GetReservationPurchaseRecommendation response -> instance recs."""
    out = []
    for rec in response.get("Recommendations", []):
        for detail in rec.get("RecommendationDetails", []):
            instance = detail.get("InstanceDetails", {})
            ec2 = instance.get("EC2InstanceDetails", {})
            rds = instance.get("RDSInstanceDetails", {})
            spec = ec2 or rds
            out.append({
                "service": service,
                "instance_type": spec.get("InstanceType")
                or spec.get("InstanceClass", "?"),
                "count": int(detail.get("RecommendedNumberOfInstancesToPurchase", 0) or 0),
                "monthly_savings": float(
                    detail.get("EstimatedMonthlySavingsAmount", 0) or 0
                ),
            })
    return out


def render_section(sp: dict | None, ris: list[dict]) -> str:
    lines = ["COMMITMENTS (weekly)"]
    if sp:
        lines.append(
            f"  Compute Savings Plan ({sp['term']}, {sp['payment']}): commit "
            f"${sp['hourly_commitment']:.3f}/hr -> save "
            f"~${sp['monthly_savings']:.2f}/mo ({sp['savings_pct']:.0f}%)"
        )
    total_ri = sum(r["monthly_savings"] for r in ris)
    for r in ris:
        if r["count"] < 1:
            continue
        lines.append(
            f"  RI: {r['count']}x {r['instance_type']} ({r['service']}) -> "
            f"save ~${r['monthly_savings']:.2f}/mo"
        )
    if not sp and not any(r["count"] >= 1 for r in ris):
        lines.append(
            "  No recommendations — not enough steady on-demand usage yet."
        )
    elif sp and total_ri > 0:
        lines.append(
            "  Note: SP and RI recommendations overlap the same usage; "
            "pick one strategy, do not sum the savings."
        )
    return "\n".join(lines)


def run(session) -> str:
    ce = session.client("ce", region_name="us-east-1")

    sp_resp = ce.get_savings_plans_purchase_recommendation(
        SavingsPlansType="COMPUTE_SP",
        TermInYears=SP_TERM,
        PaymentOption=SP_PAYMENT,
        LookbackPeriodInDays=LOOKBACK,
    )
    sp = summarize_sp(sp_resp)

    ris: list[dict] = []
    for service in RI_SERVICES:
        resp = ce.get_reservation_purchase_recommendation(
            Service=service,
            TermInYears=SP_TERM,
            PaymentOption=SP_PAYMENT,
            LookbackPeriodInDays=LOOKBACK,
        )
        ris.extend(summarize_ri(resp, service))

    return render_section(sp, ris)
