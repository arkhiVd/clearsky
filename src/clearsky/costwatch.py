"""Daily cost watch: yesterday's spend vs trailing baselines, per service.

Data source is the Cost Explorer API (one GetCostAndUsage call per run,
~$0.01). Analysis and rendering are pure functions over the API response
so they are fixture-testable without AWS.

A service is reported as a mover when yesterday deviates from its 7-day
average by both an absolute and a relative threshold; both are small
because this runs in near-zero-spend accounts too.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import date, timedelta

ABS_THRESHOLD_USD = 0.25
REL_THRESHOLD = 0.5  # 50% above/below the 7-day average
LOOKBACK_DAYS = 31


@dataclass
class CostReport:
    day: str
    yesterday_total: float
    avg_7d_total: float
    avg_30d_total: float
    top_services: list = field(default_factory=list)   # (service, cost)
    movers: list = field(default_factory=list)         # dicts, see analyze()
    daily_totals: dict = field(default_factory=dict)   # date -> total


def fetch_cost_and_usage(session, end: date | None = None) -> dict:
    """One CE call: last LOOKBACK_DAYS days, daily, grouped by service."""
    end = end or date.today()
    start = end - timedelta(days=LOOKBACK_DAYS)
    ce = session.client("ce", region_name="us-east-1")
    results = []
    token = None
    while True:
        kwargs = dict(
            TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        if token:
            kwargs["NextPageToken"] = token
        resp = ce.get_cost_and_usage(**kwargs)
        results.extend(resp["ResultsByTime"])
        token = resp.get("NextPageToken")
        if not token:
            return {"ResultsByTime": results}


def _by_day_service(response: dict) -> dict[str, dict[str, float]]:
    days: dict[str, dict[str, float]] = {}
    for period in response.get("ResultsByTime", []):
        day = period["TimePeriod"]["Start"]
        services = days.setdefault(day, {})
        for group in period.get("Groups", []):
            amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
            if amount != 0.0:
                services[group["Keys"][0]] = amount
    return days


def analyze(response: dict) -> CostReport:
    """CE response -> report for the most recent complete day."""
    days = _by_day_service(response)
    if not days:
        return CostReport(day="n/a", yesterday_total=0.0,
                          avg_7d_total=0.0, avg_30d_total=0.0)

    ordered = sorted(days)
    yesterday = ordered[-1]
    daily_totals = {d: sum(days[d].values()) for d in ordered}

    def avg(window: list[str]) -> float:
        return sum(daily_totals[d] for d in window) / len(window) if window else 0.0

    prior = ordered[:-1]
    report = CostReport(
        day=yesterday,
        yesterday_total=daily_totals[yesterday],
        avg_7d_total=avg(prior[-7:]),
        avg_30d_total=avg(prior[-30:]),
        top_services=sorted(
            days[yesterday].items(), key=lambda kv: kv[1], reverse=True
        )[:10],
        daily_totals=daily_totals,
    )

    baseline_days = prior[-7:]
    all_services = set(days[yesterday]) | {
        s for d in baseline_days for s in days[d]
    }
    for service in sorted(all_services):
        current = days[yesterday].get(service, 0.0)
        baseline = (
            sum(days[d].get(service, 0.0) for d in baseline_days) / len(baseline_days)
            if baseline_days else 0.0
        )
        delta = current - baseline
        if abs(delta) < ABS_THRESHOLD_USD:
            continue
        if baseline > 0 and abs(delta) / baseline < REL_THRESHOLD:
            continue
        report.movers.append({
            "service": service,
            "yesterday": round(current, 4),
            "avg_7d": round(baseline, 4),
            "delta": round(delta, 4),
        })
    report.movers.sort(key=lambda m: abs(m["delta"]), reverse=True)
    return report


def render_section(report: CostReport) -> str:
    lines = [
        "COST WATCH",
        f"  {report.day}: ${report.yesterday_total:.2f}"
        f"  (7d avg ${report.avg_7d_total:.2f},"
        f" 30d avg ${report.avg_30d_total:.2f})",
    ]
    if report.movers:
        lines.append("  Movers vs 7d average:")
        for m in report.movers:
            arrow = "UP" if m["delta"] > 0 else "DOWN"
            lines.append(
                f"    {arrow} {m['service']}: ${m['yesterday']:.2f}"
                f" (avg ${m['avg_7d']:.2f}, {m['delta']:+.2f})"
            )
    else:
        lines.append("  No unusual movement vs 7d average.")
    if report.top_services:
        lines.append("  Top services yesterday:")
        lines.extend(
            f"    {name}: ${cost:.2f}" for name, cost in report.top_services[:5]
        )
    return "\n".join(lines)


def snapshot_to_s3(report: CostReport, s3=None, bucket: str | None = None) -> str:
    """Persist the daily snapshot for history/dashboard. Returns the key."""
    import boto3

    bucket = bucket or os.environ["REPORTS_BUCKET"]
    s3 = s3 or boto3.client("s3")
    y, m, d = report.day.split("-")
    key = f"costwatch/{y}/{m}/{d}.json"
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps({
            "day": report.day,
            "yesterday_total": report.yesterday_total,
            "avg_7d_total": report.avg_7d_total,
            "avg_30d_total": report.avg_30d_total,
            "top_services": report.top_services,
            "movers": report.movers,
            "daily_totals": report.daily_totals,
        }, default=str).encode(),
        ContentType="application/json",
    )
    return key
