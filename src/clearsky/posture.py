"""Security posture score: weighted pass rate over security findings,
persisted daily so the digest can show the trend.

Score = 100 - severity-weighted penalty, floored at 0. Deterministic and
explainable: the digest lists exactly which findings cost points.
"""

import json
import os
from datetime import datetime, timedelta, timezone

PENALTY = {"HIGH": 15, "MEDIUM": 5, "LOW": 1}


def compute_score(sec_findings: list[dict]) -> int:
    penalty = sum(
        PENALTY.get(f.get("severity", "LOW"), 1) for f in sec_findings
    )
    return max(0, 100 - penalty)


def _key(day: str) -> str:
    y, m, d = day.split("-")
    return f"posture/{y}/{m}/{d}.json"


def load_previous_score(s3, bucket: str, today: str) -> int | None:
    day = datetime.fromisoformat(today).date()
    for back in range(1, 8):
        key = _key((day - timedelta(days=back)).isoformat())
        try:
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            return json.loads(body)["score"]
        except s3.exceptions.NoSuchKey:
            continue
    return None


def render_section(score: int, previous: int | None,
                   sec_findings: list[dict]) -> str:
    trend = ""
    if previous is not None and previous != score:
        arrow = "improved" if score > previous else "DROPPED"
        trend = f"  ({arrow} from {previous})"
    lines = [f"SECURITY POSTURE: {score}/100{trend}"]
    high = [f for f in sec_findings if f.get("severity") == "HIGH"]
    if high:
        lines.append("  HIGH severity open:")
        lines.extend(f"    - {f['title']}" for f in high)
    if not sec_findings:
        lines.append("  All security checks clean.")
    return "\n".join(lines)


def run(all_findings: list[dict], bucket: str | None = None) -> str:
    import boto3

    bucket = bucket or os.environ["REPORTS_BUCKET"]
    s3 = boto3.client("s3")
    today = datetime.now(timezone.utc).date().isoformat()

    sec = [f for f in all_findings if f.get("detector", "").startswith("sec.")]
    score = compute_score(sec)
    previous = load_previous_score(s3, bucket, today)
    s3.put_object(
        Bucket=bucket,
        Key=_key(today),
        Body=json.dumps({
            "day": today,
            "score": score,
            "high": sum(1 for f in sec if f.get("severity") == "HIGH"),
            "total_findings": len(sec),
        }).encode(),
        ContentType="application/json",
    )
    return render_section(score, previous, sec)
