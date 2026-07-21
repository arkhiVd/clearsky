"""Clearsky API Lambda: read-only JSON API behind a Lambda function URL.

The multipage dashboard is static (CloudFront + S3); this function serves
only /api/*. CloudFront routes /api/* here through an Origin Access
Control (SigV4) so nothing else can invoke the URL, and every request is
additionally authenticated in-process: the browser sends the Cognito ID
token as a Bearer header and clearsky.authn verifies it (signature, exp,
audience, issuer) before any route runs.

  GET /api/summary    posture score, open finding counts, est. waste
  GET /api/findings   active (non-resolved) findings
  GET /api/costwatch  latest daily cost snapshot
  GET /api/inventory  latest inventory snapshot + deltas vs previous
  GET /api/regions    scanned + all enabled regions (for pickers)
  ... plus chat/settings/scan/accounts/architecture (see lambda_handler)
"""

import json
import os
import re
from datetime import datetime, timezone

import boto3

from clearsky import authn
from clearsky.inventory import diff as inventory_diff

_dynamodb = boto3.resource("dynamodb")
_s3 = boto3.client("s3")
_ssm = boto3.client("ssm")
_lambda = boto3.client("lambda")


def _json(payload, status=200):
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(payload, default=str),
    }


def _active_findings() -> list[dict]:
    table = _dynamodb.Table(os.environ["FINDINGS_TABLE"])
    items, kwargs = [], {}
    while True:
        resp = table.scan(**kwargs)
        items.extend(
            i for i in resp.get("Items", []) if i.get("status") != "resolved"
        )
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    items.sort(
        key=lambda i: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(i.get("severity"), 3),
                       -float(i.get("estimated_monthly_cost", 0) or 0))
    )
    return items


def _latest(prefix: str, back: int = 0):
    """back=0 -> newest object under prefix, back=1 -> second newest."""
    bucket = os.environ["REPORTS_BUCKET"]
    keys = []
    kwargs = {"Bucket": bucket, "Prefix": prefix}
    while True:
        resp = _s3.list_objects_v2(**kwargs)
        keys.extend(o["Key"] for o in resp.get("Contents", []))
        if not resp.get("IsTruncated"):
            break
        kwargs["ContinuationToken"] = resp["NextContinuationToken"]
    json_keys = sorted(k for k in keys if k.endswith(".json"))
    if len(json_keys) <= back:
        return None
    body = _s3.get_object(Bucket=bucket, Key=json_keys[-1 - back])["Body"].read()
    return json.loads(body)


def _summary():
    findings = _active_findings()
    posture = _latest("posture/") or {}
    by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    waste = 0.0
    for f in findings:
        by_severity[f.get("severity", "LOW")] = by_severity.get(
            f.get("severity", "LOW"), 0) + 1
        waste += float(f.get("estimated_monthly_cost", 0) or 0)
    cost = _latest("costwatch/") or {}
    return {
        "posture_score": posture.get("score"),
        "posture_day": posture.get("day"),
        "open_findings": len(findings),
        "by_severity": by_severity,
        "estimated_monthly_waste": round(waste, 2),
        "yesterday_spend": cost.get("yesterday_total"),
        "spend_7d_avg": cost.get("avg_7d_total"),
    }


def _inventory():
    current = _latest("inventory/")
    previous = _latest("inventory/", back=1)
    if not current:
        return {"metrics": {}, "deltas": {}}
    deltas = inventory_diff(
        current["metrics"], previous["metrics"] if previous else None
    )
    return {"day": current["day"], "metrics": current["metrics"], "deltas": deltas}


ROUTES = {
    "/api/summary": _summary,
    "/api/findings": _active_findings,
    "/api/costwatch": lambda: _latest("costwatch/") or {},
    "/api/inventory": _inventory,
}


# ---------- chat (agentic AI investigation) ----------

def _user_email(event) -> str:
    claims = event.get("_claims") or {}
    return claims.get("email") or claims.get("cognito:username") or "unknown"


def _chat_table():
    return _dynamodb.Table(os.environ["CHAT_TABLE"])


def _chat_post(event):
    import uuid
    from datetime import datetime, timezone

    body = json.loads(event.get("body") or "{}")
    message = (body.get("message") or "").strip()
    if not message:
        return _json({"error": "message required"}, 400)
    if len(message) > 2000:
        return _json({"error": "message too long"}, 400)

    owner = _user_email(event)
    table = _chat_table()
    conversation_id = body.get("conversation_id")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    context = {}
    if conversation_id:
        item = table.get_item(Key={"pk": conversation_id}).get("Item")
        if not item or item.get("owner") != owner:
            return _json({"error": "conversation not found"}, 404)
        if item.get("status") == "thinking":
            return _json({"error": "still thinking, wait for the reply"}, 409)
        history = json.loads(item["messages"])
        context = item.get("context") or {}
    else:
        conversation_id = uuid.uuid4().hex
        history = []

    # optional context: which architecture job the dashboard has open,
    # so the chat agent's diagram tools know what to edit
    arch_job_id = ((body.get("context") or {}).get("arch_job_id") or "").strip()
    if arch_job_id and "/" not in arch_job_id and len(arch_job_id) <= 64:
        context["arch_job_id"] = arch_job_id

    history.append({"role": "user", "text": message, "at": now})
    table.put_item(Item={
        "pk": conversation_id, "owner": owner, "status": "thinking",
        "messages": json.dumps(history), "updated": now,
        "context": context,
    })
    boto3.client("lambda").invoke(
        FunctionName=os.environ["CHAT_FUNCTION"],
        InvocationType="Event",
        Payload=json.dumps({"conversation_id": conversation_id}).encode(),
    )
    return _json({"conversation_id": conversation_id, "status": "thinking"})


def _chat_get(event):
    conversation_id = (event.get("queryStringParameters") or {}).get("id")
    if not conversation_id:
        return _json({"error": "id required"}, 400)
    item = _chat_table().get_item(Key={"pk": conversation_id}).get("Item")
    if not item or item.get("owner") != _user_email(event):
        return _json({"error": "not found"}, 404)
    return _json({
        "conversation_id": conversation_id,
        "status": item.get("status"),
        "messages": json.loads(item["messages"]),
    })


# ---------- provider settings (SSM) + on-demand scan ----------

def _load_settings() -> dict:
    """Current provider config from SSM; {} if unset. Includes the key."""
    param = os.environ.get("CHAT_CONFIG_PARAM")
    if not param:
        return {}
    try:
        raw = _ssm.get_parameter(Name=param, WithDecryption=True)
        return json.loads(raw["Parameter"]["Value"] or "{}")
    except Exception:  # noqa: BLE001 - unset/placeholder param
        return {}


def _settings_get(_event):
    s = _load_settings()
    return _json({
        "api_base": s.get("api_base", ""),
        "model_id": s.get("model_id", ""),
        "has_key": bool(s.get("api_key")),
    })


def _settings_post(event):
    param = os.environ.get("CHAT_CONFIG_PARAM")
    if not param:
        return _json({"error": "settings storage not configured"}, 500)
    body = json.loads(event.get("body") or "{}")
    current = _load_settings()
    # keep the existing key when the client submits a blank field
    new_key = (body.get("api_key") or "").strip() or current.get("api_key", "")
    merged = {
        "api_base": (body.get("api_base") or current.get("api_base", "")).strip(),
        "model_id": (body.get("model_id") or current.get("model_id", "")).strip(),
        "api_key": new_key,
    }
    _ssm.put_parameter(
        Name=param, Type="SecureString",
        Value=json.dumps(merged), Overwrite=True,
    )
    return _json({"ok": True, "has_key": bool(new_key)})


def _scan_post(event):
    fn = os.environ.get("SCANNER_FUNCTION")
    if not fn:
        return _json({"error": "scanner not configured"}, 500)
    body = json.loads(event.get("body") or "{}")
    payload: dict = {}
    if isinstance(body.get("accounts"), list) and body["accounts"]:
        payload["accounts"] = [str(a) for a in body["accounts"]][:20]
    _lambda.invoke(FunctionName=fn, InvocationType="Event",
                   Payload=json.dumps(payload).encode())
    return _json({"status": "scanning", **payload}, 202)


# ---------- cost explorer (compare periods, cached) ----------

_COST_PRESETS = ("daily-14", "mtd", "monthly-6", "yearly")


def _cost_periods(preset: str, today):
    """(current_start, current_end, prior_start, prior_end, granularity).
    CE ends are exclusive. Pure."""
    from datetime import date, timedelta
    if preset == "daily-14":
        cur_start = today - timedelta(days=14)
        return cur_start, today, cur_start - timedelta(days=14), cur_start, "DAILY"
    if preset == "mtd":
        cur_start = today.replace(day=1)
        prior_start = (cur_start - timedelta(days=1)).replace(day=1)
        # same number of elapsed days in the prior month, capped at its length
        days = (today - cur_start).days or 1
        prior_end = min(prior_start + timedelta(days=days), cur_start)
        return cur_start, today, prior_start, prior_end, "DAILY"
    if preset == "monthly-6":
        # last 6 complete months vs the 6 before them
        def back(d, months):
            m = d.month - months
            y = d.year + (m - 1) // 12
            return date(y, (m - 1) % 12 + 1, 1)
        first = today.replace(day=1)
        cur_start = back(first, 6)
        return cur_start, first, back(first, 12), cur_start, "MONTHLY"
    # yearly: this year vs last year
    cur_start = today.replace(month=1, day=1)
    prior_start = cur_start.replace(year=cur_start.year - 1)
    return cur_start, today, prior_start, cur_start, "MONTHLY"


def _ce_series(ce, start, end, granularity):
    resp = ce.get_cost_and_usage(
        TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
        Granularity=granularity, Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    series, services = [], {}
    for period in resp.get("ResultsByTime", []):
        total = 0.0
        for g in period.get("Groups", []):
            amt = float(g["Metrics"]["UnblendedCost"]["Amount"])
            total += amt
            if amt > 0:
                services[g["Keys"][0]] = round(services.get(g["Keys"][0], 0) + amt, 4)
        series.append({"date": period["TimePeriod"]["Start"], "total": round(total, 4)})
    return series, services


def _cost_explore(event):
    """Cost-Explorer-style comparison: current vs prior period. Results are
    cached in S3 per (preset, day) — each fresh computation is two paid CE
    calls ($0.01 each), so repeat views are free."""
    from datetime import datetime, timezone
    preset = ((event.get("queryStringParameters") or {}).get("preset")
              or "daily-14")
    if preset not in _COST_PRESETS:
        return _json({"error": f"preset must be one of {_COST_PRESETS}"}, 400)
    bucket = os.environ["REPORTS_BUCKET"]
    today = datetime.now(timezone.utc).date()
    key = f"costexplore/{preset}/{today.isoformat()}.json"
    try:
        body = _s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        return _json(json.loads(body))
    except Exception:  # noqa: BLE001 - cache miss
        pass
    ce = boto3.client("ce", region_name="us-east-1")
    cs, ce_end, ps, pe, gran = _cost_periods(preset, today)
    cur_series, cur_services = _ce_series(ce, cs, ce_end, gran)
    prior_series, _ = _ce_series(ce, ps, pe, gran)
    payload = {
        "preset": preset, "granularity": gran,
        "current": {"start": cs.isoformat(), "end": ce_end.isoformat(),
                    "series": cur_series,
                    "total": round(sum(p["total"] for p in cur_series), 4)},
        "prior": {"start": ps.isoformat(), "end": pe.isoformat(),
                  "series": prior_series,
                  "total": round(sum(p["total"] for p in prior_series), 4)},
        "services": dict(sorted(cur_services.items(),
                                key=lambda kv: -kv[1])[:10]),
    }
    _s3.put_object(Bucket=bucket, Key=key,
                   Body=json.dumps(payload).encode(),
                   ContentType="application/json")
    return _json(payload)


# ---------- member-account registry (SSM) ----------

def _load_accounts() -> list[dict]:
    from clearsky import accounts as accounts_mod
    return accounts_mod.configured_accounts()


def _save_accounts(entries: list[dict]) -> None:
    _ssm.put_parameter(
        Name=os.environ["ACCOUNTS_PARAM"], Type="String",
        Value=json.dumps(entries), Overwrite=True,
    )


def _accounts_get(_event):
    """Registry + everything the UI needs to render onboarding
    instructions (trust principals, conventional role name)."""
    return _json({
        "accounts": _load_accounts(),
        "trusted_role_arns": [a for a in
                              os.environ.get("TRUSTED_ROLE_ARNS", "").split(",")
                              if a],
        "role_name": os.environ.get("MEMBER_ROLE_NAME",
                                    "clearsky-readonly"),
    })


_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(\d{12}):role/[\w+=,.@/-]+$")


def _accounts_post(event):
    from clearsky import accounts as accounts_mod
    if not os.environ.get("ACCOUNTS_PARAM"):
        return _json({"error": "accounts storage not configured"}, 500)
    body = json.loads(event.get("body") or "{}")

    remove = str(body.get("remove") or "").strip()
    if remove:
        entries = [a for a in _load_accounts() if a["account_id"] != remove]
        _save_accounts(entries)
        return _json({"ok": True, "accounts": entries})

    role_arn = str(body.get("role_arn") or "").strip()
    m = _ROLE_ARN_RE.match(role_arn)
    if not m:
        return _json({"error": "role_arn must look like "
                               "arn:aws:iam::<account>:role/<name>"}, 400)
    account_id = m.group(1)
    entries = _load_accounts()
    if any(a["account_id"] == account_id for a in entries):
        return _json({"error": f"account {account_id} already onboarded"}, 409)
    # prove the trust policy works before saving — a registry entry that
    # can't be assumed would just poison every scan with errors
    try:
        session = accounts_mod.assume_session(role_arn)
        session.client("sts").get_caller_identity()
    except Exception as err:  # noqa: BLE001 - surface the trust problem
        return _json({"error": f"could not assume role: {err}"}, 400)
    entries.append({
        "account_id": account_id, "role_arn": role_arn,
        "label": str(body.get("label") or "").strip()[:60],
        "added_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    _save_accounts(entries)
    return _json({"ok": True, "account_id": account_id, "accounts": entries})


# ---------- architecture diagram (async worker + S3 artifact) ----------

def _scanned_regions() -> list[str]:
    """Interactive path: explicit list or the scanner's cached auto-discovery
    (never probes inline — the scanner refreshes the cache daily)."""
    from clearsky.regions import resolve_regions
    return resolve_regions(boto3.Session(),
                           os.environ.get("SCAN_REGIONS", "us-east-1"),
                           bucket=os.environ.get("REPORTS_BUCKET"),
                           allow_discovery=False)


_ENABLED_REGIONS: list[str] = []


def _enabled_regions() -> list[str]:
    """Every region enabled on the account (one DescribeRegions call, cached
    for the lambda container's lifetime) — the selectable diagram universe."""
    global _ENABLED_REGIONS
    if not _ENABLED_REGIONS:
        try:
            resp = boto3.client("ec2", region_name="us-east-1").describe_regions()
            _ENABLED_REGIONS = sorted(r["RegionName"] for r in resp["Regions"])
        except Exception:  # noqa: BLE001 - fall back to the scanned set
            return _scanned_regions()
    return _ENABLED_REGIONS


def _arch_post(event):
    import uuid
    fn = os.environ.get("ARCH_FUNCTION")
    if not fn:
        return _json({"error": "architecture worker not configured"}, 500)
    body = json.loads(event.get("body") or "{}")
    scanned = _scanned_regions()
    avail = set(_enabled_regions()) | set(scanned)
    regions = [r for r in (body.get("regions") or scanned) if r in avail] or scanned[:1]
    include = [g for g in (body.get("include") or [])
               if g in ("network", "serverless", "data", "cost")] \
        or ["network", "serverless", "data", "cost"]
    job_id = uuid.uuid4().hex
    bucket = os.environ["REPORTS_BUCKET"]
    _s3.put_object(Bucket=bucket, Key=f"architecture/jobs/{job_id}.json",
                   Body=json.dumps({"status": "running"}).encode(),
                   ContentType="application/json")
    global_mode = body.get("global_mode")
    if global_mode not in ("all", "connected", "none"):
        global_mode = "all"
    account = str(body.get("account") or "").strip()
    if account and not account.isdigit():
        account = ""          # "home" / junk -> home account
    _lambda.invoke(
        FunctionName=fn, InvocationType="Event",
        Payload=json.dumps({"job_id": job_id, "regions": regions,
                            "include": include, "ai": bool(body.get("ai")),
                            "overlay": bool(body.get("overlay")),
                            "optimize": bool(body.get("optimize")),
                            "account": account,
                            "global_mode": global_mode}).encode(),
    )
    return _json({"job_id": job_id, "status": "running"})


def _arch_get(event):
    job_id = (event.get("queryStringParameters") or {}).get("id")
    if not job_id or "/" in job_id:
        return _json({"error": "id required"}, 400)
    bucket = os.environ["REPORTS_BUCKET"]
    try:
        body = _s3.get_object(
            Bucket=bucket, Key=f"architecture/jobs/{job_id}.json")["Body"].read()
    except _s3.exceptions.NoSuchKey:
        return _json({"status": "running"})
    return _json(json.loads(body))


def _regions_get():
    return _json({"regions": _scanned_regions(),
                  "all_regions": _enabled_regions()})


def lambda_handler(event, context):
    path = event.get("rawPath", "")
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")

    # network gate: only CloudFront knows the origin-verify secret, so the
    # public function URL is unusable directly
    expected = os.environ.get("ORIGIN_VERIFY", "")
    got = (event.get("headers") or {}).get("x-origin-verify", "")
    if expected and got != expected:
        return _json({"error": "forbidden"}, 403)

    try:
        event["_claims"] = authn.authenticate(event)
    except authn.AuthError as err:
        return _json({"error": f"unauthorized: {err}"}, 401)

    if path == "/api/regions":
        try:
            return _regions_get()
        except Exception as err:  # noqa: BLE001
            return _json({"error": str(err)}, 500)

    if path == "/api/chat":
        try:
            return _chat_post(event) if method == "POST" else _chat_get(event)
        except Exception as err:  # noqa: BLE001
            return _json({"error": str(err)}, 500)

    if path == "/api/settings":
        try:
            return _settings_post(event) if method == "POST" else _settings_get(event)
        except Exception as err:  # noqa: BLE001
            return _json({"error": str(err)}, 500)

    if path == "/api/scan" and method == "POST":
        try:
            return _scan_post(event)
        except Exception as err:  # noqa: BLE001
            return _json({"error": str(err)}, 500)

    if path == "/api/cost/explore":
        try:
            return _cost_explore(event)
        except Exception as err:  # noqa: BLE001
            return _json({"error": str(err)}, 500)

    if path == "/api/accounts":
        try:
            return _accounts_post(event) if method == "POST" else _accounts_get(event)
        except Exception as err:  # noqa: BLE001
            return _json({"error": str(err)}, 500)

    if path == "/api/architecture":
        try:
            return _arch_post(event) if method == "POST" else _arch_get(event)
        except Exception as err:  # noqa: BLE001
            return _json({"error": str(err)}, 500)

    handler = ROUTES.get(path)
    if handler is not None:
        try:
            return _json(handler())
        except Exception as err:  # noqa: BLE001
            return _json({"error": str(err)}, 500)
    return _json({"error": "not found"}, 404)
