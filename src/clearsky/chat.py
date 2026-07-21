"""Agentic chat: an LLM investigates the account live.

Invoked asynchronously by the dashboard API. Runs a tool-use loop where
the model can read AWS configuration (read-only), the findings table, and
Cost Explorer, then writes its answer back to the conversation record in
DynamoDB for the frontend to poll.

The model runs on an external OpenAI-compatible endpoint (provider-agnostic:
OpenAI, Google Gemini, or Z.ai GLM all expose one). Bedrock was the original
target but this AWS account's Free-tier plan blocks Bedrock inference
account-wide ("ValidationException: Operation not allowed" on every model,
Converse/InvokeModel/console alike), so inference is external. The AWS
*tools* still run in-account on the Lambda's IAM role — only the LLM call
leaves the account.

Config via env: CHAT_API_BASE, CHAT_API_KEY, CHAT_MODEL_ID.

Safety model, two independent layers (unchanged):
  1. Code: only boto3 operations starting with describe_/list_/get_ are
     dispatched, minus an explicit denylist of data-plane reads
     (object contents, secrets, parameters, table items).
  2. IAM: the function role carries ViewOnlyAccess — even if layer 1
     were bypassed, the role cannot mutate anything or read data payloads.
"""

import json
import logging
import os
import urllib.request
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_ITERATIONS = 14
MAX_TOOL_RESULT_CHARS = 8000
HTTP_TIMEOUT = 120

DEFAULT_API_BASE = "https://generativelanguage.googleapis.com/v1beta/openai"
DEFAULT_MODEL_ID = "gemini-2.5-flash-lite"

ALLOWED_PREFIXES = ("describe_", "list_", "get_")
DENIED_SERVICES = {"secretsmanager", "kms"}
DENIED_OPERATIONS = {
    # data-plane reads: contents, secrets, records — not configuration
    "get_object", "get_object_torrent", "get_secret_value",
    "get_parameter", "get_parameters", "get_parameters_by_path",
    "get_item", "batch_get_item", "get_records", "get_media",
    "get_query_results", "get_log_events", "get_authorization_token",
    "get_password_data", "get_federation_token", "get_session_token",
}

SYSTEM_PROMPT = (
    "You are Cloud Detective's investigation assistant for an AWS "
    "organization (a home account plus optional onboarded member "
    "accounts), answering questions from developers and application "
    "owners on a dashboard. You have read-only tools: live AWS "
    "configuration reads, the current findings list, and Cost Explorer.\n"
    "- aws_read defaults to the home account; pass account=<12-digit id> "
    "to read from an onboarded member account. Findings from member "
    "accounts have their titles prefixed with [account-id].\n"
    "- Investigate before answering: check findings and live config "
    "rather than guessing. For cost questions, query Cost Explorer.\n"
    "- You cannot modify anything. When remediation is needed, give the "
    "exact CLI command or console step for the user to run.\n"
    "- Be concise and concrete: name resources, regions, and dollar "
    "amounts. Plain text only, no markdown tables.\n"
    "- If a tool call is denied or errors, say what you could not check.\n"
    "- When asked to run an AI investigation/scan: probe live config with "
    "aws_read for waste and risk the standard detectors miss, then record "
    "each concrete issue with add_finding (real resource ids, real numbers; "
    "no speculation). Report what you added.\n"
    "- When asked to verify a finding: re-check the live configuration "
    "first; call resolve_finding ONLY when the issue is confirmed fixed, "
    "otherwise explain exactly what still remains.\n"
    "- You can also edit the user's generated architecture diagram: call "
    "get_architecture first to see its nodes/edges/notes, then apply "
    "edit_architecture ops (add_node, remove_node, rename, add_edge, "
    "remove_edge, add_note). After editing, re-check with get_architecture "
    "and tell the user what changed — the dashboard preview refreshes "
    "automatically and they can download the result."
)

# OpenAI-compatible function/tool schema (works for OpenAI, Gemini, Z.ai).
TOOLS = [
    {"type": "function", "function": {
        "name": "aws_read",
        "description": (
            "Call a read-only AWS API (boto3 snake_case operation starting "
            "with describe_/list_/get_). Returns the JSON response, "
            "truncated if large. Configuration only — object contents, "
            "secrets, and table items are denied."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "boto3 client name, e.g. ec2, s3, rds, eks"},
                "operation": {"type": "string", "description": "snake_case operation, e.g. describe_instances"},
                "parameters": {"type": "object", "description": "operation kwargs"},
                "region": {"type": "string", "description": "default us-east-1"},
                "account": {"type": "string", "description": "12-digit member account id to read from (omit or 'home' for the home account; only onboarded accounts work)"},
            },
            "required": ["service", "operation"],
        },
    }},
    {"type": "function", "function": {
        "name": "get_findings",
        "description": "Current cost/security findings from the daily scans (new and open, resolved excluded). Includes each finding's pk for resolve_finding.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "add_finding",
        "description": (
            "Record a NEW issue you verified on a live resource during an "
            "AI investigation. Shows on the dashboard with an AI badge. "
            "Only for concrete, evidenced issues — never speculation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
                "title": {"type": "string", "description": "one line, names the resource"},
                "detail": {"type": "string", "description": "evidence + exact remediation command"},
                "resource_id": {"type": "string", "description": "instance/volume/bucket/function id"},
                "region": {"type": "string"},
                "estimated_monthly_cost": {"type": "number", "description": "USD/month waste, 0 if not costable"},
            },
            "required": ["severity", "title", "detail", "resource_id", "region"],
        },
    }},
    {"type": "function", "function": {
        "name": "resolve_finding",
        "description": (
            "Mark a finding resolved AFTER verifying with aws_read that the "
            "issue no longer exists. Pass the finding's pk from get_findings "
            "and a short note describing the verification."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pk": {"type": "string"},
                "note": {"type": "string", "description": "what was checked and confirmed"},
            },
            "required": ["pk", "note"],
        },
    }},
    {"type": "function", "function": {
        "name": "get_architecture",
        "description": (
            "Read the current architecture diagram (the one the user "
            "generated on the dashboard): its nodes, edges, and notes as "
            "JSON. Call this before and after editing."
        ),
        "parameters": {"type": "object", "properties": {
            "job_id": {"type": "string",
                       "description": "optional; defaults to the diagram open in the dashboard"},
        }},
    }},
    {"type": "function", "function": {
        "name": "edit_architecture",
        "description": (
            "Apply structured edits to the architecture diagram and "
            "re-render it. Ops: {op:'add_node',type,id,label?,sub?,region?} "
            "(type: lambda|apigw|dynamodb|s3|ec2|rds|elb), "
            "{op:'remove_node',id}, {op:'rename',id,label,sub?}, "
            "{op:'add_edge',from,to,label?}, {op:'remove_edge',from,to}, "
            "{op:'add_note',text}, {op:'remove_note',index}. "
            "Returns a per-op result log."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ops": {"type": "array", "items": {"type": "object"},
                        "description": "list of edit operations"},
                "job_id": {"type": "string",
                           "description": "optional; defaults to the diagram open in the dashboard"},
            },
            "required": ["ops"],
        },
    }},
    {"type": "function", "function": {
        "name": "get_cost",
        "description": "Query AWS Cost Explorer for daily unblended cost.",
        "parameters": {
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "lookback window, default 14, max 90"},
                "group_by": {"type": "string", "enum": ["SERVICE", "REGION", "USAGE_TYPE", "LINKED_ACCOUNT"]},
            },
        },
    }},
]


# ---------- tools ----------

def aws_read_allowed(service: str, operation: str) -> str | None:
    """Returns a denial reason, or None when the call is permitted."""
    if service in DENIED_SERVICES:
        return f"service '{service}' is denied (secrets/crypto material)"
    if not operation.startswith(ALLOWED_PREFIXES):
        return "only describe_/list_/get_ operations are permitted"
    if operation in DENIED_OPERATIONS:
        return f"'{operation}' reads data content, not configuration — denied"
    return None


def run_aws_read(tool_input: dict) -> str:
    service = tool_input.get("service", "").strip().lower()
    operation = tool_input.get("operation", "").strip().lower()
    denial = aws_read_allowed(service, operation)
    if denial:
        return f"DENIED: {denial}"
    account = str(tool_input.get("account") or "").strip()
    if account and account.lower() != "home":
        from clearsky import accounts as accounts_mod
        try:
            session = accounts_mod.member_session(account)
        except Exception as err:  # noqa: BLE001 - not onboarded / no trust
            return f"ERROR: cannot access account {account}: {err}"
        client = session.client(
            service, region_name=tool_input.get("region") or "us-east-1")
    else:
        client = boto3.client(
            service, region_name=tool_input.get("region") or "us-east-1"
        )
    method = getattr(client, operation, None)
    if method is None:
        return f"ERROR: {service} has no operation {operation}"
    response = method(**(tool_input.get("parameters") or {}))
    response.pop("ResponseMetadata", None)
    return json.dumps(response, default=str)


def run_get_findings(_tool_input: dict) -> str:
    table = boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])
    items, kwargs = [], {}
    while True:
        resp = table.scan(**kwargs)
        items.extend(
            {k: i.get(k) for k in
             ("pk", "detector", "severity", "title", "detail",
              "estimated_monthly_cost", "status", "first_seen", "region",
              "source")}
            for i in resp.get("Items", []) if i.get("status") != "resolved"
        )
        if "LastEvaluatedKey" not in resp:
            return json.dumps(items, default=str)
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def build_ai_finding(tool_input: dict, now: str) -> dict | str:
    """Validated DynamoDB item for an AI-discovered finding, or an error
    string. Pure — fixture-testable."""
    sev = str(tool_input.get("severity", "")).upper()
    if sev not in ("HIGH", "MEDIUM", "LOW"):
        return "ERROR: severity must be HIGH, MEDIUM or LOW"
    title = str(tool_input.get("title", "")).strip()[:200]
    resource_id = str(tool_input.get("resource_id", "")).strip()[:200]
    region = str(tool_input.get("region", "")).strip()[:32]
    if not (title and resource_id and region):
        return "ERROR: title, resource_id and region are required"
    try:
        cost = round(float(tool_input.get("estimated_monthly_cost") or 0), 2)
    except (TypeError, ValueError):
        cost = 0.0
    return {
        "pk": f"ai#{region}#{resource_id}",
        "detector": "ai.investigation",
        "source": "ai",
        "severity": sev,
        "title": title,
        "detail": str(tool_input.get("detail", "")).strip()[:2000],
        "resource_id": resource_id,
        "region": region,
        "estimated_monthly_cost": cost,
        "status": "new",
        "first_seen": now,
        "last_seen": now,
    }


def run_add_finding(tool_input: dict) -> str:
    from decimal import Decimal

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    item = build_ai_finding(tool_input, now)
    if isinstance(item, str):
        return item
    item["estimated_monthly_cost"] = Decimal(str(item["estimated_monthly_cost"]))
    table = boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])
    existing = table.get_item(Key={"pk": item["pk"]}).get("Item")
    if existing and existing.get("status") != "resolved":
        return f"already recorded as {item['pk']} (status {existing.get('status')})"
    table.put_item(Item=item)
    return f"finding recorded: {item['pk']}"


def run_resolve_finding(tool_input: dict) -> str:
    pk = str(tool_input.get("pk", "")).strip()
    note = str(tool_input.get("note", "")).strip()[:500]
    if not pk or not note:
        return "ERROR: pk and a verification note are required"
    table = boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])
    item = table.get_item(Key={"pk": pk}).get("Item")
    if not item:
        return f"ERROR: no finding with pk {pk}"
    if item.get("status") == "resolved":
        return f"{pk} is already resolved"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    table.update_item(
        Key={"pk": pk},
        UpdateExpression=("SET #s = :s, resolved_at = :t, resolved_by = :b, "
                          "resolution_note = :n"),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "resolved", ":t": now,
                                   ":b": "ai", ":n": note},
    )
    return f"resolved {pk}"


def run_get_cost(tool_input: dict) -> str:
    from datetime import date, timedelta

    days = min(int(tool_input.get("days") or 14), 90)
    end = date.today()
    kwargs = dict(
        TimePeriod={"Start": (end - timedelta(days=days)).isoformat(),
                    "End": end.isoformat()},
        Granularity="DAILY",
        Metrics=["UnblendedCost"],
    )
    group = tool_input.get("group_by")
    if group:
        kwargs["GroupBy"] = [{"Type": "DIMENSION", "Key": group}]
    ce = boto3.client("ce", region_name="us-east-1")
    resp = ce.get_cost_and_usage(**kwargs)
    return json.dumps(resp.get("ResultsByTime", []), default=str)


# Per-invocation context (arch job the dashboard has open); set by
# lambda_handler from the conversation record before the agent loop runs.
CONTEXT: dict = {}


def _arch_job_id(tool_input: dict) -> str | None:
    job_id = (tool_input.get("job_id") or CONTEXT.get("arch_job_id") or "").strip()
    return job_id if job_id and "/" not in job_id else None


def _compact_graph(graph: dict) -> dict:
    """Graph view small enough for the model: uid/type/label, no coords.
    'uid' ('type:id') is the identifier to pass to edit ops and edges."""
    def uid(n):
        return f"{n['type']}:{n['id']}"

    nodes = []
    for rg in graph.get("regions", []):
        for key in ("lambda", "apigw", "dynamodb", "sns", "sqs", "kinesis", "extras"):
            nodes += [{"uid": uid(n), "type": n["type"], "label": n["label"],
                       "region": rg["region"]} for n in rg.get(key, [])]
        for vpc in rg.get("vpcs", []):
            for coll in (vpc.get("nats", []), vpc.get("lbs", []), vpc.get("rds", [])):
                nodes += [{"uid": uid(n), "type": n["type"], "label": n["label"],
                           "region": rg["region"], "vpc": vpc["id"]} for n in coll]
            for sn in vpc.get("subnets", []):
                nodes += [{"uid": uid(n), "type": n["type"], "label": n["label"],
                           "region": rg["region"], "vpc": vpc["id"],
                           "subnet": sn["id"]} for n in sn.get("resources", [])]
    nodes += [{"uid": f"s3:{n['id']}", "type": "s3", "label": n["label"],
               "scope": "global"} for n in graph.get("global", {}).get("s3", [])]
    return {"nodes": nodes, "edges": graph.get("edges", []),
            "notes": graph.get("notes", [])}


def run_get_architecture(tool_input: dict) -> str:
    from clearsky import architecture

    job_id = _arch_job_id(tool_input)
    if not job_id:
        return ("ERROR: no architecture diagram in context — ask the user to "
                "generate one with the Architecture button first")
    job = architecture.load_job(boto3.client("s3"),
                                os.environ["REPORTS_BUCKET"], job_id)
    if job.get("status") != "ready":
        return f"ERROR: diagram job is {job.get('status')}"
    view = _compact_graph(job["graph"])
    view["revision"] = job.get("revision", 0)
    return json.dumps(view, default=str)


def run_edit_architecture(tool_input: dict) -> str:
    from clearsky import architecture

    job_id = _arch_job_id(tool_input)
    if not job_id:
        return ("ERROR: no architecture diagram in context — ask the user to "
                "generate one with the Architecture button first")
    s3 = boto3.client("s3")
    bucket = os.environ["REPORTS_BUCKET"]
    job = architecture.load_job(s3, bucket, job_id)
    if job.get("status") != "ready":
        return f"ERROR: diagram job is {job.get('status')}"
    graph = job["graph"]
    log = architecture.apply_ops(graph, tool_input.get("ops") or [])
    revision = int(job.get("revision", 0)) + 1
    payload = architecture.render_job(graph, job_id, revision,
                                      job.get("summary"), job.get("meta", {}))
    architecture.save_job(s3, bucket, job_id, payload)
    view = _compact_graph(graph)
    return json.dumps({"revision": revision, "results": log,
                       "node_count": len(view["nodes"]),
                       "edge_count": len(view["edges"])}, default=str)


TOOL_RUNNERS = {
    "aws_read": run_aws_read,
    "get_findings": run_get_findings,
    "add_finding": run_add_finding,
    "resolve_finding": run_resolve_finding,
    "get_cost": run_get_cost,
    "get_architecture": run_get_architecture,
    "edit_architecture": run_edit_architecture,
}


def execute_tool(name: str, tool_input: dict) -> str:
    runner = TOOL_RUNNERS.get(name)
    if runner is None:
        return f"ERROR: unknown tool {name}"
    try:
        result = runner(tool_input)
    except Exception as err:  # noqa: BLE001 - result goes back to the model
        result = f"ERROR: {err}"
    if len(result) > MAX_TOOL_RESULT_CHARS:
        result = result[:MAX_TOOL_RESULT_CHARS] + "\n...[truncated]"
    return result


# ---------- model call (OpenAI-compatible /chat/completions) ----------

class ConfigError(Exception):
    """Provider config is missing or unusable (e.g. no API key set)."""


def load_provider_config() -> dict:
    """Provider settings, from the SSM SecureString the UI writes, with env
    fallbacks for base/model. Raises ConfigError if no API key is set."""
    base = os.environ.get("CHAT_API_BASE", DEFAULT_API_BASE)
    model = os.environ.get("CHAT_MODEL_ID", DEFAULT_MODEL_ID)
    key = ""
    param = os.environ.get("CHAT_CONFIG_PARAM")
    if param:
        try:
            raw = boto3.client("ssm").get_parameter(
                Name=param, WithDecryption=True
            )["Parameter"]["Value"]
            saved = json.loads(raw or "{}")
            base = saved.get("api_base") or base
            model = saved.get("model_id") or model
            key = saved.get("api_key") or ""
        except Exception:  # noqa: BLE001 - unset/placeholder param is expected
            logger.info("no usable provider config in %s", param)
    if not key:
        raise ConfigError(
            "No model API key is configured. Open the dashboard Settings panel "
            "and add a provider API key (Gemini, OpenAI, or Z.ai)."
        )
    return {"api_base": base.rstrip("/"), "model_id": model, "api_key": key}


def call_model(messages: list[dict], config: dict) -> dict:
    """POST to the OpenAI-compatible endpoint; returns the assistant message."""
    body = json.dumps({
        "model": config["model_id"],
        "messages": messages,
        "tools": TOOLS,
        "tool_choice": "auto",
        "max_tokens": 3000,
    }).encode()
    req = urllib.request.Request(
        f"{config['api_base']}/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config['api_key']}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        payload = json.loads(resp.read())
    return payload["choices"][0]["message"]


LAYOUT_SYSTEM = (
    "You are an AWS architecture-diagram layout optimizer. Given a resource "
    "graph (nodes with uid 'type:id', and directed edges), assign each node a "
    "layer index (column, left-to-right data flow) to produce a clean diagram. "
    "Priorities, highest first: minimize edge crossings; minimize edge bends "
    "and length; consistent layers; align related resources; group services by "
    "role (edge/DNS, load-balancing/API, compute, messaging between producers "
    "and consumers, data, monitoring, security); readability above all. "
    "Typical layering: users=0, DNS/CDN/API/LB=1, compute=2, messaging=3, "
    "data=4, monitoring/security to the right or same column as what they "
    "serve. Keep producers left of consumers. "
    "Return ONLY a JSON object, no prose:\n"
    '{"layers": {"<uid>": <int 0-12>, ...}, '
    '"drop_edges": [["<from-uid>","<to-uid>"], ...], '
    '"edge_labels": {"<from-uid>-><to-uid>": "<short label>"}, '
    '"notes": ["<=4 short grouping/architecture notes"]}\n'
    "Include every node uid in layers. drop_edges only for truly redundant "
    "duplicates. Keep labels under 4 words."
)


def _extract_json(text: str) -> dict:
    """Best-effort parse of a JSON object from a model reply."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.split("```")[1].lstrip("json").strip() if "```" in text[3:] else text
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return {}
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return {}


def ai_layout_plan(graph: dict, config: dict | None = None) -> dict:
    """Ask the model to propose an optimized layout (layers/labels/notes) for
    the architecture graph. Structure only — the deterministic engine renders
    it. Returns {} on any failure so generation still succeeds."""
    from clearsky.architecture import _uid  # local import avoids cycle

    try:
        if config is None:
            config = load_provider_config()
    except ConfigError:
        return {}
    nodes = []
    for _coll, n in _iter_graph_nodes(graph):
        nodes.append({"uid": _uid(n), "type": n["type"], "label": n["label"]})
    payload = {"nodes": nodes, "edges": [
        {"from": e["from"], "to": e["to"]} for e in graph.get("edges", [])]}
    prompt = (LAYOUT_SYSTEM + "\n\nGraph:\n"
              + json.dumps(payload, default=str)[:12000])
    try:
        raw = simple_completion(prompt, config)
        return _extract_json(raw)
    except Exception:  # noqa: BLE001
        logger.exception("ai_layout_plan failed")
        return {}


def _iter_graph_nodes(graph):
    for rg in graph.get("regions", []):
        for key in ("lambda", "apigw", "dynamodb", "sns", "sqs", "kinesis", "extras"):
            for n in rg.get(key, []):
                yield key, n
        for vpc in rg.get("vpcs", []):
            for coll in (vpc.get("nats", []), vpc.get("lbs", []), vpc.get("rds", [])):
                for n in coll:
                    yield "vpc", n
            for sn in vpc.get("subnets", []):
                for n in sn.get("resources", []):
                    yield "subnet", n
    for n in graph.get("global", {}).get("s3", []):
        yield "s3", n


def simple_completion(prompt: str, config: dict) -> str:
    """One-shot, no-tools completion. Used for the architecture summary."""
    body = json.dumps({
        "model": config["model_id"],
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 700,
    }).encode()
    req = urllib.request.Request(
        f"{config['api_base']}/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config['api_key']}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        payload = json.loads(resp.read())
    return (payload["choices"][0]["message"].get("content") or "").strip()


# ---------- agent loop ----------

def agent_loop(messages: list[dict], config: dict) -> tuple[str, list[str]]:
    """Runs the tool-use loop. Returns (final_text, tool_trace)."""
    trace: list[str] = []
    for _ in range(MAX_ITERATIONS):
        message = call_model(messages, config)
        messages.append(message)
        tool_calls = message.get("tool_calls") or []
        if not tool_calls:
            return (message.get("content") or "").strip(), trace
        for call in tool_calls:
            fn = call["function"]
            name = fn["name"]
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            trace.append(f"{name}: {json.dumps(args)[:120]}")
            logger.info("tool %s args=%s", name, args)
            messages.append({
                "role": "tool",
                "tool_call_id": call["id"],
                "content": execute_tool(name, args),
            })
    return "Investigation hit the iteration limit; partial results above.", trace


# ---------- conversation persistence ----------

def _table():
    return boto3.resource("dynamodb").Table(os.environ["CHAT_TABLE"])


def lambda_handler(event, context):
    conversation_id = event["conversation_id"]
    table = _table()
    item = table.get_item(Key={"pk": conversation_id}).get("Item")
    if not item:
        logger.error("conversation %s not found", conversation_id)
        return {"error": "not found"}

    CONTEXT.clear()
    CONTEXT.update(item.get("context") or {})

    history = json.loads(item["messages"])
    # Our stored turns are {role, text}; prepend the system prompt,
    # extended with the member accounts currently onboarded.
    system = SYSTEM_PROMPT
    try:
        from clearsky import accounts as accounts_mod
        members = accounts_mod.configured_accounts()
        if members:
            listing = ", ".join(
                f'{a["account_id"]}{" (" + a["label"] + ")" if a["label"] else ""}'
                for a in members)
            system += f"\nOnboarded member accounts: {listing}."
        else:
            system += "\nNo member accounts are onboarded yet."
    except Exception:  # noqa: BLE001 - registry lookup is best-effort
        pass
    messages = [{"role": "system", "content": system}]
    messages += [{"role": m["role"], "content": m["text"]} for m in history]

    try:
        config = load_provider_config()
        answer, trace = agent_loop(messages, config)
    except ConfigError as err:
        answer, trace = (str(err), [])
    except Exception as err:  # noqa: BLE001
        logger.exception("agent loop failed")
        answer, trace = (f"Sorry — the investigation failed: {err}", [])

    history.append({
        "role": "assistant",
        "text": answer,
        "tools_used": trace,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    table.update_item(
        Key={"pk": conversation_id},
        UpdateExpression="SET messages = :m, #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":m": json.dumps(history), ":s": "ready",
        },
    )
    return {"status": "ready"}
