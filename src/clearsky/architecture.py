"""Architecture diagram generator: discover the account's live resources
(read-only) and render a deterministic draw.io (mxGraph) file plus an
inline SVG preview.

Design mirrors the rest of the tool: pure functions turn raw describe/list
responses into a normalized graph, `layout()` turns the graph into a scene
(absolute coordinates), and two pure emitters turn the scene into valid
draw.io XML and SVG — all fixture-testable without AWS.

The graph JSON is persisted alongside the render so the chat agent can
edit it (`apply_ops`) and re-render: add/remove/rename nodes, draw edges,
attach notes. AI never writes XML directly — only structured ops.

Invoked asynchronously by the dashboard API; writes the result JSON
(graph + drawio + svg + optional summary) to S3 under
`architecture/jobs/<job_id>.json`, which the API serves to the polling SPA.
"""

import base64
import json
import logging
import math
import os
import re
import xml.sax.saxutils as sx
from collections import defaultdict
from datetime import date, timedelta

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

GROUPS = ("network", "serverless", "data")  # cost is an overlay, not a group

# resource type -> (aws4 resIcon, fill colour, svg glyph, pretty name).
# Colours follow AWS service-category palettes so the diagram reads like the
# official icon set: compute #ED7100, storage #7AA116, database #2E27AD,
# networking #8C4FFF, app-integration/mgmt #E7157B, security #DD344C.
TYPE_STYLE = {
    # compute
    "ec2":      ("mxgraph.aws4.ec2", "#ED7100", "EC2", "EC2 instance"),
    "lambda":   ("mxgraph.aws4.lambda", "#ED7100", "λ", "Lambda function"),
    "ecs":      ("mxgraph.aws4.elastic_container_service", "#ED7100", "ECS", "ECS service"),
    "eks":      ("mxgraph.aws4.elastic_kubernetes_service", "#ED7100", "EKS", "EKS cluster"),
    "fargate":  ("mxgraph.aws4.fargate", "#ED7100", "FGT", "Fargate"),
    # networking / edge
    "elb":      ("mxgraph.aws4.elastic_load_balancing", "#8C4FFF", "ELB", "Load balancer"),
    "nat":      ("mxgraph.aws4.nat_gateway", "#8C4FFF", "NAT", "NAT gateway"),
    "igw":      ("mxgraph.aws4.internet_gateway", "#8C4FFF", "IGW", "Internet gateway"),
    "cloudfront": ("mxgraph.aws4.cloudfront", "#8C4FFF", "CF", "CloudFront"),
    "route53":  ("mxgraph.aws4.route_53", "#8C4FFF", "R53", "Route 53"),
    # database / storage
    "rds":      ("mxgraph.aws4.rds", "#2E27AD", "RDS", "RDS database"),
    "dynamodb": ("mxgraph.aws4.dynamodb", "#2E27AD", "DDB", "DynamoDB table"),
    "elasticache": ("mxgraph.aws4.elasticache", "#2E27AD", "EC$", "ElastiCache"),
    "s3":       ("mxgraph.aws4.s3", "#7AA116", "S3", "S3 bucket"),
    "efs":      ("mxgraph.aws4.elastic_file_system", "#7AA116", "EFS", "EFS filesystem"),
    # app integration / api / messaging
    "apigw":    ("mxgraph.aws4.api_gateway", "#E7157B", "API", "API Gateway"),
    "sns":      ("mxgraph.aws4.simple_notification_service", "#E7157B", "SNS", "SNS topic"),
    "sqs":      ("mxgraph.aws4.simple_queue_service", "#E7157B", "SQS", "SQS queue"),
    "eventbridge": ("mxgraph.aws4.eventbridge", "#E7157B", "EVB", "EventBridge"),
    "sfn":      ("mxgraph.aws4.step_functions", "#E7157B", "SFN", "Step Functions"),
    "kinesis":  ("mxgraph.aws4.kinesis", "#8C4FFF", "KIN", "Kinesis stream"),
    # management / security
    "cloudwatch": ("mxgraph.aws4.cloudwatch_2", "#E7157B", "CW", "CloudWatch"),
    "cloudtrail": ("mxgraph.aws4.cloudtrail", "#E7157B", "CT", "CloudTrail"),
    "cognito":  ("mxgraph.aws4.cognito", "#DD344C", "COG", "Cognito"),
    "secretsmanager": ("mxgraph.aws4.secrets_manager", "#DD344C", "SEC", "Secrets Manager"),
    # actor
    "users":    ("mxgraph.aws4.users", "#232F3E", "USR", "Users"),
    # generic fallback for any type discovery/AI adds that we don't map
    "generic":  ("mxgraph.aws4.resource_group", "#5A6B86", "AWS", "AWS resource"),
}


def type_style(node_type: str):
    """Style tuple for a node type, falling back to a neutral generic box so
    any resource an extended discovery or the AI adds still renders."""
    return TYPE_STYLE.get(node_type, TYPE_STYLE["generic"])

SEV_COLOUR = {"HIGH": "#D13212", "MEDIUM": "#FF9900", "LOW": "#687078"}

# group kind -> (aws4 grIcon or None, stroke, fill, dashed)
GROUP_STYLE = {
    "cloud":   ("mxgraph.aws4.group_aws_cloud_alt", "#232F3E", "none", 0),
    "region":  ("mxgraph.aws4.group_region", "#00A4A6", "none", 1),
    "vpc":     ("mxgraph.aws4.group_vpc2", "#8C4FFF", "none", 0),
    "public":  (None, "#7AA116", "#F2F6E8", 0),
    "private": (None, "#00A4A6", "#E6F6F7", 0),
}


# ---------- pure summarizers (raw AWS response -> graph pieces) ----------

def _name_tag(tags: list | None) -> str:
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""


def public_subnet_ids(route_tables: list, igw_ids: set) -> set:
    """Subnets whose (explicit or main) route table routes 0.0.0.0/0 to an IGW."""
    main_public = False
    explicit: dict[str, bool] = {}
    for rt in route_tables:
        routes_to_igw = any(
            r.get("GatewayId", "").startswith("igw-") and r.get("GatewayId") in igw_ids
            for r in rt.get("Routes", [])
        )
        for assoc in rt.get("Associations", []):
            if assoc.get("Main"):
                main_public = main_public or routes_to_igw
            elif assoc.get("SubnetId"):
                explicit[assoc["SubnetId"]] = routes_to_igw
    public = {sid for sid, pub in explicit.items() if pub}
    return public, set(explicit), main_public


def build_vpcs(vpcs, subnets, route_tables, igws, nats, instances, dbs, lbs) -> list:
    """Assemble the per-VPC topology from raw describe responses."""
    igw_by_vpc: dict[str, str] = {}
    igw_ids = set()
    for igw in igws:
        for att in igw.get("Attachments", []):
            if att.get("VpcId"):
                igw_by_vpc[att["VpcId"]] = igw["InternetGatewayId"]
                igw_ids.add(igw["InternetGatewayId"])

    pub_ids, explicit_ids, main_public = public_subnet_ids(route_tables, igw_ids)

    inst_by_subnet: dict[str, list] = {}
    for r in instances:
        state = r["State"]["Name"]
        if state == "terminated":
            continue
        sub = r.get("InstanceType", "")
        if state != "running":
            sub = f"{sub} · {state}".strip(" ·")
        inst_by_subnet.setdefault(r.get("SubnetId", ""), []).append(
            {"type": "ec2", "id": r["InstanceId"],
             "label": _name_tag(r.get("Tags")) or r["InstanceId"],
             "sub": sub}
        )

    rds_by_vpc: dict[str, list] = {}
    for db in dbs:
        vpc = (db.get("DBSubnetGroup") or {}).get("VpcId", "")
        rds_by_vpc.setdefault(vpc, []).append(
            {"type": "rds", "id": db["DBInstanceIdentifier"],
             "label": db["DBInstanceIdentifier"], "sub": db.get("Engine", "")}
        )

    lb_by_vpc: dict[str, list] = {}
    for lb in lbs:
        lb_by_vpc.setdefault(lb.get("VpcId", ""), []).append(
            {"type": "elb", "id": lb["LoadBalancerName"],
             "label": lb["LoadBalancerName"], "sub": lb.get("Type", "")}
        )

    nat_by_vpc: dict[str, list] = {}
    for nat in nats:
        if nat.get("State") in ("available", "pending"):
            nat_by_vpc.setdefault(nat.get("VpcId", ""), []).append(
                {"type": "nat", "id": nat["NatGatewayId"], "label": nat["NatGatewayId"]}
            )

    out = []
    for vpc in vpcs:
        vid = vpc["VpcId"]
        vpc_subnets = []
        for sn in subnets:
            if sn["VpcId"] != vid:
                continue
            sid = sn["SubnetId"]
            is_public = sid in pub_ids or (sid not in explicit_ids and main_public)
            vpc_subnets.append({
                "id": sid, "az": sn.get("AvailabilityZone", ""),
                "cidr": sn.get("CidrBlock", ""),
                "public": bool(is_public),
                "resources": inst_by_subnet.get(sid, []),
            })
        vpc_subnets.sort(key=lambda s: (not s["public"], s["az"]))
        out.append({
            "id": vid, "cidr": vpc.get("CidrBlock", ""),
            "label": _name_tag(vpc.get("Tags")) or vid,
            "igw": igw_by_vpc.get(vid),
            "nats": nat_by_vpc.get(vid, []),
            "lbs": lb_by_vpc.get(vid, []),
            "rds": rds_by_vpc.get(vid, []),
            "subnets": vpc_subnets,
        })
    return out


def vpc_resource_count(vpc: dict) -> int:
    """Real workloads in the VPC — an IGW alone doesn't count."""
    return (sum(len(s.get("resources", [])) for s in vpc.get("subnets", []))
            + len(vpc.get("nats", [])) + len(vpc.get("lbs", []))
            + len(vpc.get("rds", [])))


def _fn_name_from_integration(uri: str) -> str | None:
    if ":function:" in (uri or ""):
        return uri.split(":function:")[1].split("/")[0].split(":")[0]
    return None


def _arn_resource_name(arn: str) -> str:
    """Bare resource name from an ARN (or a Lambda function ARN's function
    name). Used to resolve event sources / SNS endpoints to graph nodes."""
    arn = arn or ""
    if ":function:" in arn:
        return arn.split(":function:")[1].split(":")[0]
    if ":" not in arn:
        return ""
    tail = arn.rsplit(":", 1)[-1]           # queues, topics, tables
    return tail.split("/")[-1]              # kinesis stream/<name>, table/<name>


def _uid(node: dict) -> str:
    """Stable node identity that survives same-name collisions across types
    (a Lambda and a DynamoDB table can both be 'clearsky-chat')."""
    return f"{node['type']}:{node['id']}"


def infer_edges(graph: dict) -> list[dict]:
    """Deterministic data-flow edges (keyed by uid):
      API GW  -> Lambda   (integration targets)
      SNS     -> Lambda/SQS (topic subscriptions)
      source  -> Lambda   (event-source mappings: SQS/Kinesis/…)
      Lambda  -> DynamoDB / S3 / SQS / SNS (env-var name references)
    All matching is by resource *name*; edges carry uids so same-named
    resources of different types stay distinct."""
    edges, seen = [], set()

    def add(src, dst, label=""):
        if src and dst and src != dst and (src, dst) not in seen:
            seen.add((src, dst))
            edges.append({"from": src, "to": dst, "label": label})

    bucket_uid = {b["id"]: _uid(b) for b in graph.get("global", {}).get("s3", [])}
    for rg in graph.get("regions", []):
        fn_uid = {f["id"]: _uid(f) for f in rg.get("lambda", [])}
        # name -> uid for every referenceable resource in the region + globals
        ref = dict(bucket_uid)
        for key in ("dynamodb", "sqs", "sns", "kinesis"):
            for n in rg.get(key, []):
                ref.setdefault(n["id"], _uid(n))
        for f in rg.get("lambda", []):
            ref.setdefault(f["id"], _uid(f))

        for fn in rg.get("lambda", []):
            for val in fn.get("env", []):          # config references
                if val in ref:
                    add(_uid(fn), ref[val])
            for src in fn.get("event_sources", []):  # SQS/Kinesis/DDB triggers
                if src in ref:
                    add(ref[src], _uid(fn), "event")
        for api in rg.get("apigw", []):
            for target in api.get("targets", []):
                if target in fn_uid:
                    add(_uid(api), fn_uid[target])
        for topic in rg.get("sns", []):            # topic subscriptions
            for target in topic.get("targets", []):
                if target in ref:
                    add(_uid(topic), ref[target])
    return edges


def infer_vpc_edges(instances, lbs, tgs, tg_health, sgs, igw_by_vpc,
                    user_data) -> list[dict]:
    """Deterministic VPC data-flow edges from control-plane facts:
      ELB      -> EC2   (registered target-group targets)
      EC2      -> ELB   (instance user-data references the LB's DNS name)
      EC2      -> EC2   (instance user-data references another instance's IP)
      IGW      -> ELB   (internet-facing load balancer)
      IGW      -> EC2   (public IP + a security group open to 0.0.0.0/0)
      src SG members -> dst SG members (security-group ingress references)
    Pure — all inputs are raw describe responses."""
    edges, seen = [], set()

    def add(src, dst, label=""):
        if src and dst and src != dst and (src, dst) not in seen:
            seen.add((src, dst))
            edges.append({"from": src, "to": dst, "label": label})

    live = [i for i in instances if i.get("State", {}).get("Name") != "terminated"]
    inst_uid = {i["InstanceId"]: f'ec2:{i["InstanceId"]}' for i in live}
    lb_by_arn = {lb["LoadBalancerArn"]: lb for lb in lbs
                 if lb.get("LoadBalancerArn")}

    # ELB -> registered instance targets
    for tg in tgs:
        healths = tg_health.get(tg.get("TargetGroupArn", ""), [])
        for lb_arn in tg.get("LoadBalancerArns", []):
            lb = lb_by_arn.get(lb_arn)
            if not lb:
                continue
            for hd in healths:
                tid = (hd.get("Target") or {}).get("Id", "")
                if tid in inst_uid:
                    add(f'elb:{lb["LoadBalancerName"]}', inst_uid[tid])

    # user-data references: LB DNS names and other instances' IPs
    ip_uid = {}
    for i in live:
        for key in ("PrivateIpAddress", "PublicIpAddress"):
            if i.get(key):
                ip_uid[i[key]] = inst_uid[i["InstanceId"]]
    for iid, ud in (user_data or {}).items():
        src = inst_uid.get(iid)
        if not src or not ud:
            continue
        for lb in lbs:
            if lb.get("DNSName") and lb["DNSName"] in ud:
                add(src, f'elb:{lb["LoadBalancerName"]}')
        for ip, dst in ip_uid.items():
            if dst != src and re.search(rf'(?<![\d.]){re.escape(ip)}(?![\d.])', ud):
                add(src, dst)

    # IGW -> internet entry points
    world_open = {
        g["GroupId"] for g in sgs
        if any(any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", []))
               for p in g.get("IpPermissions", []))
    }
    for lb in lbs:
        if lb.get("Scheme") == "internet-facing":
            igw = igw_by_vpc.get(lb.get("VpcId", ""))
            if igw:
                add(f"igw:{igw}", f'elb:{lb["LoadBalancerName"]}')
    for i in live:
        if not i.get("PublicIpAddress"):
            continue
        if any(sg.get("GroupId") in world_open
               for sg in i.get("SecurityGroups", [])):
            igw = igw_by_vpc.get(i.get("VpcId", ""))
            if igw:
                add(f"igw:{igw}", inst_uid[i["InstanceId"]])

    # security-group references (ingress from another SG -> traffic edge)
    sg_members: dict[str, list[str]] = {}
    for i in live:
        for sg in i.get("SecurityGroups", []):
            sg_members.setdefault(sg.get("GroupId", ""), []).append(
                inst_uid[i["InstanceId"]])
    for lb in lbs:
        for gid in lb.get("SecurityGroups", []):
            sg_members.setdefault(gid, []).append(
                f'elb:{lb["LoadBalancerName"]}')
    for g in sgs:
        for p in g.get("IpPermissions", []):
            for pair in p.get("UserIdGroupPairs", []):
                for src in sg_members.get(pair.get("GroupId", ""), []):
                    for dst in sg_members.get(g["GroupId"], []):
                        add(src, dst)
    return edges


# ---------- discovery (talks to AWS) ----------

def _paginate(client, op, key, **kw):
    items = []
    for page in client.get_paginator(op).paginate(**kw):
        items.extend(page.get(key, []))
    return items


def discover(session, regions: list[str], include: set[str]) -> dict:
    account = session.client("sts").get_caller_identity()["Account"]
    graph = {"account": account, "regions": [], "global": {}, "cost": {},
             "edges": [], "notes": []}
    vpc_edges: list[dict] = []

    for region in regions:
        rg = {"region": region, "vpcs": [], "lambda": [], "apigw": [],
              "dynamodb": [], "sns": [], "sqs": [], "kinesis": [], "extras": []}
        if "network" in include:
            ec2 = session.client("ec2", region_name=region)
            elb = session.client("elbv2", region_name=region)
            rds = session.client("rds", region_name=region)
            lbs = _paginate(elb, "describe_load_balancers", "LoadBalancers")
            dbs = _paginate(rds, "describe_db_instances", "DBInstances")
            instances = [i for r in _paginate(ec2, "describe_instances", "Reservations")
                         for i in r.get("Instances", [])]
            igws = ec2.describe_internet_gateways()["InternetGateways"]
            rg["vpcs"] = build_vpcs(
                ec2.describe_vpcs()["Vpcs"],
                _paginate(ec2, "describe_subnets", "Subnets"),
                _paginate(ec2, "describe_route_tables", "RouteTables"),
                igws,
                ec2.describe_nat_gateways()["NatGateways"],
                instances, dbs, lbs,
            )
            vpc_edges.extend(_discover_vpc_edges(ec2, elb, instances, lbs, igws))
        if "serverless" in include:
            lam = session.client("lambda", region_name=region)
            functions = _paginate(lam, "list_functions", "Functions")
            # event-source mappings: SQS/Kinesis/DDB-stream -> Lambda triggers
            evt_by_fn: dict[str, list] = {}
            try:
                for m in _paginate(lam, "list_event_source_mappings", "EventSourceMappings"):
                    fn = (m.get("FunctionArn") or "").split(":function:")[-1].split(":")[0]
                    src = _arn_resource_name(m.get("EventSourceArn", ""))
                    if fn and src:
                        evt_by_fn.setdefault(fn, []).append(src)
            except Exception:  # noqa: BLE001
                pass
            rg["lambda"] = [
                {"type": "lambda", "id": f["FunctionName"],
                 "label": f["FunctionName"], "sub": f.get("Runtime", ""),
                 "env": sorted({str(v) for v in
                                (f.get("Environment") or {}).get("Variables", {}).values()}),
                 "event_sources": sorted(set(evt_by_fn.get(f["FunctionName"], [])))}
                for f in functions]

            # SNS topics + their Lambda/SQS subscriptions
            try:
                sns = session.client("sns", region_name=region)
                for t in _paginate(sns, "list_topics", "Topics"):
                    arn = t.get("TopicArn", "")
                    name = arn.rsplit(":", 1)[-1]
                    if not name:
                        continue
                    targets = set()
                    try:
                        for s in _paginate(sns, "list_subscriptions_by_topic",
                                           "Subscriptions", TopicArn=arn):
                            tgt = _arn_resource_name(s.get("Endpoint", ""))
                            if tgt and s.get("Protocol") in ("lambda", "sqs"):
                                targets.add(tgt)
                    except Exception:  # noqa: BLE001
                        pass
                    rg["sns"].append({"type": "sns", "id": name, "label": name,
                                      "targets": sorted(targets)})
            except Exception:  # noqa: BLE001
                logger.info("sns unavailable in %s", region)

            # SQS queues
            try:
                sqs = session.client("sqs", region_name=region)
                urls = sqs.list_queues().get("QueueUrls", [])
                rg["sqs"] = [{"type": "sqs", "id": u.rsplit("/", 1)[-1],
                              "label": u.rsplit("/", 1)[-1]} for u in urls]
            except Exception:  # noqa: BLE001
                logger.info("sqs unavailable in %s", region)

            try:
                agw = session.client("apigatewayv2", region_name=region)
                apis = agw.get_apis().get("Items", [])
                rg["apigw"] = []
                for a in apis:
                    targets = set()
                    try:
                        for it in agw.get_integrations(ApiId=a["ApiId"]).get("Items", []):
                            name = _fn_name_from_integration(it.get("IntegrationUri", ""))
                            if name:
                                targets.add(name)
                    except Exception:  # noqa: BLE001
                        pass
                    rg["apigw"].append(
                        {"type": "apigw", "id": a["ApiId"],
                         "label": a.get("Name", a["ApiId"]),
                         "sub": a.get("ProtocolType", ""),
                         "targets": sorted(targets)})
            except Exception:  # noqa: BLE001
                logger.info("apigatewayv2 unavailable in %s", region)
        if "data" in include:
            ddb = session.client("dynamodb", region_name=region)
            rg["dynamodb"] = [{"type": "dynamodb", "id": t, "label": t}
                              for t in _paginate(ddb, "list_tables", "TableNames")]
        graph["regions"].append(rg)

    if "data" in include:
        s3 = session.client("s3")
        graph["global"]["s3"] = [{"type": "s3", "id": b["Name"], "label": b["Name"]}
                                 for b in s3.list_buckets()["Buckets"]]
    if "cost" in include:
        graph["cost"] = fetch_cost(session)
    graph["edges"] = infer_edges(graph)
    have = {(e["from"], e["to"]) for e in graph["edges"]}
    graph["edges"] += [e for e in vpc_edges
                       if (e["from"], e["to"]) not in have]
    return graph


def _discover_vpc_edges(ec2, elb, instances, lbs, igws) -> list[dict]:
    """Gather the extra describe responses infer_vpc_edges needs (target
    groups + health, security groups, per-instance user-data) and run it.
    Everything is best-effort — a denied call just means fewer edges."""
    try:
        tgs = _paginate(elb, "describe_target_groups", "TargetGroups")
    except Exception:  # noqa: BLE001
        tgs = []
    tg_health = {}
    for tg in tgs:
        try:
            tg_health[tg["TargetGroupArn"]] = elb.describe_target_health(
                TargetGroupArn=tg["TargetGroupArn"])["TargetHealthDescriptions"]
        except Exception:  # noqa: BLE001
            tg_health[tg["TargetGroupArn"]] = []
    try:
        sgs = _paginate(ec2, "describe_security_groups", "SecurityGroups")
    except Exception:  # noqa: BLE001
        sgs = []
    igw_by_vpc = {att["VpcId"]: igw["InternetGatewayId"]
                  for igw in igws for att in igw.get("Attachments", [])
                  if att.get("VpcId")}
    live = [i for i in instances
            if i.get("State", {}).get("Name") != "terminated"][:25]
    user_data = {}
    for inst in live:
        try:
            raw = (ec2.describe_instance_attribute(
                InstanceId=inst["InstanceId"], Attribute="userData")
                .get("UserData") or {}).get("Value", "")
            user_data[inst["InstanceId"]] = (
                base64.b64decode(raw).decode("utf-8", "ignore") if raw else "")
        except Exception:  # noqa: BLE001
            user_data[inst["InstanceId"]] = ""
    return infer_vpc_edges(instances, lbs, tgs, tg_health, sgs,
                           igw_by_vpc, user_data)


def fetch_cost(session) -> dict:
    """Last 30d unblended cost by service -> {service: usd}."""
    ce = session.client("ce", region_name="us-east-1")
    end = date.today()
    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": (end - timedelta(days=30)).isoformat(),
                        "End": end.isoformat()},
            Granularity="MONTHLY", Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
    except Exception:  # noqa: BLE001
        return {}
    out: dict[str, float] = {}
    for period in resp.get("ResultsByTime", []):
        for g in period.get("Groups", []):
            amt = float(g["Metrics"]["UnblendedCost"]["Amount"])
            if amt > 0:
                out[g["Keys"][0]] = round(out.get(g["Keys"][0], 0) + amt, 2)
    return out


# ---------- layout (graph -> scene with absolute coordinates) ----------
#
# Data-flow layered layout, modelled on hand-drawn AWS reference diagrams:
# nodes are assigned columns by longest-path over the inferred edge DAG
# (actor -> gateway -> compute -> data), so arrows run left-to-right between
# adjacent nodes. Rows within a column are barycenter-ordered to cut
# crossings, and parallel edges are spread across per-gap channels rather
# than bundled. Containment (Cloud > Region > VPC > Subnet) is drawn as
# frames sized to the nodes they hold.

ICON = 76          # AWS icon box
NODE_W = 196       # horizontal slot per icon (icon + side breathing room)
NODE_H = 138       # vertical slot per icon (icon + 2 label lines + gap)
COL_GAP = 120      # gap between flow columns — room for edge channels
PAD = 42           # padding inside group frames
HEADER = 44        # group label band
BAND_GAP = 66      # gap between stacked frames
SUBNET_COLS = 4


# region-level (non-VPC) service lists that flow through the tiered layout
FLOW_LISTS = ("apigw", "lambda", "dynamodb", "sns", "sqs", "kinesis", "extras")


def _has_content(rg: dict) -> bool:
    return (any(vpc_resource_count(v) for v in rg.get("vpcs", []))
            or any(rg.get(k) for k in FLOW_LISTS))


# Base column per service role, so nodes group into readable tiers
# (actor -> gateway -> compute -> data) even when a compute node has no
# inbound edge — e.g. an EventBridge-triggered Lambda. Longest-path only
# ever pushes a node further right, never left of its role tier.
TYPE_TIER = {
    "users": 0,
    "cloudfront": 1, "route53": 1, "cognito": 1,
    "igw": 1, "apigw": 1, "elb": 1, "nat": 1,
    "lambda": 2, "ec2": 2, "ecs": 2, "eks": 2, "fargate": 2,
    "sns": 2, "sqs": 2, "eventbridge": 2, "sfn": 2, "kinesis": 2,
    "dynamodb": 3, "rds": 3, "elasticache": 3, "s3": 3, "efs": 3,
    "cloudwatch": 3, "cloudtrail": 3, "secretsmanager": 3,
}


def _tier(uid: str) -> int:
    return TYPE_TIER.get(uid.split(":", 1)[0], 2)


def _layer_columns(uids: set, edges: list,
                   fixed: dict | None = None) -> tuple[dict, dict, dict]:
    """Column per node. A node's column is its role tier, pushed right only
    by predecessors in a *lower* tier — so same-tier edges (e.g. a Lambda
    invoking another Lambda) keep both in one column and every cross-tier
    edge stays a clean adjacent hop. `fixed` optionally pins uid->column
    (used by the AI layout pass). Returns (col, succ, pred)."""
    fixed = fixed or {}
    succ = {u: set() for u in uids}
    pred = {u: set() for u in uids}
    for e in edges:
        a, b = e["from"], e["to"]
        if a in uids and b in uids and a != b:
            succ[a].add(b)
            pred[b].add(a)
    col: dict = {}

    def visit(u, stack):
        if u in col:
            return col[u]
        if u in fixed:
            col[u] = fixed[u]
            return col[u]
        base = _tier(u)
        # only lower-tier predecessors push a node into a deeper column
        deeper = [p for p in pred[u] if p not in stack and _tier(p) < base]
        if not deeper:
            col[u] = base
            return base
        col[u] = max(base, 1 + max(visit(p, stack | {u}) for p in deeper))
        return col[u]

    for u in uids:
        visit(u, set())
    return col, succ, pred


def _order_rows(col: dict, succ: dict, pred: dict) -> dict:
    """Group uids by column and order each column by barycenter of neighbours
    to reduce edge crossings. Returns {column_index: [uid, ...]}."""
    cols: dict = defaultdict(list)
    for u, c in col.items():
        cols[c].append(u)
    for c in cols:
        cols[c].sort()
    pos: dict = {}

    def reindex():
        for us in cols.values():
            for i, u in enumerate(us):
                pos[u] = i

    reindex()
    for _ in range(4):
        for c in sorted(cols):
            def bary(u, c=c):
                neigh = [n for n in (pred[u] if c > 0 else succ[u]) if n in pos]
                return sum(pos[n] for n in neigh) / len(neigh) if neigh else pos[u]
            cols[c].sort(key=bary)
        reindex()
    return dict(cols)


def layout(graph: dict, options: dict | None = None) -> dict:
    """Compute absolute positions for every group and node. Pure."""
    scene: dict = {"groups": [], "nodes": [], "edges": [], "w": 0, "h": 0}
    placed: dict[str, dict] = {}

    def put(node, x, y):
        n = dict(node)
        n["uid"] = _uid(n)
        n["_x"], n["_y"] = x, y
        scene["nodes"].append(n)
        placed[n["uid"]] = n
        return n

    def place_vpc(vpc, x, y) -> tuple[int, int]:
        inner = x + PAD
        iy = y + HEADER + 12
        gateways = ([{"type": "igw", "id": vpc["igw"], "label": vpc["igw"]}]
                    if vpc.get("igw") else [])
        gateways += vpc.get("nats", []) + vpc.get("lbs", []) + vpc.get("rds", [])
        for i, g in enumerate(gateways):
            put(g, inner + i * NODE_W + (NODE_W - ICON) // 2, iy)
        gw_w = len(gateways) * NODE_W
        sy = iy + (NODE_H + 14 if gateways else 0)
        sub_w = 0
        for sn in vpc.get("subnets", []):
            res = sn.get("resources", [])
            if not res:
                continue
            cols = min(SUBNET_COLS, len(res))
            rows = (len(res) + cols - 1) // cols
            lane_w = cols * NODE_W + PAD
            lane_h = rows * NODE_H + HEADER
            scene["groups"].append(
                {"kind": "public" if sn["public"] else "private",
                 "x": inner, "y": sy, "w": lane_w, "h": lane_h,
                 "label": f'{"Public" if sn["public"] else "Private"} subnet · '
                          f'{sn["az"]} · {sn["cidr"]}'})
            for i, r in enumerate(res):
                put(r, inner + PAD // 2 + (i % cols) * NODE_W + (NODE_W - ICON) // 2,
                    sy + HEADER + (i // cols) * NODE_H)
            sy += lane_h + 14
            sub_w = max(sub_w, lane_w)
        w = max(gw_w, sub_w, 2 * NODE_W) + 2 * PAD
        h = sy - y + PAD // 2
        scene["groups"].append(
            {"kind": "vpc", "x": x, "y": y, "w": w, "h": h,
             "label": f'VPC {vpc["label"]} · {vpc["cidr"]}'})
        return w, h

    edges = [dict(e) for e in graph.get("edges", [])]
    globals_s3 = graph.get("global", {}).get("s3", [])
    s3_by_uid = {_uid(b): b for b in globals_s3}
    consumed = {e["to"] for e in edges if e["to"] in s3_by_uid}
    # optional AI layout pass pins uid -> column (see ai_layout_plan)
    layer_hints = (graph.get("layout_hints") or {}).get("layers") or {}
    folded: set = set()   # a shared bucket is folded into one region only

    cloud_x, cloud_y = 60, 64
    inner_x = cloud_x + PAD
    cur_y = cloud_y + HEADER + 16
    cloud_right = inner_x

    for rg in graph["regions"]:
        if not _has_content(rg):
            continue
        ry = cur_y
        fx = inner_x + PAD
        fy = ry + HEADER + 16

        # VPC blocks in a row across the top of the region band
        vx, vpc_h = fx, 0
        for vpc in rg.get("vpcs", []):
            if not vpc_resource_count(vpc):
                continue
            w, h = place_vpc(vpc, vx, fy)
            vx += w + BAND_GAP
            vpc_h = max(vpc_h, h)
        vpc_row_w = (vx - fx - BAND_GAP) if vpc_h else 0
        flow_y0 = fy + (vpc_h + BAND_GAP if vpc_h else 0)

        # region-level managed services + consumed global buckets + actor
        fnodes: dict = {}
        for key in FLOW_LISTS:
            for n in rg.get(key, []):
                fnodes[_uid(n)] = n
        region_uids = set(fnodes)
        for e in edges:
            if (e["from"] in region_uids and e["to"] in consumed
                    and e["to"] not in folded):
                fnodes[e["to"]] = s3_by_uid[e["to"]]
                folded.add(e["to"])
        apigw_uids = [_uid(a) for a in rg.get("apigw", [])]
        users_uid = "users:__users__" if apigw_uids else None
        if users_uid:
            fnodes[users_uid] = {"type": "users", "id": "__users__", "label": "Users"}

        flow_uids = set(fnodes)
        fedges = [e for e in edges
                  if e["from"] in flow_uids and e["to"] in flow_uids]
        for au in apigw_uids:
            fedges.append({"from": users_uid, "to": au, "label": "HTTPS"})

        col, succ, pred = _layer_columns(flow_uids, fedges, fixed=layer_hints)
        cols = _order_rows(col, succ, pred)
        maxrows = max((len(v) for v in cols.values()), default=0)
        flow_h = maxrows * NODE_H
        # compact empty tiers so columns are contiguous left-to-right
        dense = {c: i for i, c in enumerate(sorted(cols))}
        ncols = len(dense)
        for c in sorted(cols):
            us = cols[c]
            colx = fx + dense[c] * (NODE_W + COL_GAP)
            off = (flow_h - len(us) * NODE_H) // 2
            for i, u in enumerate(us):
                n = put(fnodes[u], colx + (NODE_W - ICON) // 2,
                        flow_y0 + off + i * NODE_H)
                n["_col"] = dense[c]
        flow_w = ncols * NODE_W + (ncols - 1) * COL_GAP if ncols else 0

        scene["edges"].extend(fedges)
        content_w = max(vpc_row_w, flow_w)
        frame_w = content_w + 2 * PAD
        frame_h = (flow_y0 + flow_h) - ry + PAD
        scene["groups"].append(
            {"kind": "region", "x": inner_x, "y": ry, "w": frame_w, "h": frame_h,
             "label": f'Region · {rg["region"]}'})
        cur_y = ry + frame_h + BAND_GAP
        cloud_right = max(cloud_right, inner_x + frame_w)

    # unconsumed global buckets -> a Global band at the bottom
    leftover = [b for b in globals_s3 if _uid(b) not in consumed]
    if leftover:
        cols_n = min(SUBNET_COLS, len(leftover))
        rows_n = (len(leftover) + cols_n - 1) // cols_n
        gw = cols_n * NODE_W + 2 * PAD
        gh = rows_n * NODE_H + HEADER + PAD // 2
        gy = cur_y
        scene["groups"].append(
            {"kind": "region", "x": inner_x, "y": gy, "w": gw, "h": gh,
             "label": "Global · S3"})
        for i, b in enumerate(leftover):
            put(b, inner_x + PAD + (i % cols_n) * NODE_W + (NODE_W - ICON) // 2,
                gy + HEADER + (i // cols_n) * NODE_H)
        cur_y = gy + gh + BAND_GAP
        cloud_right = max(cloud_right, inner_x + gw)

    cloud_w = cloud_right - cloud_x + PAD
    cloud_h = cur_y - cloud_y - BAND_GAP + PAD
    scene["groups"].append(
        {"kind": "cloud", "x": cloud_x, "y": cloud_y, "w": cloud_w, "h": cloud_h,
         "label": f'AWS Cloud · account {graph.get("account", "")}'})
    # frames render outermost-first so inner frames sit on top
    order = {"cloud": 0, "region": 1, "vpc": 2, "public": 3, "private": 3}
    scene["groups"].sort(key=lambda g: order.get(g["kind"], 9))

    # VPC-level edges (ELB->EC2, IGW entry, user-data refs) aren't part of
    # the flow layout — add any remaining edge whose ends are both placed
    have = {(e["from"], e["to"]) for e in scene["edges"]}
    scene["edges"] += [e for e in edges
                       if (e["from"], e["to"]) not in have
                       and e["from"] in placed and e["to"] in placed]
    scene["edges"] = [e for e in scene["edges"]
                      if e["from"] in placed and e["to"] in placed]
    _route_edges(scene, placed)

    # ----- cost overlay note -----
    cost = graph.get("cost", {})
    if cost and (options or {}).get("cost", True):
        top = sorted(cost.items(), key=lambda kv: -kv[1])[:8]
        lines = "\n".join(f"{k}: ${v:.2f}" for k, v in top)
        scene["note"] = {"label": f"Cost (30d) — top services\n{lines}",
                         "x": cloud_x + cloud_w + BAND_GAP, "y": cloud_y,
                         "w": 300, "h": 44 + 18 * len(top)}
        scene["w"] = scene["note"]["x"] + 300 + 60
    else:
        scene["w"] = cloud_x + cloud_w + 60

    for text in graph.get("notes", []) or []:
        scene.setdefault("annotations", []).append(text)

    scene["h"] = cloud_y + cloud_h + 60 + 30 * len(scene.get("annotations", []))
    return scene


def _route_edges(scene: dict, placed: dict) -> None:
    """Curved connectivity routing: every edge is a cubic bezier
    (`points = [p0, c1, c2, p1]`, `curve = True`) anchored to the facing
    borders of the two icons. Edges sharing a source or target fan out with
    distinct bows, so parallel connections never lie on top of each other —
    replacing the old straight/orthogonal channel logic that stacked
    overlapping segments."""
    edges = scene["edges"]
    by_src, by_dst = defaultdict(list), defaultdict(list)
    for e in edges:
        by_src[e["from"]].append(e)
        by_dst[e["to"]].append(e)

    idx = {}   # id(edge) -> (src_i, src_n, dst_i, dst_n)
    for group, other in ((by_src, "to"), (by_dst, "from")):
        for es in group.values():
            es.sort(key=lambda e, k=other: (placed[e[k]]["_y"],
                                            placed[e[k]]["_x"]))
            for i, e in enumerate(es):
                si, sn, di, dn = idx.get(id(e), (0, 1, 0, 1))
                if other == "to":
                    idx[id(e)] = (i, len(es), di, dn)
                else:
                    idx[id(e)] = (si, sn, i, len(es))

    for e in edges:
        a, b = placed[e["from"]], placed[e["to"]]
        ax, ay = a["_x"] + ICON / 2, a["_y"] + ICON / 2
        bx, by = b["_x"] + ICON / 2, b["_y"] + ICON / 2
        dx, dy = bx - ax, by - ay
        if abs(dx) >= abs(dy):    # horizontal-dominant: leave/enter side faces
            p0 = (a["_x"] + ICON if dx >= 0 else a["_x"], ay)
            p1 = (b["_x"] if dx >= 0 else b["_x"] + ICON, by)
        else:                     # vertical-dominant: leave/enter top/bottom
            p0 = (ax, a["_y"] + ICON if dy >= 0 else a["_y"])
            p1 = (bx, b["_y"] if dy >= 0 else b["_y"] + ICON)
        vx, vy = p1[0] - p0[0], p1[1] - p0[1]
        dist = math.hypot(vx, vy) or 1.0
        nx, ny = -vy / dist, vx / dist            # unit normal (bow direction)
        si, sn, di, dn = idx[id(e)]
        spread = 26 + dist * 0.04                 # fan lanes widen with length
        off = spread * ((si - (sn - 1) / 2) + (di - (dn - 1) / 2))
        if off == 0:                              # lone edge: gentle arc
            off = min(16.0, dist * 0.05)
        c1 = (p0[0] + vx * 0.35 + nx * off, p0[1] + vy * 0.35 + ny * off)
        c2 = (p0[0] + vx * 0.65 + nx * off, p0[1] + vy * 0.65 + ny * off)
        e["points"] = [p0, c1, c2, p1]
        e["curve"] = True


def _bezier_mid(pts) -> tuple[float, float]:
    """Point at t=0.5 on a cubic bezier [p0, c1, c2, p1]."""
    (x0, y0), (x1, y1), (x2, y2), (x3, y3) = pts
    return ((x0 + 3 * x1 + 3 * x2 + x3) / 8, (y0 + 3 * y1 + 3 * y2 + y3) / 8)


# ---------- emitters (scene -> draw.io XML / SVG) — pure ----------

def _cell_id(node_id: str) -> str:
    return "nd-" + re.sub(r"[^A-Za-z0-9_.-]", "_", str(node_id))


def scene_to_drawio(scene: dict) -> str:
    cells: list[str] = []
    seq = [100]

    def next_id() -> str:
        seq[0] += 1
        return f"g{seq[0]}"

    def vertex(cid, label, x, y, w, h, style):
        cells.append(
            f'<mxCell id="{cid}" value="{sx.escape(label)}" style="{style}" '
            f'vertex="1" parent="1"><mxGeometry x="{int(x)}" y="{int(y)}" '
            f'width="{int(w)}" height="{int(h)}" as="geometry"/></mxCell>')

    for g in scene["groups"]:
        gr_icon, stroke, fill, dashed = GROUP_STYLE[g["kind"]]
        if gr_icon:
            style = (f"points=[[0,0],[0.25,0],[0.5,0],[0.75,0],[1,0],[1,0.25],"
                     f"[1,0.5],[1,0.75],[1,1],[0.75,1],[0.5,1],[0.25,1],[0,1],"
                     f"[0,0.75],[0,0.5],[0,0.25]];outlineConnect=0;gradientColor=none;"
                     f"html=1;whiteSpace=wrap;fontSize=14;fontStyle=1;container=0;"
                     f"pointerEvents=0;collapsible=0;recursiveResize=0;"
                     f"shape=mxgraph.aws4.group;grIcon={gr_icon};grStroke=1;"
                     f"verticalAlign=top;align=left;spacingLeft=40;spacingTop=4;"
                     f"fontColor={stroke};strokeColor={stroke};fillColor={fill};"
                     f"dashed={dashed};")
        else:
            style = (f"rounded=0;whiteSpace=wrap;html=1;fontSize=13;fontStyle=1;"
                     f"verticalAlign=top;align=left;spacing=10;container=0;"
                     f"pointerEvents=0;fontColor={stroke};strokeColor={stroke};"
                     f"fillColor={fill};dashed={dashed};")
        vertex(next_id(), g["label"], g["x"], g["y"], g["w"], g["h"], style)

    for n in scene["nodes"]:
        res, fill, _glyph, _pretty = type_style(n["type"])
        label = n["label"]
        if n.get("sub"):
            label += f"\n{n['sub']}"
        style = (f"sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;"
                 f"fillColor={fill};strokeColor=none;dashed=0;"
                 f"verticalLabelPosition=bottom;verticalAlign=top;align=center;"
                 f"html=1;fontSize=12;fontStyle=0;aspect=fixed;"
                 f"shape=mxgraph.aws4.resourceIcon;resIcon={res};")
        vertex(_cell_id(n.get("uid") or _uid(n)), label, n["_x"], n["_y"],
               ICON, ICON, style)

    for e in scene["edges"]:
        style = ("edgeStyle=none;curved=1;rounded=0;html=1;"
                 "strokeColor=#545B64;strokeWidth=1.6;"
                 "fontSize=11;fontColor=#545B64;")
        # curved edges pass one on-curve waypoint (the bezier midpoint) so
        # draw.io bows the spline the same way the SVG preview does
        raw = e.get("points") or []
        pts = ([_bezier_mid(raw)] if e.get("curve") and len(raw) == 4
               else raw[1:-1])
        waypoints = ("<Array as=\"points\">"
                     + "".join(f'<mxPoint x="{int(px)}" y="{int(py)}"/>'
                               for px, py in pts)
                     + "</Array>") if pts else ""
        cells.append(
            f'<mxCell id="{next_id()}" value="{sx.escape(e.get("label", ""))}" '
            f'style="{style}" edge="1" parent="1" '
            f'source="{_cell_id(e["from"])}" target="{_cell_id(e["to"])}">'
            f'<mxGeometry relative="1" as="geometry">{waypoints}</mxGeometry>'
            f'</mxCell>')

    for n in scene["nodes"]:
        badge = n.get("badge")
        if not badge:
            continue
        colour = SEV_COLOUR.get(badge.get("sev", "MEDIUM"), "#FF9900")
        style = (f"ellipse;fillColor={colour};strokeColor=#FFFFFF;strokeWidth=2;"
                 f"fontColor=#FFFFFF;fontSize=11;fontStyle=1;html=1;")
        cells.append(
            f'<mxCell id="{next_id()}" value="{badge.get("count", 1)}" '
            f'style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{int(n["_x"] + ICON - 12)}" y="{int(n["_y"] - 12)}" '
            f'width="24" height="24" as="geometry"/></mxCell>')

    note = scene.get("note")
    if note:
        style = ("rounded=1;whiteSpace=wrap;html=1;fillColor=#F7F7F7;"
                 "strokeColor=#545B64;align=left;verticalAlign=top;spacing=10;"
                 "fontSize=12;")
        vertex(next_id(), note["label"], note["x"], note["y"],
               note["w"], note["h"], style)

    for i, text in enumerate(scene.get("annotations", [])):
        style = ("text;html=1;align=left;verticalAlign=top;fontSize=12;"
                 "fontColor=#545B64;")
        vertex(next_id(), f"• {text}", 60,
               scene["h"] - 40 - 26 * (len(scene.get("annotations", [])) - i),
               scene["w"] - 120, 22, style)

    body = "".join(cells)
    return (
        '<mxfile host="clearsky">'
        '<diagram id="arch" name="Architecture">'
        f'<mxGraphModel dx="1400" dy="900" grid="0" gridSize="10" guides="1" '
        f'tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" '
        f'pageWidth="{int(scene["w"])}" pageHeight="{int(scene["h"])}" '
        f'background="#FFFFFF" math="0" shadow="0"><root>'
        '<mxCell id="0"/><mxCell id="1" parent="0"/>'
        f'{body}</root></mxGraphModel></diagram></mxfile>'
    )


# White-on-colour vector glyphs in a 48x48 box, modelled on the official
# AWS architecture icon silhouettes (self-contained — no external assets).
ICON_GLYPH = {
    "lambda": ['<path d="M12 8h9l13.5 28.5 5-10.5h6.5v3.5L38 43h-7L21.5 22 13 40H7l12-25-5-10.5z"/>'],
    "s3": ['<path d="M9 13c0-3.9 6.7-7 15-7s15 3.1 15 7l-3.4 24.5c-.4 3.1-5.4 5.5-11.6 5.5s-11.2-2.4-11.6-5.5z"/>',
           '<ellipse cx="24" cy="13" rx="15" ry="7" fill="none" stroke-width="2.4" class="ic-cut"/>'],
    "dynamodb": ['<path d="M10 11c0-3.3 6.3-6 14-6s14 2.7 14 6v26c0 3.3-6.3 6-14 6s-14-2.7-14-6z"/>',
                 '<path d="M10 19c3 2.5 8 4 14 4s11-1.5 14-4M10 29c3 2.5 8 4 14 4s11-1.5 14-4" fill="none" stroke-width="2.4" class="ic-cut"/>'],
    "rds": ['<path d="M10 11c0-3.3 6.3-6 14-6s14 2.7 14 6v26c0 3.3-6.3 6-14 6s-14-2.7-14-6z"/>',
            '<path d="M10 13c3 2.7 8 4.2 14 4.2S35 15.7 38 13" fill="none" stroke-width="2.4" class="ic-cut"/>'],
    "apigw": ['<path d="M15 10 5 24l10 14h6L11 24 21 10zM33 10l10 14-10 14h-6l10-14L27 10z"/>',
              '<rect x="21.5" y="21" width="5" height="6" rx="1"/>'],
    "ec2": ['<rect x="12" y="12" width="24" height="24" rx="2" fill="none" stroke-width="2.6" class="ic-stroke"/>',
            '<rect x="18" y="18" width="12" height="12" rx="1"/>',
            '<path d="M17 5v5M24 5v5M31 5v5M17 38v5M24 38v5M31 38v5M5 17h5M5 24h5M5 31h5M38 17h5M38 24h5M38 31h5" stroke-width="2.6" class="ic-stroke"/>'],
    "elb": ['<circle cx="12" cy="24" r="7"/>',
            '<circle cx="38" cy="10" r="5"/><circle cx="38" cy="24" r="5"/><circle cx="38" cy="38" r="5"/>',
            '<path d="M18 21 33 11M19 24h14M18 27l15 10" fill="none" stroke-width="2.4" class="ic-stroke"/>'],
    "nat": ['<path d="M6 20h22v-6l14 10-14 10v-6H6z"/>',
            '<path d="M6 12v24" stroke-width="3" class="ic-stroke"/>'],
    "igw": ['<circle cx="24" cy="24" r="12" fill="none" stroke-width="2.6" class="ic-stroke"/>',
            '<path d="M4 24h8M36 24h8" stroke-width="2.6" class="ic-stroke"/>',
            '<path d="M14 10l4 5-4 5zM34 28l-4 5 4 5z"/>',
            '<path d="M24 12v24M14 24h20" fill="none" stroke-width="2" class="ic-stroke"/>'],
    "users": ['<circle cx="17" cy="16" r="7"/>',
              '<path d="M5 40c0-8 5.4-13 12-13s12 5 12 13z"/>',
              '<circle cx="33" cy="14" r="5.4"/>',
              '<path d="M31 25.5c6.5-1.5 12 3.5 12 11.5h-9.5c-.3-4.6-1.1-8.6-2.5-11.5z"/>'],
}


def _icon_svg(node_type: str, fill: str, x: float, y: float) -> str:
    glyph = ICON_GLYPH.get(node_type)
    if not glyph:
        # no hand-drawn vector for this type: show its short label so any
        # service (including ones the AI adds) is still legible in the preview
        text = sx.escape(str(type_style(node_type)[2]))
        return (f'<g transform="translate({x:.0f},{y:.0f})">'
                f'<rect width="{ICON}" height="{ICON}" rx="8" fill="{fill}"/>'
                f'<text x="{ICON / 2:.0f}" y="{ICON / 2 + 6:.0f}" font-size="20" '
                f'font-weight="700" fill="#FFFFFF" text-anchor="middle">'
                f'{text}</text></g>')
    body = "".join(glyph)
    body = (body.replace('class="ic-stroke"', 'stroke="#FFFFFF"')
                .replace('class="ic-cut"', f'stroke="{fill}"'))
    scale = ICON / 48
    return (f'<g transform="translate({x:.0f},{y:.0f})">'
            f'<rect width="{ICON}" height="{ICON}" rx="8" fill="{fill}"/>'
            f'<g transform="scale({scale:.3f})" fill="#FFFFFF" '
            f'stroke="none" stroke-linecap="round">{body}</g></g>')


def scene_to_svg(scene: dict) -> str:
    """Self-contained SVG preview of the same scene (no external assets)."""
    w, h = int(scene["w"]), int(scene["h"])
    e = sx.escape
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
        f'font-family="Helvetica,Arial,sans-serif">',
        '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0,0L10,5L0,10z" fill="#545B64"/></marker></defs>',
        f'<rect width="{w}" height="{h}" fill="#FFFFFF"/>',
    ]

    for g in scene["groups"]:
        _icon, stroke, fill, dashed = GROUP_STYLE[g["kind"]]
        dash = ' stroke-dasharray="8 5"' if dashed else ""
        fill_attr = "none" if fill == "none" else fill
        parts.append(
            f'<rect x="{g["x"]}" y="{g["y"]}" width="{g["w"]}" height="{g["h"]}" '
            f'fill="{fill_attr}" stroke="{stroke}" stroke-width="1.6"{dash} rx="4"/>')
        parts.append(
            f'<text x="{g["x"] + 14}" y="{g["y"] + 26}" font-size="15" '
            f'font-weight="bold" fill="{stroke}">{e(g["label"])}</text>')

    # curved connectivity edges (cubic beziers from the router)
    for edge in scene["edges"]:
        pts = edge.get("points") or []
        if len(pts) < 2:
            continue
        if edge.get("curve") and len(pts) == 4:
            (x0, y0), (x1, y1), (x2, y2), (x3, y3) = pts
            d = (f"M{x0:.0f},{y0:.0f} C{x1:.0f},{y1:.0f} "
                 f"{x2:.0f},{y2:.0f} {x3:.0f},{y3:.0f}")
            lx, ly = _bezier_mid(pts)
        else:
            d = f"M{pts[0][0]:.0f},{pts[0][1]:.0f}" + "".join(
                f" L{px:.0f},{py:.0f}" for px, py in pts[1:])
            lx = (pts[0][0] + pts[1][0]) / 2
            ly = (pts[0][1] + pts[1][1]) / 2
        parts.append(
            f'<path d="{d}" fill="none" stroke="#545B64" stroke-width="1.8" '
            f'stroke-linejoin="round" marker-end="url(#arr)"/>')
        if edge.get("label"):
            parts.append(
                f'<text x="{lx:.0f}" y="{ly - 6:.0f}" font-size="11" '
                f'fill="#545B64" text-anchor="middle">{e(edge["label"])}</text>')

    for n in scene["nodes"]:
        _res, fill, _glyph, _pretty = type_style(n["type"])
        x, y = n["_x"], n["_y"]
        parts.append(_icon_svg(n["type"], fill, x, y))
        badge = n.get("badge")
        if badge:
            colour = SEV_COLOUR.get(badge.get("sev", "MEDIUM"), "#FF9900")
            parts.append(
                f'<circle cx="{x + ICON:.0f}" cy="{y:.0f}" r="12" fill="{colour}" '
                f'stroke="#FFFFFF" stroke-width="2"/>'
                f'<text x="{x + ICON:.0f}" y="{y + 4:.0f}" font-size="12" '
                f'font-weight="bold" fill="#FFFFFF" text-anchor="middle">'
                f'{badge.get("count", 1)}</text>')
        label = str(n["label"])
        if len(label) > 26:
            label = label[:24] + "…"
        parts.append(
            f'<text x="{x + ICON / 2:.0f}" y="{y + ICON + 18}" font-size="12" '
            f'fill="#232F3E" text-anchor="middle">{e(label)}</text>')
        if n.get("sub"):
            parts.append(
                f'<text x="{x + ICON / 2:.0f}" y="{y + ICON + 34}" font-size="11" '
                f'fill="#687078" text-anchor="middle">{e(str(n["sub"]))}</text>')

    note = scene.get("note")
    if note:
        parts.append(
            f'<rect x="{note["x"]}" y="{note["y"]}" width="{note["w"]}" '
            f'height="{note["h"]}" fill="#F7F7F7" stroke="#545B64" rx="6"/>')
        for i, line in enumerate(note["label"].split("\n")):
            parts.append(
                f'<text x="{note["x"] + 12}" y="{note["y"] + 24 + i * 18}" '
                f'font-size="12" fill="#232F3E">{e(line)}</text>')

    for i, text in enumerate(scene.get("annotations", [])):
        parts.append(
            f'<text x="60" y="{h - 20 - 26 * i}" font-size="13" '
            f'fill="#545B64">• {e(text)}</text>')

    parts.append("</svg>")
    return "".join(parts)


def build_drawio(graph: dict, options: dict | None = None) -> str:
    return scene_to_drawio(layout(graph, options))


def build_svg(graph: dict, options: dict | None = None) -> str:
    return scene_to_svg(layout(graph, options))


# ---------- structured edit ops (used by the chat agent) — pure ----------

EDITABLE_TYPES = set(TYPE_STYLE) - {"users", "igw", "nat", "generic"}
REGION_LISTS = FLOW_LISTS


def _iter_nodes(graph):
    """Yields (container_list, node) for every node in the graph."""
    for rg in graph.get("regions", []):
        for key in REGION_LISTS:
            for n in rg.get(key, []):
                yield rg[key], n
        for vpc in rg.get("vpcs", []):
            for coll in (vpc.get("nats", []), vpc.get("lbs", []), vpc.get("rds", [])):
                for n in coll:
                    yield coll, n
            for sn in vpc.get("subnets", []):
                for n in sn.get("resources", []):
                    yield sn["resources"], n
    for n in graph.get("global", {}).get("s3", []):
        yield graph["global"]["s3"], n


def _find_node(graph, ref):
    """Locate a node by uid ('type:id') or, unambiguously, by bare id."""
    ref = str(ref)
    by_id = None
    for coll, n in _iter_nodes(graph):
        if _uid(n) == ref:
            return coll, n
        if n.get("id") == ref:
            by_id = (coll, n)
    return by_id if by_id else (None, None)


def apply_ops(graph: dict, ops: list[dict]) -> list[str]:
    """Apply structured edit ops to the graph in place. Returns a log line
    per op (applied or the reason it was rejected). Never raises."""
    log = []
    graph.setdefault("edges", [])
    graph.setdefault("notes", [])
    for op in ops if isinstance(ops, list) else []:
        try:
            log.append(_apply_one(graph, op))
        except Exception as err:  # noqa: BLE001 - log goes back to the model
            log.append(f"error on {op.get('op', '?')}: {err}")
    return log


def _apply_one(graph: dict, op: dict) -> str:
    kind = op.get("op", "")

    if kind == "add_node":
        ntype, nid = op.get("type", ""), str(op.get("id", "")).strip()
        if ntype not in EDITABLE_TYPES:
            return f"rejected add_node: type must be one of {sorted(EDITABLE_TYPES)}"
        if not nid:
            return "rejected add_node: id required"
        if _find_node(graph, nid)[1]:
            return f"rejected add_node: id '{nid}' already exists"
        node = {"type": ntype, "id": nid,
                "label": op.get("label") or nid, "sub": op.get("sub", "")}
        if ntype == "s3":
            graph.setdefault("global", {}).setdefault("s3", []).append(node)
        else:
            regions = graph.get("regions", [])
            rg = next((r for r in regions
                       if r["region"] == op.get("region")), regions[0] if regions else None)
            if rg is None:
                return "rejected add_node: graph has no regions"
            key = ntype if ntype in FLOW_LISTS else "extras"
            rg.setdefault(key, []).append(node)
        return f"added {ntype} '{nid}'"

    if kind == "remove_node":
        nid = str(op.get("id", ""))
        coll, node = _find_node(graph, nid)
        if not node:
            return f"rejected remove_node: '{nid}' not found"
        uid = _uid(node)
        coll.remove(node)
        graph["edges"] = [e for e in graph["edges"]
                          if e["from"] != uid and e["to"] != uid]
        return f"removed '{nid}' (and its edges)"

    if kind == "rename":
        nid = str(op.get("id", ""))
        _, node = _find_node(graph, nid)
        if not node:
            return f"rejected rename: '{nid}' not found"
        node["label"] = op.get("label") or node["label"]
        if "sub" in op:
            node["sub"] = op["sub"]
        return f"renamed '{nid}' to '{node['label']}'"

    if kind == "add_edge":
        nodes = []
        for ref in (op.get("from", ""), op.get("to", "")):
            _, node = _find_node(graph, str(ref))
            if not node:
                return f"rejected add_edge: '{ref}' not found"
            nodes.append(node)
        src, dst = _uid(nodes[0]), _uid(nodes[1])
        if any(e["from"] == src and e["to"] == dst for e in graph["edges"]):
            return f"edge {src} -> {dst} already exists"
        graph["edges"].append({"from": src, "to": dst,
                               "label": op.get("label", "")})
        return f"added edge {src} -> {dst}"

    if kind == "remove_edge":
        _, sn = _find_node(graph, str(op.get("from", "")))
        _, dn = _find_node(graph, str(op.get("to", "")))
        src = _uid(sn) if sn else str(op.get("from", ""))
        dst = _uid(dn) if dn else str(op.get("to", ""))
        before = len(graph["edges"])
        graph["edges"] = [e for e in graph["edges"]
                          if not (e["from"] == src and e["to"] == dst)]
        return (f"removed edge {src} -> {dst}" if len(graph["edges"]) < before
                else f"rejected remove_edge: {src} -> {dst} not found")

    if kind == "add_note":
        text = str(op.get("text", "")).strip()
        if not text:
            return "rejected add_note: text required"
        graph["notes"].append(text[:200])
        return "added note"

    if kind == "remove_note":
        idx = int(op.get("index", -1))
        if 0 <= idx < len(graph["notes"]):
            graph["notes"].pop(idx)
            return f"removed note {idx}"
        return f"rejected remove_note: index {idx} out of range"

    return f"rejected: unknown op '{kind}'"


_SEV_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def attach_findings(graph: dict, findings: list[dict]) -> int:
    """Badge diagram nodes with open findings (matched on resource_id).
    Returns how many nodes got a badge. Pure."""
    by_resource: dict[str, list[str]] = {}
    for f in findings:
        rid = str(f.get("resource_id") or "")
        if rid:
            by_resource.setdefault(rid, []).append(f.get("severity", "LOW"))
    hits = 0
    for _, node in _iter_nodes(graph):
        sevs = by_resource.get(str(node.get("id")))
        if sevs:
            node["badge"] = {
                "sev": min(sevs, key=lambda s: _SEV_RANK.get(s, 3)),
                "count": len(sevs),
            }
            hits += 1
    return hits


def apply_layout_plan(graph: dict, plan: dict) -> list[str]:
    """Apply an AI layout plan to the graph in place. The model proposes only
    high-level structure — column per node, redundant edges to drop, edge
    labels, grouping notes — and the deterministic engine renders it, so the
    result is always valid. Returns a short log. Never raises."""
    log: list[str] = []
    if not isinstance(plan, dict):
        return ["ignored: plan was not an object"]

    known = {_uid(n) for _, n in _iter_nodes(graph)}
    layers = plan.get("layers") or {}
    clean = {}
    for uid, col in layers.items():
        try:
            c = int(col)
        except (TypeError, ValueError):
            continue
        if uid in known and 0 <= c <= 12:
            clean[uid] = c
    if clean:
        graph.setdefault("layout_hints", {})["layers"] = clean
        log.append(f"pinned {len(clean)} nodes to AI layers")

    labels = plan.get("edge_labels") or {}
    if labels:
        n = 0
        for e in graph.get("edges", []):
            key = f'{e["from"]}->{e["to"]}'
            if key in labels and not e.get("label"):
                e["label"] = str(labels[key])[:40]
                n += 1
        if n:
            log.append(f"labelled {n} edges")

    drop = plan.get("drop_edges") or []
    drop_set = {(d[0], d[1]) for d in drop if isinstance(d, (list, tuple)) and len(d) == 2}
    if drop_set:
        before = len(graph.get("edges", []))
        graph["edges"] = [e for e in graph.get("edges", [])
                          if (e["from"], e["to"]) not in drop_set]
        removed = before - len(graph["edges"])
        if removed:
            log.append(f"dropped {removed} redundant edges")

    for note in (plan.get("notes") or [])[:4]:
        text = str(note).strip()[:200]
        if text:
            graph.setdefault("notes", []).append(text)
            log.append("added grouping note")

    return log or ["no changes"]


def filter_global(graph: dict, mode: str) -> None:
    """Trim global services for single-region sheets. Modes:
    'all' (default, keep), 'connected' (only buckets wired to shown
    resources), 'none' (drop the global lane). Pure."""
    buckets = graph.get("global", {}).get("s3", [])
    if mode == "none":
        graph["global"]["s3"] = []
    elif mode == "connected" and buckets:
        wired = ({e["from"] for e in graph.get("edges", [])}
                 | {e["to"] for e in graph.get("edges", [])})
        graph["global"]["s3"] = [b for b in buckets if _uid(b) in wired]


# ---------- job persistence (shared with the chat agent) ----------

def job_key(job_id: str) -> str:
    return f"architecture/jobs/{job_id}.json"


def render_job(graph: dict, job_id: str, revision: int,
               summary: str | None, meta: dict) -> dict:
    scene = layout(graph)
    return {"status": "ready", "job_id": job_id, "revision": revision,
            "graph": graph, "drawio": scene_to_drawio(scene),
            "svg": scene_to_svg(scene), "summary": summary, "meta": meta}


def load_job(s3, bucket: str, job_id: str) -> dict:
    body = s3.get_object(Bucket=bucket, Key=job_key(job_id))["Body"].read()
    return json.loads(body)


def save_job(s3, bucket: str, job_id: str, payload: dict) -> None:
    s3.put_object(Bucket=bucket, Key=job_key(job_id),
                  Body=json.dumps(payload, default=str).encode(),
                  ContentType="application/json")


# ---------- optional AI summary ----------

def summarize(graph: dict) -> str | None:
    try:
        from clearsky.chat import load_provider_config, simple_completion
        config = load_provider_config()
    except Exception:  # noqa: BLE001 - no key / import issue -> skip
        return None
    counts = {
        "vpcs": sum(len(r.get("vpcs", [])) for r in graph["regions"]),
        "instances": sum(len(s.get("resources", []))
                         for r in graph["regions"] for v in r.get("vpcs", [])
                         for s in v.get("subnets", [])),
        "lambda": sum(len(r.get("lambda", [])) for r in graph["regions"]),
        "dynamodb": sum(len(r.get("dynamodb", [])) for r in graph["regions"]),
        "s3": len(graph.get("global", {}).get("s3", [])),
    }
    prompt = (
        "You are a cloud architect. Given this AWS account resource inventory "
        f"(JSON), write ~6 sentences describing the architecture, likely data "
        "flow, and any structural risks or grouping suggestions. Plain text.\n\n"
        + json.dumps({"counts": counts, "regions":
                      [{"region": r["region"],
                        "vpcs": [{"cidr": v["cidr"],
                                  "subnets": len(v["subnets"])}
                                 for v in r.get("vpcs", [])]}
                       for r in graph["regions"]]}, default=str)
    )
    try:
        return simple_completion(prompt, config)
    except Exception:  # noqa: BLE001
        logger.exception("architecture summary failed")
        return None


# ---------- lambda handler (async worker) ----------

def lambda_handler(event, context):
    bucket = os.environ["REPORTS_BUCKET"]
    s3 = boto3.client("s3")
    job_id = event["job_id"]

    try:
        from clearsky.regions import resolve_regions
        home_session = boto3.Session()
        scanned = resolve_regions(home_session, os.environ.get("SCAN_REGIONS", ""),
                                  bucket=bucket)
        # member-account diagram: discover through the onboarded role's
        # assumed session; discover() stamps graph["account"] from STS
        account = str(event.get("account") or "").strip()
        if account:
            from clearsky import accounts as accounts_mod
            session = accounts_mod.member_session(account)
        else:
            session = home_session
        # any enabled region on the *target* account is selectable
        try:
            enabled = {r["RegionName"] for r in
                       session.client("ec2", region_name="us-east-1")
                       .describe_regions()["Regions"]}
        except Exception:  # noqa: BLE001
            enabled = set(scanned)
        regions = ([r for r in event.get("regions") or scanned if r in enabled]
                   or scanned[:1])
        include = set(event.get("include") or list(GROUPS) + ["cost"])
        graph = discover(session, regions, include)
        filter_global(graph, event.get("global_mode") or "all")
        if event.get("optimize"):
            try:
                from clearsky.chat import ai_layout_plan
                plan = ai_layout_plan(graph)
                logger.info("ai layout plan: %s", apply_layout_plan(graph, plan))
            except Exception:  # noqa: BLE001 - optimization is best-effort
                logger.exception("ai layout optimization skipped")
        if event.get("overlay") and os.environ.get("FINDINGS_TABLE"):
            table = boto3.resource("dynamodb").Table(os.environ["FINDINGS_TABLE"])
            items, kwargs = [], {}
            while True:
                resp = table.scan(**kwargs)
                items += [i for i in resp.get("Items", [])
                          if i.get("status") != "resolved"]
                if "LastEvaluatedKey" not in resp:
                    break
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            attach_findings(graph, items)
        summary = summarize(graph) if event.get("ai") else None
        payload = render_job(graph, job_id, revision=0, summary=summary,
                             meta={"regions": regions, "include": sorted(include),
                                   "account": account or "home",
                                   "overlay": bool(event.get("overlay")),
                                   "optimized": bool(event.get("optimize")),
                                   "global_mode": event.get("global_mode") or "all"})
        save_job(s3, bucket, job_id, payload)
        return {"status": "ready"}
    except Exception as err:  # noqa: BLE001
        logger.exception("architecture generation failed")
        save_job(s3, bucket, job_id, {"status": "error", "error": str(err)})
        return {"status": "error"}
