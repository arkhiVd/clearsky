"""Pure tests for architecture discovery summarizers + draw.io builder.
No AWS: raw describe-shaped dicts in, graph/XML out."""

import xml.etree.ElementTree as ET

from clearsky import architecture as arch


def test_public_subnet_ids_classifies_by_route_table():
    route_tables = [
        {  # explicit public: routes 0.0.0.0/0 -> igw
            "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}],
            "Associations": [{"SubnetId": "subnet-pub", "Main": False}],
        },
        {  # explicit private: only local
            "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}],
            "Associations": [{"SubnetId": "subnet-priv", "Main": False}],
        },
        {  # main table, not public
            "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}],
            "Associations": [{"Main": True}],
        },
    ]
    public, explicit, main_public = arch.public_subnet_ids(route_tables, {"igw-1"})
    assert public == {"subnet-pub"}
    assert explicit == {"subnet-pub", "subnet-priv"}
    assert main_public is False


def test_build_vpcs_assembles_topology():
    vpcs = [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16",
             "Tags": [{"Key": "Name", "Value": "app"}]}]
    subnets = [
        {"SubnetId": "subnet-pub", "VpcId": "vpc-1", "AvailabilityZone": "us-east-1a",
         "CidrBlock": "10.0.1.0/24"},
        {"SubnetId": "subnet-priv", "VpcId": "vpc-1", "AvailabilityZone": "us-east-1b",
         "CidrBlock": "10.0.2.0/24"},
    ]
    route_tables = [
        {"Routes": [{"GatewayId": "igw-1", "DestinationCidrBlock": "0.0.0.0/0"}],
         "Associations": [{"SubnetId": "subnet-pub", "Main": False}]},
        {"Routes": [{"GatewayId": "local"}],
         "Associations": [{"SubnetId": "subnet-priv", "Main": False}]},
    ]
    igws = [{"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-1"}]}]
    nats = [{"NatGatewayId": "nat-1", "VpcId": "vpc-1", "State": "available"}]
    instances = [{"InstanceId": "i-1", "SubnetId": "subnet-pub",
                  "InstanceType": "t3.micro", "State": {"Name": "running"}, "Tags": []}]
    dbs = [{"DBInstanceIdentifier": "db-1", "Engine": "postgres",
            "DBSubnetGroup": {"VpcId": "vpc-1"}}]
    lbs = [{"LoadBalancerName": "alb-1", "VpcId": "vpc-1", "Type": "application"}]

    out = arch.build_vpcs(vpcs, subnets, route_tables, igws, nats, instances, dbs, lbs)
    assert len(out) == 1
    vpc = out[0]
    assert vpc["label"] == "app" and vpc["igw"] == "igw-1"
    assert [n["id"] for n in vpc["nats"]] == ["nat-1"]
    assert [n["id"] for n in vpc["rds"]] == ["db-1"]
    assert [n["id"] for n in vpc["lbs"]] == ["alb-1"]
    pub = next(s for s in vpc["subnets"] if s["id"] == "subnet-pub")
    priv = next(s for s in vpc["subnets"] if s["id"] == "subnet-priv")
    assert pub["public"] is True and priv["public"] is False
    assert [r["id"] for r in pub["resources"]] == ["i-1"]
    # public subnet sorts before private
    assert vpc["subnets"][0]["id"] == "subnet-pub"


def test_build_vpcs_skips_terminated_instances():
    instances = [{"InstanceId": "i-dead", "SubnetId": "subnet-x",
                  "State": {"Name": "terminated"}, "Tags": []}]
    out = arch.build_vpcs(
        [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}],
        [{"SubnetId": "subnet-x", "VpcId": "vpc-1", "AvailabilityZone": "a", "CidrBlock": "10.0.1.0/24"}],
        [], [], [], instances, [], [])
    assert out[0]["subnets"][0]["resources"] == []


def _sample_graph():
    return {
        "account": "123",
        "regions": [{
            "region": "us-east-1",
            "vpcs": arch.build_vpcs(
                [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}],
                [{"SubnetId": "subnet-1", "VpcId": "vpc-1",
                  "AvailabilityZone": "us-east-1a", "CidrBlock": "10.0.1.0/24"}],
                [], [{"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-1"}]}],
                [{"NatGatewayId": "nat-1", "VpcId": "vpc-1", "State": "available"}],
                [{"InstanceId": "i-1", "SubnetId": "subnet-1",
                  "InstanceType": "t3.micro", "State": {"Name": "running"}, "Tags": []}],
                [], []),
            "lambda": [{"type": "lambda", "id": "fn-1", "label": "fn-1", "sub": "python3.13"}],
            "apigw": [], "dynamodb": [{"type": "dynamodb", "id": "tbl", "label": "tbl"}],
        }],
        "global": {"s3": [{"type": "s3", "id": "b1", "label": "b1"}]},
        "cost": {"Amazon Simple Storage Service": 1.23},
    }


def test_build_drawio_is_wellformed_xml_with_nodes():
    xml = arch.build_drawio(_sample_graph(), {"cost": True})
    root = ET.fromstring(xml)  # raises on malformed
    assert root.tag == "mxfile"
    values = [c.get("value", "") for c in root.iter("mxCell")]
    joined = "\n".join(values)
    assert "VPC vpc-1" in joined
    assert "i-1" in joined            # ec2 instance icon
    assert "fn-1" in joined           # lambda icon
    assert "b1" in joined             # s3 global icon
    assert "Region · us-east-1" in joined
    assert "Cost (30d)" in joined     # cost overlay note


def test_build_drawio_escapes_labels():
    graph = {"account": "1", "regions": [], "global":
             {"s3": [{"type": "s3", "id": "b", "label": "a<b>&c"}]}, "cost": {}}
    xml = arch.build_drawio(graph)
    ET.fromstring(xml)  # would raise if '<' / '&' not escaped


def test_layout_skips_empty_vpcs_and_subnets():
    empty_vpc = arch.build_vpcs(
        [{"VpcId": "vpc-empty", "CidrBlock": "172.31.0.0/16"}],
        [{"SubnetId": "subnet-e", "VpcId": "vpc-empty",
          "AvailabilityZone": "us-east-1a", "CidrBlock": "172.31.0.0/20"}],
        [], [{"InternetGatewayId": "igw-e", "Attachments": [{"VpcId": "vpc-empty"}]}],
        [], [], [], [])
    graph = {"account": "1", "regions": [{
        "region": "us-east-1", "vpcs": empty_vpc,
        "lambda": [{"type": "lambda", "id": "fn", "label": "fn"}],
        "apigw": [], "dynamodb": []}], "global": {}, "cost": {}}
    scene = arch.layout(graph)
    kinds = [g["kind"] for g in scene["groups"]]
    assert "vpc" not in kinds and "public" not in kinds and "private" not in kinds
    assert any(n["id"] == "fn" for n in scene["nodes"])
    xml = arch.build_drawio(graph)
    assert "vpc-empty" not in xml


def test_infer_edges_from_env_and_integrations():
    graph = {
        "regions": [{
            "region": "us-east-1",
            "lambda": [{"type": "lambda", "id": "fn-a", "label": "fn-a",
                        "env": ["tbl-1", "bkt-1", "unrelated"]}],
            "apigw": [{"type": "apigw", "id": "api-1", "label": "api",
                       "targets": ["fn-a", "fn-missing"]}],
            "dynamodb": [{"type": "dynamodb", "id": "tbl-1", "label": "tbl-1"}],
        }],
        "global": {"s3": [{"type": "s3", "id": "bkt-1", "label": "bkt-1"}]},
    }
    edges = {(e["from"], e["to"]) for e in arch.infer_edges(graph)}
    assert edges == {("lambda:fn-a", "dynamodb:tbl-1"),
                     ("lambda:fn-a", "s3:bkt-1"),
                     ("apigw:api-1", "lambda:fn-a")}


def test_infer_edges_distinguishes_same_name_lambda_and_table():
    # a Lambda and a DynamoDB table can share a name; uid keeps them distinct
    graph = {
        "regions": [{
            "region": "us-east-1",
            "lambda": [{"type": "lambda", "id": "chat", "label": "chat",
                        "env": ["chat"]}],
            "apigw": [],
            "dynamodb": [{"type": "dynamodb", "id": "chat", "label": "chat"}],
        }],
        "global": {"s3": []},
    }
    edges = arch.infer_edges(graph)
    assert edges == [{"from": "lambda:chat", "to": "dynamodb:chat", "label": ""}]


def test_edges_and_users_actor_in_outputs():
    graph = {
        "account": "1",
        "regions": [{
            "region": "us-east-1",
            "lambda": [{"type": "lambda", "id": "fn-a", "label": "fn-a"}],
            "apigw": [{"type": "apigw", "id": "api-1", "label": "api"}],
            "dynamodb": [{"type": "dynamodb", "id": "tbl-1", "label": "tbl-1"}],
        }],
        "global": {}, "cost": {},
        "edges": [{"from": "lambda:fn-a", "to": "dynamodb:tbl-1", "label": ""}],
    }
    scene = arch.layout(graph)
    uids = {n["uid"] for n in scene["nodes"]}
    assert "users:__users__" in uids  # actor added because an API GW exists
    pairs = {(e["from"], e["to"]) for e in scene["edges"]}
    assert ("lambda:fn-a", "dynamodb:tbl-1") in pairs
    assert ("users:__users__", "apigw:api-1") in pairs
    xml = arch.build_drawio(graph)
    ET.fromstring(xml)
    assert 'edge="1"' in xml and 'source="nd-lambda_fn-a"' in xml
    svg = arch.build_svg(graph)
    assert svg.startswith("<svg") and "marker-end" in svg


def test_apply_ops_edit_cycle():
    graph = {
        "regions": [{"region": "us-east-1",
                     "lambda": [{"type": "lambda", "id": "fn-a", "label": "fn-a"}],
                     "apigw": [], "dynamodb": []}],
        "global": {"s3": []}, "edges": [], "notes": [],
    }
    log = arch.apply_ops(graph, [
        {"op": "add_node", "type": "dynamodb", "id": "tbl-x", "label": "orders"},
        {"op": "add_edge", "from": "lambda:fn-a", "to": "tbl-x", "label": "writes"},
        {"op": "rename", "id": "fn-a", "label": "order-worker"},
        {"op": "add_note", "text": "orders flow"},
        {"op": "add_edge", "from": "fn-a", "to": "nope"},      # rejected
        {"op": "add_node", "type": "users", "id": "u"},        # rejected type
    ])
    assert log[0].startswith("added") and log[1].startswith("added edge")
    assert log[2].startswith("renamed") and log[3] == "added note"
    assert log[4].startswith("rejected") and log[5].startswith("rejected")
    assert graph["regions"][0]["dynamodb"][0]["id"] == "tbl-x"
    # edges are stored by uid, resolved from either a bare id or a uid
    assert graph["edges"] == [{"from": "lambda:fn-a", "to": "dynamodb:tbl-x",
                               "label": "writes"}]
    assert graph["regions"][0]["lambda"][0]["label"] == "order-worker"

    log2 = arch.apply_ops(graph, [{"op": "remove_node", "id": "tbl-x"}])
    assert log2[0].startswith("removed")
    assert graph["edges"] == []  # dangling edge dropped with the node
    # graph still renders after edits
    ET.fromstring(arch.build_drawio(graph))


def test_svg_escapes_labels():
    graph = {"account": "1", "regions": [], "global":
             {"s3": [{"type": "s3", "id": "b", "label": "a<b>&c"}]}, "cost": {}}
    svg = arch.build_svg(graph)
    assert "a&lt;b&gt;&amp;c" in svg


def test_forward_edges_route_left_to_right_between_columns():
    # api -> fn -> table: each hop should exit right of source, enter left of
    # target, and the whole path stays inside the region frame (no corridor).
    graph = {
        "account": "1",
        "regions": [{
            "region": "us-east-1",
            "lambda": [{"type": "lambda", "id": "fn", "label": "fn"}],
            "apigw": [{"type": "apigw", "id": "api", "label": "api",
                       "targets": ["fn"]}],
            "dynamodb": [{"type": "dynamodb", "id": "t", "label": "t"}],
        }],
        "global": {"s3": []}, "cost": {},
    }
    graph["edges"] = arch.infer_edges(graph)
    scene = arch.layout(graph)
    placed = {n["uid"]: n for n in scene["nodes"]}
    frame = next(g for g in scene["groups"] if g["kind"] == "region")
    for e in scene["edges"]:
        a, b = placed[e["from"]], placed[e["to"]]
        pts = e["points"]
        # exits source's right face, enters target's left face
        assert pts[0][0] >= a["_x"] + arch.ICON - 1
        assert pts[-1][0] <= b["_x"] + 1
        # every waypoint stays within the region frame — nothing bundled out
        for x, _y in pts:
            assert frame["x"] - 1 <= x <= frame["x"] + frame["w"] + 1


def test_global_bucket_consumed_by_lambda_folds_into_flow():
    # a bucket referenced by a lambda is placed in the region flow (short
    # edge), not stranded in a separate Global band forcing a long arrow.
    graph = {
        "account": "1",
        "regions": [{
            "region": "us-east-1",
            "lambda": [{"type": "lambda", "id": "fn", "label": "fn",
                        "env": ["reports"]}],
            "apigw": [], "dynamodb": [],
        }],
        "global": {"s3": [{"type": "s3", "id": "reports", "label": "reports"},
                          {"type": "s3", "id": "unused", "label": "unused"}]},
        "cost": {},
    }
    graph["edges"] = arch.infer_edges(graph)
    scene = arch.layout(graph)
    labels = [g["label"] for g in scene["groups"]]
    # consumed bucket folded into region; only the unused one gets a Global band
    assert "Global · S3" in labels
    placed = {n["uid"]: n for n in scene["nodes"]}
    assert "s3:reports" in placed and "s3:unused" in placed
    # the lambda->reports edge is a single forward hop (2 or 4 points)
    e = next(e for e in scene["edges"] if e["to"] == "s3:reports")
    assert len(e["points"]) in (2, 4)


def test_attach_findings_badges_matching_nodes():
    graph = {"regions": [{"region": "r",
                          "lambda": [{"type": "lambda", "id": "fn", "label": "fn"}],
                          "apigw": [], "dynamodb": []}],
             "global": {"s3": []}}
    hits = arch.attach_findings(graph, [
        {"resource_id": "fn", "severity": "LOW"},
        {"resource_id": "fn", "severity": "HIGH"},
        {"resource_id": "other", "severity": "MEDIUM"},
    ])
    assert hits == 1
    badge = graph["regions"][0]["lambda"][0]["badge"]
    assert badge == {"sev": "HIGH", "count": 2}
    svg = arch.build_svg({**graph, "account": "1", "cost": {}, "edges": []})
    assert "circle" in svg and ">2</text>" in svg


def _wired_bucket_graph():
    return {
        "account": "1",
        "regions": [{
            "region": "us-east-1",
            "lambda": [{"type": "lambda", "id": "fn", "label": "fn"}],
            "apigw": [], "dynamodb": []}],
        "global": {"s3": [{"type": "s3", "id": "bkt", "label": "bkt"}]},
        "cost": {},
        "edges": [{"from": "lambda:fn", "to": "s3:bkt", "label": ""}],
    }


def test_filter_global_connected_and_none():
    g = _wired_bucket_graph()
    arch.filter_global(g, "connected")
    assert [b["id"] for b in g["global"]["s3"]] == ["bkt"]  # wired -> kept
    g2 = _wired_bucket_graph()
    g2["edges"] = []
    arch.filter_global(g2, "connected")
    assert g2["global"]["s3"] == []                          # unwired -> pruned
    g3 = _wired_bucket_graph()
    arch.filter_global(g3, "none")
    assert g3["global"]["s3"] == []


def test_infer_edges_event_driven_sns_sqs_and_mappings():
    graph = {
        "regions": [{
            "region": "us-east-1",
            "lambda": [
                {"type": "lambda", "id": "ingest", "label": "ingest",
                 "env": [], "event_sources": ["jobs-queue"]},
                {"type": "lambda", "id": "notify", "label": "notify", "env": []},
            ],
            "apigw": [],
            "dynamodb": [],
            "sns": [{"type": "sns", "id": "alerts", "label": "alerts",
                     "targets": ["notify", "jobs-queue"]}],
            "sqs": [{"type": "sqs", "id": "jobs-queue", "label": "jobs-queue"}],
        }],
        "global": {"s3": []},
    }
    edges = {(e["from"], e["to"]) for e in arch.infer_edges(graph)}
    assert ("sqs:jobs-queue", "lambda:ingest") in edges       # event source
    assert ("sns:alerts", "lambda:notify") in edges           # subscription
    assert ("sns:alerts", "sqs:jobs-queue") in edges          # fan-out to queue


def test_arn_resource_name_variants():
    assert arch._arn_resource_name(
        "arn:aws:sqs:us-east-1:1:jobs-queue") == "jobs-queue"
    assert arch._arn_resource_name(
        "arn:aws:lambda:us-east-1:1:function:notify") == "notify"
    assert arch._arn_resource_name(
        "arn:aws:kinesis:us-east-1:1:stream/events") == "events"
    assert arch._arn_resource_name("not-an-arn") == ""


def test_unknown_node_type_renders_with_fallback():
    # a service type we don't explicitly map must still render (generic box)
    graph = {"account": "1", "regions": [{
        "region": "us-east-1", "apigw": [], "lambda": [], "dynamodb": [],
        "extras": [{"type": "glue", "id": "etl", "label": "etl-job"}]}],
        "global": {}, "cost": {}}
    xml = arch.build_drawio(graph)
    ET.fromstring(xml)                      # valid despite unknown type
    assert "etl-job" in xml
    svg = arch.build_svg(graph)
    assert svg.startswith("<svg") and "etl-job" in svg


def test_same_tier_edges_do_not_deepen_column():
    # api Lambda invokes worker Lambda (same tier) and writes a table.
    # Both Lambdas must stay in one column; the table is one column right.
    graph = {
        "account": "1",
        "regions": [{
            "region": "us-east-1",
            "apigw": [{"type": "apigw", "id": "api", "label": "api", "targets": ["front"]}],
            "lambda": [
                {"type": "lambda", "id": "front", "label": "front",
                 "env": ["worker", "tbl"]},   # invokes worker, writes tbl
                {"type": "lambda", "id": "worker", "label": "worker", "env": ["tbl"]},
            ],
            "dynamodb": [{"type": "dynamodb", "id": "tbl", "label": "tbl"}],
        }],
        "global": {"s3": []}, "cost": {},
    }
    graph["edges"] = arch.infer_edges(graph)
    scene = arch.layout(graph)
    col = {n["uid"]: n["_col"] for n in scene["nodes"] if "_col" in n}
    assert col["lambda:front"] == col["lambda:worker"]      # same column
    assert col["dynamodb:tbl"] == col["lambda:front"] + 1   # data one right
    assert col["apigw:api"] == col["lambda:front"] - 1


def test_apply_layout_plan_pins_layers_and_drops_edges():
    graph = {
        "account": "1",
        "regions": [{
            "region": "us-east-1",
            "lambda": [{"type": "lambda", "id": "fn", "label": "fn"}],
            "apigw": [], "dynamodb": [{"type": "dynamodb", "id": "t", "label": "t"}],
        }],
        "global": {"s3": []}, "notes": [],
        "edges": [{"from": "lambda:fn", "to": "dynamodb:t", "label": ""},
                  {"from": "lambda:fn", "to": "dynamodb:t", "label": ""}],
    }
    log = arch.apply_layout_plan(graph, {
        "layers": {"lambda:fn": 2, "dynamodb:t": 3, "bogus:x": 9, "lambda:fn2": 99},
        "edge_labels": {"lambda:fn->dynamodb:t": "writes"},
        "drop_edges": [["lambda:fn", "dynamodb:t"]],
        "notes": ["backend tier"],
    })
    assert graph["layout_hints"]["layers"] == {"lambda:fn": 2, "dynamodb:t": 3}
    assert "backend tier" in graph["notes"]
    assert any("pinned" in m for m in log)
    # AI layers are honored by layout
    scene = arch.layout(graph)
    col = {n["uid"]: n["_col"] for n in scene["nodes"] if "_col" in n}
    assert col["dynamodb:t"] > col["lambda:fn"]


def test_apply_layout_plan_tolerates_junk():
    graph = {"regions": [], "global": {"s3": []}, "edges": []}
    assert arch.apply_layout_plan(graph, "not a dict")[0].startswith("ignored")
    assert arch.apply_layout_plan(graph, {}) == ["no changes"]


def test_infer_vpc_edges_recovers_lb_chain():
    # fe (public, world-open SG, user-data -> ALB dns) -> ALB -> app1
    # (target group) -> app2 (user-data has app2's private IP): the full
    # nginx microservice chain from control-plane facts alone.
    instances = [
        {"InstanceId": "i-fe", "State": {"Name": "running"}, "VpcId": "vpc-1",
         "PublicIpAddress": "44.0.0.1", "PrivateIpAddress": "172.31.0.10",
         "SecurityGroups": [{"GroupId": "sg-fe"}]},
        {"InstanceId": "i-app1", "State": {"Name": "running"}, "VpcId": "vpc-1",
         "PrivateIpAddress": "172.31.0.11",
         "SecurityGroups": [{"GroupId": "sg-app"}]},
        {"InstanceId": "i-app2", "State": {"Name": "running"}, "VpcId": "vpc-1",
         "PrivateIpAddress": "172.31.0.12",
         "SecurityGroups": [{"GroupId": "sg-app"}]},
    ]
    lbs = [{"LoadBalancerArn": "arn:lb/poc-alb", "LoadBalancerName": "poc-alb",
            "DNSName": "internal-poc-alb.elb.amazonaws.com",
            "Scheme": "internal", "VpcId": "vpc-1",
            "SecurityGroups": ["sg-alb"]}]
    tgs = [{"TargetGroupArn": "arn:tg/tg-8081",
            "LoadBalancerArns": ["arn:lb/poc-alb"]}]
    tg_health = {"arn:tg/tg-8081": [{"Target": {"Id": "i-app1"}}]}
    sgs = [{"GroupId": "sg-fe", "IpPermissions": [
                {"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
           {"GroupId": "sg-app", "IpPermissions": [
                {"IpRanges": [{"CidrIp": "172.31.0.0/16"}]}]},
           {"GroupId": "sg-alb", "IpPermissions": [
                {"IpRanges": [{"CidrIp": "172.31.0.0/16"}]}]}]
    user_data = {
        "i-fe": "proxy_pass http://internal-poc-alb.elb.amazonaws.com:8081;",
        "i-app1": "proxy_pass http://172.31.0.12:8082;",
        "i-app2": "",
    }
    edges = arch.infer_vpc_edges(instances, lbs, tgs, tg_health, sgs,
                                 {"vpc-1": "igw-1"}, user_data)
    pairs = {(e["from"], e["to"]) for e in edges}
    assert ("igw:igw-1", "ec2:i-fe") in pairs        # internet entry
    assert ("ec2:i-fe", "elb:poc-alb") in pairs      # user-data LB DNS ref
    assert ("elb:poc-alb", "ec2:i-app1") in pairs    # target-group target
    assert ("ec2:i-app1", "ec2:i-app2") in pairs     # user-data IP ref
    # partial-IP text must not match (172.31.0.1 is not 172.31.0.10/11/12)
    assert ("ec2:i-app1", "ec2:i-fe") not in pairs


def test_infer_vpc_edges_sg_reference():
    instances = [
        {"InstanceId": "i-a", "State": {"Name": "running"}, "VpcId": "v",
         "PrivateIpAddress": "10.0.0.1",
         "SecurityGroups": [{"GroupId": "sg-a"}]},
        {"InstanceId": "i-b", "State": {"Name": "running"}, "VpcId": "v",
         "PrivateIpAddress": "10.0.0.2",
         "SecurityGroups": [{"GroupId": "sg-b"}]},
    ]
    sgs = [{"GroupId": "sg-b", "IpPermissions": [
                {"UserIdGroupPairs": [{"GroupId": "sg-a"}]}]},
           {"GroupId": "sg-a", "IpPermissions": []}]
    edges = arch.infer_vpc_edges(instances, [], [], {}, sgs, {}, {})
    assert {(e["from"], e["to"]) for e in edges} == {("ec2:i-a", "ec2:i-b")}


def test_vpc_edges_render_as_curves_in_svg_and_drawio():
    graph = {
        "account": "1",
        "regions": [{
            "region": "us-east-1", "lambda": [], "apigw": [], "dynamodb": [],
            "vpcs": [{
                "id": "vpc-1", "cidr": "172.31.0.0/16", "label": "vpc-1",
                "igw": "igw-1", "nats": [],
                "lbs": [{"type": "elb", "id": "poc-alb", "label": "poc-alb",
                         "sub": "application"}],
                "rds": [],
                "subnets": [{"id": "s-1", "az": "us-east-1a",
                             "cidr": "172.31.0.0/20", "public": True,
                             "resources": [
                                 {"type": "ec2", "id": "i-fe", "label": "fe"},
                                 {"type": "ec2", "id": "i-app1", "label": "app1"},
                             ]}],
            }],
        }],
        "global": {"s3": []}, "cost": {},
        "edges": [
            {"from": "igw:igw-1", "to": "ec2:i-fe", "label": ""},
            {"from": "ec2:i-fe", "to": "elb:poc-alb", "label": ""},
            {"from": "elb:poc-alb", "to": "ec2:i-app1", "label": ""},
        ],
    }
    scene = arch.layout(graph)
    # every VPC edge survives into the scene and is a 4-point cubic bezier
    assert len(scene["edges"]) == 3
    for e in scene["edges"]:
        assert e.get("curve") and len(e["points"]) == 4
    svg = arch.scene_to_svg(scene)
    assert svg.count(" C") >= 3                      # curved path commands
    xml = arch.scene_to_drawio(scene)
    assert "curved=1" in xml
    ET.fromstring(xml)


def test_parallel_edges_fan_out_distinct_bows():
    # one API fanning into three lambdas: each curve must take a distinct
    # midpoint so the arrows never lie on top of each other
    graph = {
        "account": "1",
        "regions": [{
            "region": "us-east-1",
            "lambda": [{"type": "lambda", "id": f"fn{i}", "label": f"fn{i}"}
                       for i in range(3)],
            "apigw": [{"type": "apigw", "id": "api", "label": "api",
                       "targets": ["fn0", "fn1", "fn2"]}],
            "dynamodb": [],
        }],
        "global": {"s3": []}, "cost": {},
    }
    graph["edges"] = arch.infer_edges(graph)
    scene = arch.layout(graph)
    fan = [e for e in scene["edges"] if e["from"] == "apigw:api"]
    assert len(fan) == 3
    mids = {arch._bezier_mid(e["points"]) for e in fan}
    assert len(mids) == 3
