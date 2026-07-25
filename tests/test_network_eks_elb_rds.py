from datetime import date

from clearsky.detectors.eks import (
    evaluate_cluster_versions,
    evaluate_node_utilization,
)
from clearsky.detectors.elb_rds import (
    evaluate_load_balancers,
    evaluate_rds_connections,
)
from clearsky.detectors.network import (
    evaluate_gateway_endpoints,
    evaluate_nat_traffic,
)

TODAY = date(2026, 7, 6)


# ---------- gateway endpoints ----------

def test_nat_vpc_missing_both_endpoints():
    nats = [{"NatGatewayId": "nat-1", "VpcId": "vpc-a", "State": "available"}]
    findings = evaluate_gateway_endpoints(nats, [], "us-east-1")
    assert len(findings) == 1
    assert "dynamodb and s3" in findings[0].title


def test_nat_vpc_with_s3_endpoint_flags_dynamodb_only():
    nats = [{"NatGatewayId": "nat-1", "VpcId": "vpc-a", "State": "available"}]
    endpoints = [{
        "VpcId": "vpc-a", "VpcEndpointType": "Gateway", "State": "Available",
        "ServiceName": "com.amazonaws.us-east-1.s3",
    }]
    findings = evaluate_gateway_endpoints(nats, endpoints, "us-east-1")
    assert "no dynamodb gateway endpoint" in findings[0].title


def test_vpc_with_both_endpoints_clean_and_deleted_nat_ignored():
    nats = [
        {"NatGatewayId": "nat-1", "VpcId": "vpc-a", "State": "available"},
        {"NatGatewayId": "nat-2", "VpcId": "vpc-b", "State": "deleted"},
    ]
    endpoints = [
        {"VpcId": "vpc-a", "VpcEndpointType": "Gateway", "State": "Available",
         "ServiceName": "com.amazonaws.us-east-1.s3"},
        {"VpcId": "vpc-a", "VpcEndpointType": "Gateway", "State": "Available",
         "ServiceName": "com.amazonaws.us-east-1.dynamodb"},
    ]
    assert evaluate_gateway_endpoints(nats, endpoints, "us-east-1") == []


def test_nat_idle_flagged_busy_not():
    stats = [
        {"id": "nat-idle", "vpc_id": "vpc-a", "total_gb": 0.02, "days": 14},
        {"id": "nat-busy", "vpc_id": "vpc-b", "total_gb": 250.0, "days": 14},
        {"id": "nat-new", "vpc_id": "vpc-c", "total_gb": 0.0, "days": 2},
    ]
    findings = evaluate_nat_traffic(stats, "us-east-1")
    assert [f.resource_id for f in findings] == ["nat-idle"]
    assert findings[0].estimated_monthly_cost > 30


# ---------- EKS ----------

def test_extended_support_cluster_flagged():
    clusters = [{"name": "legacy", "version": "1.29"}]
    findings = evaluate_cluster_versions(clusters, "us-east-1", today=TODAY)
    assert findings[0].detector == "eks.extended_support"
    assert findings[0].severity == "HIGH"
    assert findings[0].estimated_monthly_cost == 365.0


def test_support_ending_soon_warns():
    clusters = [{"name": "aging", "version": "1.33"}]  # ends 2026-07-29
    findings = evaluate_cluster_versions(clusters, "us-east-1", today=TODAY)
    assert findings[0].detector == "eks.support_ending"
    assert findings[0].severity == "MEDIUM"


def test_unknown_newer_version_clean():
    clusters = [{"name": "fresh", "version": "1.34"}]
    assert evaluate_cluster_versions(clusters, "us-east-1", today=TODAY) == []


def test_all_nodes_underutilized_flagged():
    clusters = [{
        "name": "quiet",
        "nodes": [
            {"id": "i-1", "daily_p95": [5, 8, 3, 6, 7, 4, 5, 6]},
            {"id": "i-2", "daily_p95": [2, 3, 4, 2, 3, 5, 4, 3]},
        ],
    }]
    findings = evaluate_node_utilization(clusters, "us-east-1")
    assert len(findings) == 1
    assert "all 2 nodes" in findings[0].title


def test_one_busy_node_means_clean():
    clusters = [{
        "name": "mixed",
        "nodes": [
            {"id": "i-1", "daily_p95": [5, 8, 3, 6, 7, 4, 5, 6]},
            {"id": "i-2", "daily_p95": [60, 70, 55, 80, 75, 65, 70, 60]},
        ],
    }]
    assert evaluate_node_utilization(clusters, "us-east-1") == []


# ---------- ELB / RDS ----------

def test_orphaned_and_unhealthy_lbs_flagged():
    lbs = [
        {"name": "empty-alb", "type": "application",
         "healthy_targets": 0, "total_targets": 0},
        {"name": "dead-nlb", "type": "network",
         "healthy_targets": 0, "total_targets": 3},
        {"name": "good-alb", "type": "application",
         "healthy_targets": 2, "total_targets": 2},
    ]
    findings = evaluate_load_balancers(lbs, "us-east-1")
    by_name = {f.resource_id: f for f in findings}
    assert set(by_name) == {"empty-alb", "dead-nlb"}
    assert "no registered targets" in by_name["empty-alb"].title
    assert "no healthy targets" in by_name["dead-nlb"].title


def test_idle_rds_flagged_active_and_young_not():
    instances = [
        {"id": "db-idle", "instance_class": "db.t3.micro",
         "daily_max_connections": [0, 0, 0, 0, 0, 0, 0, 0]},
        {"id": "db-active", "instance_class": "db.t3.micro",
         "daily_max_connections": [0, 0, 0, 5, 0, 0, 0, 0]},
        {"id": "db-young", "instance_class": "db.t3.micro",
         "daily_max_connections": [0, 0]},
    ]
    findings = evaluate_rds_connections(instances, "us-east-1")
    assert [f.resource_id for f in findings] == ["db-idle"]
