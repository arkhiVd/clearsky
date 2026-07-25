"""Pure tests for the long-stopped EC2 detector."""

from datetime import datetime, timezone

from clearsky.detectors import ec2_stopped


NOW = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)


def _inst(iid, reason, state="stopped", name=None):
    return {
        "InstanceId": iid,
        "State": {"Name": state},
        "StateTransitionReason": reason,
        "Tags": [{"Key": "Name", "Value": name}] if name else [],
    }


def test_flags_instance_stopped_past_threshold():
    instances = [_inst("i-1", "User initiated (2026-07-01 07:05:20 GMT)",
                       name="k3s-node")]
    out = ec2_stopped.parse_stopped(instances, {"i-1": 15}, "ap-northeast-1",
                                    now=NOW)
    assert len(out) == 1
    f = out[0]
    assert f.detector == "ec2.stopped" and f.resource_id == "i-1"
    assert "k3s-node" in f.title and "5 days" in f.title
    assert "15 GiB" in f.title
    assert "create-image" in f.detail
    # saving = 15 * (0.096 - 0.05)
    assert f.estimated_monthly_cost == 0.69


def test_recently_stopped_not_flagged():
    instances = [_inst("i-2", "User initiated (2026-07-05 07:00:00 GMT)")]
    assert ec2_stopped.parse_stopped(instances, {"i-2": 10}, "us-east-1",
                                     now=NOW) == []


def test_unparseable_reason_and_wrong_state_skipped():
    instances = [
        _inst("i-3", ""),                       # no timestamp
        _inst("i-4", "Server.SpotInstanceTermination"),
        _inst("i-5", "User initiated (2026-06-01 00:00:00 GMT)",
              state="running"),                 # not stopped
    ]
    assert ec2_stopped.parse_stopped(instances, {}, "us-east-1", now=NOW) == []


def test_no_volumes_still_flags_with_zero_saving():
    instances = [_inst("i-6", "User initiated (2026-06-20 00:00:00 GMT)")]
    out = ec2_stopped.parse_stopped(instances, {}, "us-east-1", now=NOW)
    assert len(out) == 1 and out[0].estimated_monthly_cost == 0.0
