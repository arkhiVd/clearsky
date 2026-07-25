from clearsky.inventory import (
    diff,
    render_section,
    summarize_backup_jobs,
    summarize_db_instances,
    summarize_instances,
    summarize_volumes,
)


def test_summarize_instances_counts_states_and_types():
    reservations = [
        {"Instances": [
            {"State": {"Name": "running"}, "InstanceType": "t3.micro"},
            {"State": {"Name": "stopped"}, "InstanceType": "t3.micro"},
            {"State": {"Name": "terminated"}, "InstanceType": "t3.micro"},
        ]},
        {"Instances": [
            {"State": {"Name": "running"}, "InstanceType": "t2.micro"},
        ]},
    ]
    counts = summarize_instances(reservations)
    assert counts["ec2.total"] == 3  # terminated excluded
    assert counts["ec2.running"] == 2
    assert counts["ec2.stopped"] == 1
    assert counts["ec2.type.t3.micro"] == 2


def test_summarize_volumes_unattached():
    volumes = [
        {"Attachments": [{"InstanceId": "i-1"}]},
        {"Attachments": []},
        {},
    ]
    counts = summarize_volumes(volumes)
    assert counts == {"ebs.volumes": 3, "ebs.unattached": 2}


def test_summarize_backup_jobs_failures():
    jobs = [
        {"State": "COMPLETED"},
        {"State": "FAILED"},
        {"State": "ABORTED"},
        {"State": "RUNNING"},
    ]
    counts = summarize_backup_jobs(jobs)
    assert counts == {"backup.jobs_24h": 4, "backup.failed_24h": 2}


def test_summarize_db_instances_engines():
    counts = summarize_db_instances(
        [{"Engine": "postgres"}, {"Engine": "postgres"}, {"Engine": "mysql"}]
    )
    assert counts["rds.instances"] == 3
    assert counts["rds.engine.postgres"] == 2


def test_diff_deltas_and_no_previous():
    assert diff({"a": 1}, None) == {}
    assert diff({"a": 2, "b": 1}, {"a": 1, "c": 3}) == {"a": 1, "b": 1, "c": -3}


def test_render_section_shows_deltas_and_backup_alert():
    metrics = {
        "ec2.running": 2,
        "ec2.stopped": 1,
        "s3.buckets": 4,
        "backup.jobs_24h": 3,
        "backup.failed_24h": 1,
    }
    section = render_section(metrics, {"ec2.running": 1})
    assert "EC2 running: 2  (+1 vs prev)" in section
    assert "Backup FAILED 24h: 1  <-- ATTENTION" in section


def test_render_section_hides_backup_line_when_no_jobs():
    section = render_section({"ec2.running": 1}, {})
    assert "Backup FAILED" not in section
