import json
from pathlib import Path

from clearsky.costwatch import analyze, render_section

FIXTURES = Path(__file__).parent / "fixtures"


def load():
    return json.loads((FIXTURES / "cost_and_usage.json").read_text())


def test_yesterday_totals():
    report = analyze(load())
    assert report.day == "2026-07-05"
    assert report.yesterday_total == 4.96  # 0.10 + 0.05 + 4.80 + 0.01
    assert abs(report.avg_7d_total - 0.15) < 1e-9


def test_ec2_spike_is_mover_small_noise_is_not():
    report = analyze(load())
    movers = {m["service"]: m for m in report.movers}
    # EC2 appeared from nothing at $4.80 -> mover
    assert "Amazon Elastic Compute Cloud - Compute" in movers
    assert movers["Amazon Elastic Compute Cloud - Compute"]["delta"] == 4.8
    # Cost Explorer $0.01 blip is below the absolute threshold
    assert "AWS Cost Explorer" not in movers
    # steady services are not movers
    assert "AWS Lambda" not in movers


def test_top_services_ordering():
    report = analyze(load())
    assert report.top_services[0][0] == "Amazon Elastic Compute Cloud - Compute"


def test_render_section_mentions_spike():
    section = render_section(analyze(load()))
    assert "COST WATCH" in section
    assert "UP Amazon Elastic Compute Cloud - Compute" in section
    assert "$4.96" in section


def test_empty_account():
    report = analyze({"ResultsByTime": []})
    assert report.yesterday_total == 0.0
    assert "COST WATCH" in render_section(report)
