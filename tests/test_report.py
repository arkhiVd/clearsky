from clearsky.report import render_digest


def _item(title="Unused EIP", cost=3.65, severity="LOW"):
    return {
        "title": title,
        "detail": "release it",
        "severity": severity,
        "estimated_monthly_cost": cost,
    }


def test_digest_counts_and_waste():
    subject, body = render_digest(
        {"new": [_item()], "open": [_item(cost=10)], "resolved": []},
        "123456789012",
    )
    assert "1 new, 1 open, 0 resolved" in subject
    assert "$13.65/month" in body
    assert "NEW (1)" in body
    assert "RESOLVED (0)" in body
    assert "none" in body


def test_digest_empty():
    subject, body = render_digest(
        {"new": [], "open": [], "resolved": []}, "123456789012"
    )
    assert "0 new, 0 open, 0 resolved" in subject
    assert "$0.00/month" in body
