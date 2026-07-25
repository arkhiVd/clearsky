from datetime import datetime, timezone

from clearsky.commitments import (
    is_commitments_day,
    render_section,
    summarize_ri,
    summarize_sp,
)


def test_monday_gate():
    assert is_commitments_day(datetime(2026, 7, 6, tzinfo=timezone.utc))   # Mon
    assert not is_commitments_day(datetime(2026, 7, 7, tzinfo=timezone.utc))


def test_summarize_sp_with_recommendation():
    resp = {"SavingsPlansPurchaseRecommendation": {
        "SavingsPlansPurchaseRecommendationSummary": {
            "HourlyCommitmentToPurchase": "0.043",
            "EstimatedMonthlySavingsAmount": "11.20",
            "EstimatedSavingsPercentage": "23.5",
        },
        "SavingsPlansPurchaseRecommendationDetails": [{"anything": 1}],
    }}
    sp = summarize_sp(resp)
    assert sp["hourly_commitment"] == 0.043
    assert sp["monthly_savings"] == 11.2


def test_summarize_sp_empty():
    assert summarize_sp({}) is None
    assert summarize_sp({"SavingsPlansPurchaseRecommendation": {
        "SavingsPlansPurchaseRecommendationDetails": [],
    }}) is None


def test_summarize_ri_ec2_and_rds():
    ec2_resp = {"Recommendations": [{"RecommendationDetails": [{
        "InstanceDetails": {"EC2InstanceDetails": {"InstanceType": "t3.small"}},
        "RecommendedNumberOfInstancesToPurchase": "2",
        "EstimatedMonthlySavingsAmount": "9.5",
    }]}]}
    ris = summarize_ri(ec2_resp, "EC2")
    assert ris == [{"service": "EC2", "instance_type": "t3.small",
                    "count": 2, "monthly_savings": 9.5}]

    rds_resp = {"Recommendations": [{"RecommendationDetails": [{
        "InstanceDetails": {"RDSInstanceDetails": {"InstanceClass": "db.t3.micro"}},
        "RecommendedNumberOfInstancesToPurchase": "1",
        "EstimatedMonthlySavingsAmount": "4.1",
    }]}]}
    assert summarize_ri(rds_resp, "RDS")[0]["instance_type"] == "db.t3.micro"


def test_render_with_recs_warns_about_overlap():
    sp = {"hourly_commitment": 0.05, "monthly_savings": 12.0,
          "savings_pct": 20.0, "term": "ONE_YEAR", "payment": "NO_UPFRONT"}
    ris = [{"service": "EC2", "instance_type": "t3.small",
            "count": 2, "monthly_savings": 9.5}]
    section = render_section(sp, ris)
    assert "commit $0.050/hr" in section
    assert "2x t3.small" in section
    assert "do not sum the savings" in section


def test_render_empty_account():
    section = render_section(None, [])
    assert "No recommendations" in section
