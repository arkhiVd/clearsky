import json

from clearsky.ai_triage import build_prompt, enabled, summarize


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AI_TRIAGE_ENABLED", raising=False)
    assert not enabled()
    assert summarize([], "report") is None


def test_enabled_flag(monkeypatch):
    monkeypatch.setenv("AI_TRIAGE_ENABLED", "true")
    assert enabled()
    monkeypatch.setenv("AI_TRIAGE_ENABLED", "false")
    assert not enabled()


def test_build_prompt_contains_findings_and_report():
    findings = [{
        "detector": "ebs.unattached", "severity": "MEDIUM",
        "title": "Unattached volume vol-1", "estimated_monthly_cost": 10,
        "status": "open",
    }]
    prompt = build_prompt(findings, "FULL DIGEST TEXT")
    assert "Unattached volume vol-1" in prompt
    assert "FULL DIGEST TEXT" in prompt
    assert "Do not invent findings" in prompt
    # findings serialized as valid JSON inside the prompt
    payload = prompt.split("FINDINGS JSON:\n")[1].split("\n\nFULL REPORT")[0]
    assert json.loads(payload)[0]["detector"] == "ebs.unattached"


def test_build_prompt_caps_findings():
    findings = [{"detector": f"d{i}", "severity": "LOW", "title": f"t{i}"}
                for i in range(200)]
    prompt = build_prompt(findings, "report")
    payload = prompt.split("FINDINGS JSON:\n")[1].split("\n\nFULL REPORT")[0]
    assert len(json.loads(payload)) == 50
