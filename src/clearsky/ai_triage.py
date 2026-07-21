"""Optional AI triage: an executive summary on top of the deterministic
digest, produced by Claude on Amazon Bedrock.

Design rule: rules detect, AI explains. Nothing here influences
detection, findings, scores, or lifecycle — the model only reads the
already-computed results and writes a prioritized narrative. Disabled
by default (AI_TRIAGE_ENABLED=true to enable); any failure degrades to
the plain digest.

Uses the Bedrock Converse API via boto3 so the Lambda keeps zero
external dependencies. Model is configurable; default Claude Opus.
"""

import json
import logging
import os

logger = logging.getLogger(__name__)

DEFAULT_MODEL_ID = "anthropic.claude-opus-4-8"
MAX_FINDINGS_IN_PROMPT = 50


def enabled() -> bool:
    return os.environ.get("AI_TRIAGE_ENABLED", "false").lower() == "true"


def build_prompt(active_findings: list[dict], digest_body: str) -> str:
    """Pure function so prompt construction is unit-testable."""
    findings_payload = [
        {
            "detector": f.get("detector"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "estimated_monthly_cost": float(
                f.get("estimated_monthly_cost", 0) or 0
            ),
            "status": f.get("status"),
        }
        for f in active_findings[:MAX_FINDINGS_IN_PROMPT]
    ]
    return (
        "You are a FinOps and cloud security analyst. Below is today's "
        "automated scan output for an AWS account: a findings list (JSON) "
        "and the full plain-text report.\n\n"
        "Write a brief executive triage, plain text only (this is prepended "
        "to a plain-text email — no markdown):\n"
        "1. TOP ACTIONS: the 3 highest-impact actions, ranked by savings "
        "and risk reduction versus effort, one line each with the concrete "
        "resource named.\n"
        "2. One sentence on overall trend (cost and security), only if the "
        "report contains trend data.\n"
        "Keep it under 150 words. Do not restate the whole report. Do not "
        "invent findings that are not listed.\n\n"
        f"FINDINGS JSON:\n{json.dumps(findings_payload)}\n\n"
        f"FULL REPORT:\n{digest_body}"
    )


def summarize(active_findings: list[dict], digest_body: str) -> str | None:
    """Returns the triage text, or None when disabled or failed."""
    if not enabled():
        return None
    try:
        import boto3

        bedrock = boto3.client(
            "bedrock-runtime",
            region_name=os.environ.get("BEDROCK_REGION", "us-east-1"),
        )
        response = bedrock.converse(
            modelId=os.environ.get("BEDROCK_MODEL_ID", DEFAULT_MODEL_ID),
            messages=[{
                "role": "user",
                "content": [{"text": build_prompt(active_findings, digest_body)}],
            }],
            inferenceConfig={"maxTokens": 1000},
        )
        parts = response["output"]["message"]["content"]
        text = "\n".join(p["text"] for p in parts if "text" in p).strip()
        return text or None
    except Exception:
        logger.exception("AI triage failed; sending plain digest")
        return None
