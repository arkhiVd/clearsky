"""Lambda entrypoint: run all detectors, reconcile lifecycle, notify."""

import json
import logging
import os

import boto3

from clearsky import accounts, ai_triage, commitments, costwatch, inventory, posture
from clearsky import regions as regions_mod
from clearsky.registry import all_detectors
from clearsky.report import render_digest
from clearsky.store import FindingStore

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    session = boto3.Session()
    account_id = boto3.client("sts").get_caller_identity()["Account"]
    # "auto" discovers regions with infra and caches the list for the
    # API / diagram lambdas; an explicit comma list is used as-is
    REGIONS = regions_mod.resolve_regions(
        session, os.environ.get("SCAN_REGIONS", "us-east-1"),
        bucket=os.environ.get("REPORTS_BUCKET"))
    logger.info("scanning regions: %s", REGIONS)

    findings = []
    assume_errors = []
    scanned_accounts: set[str] = set()
    only = (event or {}).get("accounts")  # optional account-id filter
    for account, target_session, error in accounts.scan_targets(session, only):
        if error:
            assume_errors.append(f"  member {account}: assume failed ({error})")
            continue
        scanned_accounts.add(account)
        account_findings = []
        for detector in all_detectors():
            # global-scope detectors (IAM, CloudTrail, S3 account view) run once
            regions = (
                REGIONS[:1] if getattr(detector, "scope", "") == "global" else REGIONS
            )
            for region in regions:
                try:
                    found = detector.run(target_session, region)
                    logger.info(
                        "account=%s detector=%s region=%s findings=%d",
                        account or "home", detector.id, region, len(found),
                    )
                    account_findings.extend(found)
                except Exception:
                    logger.exception(
                        "account=%s detector=%s region=%s failed",
                        account or "home", detector.id, region,
                    )
        findings.extend(accounts.tag_account(account_findings, account))

    result = FindingStore().reconcile(findings, scanned_accounts=scanned_accounts)
    subject, body = render_digest(result, account_id)
    if assume_errors:
        body += "\n\nMEMBER ACCOUNT ERRORS\n" + "\n".join(assume_errors)

    try:
        cost_report = costwatch.analyze(costwatch.fetch_cost_and_usage(session))
        body = costwatch.render_section(cost_report) + "\n\n" + body
        subject += f" | spend ${cost_report.yesterday_total:.2f}"
        if os.environ.get("REPORTS_BUCKET"):
            costwatch.snapshot_to_s3(cost_report)
    except Exception:
        logger.exception("cost watch failed")
        body = "COST WATCH\n  failed this run, see logs\n\n" + body

    try:
        body += "\n" + inventory.run(session, REGIONS)
    except Exception:
        logger.exception("inventory failed")
        body += "\nINVENTORY\n  failed this run, see logs"

    try:
        active = result["new"] + result["open"]
        body += "\n\n" + posture.run(active)
    except Exception:
        logger.exception("posture failed")
        body += "\n\nSECURITY POSTURE\n  failed this run, see logs"

    if commitments.is_commitments_day() or (event or {}).get("force_commitments"):
        try:
            body += "\n\n" + commitments.run(session)
        except Exception:
            logger.exception("commitments failed")
            body += "\n\nCOMMITMENTS\n  failed this run, see logs"

    triage = ai_triage.summarize(result["new"] + result["open"], body)
    if triage:
        body = "AI TRIAGE\n" + triage + "\n\n" + body

    topic_arn = os.environ.get("REPORT_TOPIC_ARN")
    if topic_arn:
        boto3.client("sns").publish(
            TopicArn=topic_arn, Subject=subject[:100], Message=body
        )

    summary = {k: len(v) for k, v in result.items()}
    logger.info("run complete: %s", json.dumps(summary))
    return summary
