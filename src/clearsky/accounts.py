"""Multi-account fan-out: operate on the home account plus any member
accounts reachable through a cross-account read-only role.

Member accounts come from two places, merged:
  - the SSM registry (ACCOUNTS_PARAM, JSON list of {account_id, role_arn,
    label, added_at}) written by the dashboard's Accounts panel — the
    normal, UI-driven path;
  - the legacy MEMBER_ROLE_ARNS env var (comma-separated role ARNs) set
    from terraform, kept for backward compatibility.

Deploy terraform/member-role in each member account (trusting the home
scanner/chat/arch/api roles) to make it reachable.

A member account that fails to assume is reported in the digest, not
fatal — one broken trust policy must not kill the whole scan.
"""

import dataclasses
import json
import logging
import os

import boto3

logger = logging.getLogger(__name__)

SESSION_NAME = "clearsky-scan"
HOME = ""   # account id used for the home account in keys/targets


def member_role_arns() -> list[str]:
    raw = os.environ.get("MEMBER_ROLE_ARNS", "")
    return [arn.strip() for arn in raw.split(",") if arn.strip()]


def configured_accounts() -> list[dict]:
    """Member accounts from the SSM registry plus legacy env ARNs.
    Each entry: {account_id, role_arn, label}. Never raises — no registry
    (or no permission) simply means no member accounts."""
    out, seen = [], set()
    param = os.environ.get("ACCOUNTS_PARAM", "")
    if param:
        try:
            raw = boto3.client("ssm").get_parameter(
                Name=param)["Parameter"]["Value"]
            for entry in json.loads(raw or "[]"):
                arn = str(entry.get("role_arn", ""))
                acct = str(entry.get("account_id", "")) or (
                    account_id_from_arn(arn) if arn.count(":") >= 5 else "")
                if arn and acct and acct not in seen:
                    seen.add(acct)
                    out.append({"account_id": acct, "role_arn": arn,
                                "label": str(entry.get("label", ""))})
        except Exception:  # noqa: BLE001 - registry is optional
            logger.info("accounts registry unavailable (%s)", param)
    for arn in member_role_arns():
        acct = account_id_from_arn(arn)
        if acct not in seen:
            seen.add(acct)
            out.append({"account_id": acct, "role_arn": arn, "label": ""})
    return out


def role_arn_for(account_id: str) -> str | None:
    for entry in configured_accounts():
        if entry["account_id"] == str(account_id):
            return entry["role_arn"]
    return None


def member_session(account_id: str) -> boto3.Session:
    """Assumed-role session for a configured member account id."""
    arn = role_arn_for(account_id)
    if not arn:
        raise ValueError(f"account {account_id} is not onboarded")
    return assume_session(arn)


def account_id_from_arn(arn: str) -> str:
    return arn.split(":")[4]


def assume_session(role_arn: str) -> boto3.Session:
    creds = boto3.client("sts").assume_role(
        RoleArn=role_arn, RoleSessionName=SESSION_NAME
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def scan_targets(home_session: boto3.Session, only: list[str] | None = None):
    """Yields (account_id_or_empty, session, error_or_None) per target.

    Home account first with account id "" so its finding keys keep the
    original single-account format. `only` optionally restricts to a list
    of account ids ("home" or "" selects the home account)."""
    selected = None
    if only is not None:
        selected = {HOME if str(a).lower() in ("home", "") else str(a)
                    for a in only}
    if selected is None or HOME in selected:
        yield HOME, home_session, None
    for entry in configured_accounts():
        account = entry["account_id"]
        if selected is not None and account not in selected:
            continue
        try:
            yield account, assume_session(entry["role_arn"]), None
        except Exception as err:  # noqa: BLE001 - report, don't crash scan
            logger.exception("assume failed for %s", entry["role_arn"])
            yield account, None, str(err)


def tag_account(findings: list, account: str) -> list:
    """Stamp member-account findings so keys and titles carry the account."""
    if not account:
        return findings
    return [
        dataclasses.replace(
            f, account=account, title=f"[{account}] {f.title}"
        )
        for f in findings
    ]
