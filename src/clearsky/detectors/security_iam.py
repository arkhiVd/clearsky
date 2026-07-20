"""IAM hygiene: console users without MFA, old access keys, direct admin.

Global service: runner is marked scope="global" so it executes once per
scan, not once per region.
"""

from clearsky.models import Finding
from clearsky.registry import register

OLD_KEY_DAYS = 90


def evaluate_users(users: list[dict], region: str = "global") -> list[Finding]:
    """users: [{name, has_console, mfa_count, key_ages_days: [int],
                attached_policies: [str]}]"""
    findings = []
    for user in users:
        name = user["name"]

        if user.get("has_console") and not user.get("mfa_count"):
            findings.append(Finding(
                detector="sec.iam_no_mfa",
                resource_id=name,
                severity="HIGH",
                title=f"IAM user {name} has console access without MFA",
                detail=(
                    "Password-only console access. Enable a virtual MFA "
                    "device for this user in the IAM console."
                ),
                region=region,
            ))

        for age in user.get("key_ages_days", []):
            if age >= OLD_KEY_DAYS:
                findings.append(Finding(
                    detector="sec.iam_old_key",
                    resource_id=f"{name}/key",
                    severity="MEDIUM",
                    title=f"IAM user {name} has an access key {age} days old",
                    detail=(
                        f"Keys older than {OLD_KEY_DAYS} days should be "
                        "rotated: create a new key, migrate callers, then "
                        "deactivate and delete the old one."
                    ),
                    region=region,
                ))
                break  # one finding per user is enough

        if "AdministratorAccess" in user.get("attached_policies", []):
            findings.append(Finding(
                detector="sec.iam_admin_user",
                resource_id=name,
                severity="MEDIUM",
                title=f"IAM user {name} has AdministratorAccess attached directly",
                detail=(
                    "Prefer role assumption with least-privilege policies "
                    "over standing admin on a user principal."
                ),
                region=region,
            ))
    return findings


@register
class IamHygieneDetector:
    id = "sec.iam"
    title = "IAM hygiene"
    scope = "global"

    def run(self, session, region: str) -> list[Finding]:
        from datetime import datetime, timezone

        iam = session.client("iam")
        now = datetime.now(timezone.utc)
        users = []
        for page in iam.get_paginator("list_users").paginate():
            for u in page["Users"]:
                name = u["UserName"]
                try:
                    iam.get_login_profile(UserName=name)
                    has_console = True
                except iam.exceptions.NoSuchEntityException:
                    has_console = False
                mfa = iam.list_mfa_devices(UserName=name)["MFADevices"]
                keys = iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
                policies = iam.list_attached_user_policies(UserName=name)[
                    "AttachedPolicies"
                ]
                users.append({
                    "name": name,
                    "has_console": has_console,
                    "mfa_count": len(mfa),
                    "key_ages_days": [
                        (now - k["CreateDate"]).days
                        for k in keys if k["Status"] == "Active"
                    ],
                    "attached_policies": [p["PolicyName"] for p in policies],
                })
        return evaluate_users(users)
