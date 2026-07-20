"""Finding lifecycle persistence in DynamoDB.

Lifecycle:
  new      - first time this finding key is seen
  open     - seen again on a later run
  resolved - previously open, no longer detected

Table schema: PK "pk" = finding key (detector#region#resource_id).
"""

import os
from datetime import datetime, timezone
from decimal import Decimal

import boto3

from clearsky.models import Finding

TABLE_ENV = "FINDINGS_TABLE"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class FindingStore:
    def __init__(self, table_name: str | None = None, dynamodb=None):
        table_name = table_name or os.environ[TABLE_ENV]
        dynamodb = dynamodb or boto3.resource("dynamodb")
        self.table = dynamodb.Table(table_name)

    def reconcile(self, current: list[Finding],
                  scanned_accounts: set[str] | None = None) -> dict[str, list[dict]]:
        """Merge current detection results with stored state.

        Returns {"new": [...], "open": [...], "resolved": [...]} where each
        item is the stored representation (dict) of a finding.

        `scanned_accounts` is the set of account ids this run actually
        covered ("" = home). When given, findings belonging to accounts
        NOT in the set are left untouched — a single-account scan must
        never auto-resolve another account's findings. None = legacy
        behavior (everything was scanned).
        """
        now = _now()
        stored = self._load_active()
        current_by_key = {f.key: f for f in current}

        result: dict[str, list[dict]] = {"new": [], "open": [], "resolved": []}

        for key, finding in current_by_key.items():
            if key in stored:
                item = stored[key]
                item["last_seen"] = now
                item["status"] = "open"
                result["open"].append(item)
            else:
                item = finding.to_dict()
                item["pk"] = key
                item["status"] = "new"
                item["first_seen"] = now
                item["last_seen"] = now
                item["estimated_monthly_cost"] = Decimal(
                    str(finding.estimated_monthly_cost)
                )
                result["new"].append(item)
            self.table.put_item(Item=item)

        for key, item in stored.items():
            if key not in current_by_key:
                # AI-added findings aren't re-emitted by detectors; they are
                # resolved explicitly (user or AI verification), never here
                if item.get("source") == "ai":
                    continue
                if (scanned_accounts is not None
                        and item.get("account", "") not in scanned_accounts):
                    continue
                item["status"] = "resolved"
                item["resolved_at"] = now
                self.table.put_item(Item=item)
                result["resolved"].append(item)

        return result

    def _load_active(self) -> dict[str, dict]:
        """All findings not yet resolved. Table stays small; scan is fine."""
        items: dict[str, dict] = {}
        kwargs: dict = {}
        while True:
            resp = self.table.scan(**kwargs)
            for item in resp.get("Items", []):
                if item.get("status") != "resolved":
                    items[item["pk"]] = item
            if "LastEvaluatedKey" not in resp:
                return items
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
