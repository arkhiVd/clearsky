"""Plain-text digest rendering. Deterministic templates, no AI."""


def _line(item: dict) -> str:
    cost = float(item.get("estimated_monthly_cost", 0) or 0)
    cost_part = f" (~${cost:.2f}/mo)" if cost else ""
    return f"  - [{item['severity']}] {item['title']}{cost_part}\n    {item['detail']}"


def render_digest(result: dict[str, list[dict]], account_id: str) -> tuple[str, str]:
    """Returns (subject, body) for the notification email."""
    new, opened, resolved = result["new"], result["open"], result["resolved"]
    total_waste = sum(
        float(i.get("estimated_monthly_cost", 0) or 0) for i in new + opened
    )

    subject = (
        f"[clearsky] {account_id}: "
        f"{len(new)} new, {len(opened)} open, {len(resolved)} resolved"
    )

    sections = [
        f"Cloud Detective daily report for account {account_id}",
        f"Estimated waste from open findings: ${total_waste:.2f}/month",
        "",
    ]
    for label, items in (("NEW", new), ("STILL OPEN", opened), ("RESOLVED", resolved)):
        sections.append(f"{label} ({len(items)})")
        if items:
            sections.extend(_line(i) for i in items)
        else:
            sections.append("  none")
        sections.append("")

    return subject, "\n".join(sections)
