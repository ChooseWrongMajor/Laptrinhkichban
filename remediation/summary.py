from collections import Counter

from core.models import (
    PENDING_APPROVAL, PLANNED, REMEDIATED, REMEDIATION_FAILED,
)
from core.report import control_status, print_table

SUMMARY_FIELDS = [
    "cis_id", "title", "tier", "targets", "planned", "remediated", "pending", "skipped",
    "failed", "before", "after", "action",
]


def summarize_remediation(results, controls, audit_findings, post_findings=None):
    """
    Mỗi CIS ID có FAIL trong audit thành một dòng.
    before = trạng thái control trong lần audit; after = trạng thái sau re-audit (nếu có).
    """
    rows = []
    for control in controls:
        items = [r for r in results if r.cis_id == control.cis_id]
        if not items:
            continue
        count = Counter(r.status for r in items)
        before = control_status([f for f in audit_findings if f.cis_id == control.cis_id])
        after = ""
        if post_findings is not None:
            after = control_status([f for f in post_findings if f.cis_id == control.cis_id])
        actions = [r.action for r in items if r.action != "-"]
        rows.append({
            "cis_id": control.cis_id,
            "title": control.title,
            "tier": control.remediation,
            "targets": len(items),
            "planned": count[PLANNED],
            "remediated": count[REMEDIATED],
            "pending": count[PENDING_APPROVAL],
            "skipped": sum(v for k, v in count.items() if k.startswith("SKIPPED")),
            "failed": count[REMEDIATION_FAILED],
            "before": before,
            "after": after,
            "action": actions[0] if actions else (items[0].message or "-"),
        })
    return rows


def print_resource_results(results, title):
    """Bảng chi tiết: mỗi tài nguyên một dòng."""
    rows = [{**r.to_dict(), "resource": r.resource_name or r.resource_id} for r in results]
    columns = [
        ("cis_id", "CIS", 6), ("tier", "Tier", 10), ("resource", "Resource", 34),
        ("status", "Status", 20), ("before", "Before", 6), ("after", "After", 9),
        ("message", "Message", 70),
    ]
    print_table(rows, columns, title, color_keys=("status", "after"))


def print_remediation_summary(rows, title, apply_mode):
    columns = [("cis_id", "CIS", 6), ("title", "Title", 34), ("tier", "Tier", 10), ("targets", "Tgt", 3)]
    if apply_mode:
        columns += [("remediated", "Fixed", 5), ("pending", "Pend", 4)]
    else:
        columns += [("planned", "Plan", 4)]
    columns += [("skipped", "Skip", 4), ("failed", "Fail", 4), ("before", "Before", 6)]
    if apply_mode:
        columns += [("after", "After", 6)]
    columns += [("action", "Action", 60)]
    print_table(rows, columns, title, color_keys=("before", "after"))
