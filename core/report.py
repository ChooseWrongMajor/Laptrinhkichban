import csv
import json
import os
import subprocess
import sys
from datetime import datetime

from core.models import ERROR, FAIL, NOT_APPLICABLE, PASS

SUMMARY_FIELDS = [
    "cis_id", "title", "service", "level", "checked", "pass", "fail", "error",
    "status", "expected", "match", "remediation", "failed_resources",
]

_COLORS = {
    PASS: "\033[32m", FAIL: "\033[31m", ERROR: "\033[33m", NOT_APPLICABLE: "\033[90m",
    "REMEDIATED": "\033[32m", "PLANNED": "\033[36m", "PENDING_APPROVAL": "\033[33m",
    "SKIPPED_AUDIT_ONLY": "\033[90m", "SKIPPED_COMPLIANT": "\033[90m",
    "SKIPPED_OUT_OF_SCOPE": "\033[90m",
}
_RESET = "\033[0m"


def control_status(findings):
    """
    Gộp trạng thái của một CIS ID từ các tài nguyên:
    có FAIL -> FAIL; không FAIL nhưng có lỗi -> ERROR;
    không có tài nguyên áp dụng -> NOT_APPLICABLE; còn lại -> PASS.
    """
    statuses = {f.status for f in findings}
    if FAIL in statuses:
        return FAIL
    if ERROR in statuses:
        return ERROR
    if not statuses - {NOT_APPLICABLE}:
        return NOT_APPLICABLE
    return PASS


def summarize(findings, controls, expected=None):
    """Tạo mỗi CIS ID một dòng tổng hợp."""
    expected = expected or {}
    rows = []
    for control in controls:
        items = [f for f in findings if f.cis_id == control.cis_id]
        status = control_status(items)
        exp = expected.get(control.cis_id, {}).get("expected", "")
        failed = [f.resource_name or f.resource_id for f in items if f.status == FAIL]
        rows.append({
            "cis_id": control.cis_id,
            "title": control.title,
            "service": control.service,
            "level": control.level,
            "checked": sum(f.status != NOT_APPLICABLE for f in items),
            "pass": sum(f.status == PASS for f in items),
            "fail": sum(f.status == FAIL for f in items),
            "error": sum(f.status == ERROR for f in items),
            "status": status,
            "expected": exp,
            "match": ("YES" if exp == status else "NO") if exp else "",
            "remediation": control.remediation,
            "failed_resources": ", ".join(failed),
        })
    return rows


def totals(rows):
    """Thống kê toàn bộ lần audit. Tỉ lệ tuân thủ tính trên các control PASS/FAIL."""
    count = {s: sum(r["status"] == s for r in rows) for s in (PASS, FAIL, ERROR, NOT_APPLICABLE)}
    evaluated = count[PASS] + count[FAIL]
    compared = [r for r in rows if r["expected"]]
    return {
        "controls": len(rows),
        **{k.lower(): v for k, v in count.items()},
        "compliance_pct": round(100 * count[PASS] / evaluated, 1) if evaluated else 0.0,
        "expected_compared": len(compared),
        "expected_matched": sum(r["match"] == "YES" for r in compared),
    }


def _truncate(text, width):
    text = str(text)
    return text if len(text) <= width else text[:width - 3] + "..."


def print_table(rows, columns, title, footer="", color_keys=("status",)):
    """
    In bảng căn cột ra terminal.
    columns: danh sách (key, tiêu đề cột, độ rộng). Chỉ tô màu khi output là terminal.
    """
    color = sys.stdout.isatty()
    header = "  ".join(name.ljust(width) for _, name, width in columns)
    line = "-" * len(header)
    print(f"\n{title}\n{line}\n{header}\n{line}")

    for row in rows:
        cells = []
        for key, _, width in columns:
            value = row.get(key, "")
            cell = _truncate(value, width).ljust(width)
            if color and key in color_keys and value in _COLORS:
                cell = f"{_COLORS[value]}{cell}{_RESET}"
            cells.append(cell)
        print("  ".join(cells))

    print(line)
    if footer:
        print(footer)


def print_summary(rows, stats, title="CIS AUDIT SUMMARY"):
    """In bảng tổng hợp audit, mỗi CIS ID một dòng."""
    columns = [
        ("cis_id", "CIS", 6), ("title", "Title", 34), ("service", "Svc", 6),
        ("level", "Lvl", 3), ("checked", "Chk", 3), ("pass", "Pass", 4),
        ("fail", "Fail", 4), ("error", "Err", 3), ("status", "Status", 14),
    ]
    if any(r["expected"] for r in rows):
        columns += [("expected", "Expected", 8), ("match", "Match", 5)]
    columns += [("remediation", "Remediation", 11), ("failed_resources", "Failed resources", 40)]

    summary = (
        f"Total {stats['controls']} controls | PASS {stats['pass']} | FAIL {stats['fail']} | "
        f"ERROR {stats['error']} | N/A {stats['not_applicable']} | "
        f"Compliance {stats['compliance_pct']}%"
    )
    if stats["expected_compared"]:
        summary += f" | Khớp kỳ vọng {stats['expected_matched']}/{stats['expected_compared']}"
    print_table(rows, columns, title, summary)


def make_report_dir(base="reports"):
    path = os.path.join(base, datetime.now().strftime("%Y%m%d_%H%M%S"))
    os.makedirs(path, exist_ok=True)
    return path


def latest_report_dir(base="reports"):
    """Thư mục report mới nhất, dùng cho remediation khi không chỉ định."""
    if not os.path.isdir(base):
        return None
    dirs = sorted(d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d)))
    return os.path.join(base, dirs[-1]) if dirs else None


def write_csv(rows, path, fields=SUMMARY_FIELDS):
    # utf-8-sig để Excel mở đúng tiếng Việt
    with open(path, "w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(data, path):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False, default=str)


def load_expected(source):
    """
    Đọc ma trận kết quả kỳ vọng do Terraform xuất ra.
    source có thể là:
      - file JSON từ `terraform output -json cis_automated_matrix`
      - file JSON từ `terraform output -json` (toàn bộ outputs)
      - thư mục Terraform: tự chạy `terraform output -json cis_automated_matrix`
    """
    if os.path.isdir(source):
        raw = subprocess.run(
            ["terraform", f"-chdir={source}", "output", "-json", "cis_automated_matrix"],
            check=True, capture_output=True, text=True,
        ).stdout
        data = json.loads(raw)
    else:
        with open(source, encoding="utf-8") as file:
            data = json.load(file)

    if "cis_automated_matrix" in data:
        data = data["cis_automated_matrix"]["value"]
    return data
