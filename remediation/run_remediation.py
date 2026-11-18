"""
Remediation cho các khuyến nghị CIS bị FAIL trong một lần audit.

Mặc định chỉ chạy DRY-RUN (lập kế hoạch, không thay đổi AWS).

Ví dụ:
    python -m remediation.run_remediation                       # dry-run trên report audit mới nhất
    python -m remediation.run_remediation --apply               # thực thi tier A và tạo bản thay thế tier B
    python -m remediation.run_remediation --apply --allow-destructive   # xoá luôn AMI/snapshot gốc (tier B)
    python -m remediation.run_remediation --only 2.2.2,3.4 --apply
"""
import argparse
import json
import os
import sys
from datetime import datetime

from audit.engine import run_audit
from audit.registry import CONTROLS, select_controls
from core.report import (
    latest_report_dir, print_summary, summarize, totals, write_csv, write_json,
)
from core.scope import parse_scope
from core.session import AwsSession
from remediation.engine import load_findings, remediate, verify
from remediation.summary import (
    SUMMARY_FIELDS, print_remediation_summary, print_resource_results, summarize_remediation,
)


def parse_args():
    parser = argparse.ArgumentParser(description="CIS AWS Compute Services - remediation")
    parser.add_argument("--report", help="Thư mục report audit (mặc định: mới nhất trong reports/)")
    parser.add_argument("--only", help="Chỉ xử lý các CIS ID này, vd: 2.2.2,3.4")
    parser.add_argument("--tag", action="append", metavar="KEY=VALUE",
                        help="Chỉ sửa tài nguyên có tag này (mặc định: scope của lần audit)")
    parser.add_argument("--all-resources", action="store_true",
                        help="Cho phép sửa mọi tài nguyên trong account (không lọc tag)")
    parser.add_argument("--apply", action="store_true", help="Thực thi thay đổi (mặc định chỉ dry-run)")
    parser.add_argument("--allow-destructive", action="store_true",
                        help="Tier B: xoá AMI/snapshot gốc sau khi tạo bản mã hóa")
    parser.add_argument("--yes", action="store_true", help="Không hỏi xác nhận khi --apply")
    parser.add_argument("--no-reaudit", action="store_true", help="Bỏ qua bước audit lại toàn bộ sau khi sửa")
    parser.add_argument("--profile", help="AWS CLI profile")
    return parser.parse_args()


def resolve_scope(args, audit_meta):
    """
    Remediation thay đổi tài nguyên thật nên bắt buộc có phạm vi:
    --tag > scope của lần audit > --all-resources (phải chỉ định rõ).
    """
    scope = parse_scope(args.tag) or audit_meta.get("scope") or {}
    if not scope and not args.all_resources:
        sys.exit("Từ chối chạy: không có scope tag. Dùng --tag Project=computebench "
                 "hoặc --all-resources nếu thật sự muốn sửa toàn bộ account.")
    return scope


def confirm(plan_results):
    actionable = [r for r in plan_results if r.status == "PLANNED"]
    print(f"\nSẽ thay đổi {len(actionable)} tài nguyên trên AWS.")
    answer = input("Nhập 'yes' để tiếp tục: ").strip().lower()
    if answer != "yes":
        sys.exit("Đã huỷ, không có thay đổi nào.")


def main():
    args = parse_args()
    report_dir = args.report or latest_report_dir()
    if not report_dir:
        sys.exit("Không tìm thấy report audit. Chạy `python -m audit.run_audit` trước.")

    with open(os.path.join(report_dir, "audit_details.json"), encoding="utf-8") as file:
        audit = json.load(file)
    findings = load_findings(audit)
    controls = select_controls(args.only.split(",") if args.only else None)
    scope = resolve_scope(args, audit)

    aws = AwsSession(profile=args.profile)
    if aws.account_id != audit["account_id"]:
        sys.exit(f"Report thuộc account {audit['account_id']} nhưng credential hiện tại là "
                 f"{aws.account_id}. Dừng để tránh sửa nhầm account.")

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"Report: {report_dir} | Account: {aws.account_id} | Mode: {mode} | "
          f"Destructive: {args.allow_destructive} | Scope: {scope or 'toàn bộ account'}")

    def progress(control, finding):
        print(f"  [{control.cis_id}] {finding.resource_name or finding.resource_id}", file=sys.stderr)

    # Bước 1: luôn lập kế hoạch trước (EC2 dùng DryRun=True để kiểm tra quyền)
    plan = remediate(aws, findings, controls, scope, dry_run=True,
                     allow_destructive=args.allow_destructive, progress=progress)
    print_resource_results(plan, f"REMEDIATION PLAN ({len(plan)} tài nguyên FAIL)")

    results, post_findings = plan, None
    if args.apply:
        if not args.yes:
            confirm(plan)
        # Bước 2: thực thi
        results = remediate(aws, findings, controls, scope, dry_run=False,
                            allow_destructive=args.allow_destructive, progress=progress)
        # Bước 3: verify bằng chính hàm check của audit
        results = verify(aws, results, controls, scope)
        print_resource_results(results, "REMEDIATION RESULT")

        # Bước 4: audit lại toàn bộ để so sánh trước/sau
        if not args.no_reaudit:
            post_findings = run_audit(aws, audit["regions"], CONTROLS, scope)

    rows = summarize_remediation(results, controls, findings, post_findings)
    print_remediation_summary(rows, f"REMEDIATION SUMMARY ({mode})", args.apply)

    out_dir = os.path.join(report_dir, f"remediation_{datetime.now():%Y%m%d_%H%M%S}_{mode.lower()}")
    os.makedirs(out_dir, exist_ok=True)
    meta = {"audit_report": report_dir, "account_id": aws.account_id, "mode": mode,
            "allow_destructive": args.allow_destructive, "scope": scope}
    write_csv(rows, os.path.join(out_dir, "remediation_summary.csv"), SUMMARY_FIELDS)
    write_json({**meta, "results": [r.to_dict() for r in results]},
               os.path.join(out_dir, "remediation_details.json"))

    if post_findings is not None:
        before_stats = totals(summarize(findings, CONTROLS))
        post_rows = summarize(post_findings, CONTROLS)
        post_stats = totals(post_rows)
        print_summary(post_rows, post_stats, "AUDIT SAU REMEDIATION")
        print(f"Compliance: {before_stats['compliance_pct']}% -> {post_stats['compliance_pct']}% "
              f"(PASS {before_stats['pass']} -> {post_stats['pass']} / {post_stats['controls']})")
        write_csv(post_rows, os.path.join(out_dir, "post_audit_summary.csv"))
        write_json({**meta, "totals": post_stats, "findings": [f.to_dict() for f in post_findings]},
                   os.path.join(out_dir, "post_audit_details.json"))

    print(f"\nĐã lưu: {out_dir}/")


if __name__ == "__main__":
    main()
