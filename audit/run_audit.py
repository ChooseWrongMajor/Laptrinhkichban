"""
Audit tự động 15 khuyến nghị CIS AWS Compute Services Benchmark v2.0.0.

Ví dụ:
    python -m audit.run_audit
    python -m audit.run_audit --tag Project=computebench --expected infrastructure
    python -m audit.run_audit --only 2.2.1,3.4 --regions us-east-1,ap-southeast-1
"""
import argparse
import os
import sys
from datetime import datetime, timezone

from audit.engine import run_audit
from audit.registry import select_controls
from core.models import FAIL
from core.report import (
    load_expected, make_report_dir, print_summary, summarize, totals,
    write_csv, write_json,
)
from core.scope import parse_scope
from core.session import AwsSession


def parse_args():
    parser = argparse.ArgumentParser(description="CIS AWS Compute Services - automated audit")
    parser.add_argument("--profile", help="AWS CLI profile")
    parser.add_argument("--regions", help="Danh sách region, phân tách bằng dấu phẩy "
                                          "(mặc định: region của profile)")
    parser.add_argument("--only", help="Chỉ chạy các CIS ID này, vd: 2.2.1,3.4")
    parser.add_argument("--tag", action="append", metavar="KEY=VALUE",
                        help="Chỉ audit tài nguyên có tag này (lặp lại được)")
    parser.add_argument("--expected", metavar="PATH",
                        help="File JSON hoặc thư mục Terraform chứa output cis_automated_matrix")
    parser.add_argument("--out-dir", default="reports", help="Thư mục gốc lưu report")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Trả exit code 1 nếu có control FAIL (dùng cho CI)")
    return parser.parse_args()


def main():
    args = parse_args()
    scope = parse_scope(args.tag)
    controls = select_controls(args.only.split(",") if args.only else None)

    aws = AwsSession(profile=args.profile)
    regions = args.regions.split(",") if args.regions else [aws.default_region]
    expected = load_expected(args.expected) if args.expected else None

    print(f"Account: {aws.account_id} | Regions: {', '.join(regions)} | "
          f"Controls: {len(controls)} | Scope: {scope or 'toàn bộ tài nguyên'}")

    def progress(region, control):
        print(f"  [{region}] {control.cis_id:<6} {control.title}", file=sys.stderr)

    started = datetime.now(timezone.utc)
    findings = run_audit(aws, regions, controls, scope, progress)

    rows = summarize(findings, controls, expected)
    stats = totals(rows)
    print_summary(rows, stats)

    report_dir = make_report_dir(args.out_dir)
    meta = {
        "account_id": aws.account_id,
        "regions": regions,
        "scope": scope,
        "started_at": started.isoformat(timespec="seconds"),
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "benchmark": "CIS AWS Compute Services Benchmark v2.0.0",
    }
    write_csv(rows, os.path.join(report_dir, "audit_summary.csv"))
    write_json({**meta, "totals": stats, "summary": rows},
               os.path.join(report_dir, "audit_summary.json"))
    write_json({**meta, "findings": [f.to_dict() for f in findings]},
               os.path.join(report_dir, "audit_details.json"))
    print(f"\nĐã lưu report: {report_dir}/ (audit_summary.csv, audit_summary.json, audit_details.json)")

    if args.fail_on_findings and stats[FAIL.lower()]:
        sys.exit(1)


if __name__ == "__main__":
    main()
