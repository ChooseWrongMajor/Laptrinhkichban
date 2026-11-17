#!/usr/bin/env python3
"""
CIS AWS Compute Services Benchmark v2.0.0
Recommendation 8.2: Ensure Batch roles are configured for cross-service confused deputy prevention (Manual / Scripted)

Luồng thực hiện theo báo cáo (Mục 2.2.3 - Trang 16 -> 26) và CIS Benchmark (Trang 165-167):
- Bước 3: Kiểm tra quyền truy cập (aws sts get-caller-identity)
- Bước 4: Thu thập danh sách IAM Roles có Principal Service là 'batch.amazonaws.com' bằng Boto3,
          và kiểm tra AssumeRolePolicyDocument (Trust Policy):
    + Theo CIS 8.2 (Trang 165-166):
      * Statement cho phép 'batch.amazonaws.com' thực hiện 'sts:AssumeRole' bắt buộc phải có Condition
        chứa khóa 'aws:SourceArn' với ARN cụ thể của tài nguyên Batch (không chứa dấu '*' ở cuối ARN).
      * PASS: Có Condition 'aws:SourceArn' chứa ARN đầy đủ (không có wildcard '*').
      * FAIL: Không có Condition 'aws:SourceArn' hoặc 'aws:SourceArn' chứa dấu '*'.
- Bước 5: Thực hiện Remediation đối với các IAM Role của AWS Batch bị FAIL:
    + Cập nhật AssumeRolePolicyDocument bổ sung Condition 'aws:SourceArn' cụ thể và 'aws:SourceAccount'
      bằng update_assume_role_policy.
- Bước 6: Kiểm tra lại sau Remediation (Verification)
- Bước 7: Tổng hợp kết quả và xuất báo cáo (JSON & CSV)
"""

import argparse
import csv
import json
import os
from datetime import datetime, timezone
import boto3
from botocore.exceptions import BotoCoreError, ClientError

CIS_ID = "8.2"
CIS_TITLE = "Ensure Batch roles are configured for cross-service confused deputy prevention"


def check_caller_identity(session: boto3.Session) -> dict:
    """Bước 3: Kiểm tra danh tính AWS trước khi gọi API."""
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    return {
        "UserId": identity.get("UserId"),
        "Account": identity.get("Account"),
        "Arn": identity.get("Arn"),
    }


def is_batch_trust_statement(stmt: dict) -> bool:
    """Kiểm tra xem Statement trong Trust Policy có phải cho phép batch.amazonaws.com AssumeRole không."""
    if stmt.get("Effect") != "Allow":
        return False
    principal = stmt.get("Principal", {})
    if isinstance(principal, dict):
        svc = principal.get("Service", "")
        if isinstance(svc, str):
            return "batch.amazonaws.com" in svc
        if isinstance(svc, list):
            return any("batch.amazonaws.com" in s for s in svc)
    return False


def extract_source_arns(condition: dict) -> list[str]:
    """Trích xuất danh sách giá trị của aws:SourceArn từ khối Condition."""
    arns = []
    if not isinstance(condition, dict):
        return arns

    for op_key in ("ArnLike", "ArnEquals", "StringEquals", "StringLike"):
        op_block = condition.get(op_key, {})
        if isinstance(op_block, dict):
            for k, v in op_block.items():
                if k.lower() == "aws:sourcearn":
                    if isinstance(v, str):
                        arns.append(v)
                    elif isinstance(v, list):
                        arns.extend(str(item) for item in v)
    return arns


def audit_batch_roles(iam_client) -> list[dict]:
    """
    Bước 4: Tìm tất cả IAM Role gắn với dịch vụ AWS Batch (batch.amazonaws.com)
    và kiểm tra điều kiện chống lỗ hổng Cross-Service Confused Deputy (Trang 165-166 sách CIS).
    """
    results = []
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        paginator = iam_client.get_paginator("list_roles")
        batch_roles_found = False

        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                role_arn = role["Arn"]
                # Bỏ qua AWS Service-Linked Role do AWS quản lý cứng (nằm trong đường dẫn /aws-service-role/)
                if "/aws-service-role/" in role.get("Path", ""):
                    continue

                policy_doc = role.get("AssumeRolePolicyDocument", {})
                statements = policy_doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                batch_stmts = [s for s in statements if is_batch_trust_statement(s)]
                if not batch_stmts:
                    continue

                batch_roles_found = True
                role_compliant = True
                reasons = []
                collected_source_arns = []

                for stmt in batch_stmts:
                    cond = stmt.get("Condition", {})
                    src_arns = extract_source_arns(cond)
                    collected_source_arns.extend(src_arns)

                    if not src_arns:
                        role_compliant = False
                        reasons.append("Thiếu điều kiện Condition 'aws:SourceArn'")
                    elif any("*" in arn for arn in src_arns):
                        role_compliant = False
                        reasons.append(
                            f"Điều kiện 'aws:SourceArn' chứa ký tự đại diện '*': {src_arns}"
                        )

                if role_compliant:
                    status = "PASS"
                    details = (
                        f"IAM Role '{role_name}' của AWS Batch đã cấu hình chống Confused Deputy "
                        f"đạt chuẩn với aws:SourceArn = {collected_source_arns}."
                    )
                else:
                    status = "FAIL"
                    details = (
                        f"IAM Role '{role_name}' của AWS Batch chưa đạt chuẩn CIS 8.2: "
                        f"{'; '.join(reasons)}."
                    )

                results.append(
                    {
                        "cis_id": CIS_ID,
                        "check": CIS_TITLE,
                        "resource_type": "IAM_Role",
                        "resource_id": role_name,
                        "role_arn": role_arn,
                        "source_arns": collected_source_arns,
                        "status": status,
                        "details": details,
                        "timestamp": timestamp,
                    }
                )

        if not batch_roles_found:
            results.append(
                {
                    "cis_id": CIS_ID,
                    "check": CIS_TITLE,
                    "resource_type": "IAM_Role",
                    "resource_id": "NONE",
                    "role_arn": "N/A",
                    "source_arns": [],
                    "status": "NOT_APPLICABLE",
                    "details": "Không tìm thấy IAM Role khách hàng quản lý nào cho dịch vụ AWS Batch.",
                    "timestamp": timestamp,
                }
            )

    except (BotoCoreError, ClientError) as exc:
        results.append(
            {
                "cis_id": CIS_ID,
                "check": CIS_TITLE,
                "resource_type": "IAM_Role",
                "resource_id": "UNKNOWN",
                "role_arn": "N/A",
                "source_arns": [],
                "status": "ERROR",
                "details": f"Lỗi khi gọi AWS IAM API: {exc}",
                "timestamp": timestamp,
            }
        )

    return results


def remediate_batch_roles(
    iam_client,
    account_id: str,
    region: str,
    compute_env_name: str,
    audit_results: list[dict],
    dry_run: bool = False,
) -> list[dict]:
    """
    Bước 5: Khắc phục các IAM Role của AWS Batch bị FAIL bằng cách cập nhật Trust Policy
    chứa đầy đủ Condition ArnLike -> aws:SourceArn (không có '*') theo đúng mẫu trang 166 sách CIS.
    """
    actions = []
    specific_source_arn = (
        f"arn:aws:batch:{region}:{account_id}:compute-environment/{compute_env_name}"
    )

    compliant_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "batch.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": [specific_source_arn]},
                },
            }
        ],
    }

    for item in audit_results:
        if item["status"] != "FAIL":
            continue

        role_name = item["resource_id"]
        try:
            if not dry_run:
                iam_client.update_assume_role_policy(
                    RoleName=role_name,
                    PolicyDocument=json.dumps(compliant_trust_policy),
                )

            actions.append(
                {
                    "resource_id": role_name,
                    "resource_type": "IAM_Role",
                    "action": "update_batch_role_trust_policy_confused_deputy",
                    "status": "DRY_RUN" if dry_run else "SUCCESS",
                    "details": (
                        f"Đã cập nhật Trust Policy cho IAM Role '{role_name}' với "
                        f"aws:SourceArn=['{specific_source_arn}'] và aws:SourceAccount='{account_id}'."
                    ),
                }
            )
        except (BotoCoreError, ClientError) as exc:
            actions.append(
                {
                    "resource_id": role_name,
                    "resource_type": "IAM_Role",
                    "action": "update_batch_role_trust_policy_confused_deputy",
                    "status": "ERROR",
                    "details": f"Không thể cập nhật Trust Policy cho Role '{role_name}': {exc}",
                }
            )

    return actions


def export_reports(report_data: dict, json_path: str, csv_path: str) -> None:
    """Bước 7: Xuất kết quả kiểm tra ra định dạng JSON và CSV."""
    os.makedirs(os.path.dirname(json_path), exist_ok=True)

    with open(json_path, "w", encoding="utf-8") as f_json:
        json.dump(report_data, f_json, ensure_ascii=False, indent=2)

    initial_map = {
        r["resource_id"]: r for r in report_data.get("initial_audit", [])
    }
    final_map = {
        r["resource_id"]: r for r in report_data.get("post_remediation_audit", [])
    }
    action_map = {
        a["resource_id"]: a for a in report_data.get("remediation_actions", [])
    }

    fieldnames = [
        "cis_id",
        "check_name",
        "resource_id",
        "initial_source_arns",
        "initial_status",
        "initial_details",
        "remediation_action",
        "remediation_status",
        "final_source_arns",
        "final_status",
        "final_details",
        "timestamp",
    ]

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=fieldnames)
        writer.writeheader()

        for res_id, init_rec in initial_map.items():
            act_rec = action_map.get(res_id, {})
            fin_rec = final_map.get(res_id, {})
            writer.writerow(
                {
                    "cis_id": init_rec.get("cis_id", CIS_ID),
                    "check_name": init_rec.get("check", CIS_TITLE),
                    "resource_id": res_id,
                    "initial_source_arns": json.dumps(init_rec.get("source_arns", [])),
                    "initial_status": init_rec.get("status"),
                    "initial_details": init_rec.get("details"),
                    "remediation_action": act_rec.get("action", "NONE"),
                    "remediation_status": act_rec.get("status", "NOT_EXECUTED"),
                    "final_source_arns": json.dumps(
                        fin_rec.get("source_arns", init_rec.get("source_arns", []))
                    ),
                    "final_status": fin_rec.get("status", init_rec.get("status")),
                    "final_details": fin_rec.get("details", init_rec.get("details")),
                    "timestamp": fin_rec.get("timestamp", init_rec.get("timestamp")),
                }
            )


def main():
    parser = argparse.ArgumentParser(
        description="CIS 8.2 - Audit & Remediation: Ensure Batch roles are configured for cross-service confused deputy prevention"
    )
    parser.add_argument(
        "--region",
        default="ap-southeast-1",
        help="AWS Region cần kiểm tra (mặc định: ap-southeast-1)",
    )
    parser.add_argument(
        "--mode",
        choices=["audit", "remediate"],
        default="audit",
        help="Chế độ chạy: 'audit' (Audit-only) hoặc 'remediate' (Audit-and-remediate)",
    )
    parser.add_argument(
        "--compute-env-name",
        default="testCE",
        help="Tên AWS Batch Compute Environment cụ thể dùng trong aws:SourceArn (mặc định: testCE theo trang 166 sách CIS)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Chạy thử nghiệm Remediation nhưng không thay đổi thực tế trên AWS",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Thư mục xuất file báo cáo JSON/CSV",
    )
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region)
    iam_client = session.client("iam")

    print(f"[*] Bước 3: Kiểm tra danh tính kết nối AWS (Region: {args.region})...")
    try:
        caller_identity = check_caller_identity(session)
        print(f"    -> Đã xác thực với ARN: {caller_identity['Arn']}")
    except (BotoCoreError, ClientError) as exc:
        print(f"[!] Lỗi xác thực AWS CLI/Boto3: {exc}")
        return

    print(f"\n[*] Bước 4: Thu thập cấu hình và đánh giá tuân thủ CIS {CIS_ID}...")
    initial_audit = audit_batch_roles(iam_client)
    for res in initial_audit:
        print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")

    remediation_actions = []
    post_remediation_audit = []

    has_failures = any(r["status"] == "FAIL" for r in initial_audit)

    if args.mode == "remediate" and has_failures:
        print(f"\n[*] Bước 5: Thực hiện Remediation cho CIS {CIS_ID} (dry_run={args.dry_run})...")
        remediation_actions = remediate_batch_roles(
            iam_client,
            caller_identity["Account"],
            args.region,
            args.compute_env_name,
            initial_audit,
            dry_run=args.dry_run,
        )
        for act in remediation_actions:
            print(f"    - [{act['status']}] {act['action']} ({act['resource_id']}): {act['details']}")

        print(f"\n[*] Bước 6: Kiểm tra lại (Verification) sau khi Remediation...")
        post_remediation_audit = audit_batch_roles(iam_client)
        for res in post_remediation_audit:
            print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")
    elif args.mode == "remediate" and not has_failures:
        print("\n[*] Tất cả IAM Role của AWS Batch đã đạt chuẩn CIS 8.2, không cần Remediation.")

    report_data = {
        "cis_benchmark": "CIS AWS Compute Services Benchmark v2.0.0",
        "cis_id": CIS_ID,
        "title": CIS_TITLE,
        "region": args.region,
        "mode": args.mode,
        "caller_identity": caller_identity,
        "execution_time": datetime.now(timezone.utc).isoformat(),
        "initial_audit": initial_audit,
        "remediation_actions": remediation_actions,
        "post_remediation_audit": post_remediation_audit,
    }

    json_path = os.path.join(args.output_dir, "cis_8_2_report.json")
    csv_path = os.path.join(args.output_dir, "cis_8_2_report.csv")
    export_reports(report_data, json_path, csv_path)

    print(f"\n[*] Bước 7: Đã xuất báo cáo kết quả tại:")
    print(f"    - JSON: {json_path}")
    print(f"    - CSV : {csv_path}")


if __name__ == "__main__":
    main()
