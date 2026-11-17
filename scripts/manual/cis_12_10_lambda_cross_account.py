#!/usr/bin/env python3
"""
CIS AWS Compute Services Benchmark v2.0.0
Recommendation 12.10: Ensure Lambda functions do not allow unknown cross account access via permission policies. (Manual / Scripted)

Luồng thực hiện theo báo cáo (Mục 2.2.3 - Trang 16 -> 26) và CIS Benchmark (Trang 207-208):
- Bước 3: Kiểm tra quyền truy cập (aws sts get-caller-identity)
- Bước 4: Thu thập danh sách tất cả Lambda functions trong region bằng Boto3,
          gọi get_policy(FunctionName=...) để kiểm tra Resource-based policy của từng hàm:
    + Theo CIS 12.10 (Trang 207-208):
      * Kiểm tra phần tử 'Principal' trong mỗi Statement của Policy.
      * Nếu hàm không có Resource-based policy (ResourceNotFoundException) -> PASS (không cấp quyền cross-account).
      * Nếu có Statement cho phép Principal là '*' (công khai) hoặc chứa AWS Account ID không nằm trong danh sách
        trusted_accounts đã phê duyệt -> FAIL.
      * Nếu tất cả Principal đều thuộc danh sách AWS Account được phê duyệt (hoặc dịch vụ AWS hợp lệ kèm SourceAccount) -> PASS.
- Bước 5: Thực hiện Remediation đối với các Statement vi phạm:
    + Gọi remove_permission(FunctionName=..., StatementId=...) để gỡ bỏ quyền cross-account không xác định,
      và (nếu cần) gắn lại quyền chuẩn chỉ cho phép AWS Account nội bộ được phê duyệt.
- Bước 6: Kiểm tra lại sau Remediation (Verification)
- Bước 7: Tổng hợp kết quả và xuất báo cáo (JSON & CSV)
"""

import argparse
import csv
import json
import os
import re
from datetime import datetime, timezone
import boto3
from botocore.exceptions import BotoCoreError, ClientError

CIS_ID = "12.10"
CIS_TITLE = "Ensure Lambda functions do not allow unknown cross account access via permission policies."
ACCOUNT_ID_REGEX = re.compile(r"\b(\d{12})\b")


def check_caller_identity(session: boto3.Session) -> dict:
    """Bước 3: Kiểm tra danh tính AWS trước khi gọi API."""
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    return {
        "UserId": identity.get("UserId"),
        "Account": identity.get("Account"),
        "Arn": identity.get("Arn"),
    }


def extract_principals_from_statement(stmt: dict) -> list[str]:
    """Trích xuất danh sách các giá trị Principal từ một Statement của Lambda Policy."""
    principals = []
    principal = stmt.get("Principal")
    if isinstance(principal, str):
        principals.append(principal)
    elif isinstance(principal, dict):
        for _, v in principal.items():
            if isinstance(v, str):
                principals.append(v)
            elif isinstance(v, list):
                principals.extend(str(x) for x in v)
    return principals


def is_statement_compliant(stmt: dict, trusted_accounts: set[str]) -> tuple[bool, str]:
    """
    Kiểm tra xem một Statement trong Resource-based Policy của Lambda có tuân thủ CIS 12.10 không.
    Trả về (is_compliant, reason).
    """
    if stmt.get("Effect") != "Allow":
        return True, "Effect != Allow"

    principals = extract_principals_from_statement(stmt)
    cond = stmt.get("Condition", {})
    cond_str = json.dumps(cond)

    for p in principals:
        if p == "*":
            # Cho phép '*' nếu có điều kiện giới hạn chặt về trusted account
            if any(acc in cond_str for acc in trusted_accounts):
                continue
            return False, f"Principal='*' (cho phép mọi tài khoản/public)"

        # Kiểm tra nếu Principal chứa mã tài khoản AWS 12 chữ số
        matches = ACCOUNT_ID_REGEX.findall(p)
        for acc_id in matches:
            if acc_id not in trusted_accounts:
                return (
                    False,
                    f"Principal '{p}' thuộc AWS Account lạ chưa phê duyệt ({acc_id})",
                )

    return True, "Principal thuộc tài khoản AWS được phê duyệt"


def audit_lambda_cross_account_access(
    lambda_client, trusted_accounts: set[str]
) -> list[dict]:
    """
    Bước 4: Kiểm tra Resource-based policy của tất cả Lambda functions
    theo đúng hướng dẫn CLI trang 207-208 sách CIS Benchmark:
    1. aws lambda list-functions --output table --query "Functions[*].FunctionName"
    2. aws lambda get-policy --function-name <name> --output text --query "Policy"
    3. Kiểm tra phần tử "Principal" trong từng Statement.
    """
    results = []
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        paginator = lambda_client.get_paginator("list_functions")
        functions = []
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))

        if not functions:
            results.append(
                {
                    "cis_id": CIS_ID,
                    "check": CIS_TITLE,
                    "resource_type": "Lambda_Function",
                    "resource_id": "NONE",
                    "non_compliant_sids": [],
                    "principals": [],
                    "status": "NOT_APPLICABLE",
                    "details": "Không có Lambda function nào trong region này.",
                    "timestamp": timestamp,
                }
            )
            return results

        for fn in functions:
            fn_name = fn["FunctionName"]
            try:
                pol_resp = lambda_client.get_policy(FunctionName=fn_name)
                policy_str = pol_resp.get("Policy", "{}")
                policy_doc = json.loads(policy_str)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    results.append(
                        {
                            "cis_id": CIS_ID,
                            "check": CIS_TITLE,
                            "resource_type": "Lambda_Function",
                            "resource_id": fn_name,
                            "non_compliant_sids": [],
                            "principals": [],
                            "status": "PASS",
                            "details": (
                                f"Lambda function '{fn_name}' không có Resource-based policy "
                                f"(mặc định từ chối mọi truy cập cross-account)."
                            ),
                            "timestamp": timestamp,
                        }
                    )
                    continue
                raise

            statements = policy_doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            non_compliant_sids = []
            reasons = []
            all_principals = []

            for stmt in statements:
                sid = stmt.get("Sid", "UNKNOWN_SID")
                all_principals.extend(extract_principals_from_statement(stmt))
                ok, reason = is_statement_compliant(stmt, trusted_accounts)
                if not ok:
                    non_compliant_sids.append(sid)
                    reasons.append(f"Sid={sid}: {reason}")

            if non_compliant_sids:
                status = "FAIL"
                details = (
                    f"Lambda function '{fn_name}' cấp quyền truy cập liên tài khoản không được phê duyệt: "
                    f"{'; '.join(reasons)}"
                )
            else:
                status = "PASS"
                details = (
                    f"Lambda function '{fn_name}' chỉ cấp quyền trong Resource-based policy "
                    f"cho các Principal hợp lệ/được phê duyệt: {all_principals}."
                )

            results.append(
                {
                    "cis_id": CIS_ID,
                    "check": CIS_TITLE,
                    "resource_type": "Lambda_Function",
                    "resource_id": fn_name,
                    "non_compliant_sids": non_compliant_sids,
                    "principals": all_principals,
                    "status": status,
                    "details": details,
                    "timestamp": timestamp,
                }
            )

    except (BotoCoreError, ClientError) as exc:
        results.append(
            {
                "cis_id": CIS_ID,
                "check": CIS_TITLE,
                "resource_type": "Lambda_Function",
                "resource_id": "UNKNOWN",
                "non_compliant_sids": [],
                "principals": [],
                "status": "ERROR",
                "details": f"Lỗi khi gọi AWS Lambda API: {exc}",
                "timestamp": timestamp,
            }
        )

    return results


def remediate_lambda_cross_account_access(
    lambda_client,
    owner_account_id: str,
    audit_results: list[dict],
    dry_run: bool = False,
) -> list[dict]:
    """
    Bước 5: Xoá các policy statement cho phép tài khoản AWS lạ (remove_permission)
    và thêm lại permission chỉ cho phép tài khoản chủ sở hữu đã được phê duyệt (add_permission).
    """
    actions = []

    for item in audit_results:
        if item["status"] != "FAIL":
            continue

        fn_name = item["resource_id"]
        bad_sids = item.get("non_compliant_sids", [])

        try:
            if not dry_run:
                for sid in bad_sids:
                    lambda_client.remove_permission(
                        FunctionName=fn_name, StatementId=sid
                    )

                # Đảm bảo có 1 statement chuẩn chỉ cấp quyền cho chính AWS Account nội bộ đã phê duyệt
                try:
                    lambda_client.add_permission(
                        FunctionName=fn_name,
                        StatementId="AllowTrustedOrganizationAccount",
                        Action="lambda:InvokeFunction",
                        Principal=owner_account_id,
                    )
                except ClientError as e:
                    if e.response["Error"]["Code"] != "ResourceConflictException":
                        raise

            actions.append(
                {
                    "resource_id": fn_name,
                    "resource_type": "Lambda_Function",
                    "action": "remove_unknown_cross_account_permissions",
                    "status": "DRY_RUN" if dry_run else "SUCCESS",
                    "details": (
                        f"Đã xoá các statement vi phạm {bad_sids} khỏi Lambda '{fn_name}' "
                        f"và chỉ cấp quyền cho AWS Account được phê duyệt ({owner_account_id})."
                    ),
                }
            )
        except (BotoCoreError, ClientError) as exc:
            actions.append(
                {
                    "resource_id": fn_name,
                    "resource_type": "Lambda_Function",
                    "action": "remove_unknown_cross_account_permissions",
                    "status": "ERROR",
                    "details": f"Không thể cập nhật permission policy cho '{fn_name}': {exc}",
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
        "initial_principals",
        "initial_status",
        "initial_details",
        "remediation_action",
        "remediation_status",
        "final_principals",
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
                    "initial_principals": json.dumps(init_rec.get("principals", [])),
                    "initial_status": init_rec.get("status"),
                    "initial_details": init_rec.get("details"),
                    "remediation_action": act_rec.get("action", "NONE"),
                    "remediation_status": act_rec.get("status", "NOT_EXECUTED"),
                    "final_principals": json.dumps(
                        fin_rec.get("principals", init_rec.get("principals", []))
                    ),
                    "final_status": fin_rec.get("status", init_rec.get("status")),
                    "final_details": fin_rec.get("details", init_rec.get("details")),
                    "timestamp": fin_rec.get("timestamp", init_rec.get("timestamp")),
                }
            )


def main():
    parser = argparse.ArgumentParser(
        description="CIS 12.10 - Audit & Remediation: Ensure Lambda functions do not allow unknown cross account access"
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
        "--trusted-accounts",
        nargs="*",
        default=[],
        help="Danh sách các AWS Account ID (12 chữ số) được phê duyệt (mặc định: Account hiện tại)",
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
    lambda_client = session.client("lambda")

    print(f"[*] Bước 3: Kiểm tra danh tính kết nối AWS (Region: {args.region})...")
    try:
        caller_identity = check_caller_identity(session)
        print(f"    -> Đã xác thực với ARN: {caller_identity['Arn']}")
    except (BotoCoreError, ClientError) as exc:
        print(f"[!] Lỗi xác thực AWS CLI/Boto3: {exc}")
        return

    trusted_set = set(args.trusted_accounts)
    trusted_set.add(caller_identity["Account"])

    print(f"\n[*] Bước 4: Thu thập cấu hình và đánh giá tuân thủ CIS {CIS_ID} (Trusted Accounts: {sorted(trusted_set)})...")
    initial_audit = audit_lambda_cross_account_access(lambda_client, trusted_set)
    for res in initial_audit:
        print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")

    remediation_actions = []
    post_remediation_audit = []

    has_failures = any(r["status"] == "FAIL" for r in initial_audit)

    if args.mode == "remediate" and has_failures:
        print(f"\n[*] Bước 5: Thực hiện Remediation cho CIS {CIS_ID} (dry_run={args.dry_run})...")
        remediation_actions = remediate_lambda_cross_account_access(
            lambda_client,
            caller_identity["Account"],
            initial_audit,
            dry_run=args.dry_run,
        )
        for act in remediation_actions:
            print(f"    - [{act['status']}] {act['action']} ({act['resource_id']}): {act['details']}")

        print(f"\n[*] Bước 6: Kiểm tra lại (Verification) sau khi Remediation...")
        post_remediation_audit = audit_lambda_cross_account_access(
            lambda_client, trusted_set
        )
        for res in post_remediation_audit:
            print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")
    elif args.mode == "remediate" and not has_failures:
        print("\n[*] Tất cả Lambda functions đã đạt chuẩn CIS 12.10, không cần Remediation.")

    report_data = {
        "cis_benchmark": "CIS AWS Compute Services Benchmark v2.0.0",
        "cis_id": CIS_ID,
        "title": CIS_TITLE,
        "region": args.region,
        "mode": args.mode,
        "trusted_accounts": sorted(trusted_set),
        "caller_identity": caller_identity,
        "execution_time": datetime.now(timezone.utc).isoformat(),
        "initial_audit": initial_audit,
        "remediation_actions": remediation_actions,
        "post_remediation_audit": post_remediation_audit,
    }

    json_path = os.path.join(args.output_dir, "cis_12_10_report.json")
    csv_path = os.path.join(args.output_dir, "cis_12_10_report.csv")
    export_reports(report_data, json_path, csv_path)

    print(f"\n[*] Bước 7: Đã xuất báo cáo kết quả tại:")
    print(f"    - JSON: {json_path}")
    print(f"    - CSV : {csv_path}")


if __name__ == "__main__":
    main()
