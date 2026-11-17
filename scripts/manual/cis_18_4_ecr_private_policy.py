#!/usr/bin/env python3
"""
CIS AWS Compute Services Benchmark v2.0.0
Recommendation 18.4: Ensure private ECR repositories do not allow public access via resource policies (Manual / Scripted)

Luồng thực hiện theo báo cáo (Mục 2.2.3 - Trang 16 -> 26) và CIS Benchmark (Trang 243-245):
- Bước 3: Kiểm tra quyền truy cập (aws sts get-caller-identity)
- Bước 4: Thu thập danh sách tất cả Private ECR Repositories và kiểm tra Repository Policy + Registry Policy:
    + Theo CIS 18.4 (Trang 243-244):
      * Nếu Repository không có Policy (RepositoryPolicyNotFoundException) -> PASS (default-deny).
      * Nếu Repository có Policy, kiểm tra từng Statement:
        Repository bị tính là FAIL nếu có Statement thỏa mãn đồng thời:
        - Effect == 'Allow'
        - Principal là '*' hoặc {'AWS': '*'} (hoặc chứa '*')
        - Condition không tồn tại hoặc không giới hạn theo 'aws:PrincipalAccount', 'aws:PrincipalOrgID', 'aws:SourceVpce'.
      * Đồng thời kiểm tra Registry-wide Policy (get_registry_policy) với cùng tiêu chí.
- Bước 5: Thực hiện Remediation đối với các ECR Repository bị FAIL:
    + Giới hạn lại Principal trong Repository Policy chỉ cho phép tài khoản AWS nội bộ
      ('arn:aws:iam::<account_id>:root') hoặc xoá policy công khai.
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

CIS_ID = "18.4"
CIS_TITLE = "Ensure private ECR repositories do not allow public access via resource policies"
DEFAULT_REPO_NAME = "cis-compute-benchmark-private-repo"
RESTRICTIVE_CONDITION_KEYS = {
    "aws:principalaccount",
    "aws:principalorgid",
    "aws:sourcevpce",
    "aws:sourcevpc",
    "aws:sourceaccount",
}


def check_caller_identity(session: boto3.Session) -> dict:
    """Bước 3: Kiểm tra danh tính AWS trước khi gọi API."""
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    return {
        "UserId": identity.get("UserId"),
        "Account": identity.get("Account"),
        "Arn": identity.get("Arn"),
    }


def is_principal_wildcard(principal) -> bool:
    """Kiểm tra xem Principal có phải là '*' hoặc {'AWS': '*'} hay không."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for _, v in principal.items():
            if v == "*":
                return True
            if isinstance(v, list) and "*" in v:
                return True
    return False


def has_restrictive_condition(condition: dict) -> bool:
    """Kiểm tra xem khối Condition có chứa điều kiện giới hạn PrincipalAccount / PrincipalOrgID / SourceVpce không."""
    if not isinstance(condition, dict) or not condition:
        return False
    for _, cond_map in condition.items():
        if isinstance(cond_map, dict):
            for k in cond_map.keys():
                if k.lower() in RESTRICTIVE_CONDITION_KEYS:
                    return True
    return False


def evaluate_policy_statements(policy_doc: dict) -> tuple[bool, list[str], list]:
    """
    Đánh giá danh sách Statement của ECR Repository/Registry Policy theo tiêu chí trang 244 sách CIS.
    Trả về (is_compliant, offending_sids, all_principals).
    """
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    offending_sids = []
    principals = []

    for stmt in statements:
        sid = stmt.get("Sid", "UnnamedStatement")
        effect = stmt.get("Effect", "")
        principal = stmt.get("Principal")
        principals.append(principal)
        condition = stmt.get("Condition", {})

        if effect == "Allow" and is_principal_wildcard(principal):
            if not has_restrictive_condition(condition):
                offending_sids.append(sid)

    return len(offending_sids) == 0, offending_sids, principals


def audit_ecr_private_repositories(ecr_client) -> list[dict]:
    """
    Bước 4: Kiểm tra tất cả Private ECR Repositories và Registry Policy trong region
    theo đúng hướng dẫn CLI trang 243-244 sách CIS Benchmark:
    1. aws ecr describe-repositories --query 'repositories[].repositoryName'
    2. aws ecr get-repository-policy --repository-name <repo-name> --query 'policyText'
    3. aws ecr get-registry-policy --query 'policyText'
    """
    results = []
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        paginator = ecr_client.get_paginator("describe_repositories")
        repos = []
        for page in paginator.paginate():
            repos.extend(page.get("repositories", []))

        if not repos:
            results.append(
                {
                    "cis_id": CIS_ID,
                    "check": CIS_TITLE,
                    "resource_type": "ECR_Repository",
                    "resource_id": "NONE",
                    "principals": [],
                    "offending_sids": [],
                    "status": "NOT_APPLICABLE",
                    "details": "Không có Private ECR Repository nào trong region này.",
                    "timestamp": timestamp,
                }
            )
        else:
            for repo in repos:
                repo_name = repo["repositoryName"]
                try:
                    pol_resp = ecr_client.get_repository_policy(
                        repositoryName=repo_name
                    )
                    policy_text = pol_resp.get("policyText", "{}")
                    policy_doc = json.loads(policy_text)
                    is_ok, bad_sids, principals = evaluate_policy_statements(
                        policy_doc
                    )

                    if is_ok:
                        status = "PASS"
                        details = (
                            f"Private ECR Repository '{repo_name}' có Resource Policy an toàn, "
                            f"chỉ cấp quyền cho Principal cụ thể: {principals}."
                        )
                    else:
                        status = "FAIL"
                        details = (
                            f"Private ECR Repository '{repo_name}' cho phép truy cập công khai "
                            f"(Principal='*') tại các Statement Sid={bad_sids}."
                        )

                    results.append(
                        {
                            "cis_id": CIS_ID,
                            "check": CIS_TITLE,
                            "resource_type": "ECR_Repository",
                            "resource_id": repo_name,
                            "principals": principals,
                            "offending_sids": bad_sids,
                            "status": status,
                            "details": details,
                            "timestamp": timestamp,
                        }
                    )
                except ClientError as e:
                    if (
                        e.response["Error"]["Code"]
                        == "RepositoryPolicyNotFoundException"
                    ):
                        results.append(
                            {
                                "cis_id": CIS_ID,
                                "check": CIS_TITLE,
                                "resource_type": "ECR_Repository",
                                "resource_id": repo_name,
                                "principals": [],
                                "offending_sids": [],
                                "status": "PASS",
                                "details": (
                                    f"Private ECR Repository '{repo_name}' không gắn Resource Policy "
                                    f"(RepositoryPolicyNotFoundException -> Default-Deny đạt chuẩn PASS)."
                                ),
                                "timestamp": timestamp,
                            }
                        )
                    else:
                        raise

        # Bước 3 trang 244 sách CIS: Kiểm tra thêm Registry-wide Policy
        try:
            reg_pol = ecr_client.get_registry_policy()
            reg_doc = json.loads(reg_pol.get("policyText", "{}"))
            reg_ok, reg_bad_sids, reg_principals = evaluate_policy_statements(reg_doc)
            results.append(
                {
                    "cis_id": CIS_ID,
                    "check": f"{CIS_TITLE} (Registry-wide Policy)",
                    "resource_type": "ECR_Registry_Policy",
                    "resource_id": "ECR_PRIVATE_REGISTRY",
                    "principals": reg_principals,
                    "offending_sids": reg_bad_sids,
                    "status": "PASS" if reg_ok else "FAIL",
                    "details": (
                        "ECR Registry Policy đạt chuẩn."
                        if reg_ok
                        else f"ECR Registry Policy cho phép công khai tại Sid={reg_bad_sids}."
                    ),
                    "timestamp": timestamp,
                }
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "RegistryPolicyNotFoundException":
                results.append(
                    {
                        "cis_id": CIS_ID,
                        "check": f"{CIS_TITLE} (Registry-wide Policy)",
                        "resource_type": "ECR_Registry_Policy",
                        "resource_id": "ECR_PRIVATE_REGISTRY",
                        "principals": [],
                        "offending_sids": [],
                        "status": "PASS",
                        "details": "Không có ECR Registry-wide Policy (RegistryPolicyNotFoundException -> PASS).",
                        "timestamp": timestamp,
                    }
                )
            else:
                raise

    except (BotoCoreError, ClientError) as exc:
        results.append(
            {
                "cis_id": CIS_ID,
                "check": CIS_TITLE,
                "resource_type": "ECR_Repository",
                "resource_id": "UNKNOWN",
                "principals": [],
                "offending_sids": [],
                "status": "ERROR",
                "details": f"Lỗi khi gọi AWS ECR API: {exc}",
                "timestamp": timestamp,
            }
        )

    return results


def remediate_ecr_private_repositories(
    ecr_client,
    account_id: str,
    audit_results: list[dict],
    dry_run: bool = False,
) -> list[dict]:
    """
    Bước 5: Khắc phục các Private ECR Repository có Resource Policy cho phép Principal='*'
    theo đúng hướng dẫn trang 244-245 sách CIS Benchmark:
    - Thay thế "Principal": "*" bằng "Principal": {"AWS": "arn:aws:iam::<account-id>:root"}.
    """
    actions = []
    restricted_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOnlyTrustedInternalAccount",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": [
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                    "ecr:BatchCheckLayerAvailability",
                ],
            }
        ],
    }

    for item in audit_results:
        if item["status"] != "FAIL":
            continue

        res_type = item["resource_type"]
        res_id = item["resource_id"]

        if res_type == "ECR_Repository":
            try:
                if not dry_run:
                    ecr_client.set_repository_policy(
                        repositoryName=res_id,
                        policyText=json.dumps(restricted_policy),
                    )

                actions.append(
                    {
                        "resource_id": res_id,
                        "resource_type": res_type,
                        "action": "restrict_ecr_repository_policy_principal",
                        "status": "DRY_RUN" if dry_run else "SUCCESS",
                        "details": (
                            f"Đã cập nhật Resource Policy của ECR Repository '{res_id}', "
                            f"thay Principal='*' bằng 'arn:aws:iam::{account_id}:root'."
                        ),
                    }
                )
            except (BotoCoreError, ClientError) as exc:
                actions.append(
                    {
                        "resource_id": res_id,
                        "resource_type": res_type,
                        "action": "restrict_ecr_repository_policy_principal",
                        "status": "ERROR",
                        "details": f"Không thể cập nhật policy cho ECR Repository '{res_id}': {exc}",
                    }
                )
        elif res_type == "ECR_Registry_Policy":
            try:
                if not dry_run:
                    ecr_client.delete_registry_policy()
                actions.append(
                    {
                        "resource_id": res_id,
                        "resource_type": res_type,
                        "action": "delete_public_ecr_registry_policy",
                        "status": "DRY_RUN" if dry_run else "SUCCESS",
                        "details": "Đã xoá Registry Policy công khai không an toàn.",
                    }
                )
            except (BotoCoreError, ClientError) as exc:
                actions.append(
                    {
                        "resource_id": res_id,
                        "resource_type": res_type,
                        "action": "delete_public_ecr_registry_policy",
                        "status": "ERROR",
                        "details": f"Không thể xoá ECR Registry Policy: {exc}",
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
        "resource_type",
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
                    "resource_type": init_rec.get("resource_type"),
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
        description="CIS 18.4 - Audit & Remediation: Ensure private ECR repositories do not allow public access via resource policies"
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
    ecr_client = session.client("ecr")

    print(f"[*] Bước 3: Kiểm tra danh tính kết nối AWS (Region: {args.region})...")
    try:
        caller_identity = check_caller_identity(session)
        print(f"    -> Đã xác thực với ARN: {caller_identity['Arn']}")
    except (BotoCoreError, ClientError) as exc:
        print(f"[!] Lỗi xác thực AWS CLI/Boto3: {exc}")
        return

    print(f"\n[*] Bước 4: Thu thập cấu hình và đánh giá tuân thủ CIS {CIS_ID}...")
    initial_audit = audit_ecr_private_repositories(ecr_client)
    for res in initial_audit:
        print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")

    remediation_actions = []
    post_remediation_audit = []

    has_failures = any(r["status"] == "FAIL" for r in initial_audit)

    if args.mode == "remediate" and has_failures:
        print(f"\n[*] Bước 5: Thực hiện Remediation cho CIS {CIS_ID} (dry_run={args.dry_run})...")
        remediation_actions = remediate_ecr_private_repositories(
            ecr_client,
            caller_identity["Account"],
            initial_audit,
            dry_run=args.dry_run,
        )
        for act in remediation_actions:
            print(f"    - [{act['status']}] {act['action']} ({act['resource_id']}): {act['details']}")

        print(f"\n[*] Bước 6: Kiểm tra lại (Verification) sau khi Remediation...")
        post_remediation_audit = audit_ecr_private_repositories(ecr_client)
        for res in post_remediation_audit:
            print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")
    elif args.mode == "remediate" and not has_failures:
        print("\n[*] Tất cả Private ECR Repositories đã đạt chuẩn CIS 18.4, không cần Remediation.")

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

    json_path = os.path.join(args.output_dir, "cis_18_4_report.json")
    csv_path = os.path.join(args.output_dir, "cis_18_4_report.csv")
    export_reports(report_data, json_path, csv_path)

    print(f"\n[*] Bước 7: Đã xuất báo cáo kết quả tại:")
    print(f"    - JSON: {json_path}")
    print(f"    - CSV : {csv_path}")


if __name__ == "__main__":
    main()
