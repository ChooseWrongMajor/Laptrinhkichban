#!/usr/bin/env python3
"""
CIS AWS Compute Services Benchmark v2.0.0
Recommendation 2.8: Ensure the Use of IMDSv2 is Enforced on All Existing Instances (Manual / Scripted)

Luồng thực hiện theo báo cáo (Mục 2.2.3 - Trang 16 -> 26):
- Bước 3: Kiểm tra quyền truy cập (aws sts get-caller-identity)
- Bước 4: Thu thập cấu hình MetadataOptions của các EC2 instance bằng Boto3 & Đánh giá mức độ tuân thủ:
    + PASS: HttpTokens == 'required' (hoặc HttpEndpoint == 'disabled')
    + FAIL: HttpTokens == 'optional' và HttpEndpoint == 'enabled'
- Bước 5: Thực hiện Remediation đối với các EC2 instance chưa đạt:
    + Gọi API modify_instance_metadata_options(InstanceId=..., HttpTokens='required', HttpEndpoint='enabled')
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

CIS_ID = "2.8"
CIS_TITLE = "Ensure the Use of IMDSv2 is Enforced on All Existing Instances"


def check_caller_identity(session: boto3.Session) -> dict:
    """Bước 3: Kiểm tra danh tính AWS trước khi gọi API."""
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    return {
        "UserId": identity.get("UserId"),
        "Account": identity.get("Account"),
        "Arn": identity.get("Arn"),
    }


def audit_imdsv2_enforced(ec2_client) -> list[dict]:
    """
    Bước 4: Thu thập cấu hình MetadataOptions của tất cả EC2 instances hiện có (trừ terminated).
    Theo CIS Benchmark 2.8 (Trang 58-59):
    - Nếu MetadataOptions.HttpTokens == 'optional' -> FAIL (cho phép cả IMDSv1 và IMDSv2).
    - Nếu MetadataOptions.HttpTokens == 'required' -> PASS (bắt buộc IMDSv2).
    """
    results = []
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        paginator = ec2_client.get_paginator("describe_instances")
        instances_found = False

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    state = instance.get("State", {}).get("Name", "")
                    if state == "terminated":
                        continue

                    instances_found = True
                    instance_id = instance["InstanceId"]
                    metadata_opts = instance.get("MetadataOptions", {})
                    http_tokens = metadata_opts.get("HttpTokens", "optional")
                    http_endpoint = metadata_opts.get("HttpEndpoint", "enabled")
                    hop_limit = metadata_opts.get("HttpPutResponseHopLimit", 1)

                    if http_endpoint == "disabled" or http_tokens == "required":
                        status = "PASS"
                        details = (
                            f"EC2 Instance {instance_id} (State: {state}) đã bắt buộc IMDSv2 "
                            f"(HttpTokens={http_tokens}, HttpEndpoint={http_endpoint}, HopLimit={hop_limit})."
                        )
                    else:
                        status = "FAIL"
                        details = (
                            f"EC2 Instance {instance_id} (State: {state}) chưa bắt buộc IMDSv2 "
                            f"(HttpTokens={http_tokens}, HttpEndpoint={http_endpoint}). Cho phép IMDSv1."
                        )

                    results.append(
                        {
                            "cis_id": CIS_ID,
                            "check": CIS_TITLE,
                            "resource_type": "EC2_Instance",
                            "resource_id": instance_id,
                            "instance_state": state,
                            "http_tokens": http_tokens,
                            "http_endpoint": http_endpoint,
                            "status": status,
                            "details": details,
                            "timestamp": timestamp,
                        }
                    )

        if not instances_found:
            results.append(
                {
                    "cis_id": CIS_ID,
                    "check": CIS_TITLE,
                    "resource_type": "EC2_Instance",
                    "resource_id": "NONE",
                    "instance_state": "N/A",
                    "http_tokens": "N/A",
                    "http_endpoint": "N/A",
                    "status": "NOT_APPLICABLE",
                    "details": "Không có EC2 instance nào trong region này.",
                    "timestamp": timestamp,
                }
            )

    except (BotoCoreError, ClientError) as exc:
        results.append(
            {
                "cis_id": CIS_ID,
                "check": CIS_TITLE,
                "resource_type": "EC2_Instance",
                "resource_id": "UNKNOWN",
                "instance_state": "N/A",
                "http_tokens": "N/A",
                "http_endpoint": "N/A",
                "status": "ERROR",
                "details": f"Lỗi khi gọi AWS API describe_instances: {exc}",
                "timestamp": timestamp,
            }
        )

    return results


def remediate_imdsv2_enforced(
    ec2_client, audit_results: list[dict], dry_run: bool = False
) -> list[dict]:
    """
    Bước 5: Khắc phục các EC2 instance có HttpTokens='optional' bằng cách chuyển sang 'required'.
    Tương đương lệnh CLI trong CIS 2.8 (Trang 59):
    aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled
    """
    actions = []

    for item in audit_results:
        if item["status"] != "FAIL":
            continue

        instance_id = item["resource_id"]
        try:
            response_meta = {}
            if not dry_run:
                resp = ec2_client.modify_instance_metadata_options(
                    InstanceId=instance_id,
                    HttpTokens="required",
                    HttpEndpoint="enabled",
                )
                response_meta = resp.get("InstanceMetadataOptions", {})

            actions.append(
                {
                    "resource_id": instance_id,
                    "resource_type": "EC2_Instance",
                    "action": "enforce_imdsv2_http_tokens_required",
                    "status": "DRY_RUN" if dry_run else "SUCCESS",
                    "details": (
                        f"Đã gửi yêu cầu bắt buộc IMDSv2 (HttpTokens=required, HttpEndpoint=enabled) "
                        f"cho EC2 Instance {instance_id}."
                    ),
                    "api_response": response_meta,
                }
            )
        except (BotoCoreError, ClientError) as exc:
            actions.append(
                {
                    "resource_id": instance_id,
                    "resource_type": "EC2_Instance",
                    "action": "enforce_imdsv2_http_tokens_required",
                    "status": "ERROR",
                    "details": f"Lỗi khi cập nhật IMDSv2 cho instance {instance_id}: {exc}",
                }
            )

    return actions


def export_reports(report_data: dict, json_path: str, csv_path: str) -> None:
    """Bước 7: Xuất báo cáo kết quả ra file JSON và CSV."""
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
        "instance_state",
        "initial_http_tokens",
        "initial_status",
        "initial_details",
        "remediation_action",
        "remediation_status",
        "final_http_tokens",
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
                    "instance_state": init_rec.get("instance_state"),
                    "initial_http_tokens": init_rec.get("http_tokens"),
                    "initial_status": init_rec.get("status"),
                    "initial_details": init_rec.get("details"),
                    "remediation_action": act_rec.get("action", "NONE"),
                    "remediation_status": act_rec.get("status", "NOT_EXECUTED"),
                    "final_http_tokens": fin_rec.get(
                        "http_tokens", init_rec.get("http_tokens")
                    ),
                    "final_status": fin_rec.get("status", init_rec.get("status")),
                    "final_details": fin_rec.get("details", init_rec.get("details")),
                    "timestamp": fin_rec.get("timestamp", init_rec.get("timestamp")),
                }
            )


def main():
    parser = argparse.ArgumentParser(
        description="CIS 2.8 - Audit & Remediation: Ensure the Use of IMDSv2 is Enforced on All Existing Instances"
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
    ec2_client = session.client("ec2")

    print(f"[*] Bước 3: Kiểm tra danh tính kết nối AWS (Region: {args.region})...")
    try:
        caller_identity = check_caller_identity(session)
        print(f"    -> Đã xác thực với ARN: {caller_identity['Arn']}")
    except (BotoCoreError, ClientError) as exc:
        print(f"[!] Lỗi xác thực AWS CLI/Boto3: {exc}")
        return

    print(f"\n[*] Bước 4: Thu thập cấu hình và đánh giá tuân thủ CIS {CIS_ID}...")
    initial_audit = audit_imdsv2_enforced(ec2_client)
    for res in initial_audit:
        print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")

    remediation_actions = []
    post_remediation_audit = []

    has_failures = any(r["status"] == "FAIL" for r in initial_audit)

    if args.mode == "remediate" and has_failures:
        print(f"\n[*] Bước 5: Thực hiện Remediation cho CIS {CIS_ID} (dry_run={args.dry_run})...")
        remediation_actions = remediate_imdsv2_enforced(
            ec2_client, initial_audit, dry_run=args.dry_run
        )
        for act in remediation_actions:
            print(f"    - [{act['status']}] {act['action']} ({act['resource_id']}): {act['details']}")

        print(f"\n[*] Bước 6: Kiểm tra lại (Verification) sau khi Remediation...")
        post_remediation_audit = audit_imdsv2_enforced(ec2_client)
        for res in post_remediation_audit:
            print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")
    elif args.mode == "remediate" and not has_failures:
        print("\n[*] Tất cả EC2 instances đã bắt buộc IMDSv2 (PASS), không cần Remediation.")

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

    json_path = os.path.join(args.output_dir, "cis_2_8_report.json")
    csv_path = os.path.join(args.output_dir, "cis_2_8_report.csv")
    export_reports(report_data, json_path, csv_path)

    print(f"\n[*] Bước 7: Đã xuất báo cáo kết quả tại:")
    print(f"    - JSON: {json_path}")
    print(f"    - CSV : {csv_path}")


if __name__ == "__main__":
    main()
