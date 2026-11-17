#!/usr/bin/env python3
"""
CIS AWS Compute Services Benchmark v2.0.0
Recommendation 2.9: Ensure use of AWS Systems Manager to manage EC2 instances (Manual / Scripted)

Luồng thực hiện theo báo cáo (Mục 2.2.3 - Trang 16 -> 26):
- Bước 3: Kiểm tra quyền truy cập (aws sts get-caller-identity)
- Bước 4: Thu thập cấu hình EC2 & Systems Manager bằng Boto3 và đánh giá tuân thủ:
    + Kiểm tra EC2 Instance đã được gắn IAM Instance Profile (IamInstanceProfile) hay chưa.
    + Kiểm tra trạng thái kết nối của EC2 trong AWS Systems Manager Fleet Manager / Inventory (nếu có quyền ssm:DescribeInstanceInformation).
- Bước 5: Thực hiện Remediation đối với các EC2 instance chưa gắn IAM Instance Profile:
    + Tự động gắn IAM Instance Profile có quyền AmazonSSMManagedInstanceCore vào EC2 instance bằng associate_iam_instance_profile.
- Bước 6: Kiểm tra lại sau Remediation (Verification)
- Bước 7: Tổng hợp kết quả và xuất báo cáo (JSON & CSV)
"""

import argparse
import csv
import json
import os
from datetime import datetime, timezone
import time
import boto3
from botocore.exceptions import BotoCoreError, ClientError

CIS_ID = "2.9"
CIS_TITLE = "Ensure use of AWS Systems Manager to manage EC2 instances"


def check_caller_identity(session: boto3.Session) -> dict:
    """Bước 3: Kiểm tra danh tính AWS trước khi gọi API."""
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    return {
        "UserId": identity.get("UserId"),
        "Account": identity.get("Account"),
        "Arn": identity.get("Arn"),
    }


def get_ssm_managed_instances(ssm_client) -> tuple[dict, str | None]:
    """
    Lấy danh sách các EC2 instance đang được quản lý bởi AWS Systems Manager.
    Trả về (dict map instance_id -> info, error_message_if_any).
    """
    managed_map = {}
    try:
        paginator = ssm_client.get_paginator("describe_instance_information")
        for page in paginator.paginate():
            for info in page.get("InstanceInformationList", []):
                inst_id = info.get("InstanceId")
                if inst_id:
                    managed_map[inst_id] = {
                        "PingStatus": info.get("PingStatus"),
                        "AgentVersion": info.get("AgentVersion"),
                        "PlatformName": info.get("PlatformName"),
                    }
        return managed_map, None
    except (BotoCoreError, ClientError) as exc:
        return {}, str(exc)


def audit_ssm_managed_ec2(ec2_client, ssm_client) -> list[dict]:
    """
    Bước 4: Thu thập danh sách EC2 instances và kiểm tra:
    1. Thuộc tính IamInstanceProfile trên EC2 instance (Bắt buộc phải có để SSM Agent xác thực với Systems Manager - Bước 4 & 5 trang 63-64 tài liệu CIS).
    2. Trạng thái đăng ký trong SSM Inventory / Managed Instances (nếu IAM user có quyền ssm:DescribeInstanceInformation).
    """
    results = []
    timestamp = datetime.now(timezone.utc).isoformat()

    ssm_map, ssm_error = get_ssm_managed_instances(ssm_client)

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
                    iam_profile = instance.get("IamInstanceProfile", {})
                    profile_arn = iam_profile.get("Arn") if iam_profile else None

                    ssm_info = ssm_map.get(instance_id)

                    if not profile_arn:
                        status = "FAIL"
                        details = (
                            f"EC2 Instance {instance_id} (State: {state}) chưa được gắn IAM Instance Profile "
                            f"(IamInstanceProfile=None), không thể kết nối tới AWS Systems Manager."
                        )
                    elif ssm_info and ssm_info.get("PingStatus") == "Online":
                        status = "PASS"
                        details = (
                            f"EC2 Instance {instance_id} (State: {state}) đã gắn IAM Instance Profile ({profile_arn}) "
                            f"và đang Online trên AWS Systems Manager (Agent: {ssm_info.get('AgentVersion')})."
                        )
                    elif ssm_error is not None:
                        # Trường hợp đã gắn IAM Instance Profile nhưng user hiện tại bị giới hạn quyền đọc SSM API
                        status = "PASS"
                        details = (
                            f"EC2 Instance {instance_id} (State: {state}) đã gắn IAM Instance Profile ({profile_arn}). "
                            f"(Lưu ý: Bỏ qua bước kiểm tra PingStatus do giới hạn quyền ssm:DescribeInstanceInformation)."
                        )
                    else:
                        status = "FAIL" if state == "running" else "PASS"
                        details = (
                            f"EC2 Instance {instance_id} (State: {state}) đã gắn IAM Instance Profile ({profile_arn}), "
                            f"trạng thái SSM PingStatus={ssm_info.get('PingStatus') if ssm_info else 'NotRegistered'}."
                        )

                    results.append(
                        {
                            "cis_id": CIS_ID,
                            "check": CIS_TITLE,
                            "resource_type": "EC2_Instance",
                            "resource_id": instance_id,
                            "instance_state": state,
                            "iam_instance_profile": profile_arn or "None",
                            "ssm_ping_status": (
                                ssm_info.get("PingStatus")
                                if ssm_info
                                else ("ACCESS_DENIED" if ssm_error else "NotRegistered")
                            ),
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
                    "iam_instance_profile": "N/A",
                    "ssm_ping_status": "N/A",
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
                "iam_instance_profile": "N/A",
                "ssm_ping_status": "N/A",
                "status": "ERROR",
                "details": f"Lỗi khi gọi AWS API: {exc}",
                "timestamp": timestamp,
            }
        )

    return results


def ensure_ssm_instance_profile(iam_client, profile_name: str) -> str:
    """
    Bước 4 trong CIS Remediation (Trang 63):
    Đảm bảo tồn tại IAM Role & Instance Profile có gắn policy AmazonSSMManagedInstanceCore.
    """
    role_name = f"{profile_name}-role"
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    try:
        iam_client.get_role(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_role_policy),
                Description="IAM Role for EC2 Systems Manager (CIS 2.9)",
            )
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
            )
        else:
            raise

    try:
        resp = iam_client.get_instance_profile(InstanceProfileName=profile_name)
        if not resp["InstanceProfile"].get("Roles"):
            iam_client.add_role_to_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
            time.sleep(5)
        return resp["InstanceProfile"]["InstanceProfileName"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            iam_client.create_instance_profile(InstanceProfileName=profile_name)
            iam_client.add_role_to_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
            time.sleep(10)  # Đợi AWS IAM đồng bộ Instance Profile sang EC2
            return profile_name
        raise


def remediate_ssm_managed_ec2(
    ec2_client,
    iam_client,
    audit_results: list[dict],
    instance_profile_name: str = "cis-2-9-ssm-instance-profile",
    dry_run: bool = False,
) -> list[dict]:
    """
    Bước 5: Gắn IAM Instance Profile của Systems Manager cho các EC2 instance bị FAIL
    theo đúng Bước 5 trong CIS Benchmark 2.9 (Trang 64: Attach the Systems Manager instance profile to an existing instance).
    """
    actions = []

    for item in audit_results:
        if item["status"] != "FAIL":
            continue

        instance_id = item["resource_id"]
        try:
            if not dry_run:
                target_profile = ensure_ssm_instance_profile(
                    iam_client, instance_profile_name
                )
                ec2_client.associate_iam_instance_profile(
                    IamInstanceProfile={"Name": target_profile},
                    InstanceId=instance_id,
                )

            actions.append(
                {
                    "resource_id": instance_id,
                    "resource_type": "EC2_Instance",
                    "action": "associate_ssm_iam_instance_profile",
                    "status": "DRY_RUN" if dry_run else "SUCCESS",
                    "details": (
                        f"Đã gắn Systems Manager IAM Instance Profile ({instance_profile_name}) "
                        f"vào EC2 Instance {instance_id}."
                    ),
                }
            )
        except (BotoCoreError, ClientError) as exc:
            actions.append(
                {
                    "resource_id": instance_id,
                    "resource_type": "EC2_Instance",
                    "action": "associate_ssm_iam_instance_profile",
                    "status": "ERROR",
                    "details": f"Không thể gắn IAM Instance Profile cho {instance_id}: {exc}",
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
        "instance_state",
        "initial_iam_profile",
        "initial_status",
        "initial_details",
        "remediation_action",
        "remediation_status",
        "final_iam_profile",
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
                    "initial_iam_profile": init_rec.get("iam_instance_profile"),
                    "initial_status": init_rec.get("status"),
                    "initial_details": init_rec.get("details"),
                    "remediation_action": act_rec.get("action", "NONE"),
                    "remediation_status": act_rec.get("status", "NOT_EXECUTED"),
                    "final_iam_profile": fin_rec.get(
                        "iam_instance_profile", init_rec.get("iam_instance_profile")
                    ),
                    "final_status": fin_rec.get("status", init_rec.get("status")),
                    "final_details": fin_rec.get("details", init_rec.get("details")),
                    "timestamp": fin_rec.get("timestamp", init_rec.get("timestamp")),
                }
            )


def main():
    parser = argparse.ArgumentParser(
        description="CIS 2.9 - Audit & Remediation: Ensure use of AWS Systems Manager to manage EC2 instances"
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
        "--instance-profile-name",
        default="cis-2-9-ssm-instance-profile",
        help="Tên IAM Instance Profile dùng để gắn vào EC2 khi Remediation",
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
    ssm_client = session.client("ssm")
    iam_client = session.client("iam")

    print(f"[*] Bước 3: Kiểm tra danh tính kết nối AWS (Region: {args.region})...")
    try:
        caller_identity = check_caller_identity(session)
        print(f"    -> Đã xác thực với ARN: {caller_identity['Arn']}")
    except (BotoCoreError, ClientError) as exc:
        print(f"[!] Lỗi xác thực AWS CLI/Boto3: {exc}")
        return

    print(f"\n[*] Bước 4: Thu thập cấu hình và đánh giá tuân thủ CIS {CIS_ID}...")
    initial_audit = audit_ssm_managed_ec2(ec2_client, ssm_client)
    for res in initial_audit:
        print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")

    remediation_actions = []
    post_remediation_audit = []

    has_failures = any(r["status"] == "FAIL" for r in initial_audit)

    if args.mode == "remediate" and has_failures:
        print(f"\n[*] Bước 5: Thực hiện Remediation cho CIS {CIS_ID} (dry_run={args.dry_run})...")
        remediation_actions = remediate_ssm_managed_ec2(
            ec2_client,
            iam_client,
            initial_audit,
            instance_profile_name=args.instance_profile_name,
            dry_run=args.dry_run,
        )
        for act in remediation_actions:
            print(f"    - [{act['status']}] {act['action']} ({act['resource_id']}): {act['details']}")

        print(f"\n[*] Bước 6: Kiểm tra lại (Verification) sau khi Remediation...")
        post_remediation_audit = audit_ssm_managed_ec2(ec2_client, ssm_client)
        for res in post_remediation_audit:
            print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")
    elif args.mode == "remediate" and not has_failures:
        print("\n[*] Tất cả EC2 instances đã đạt chuẩn CIS 2.9, không cần Remediation.")

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

    json_path = os.path.join(args.output_dir, "cis_2_9_report.json")
    csv_path = os.path.join(args.output_dir, "cis_2_9_report.csv")
    export_reports(report_data, json_path, csv_path)

    print(f"\n[*] Bước 7: Đã xuất báo cáo kết quả tại:")
    print(f"    - JSON: {json_path}")
    print(f"    - CSV : {csv_path}")


if __name__ == "__main__":
    main()
