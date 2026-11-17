#!/usr/bin/env python3
"""
CIS AWS Compute Services Benchmark v2.0.0
Recommendation 2.7: Ensure Default EC2 Security groups are not being used. (Manual / Scripted)

Luồng thực hiện theo báo cáo (Mục 2.2.3 - Trang 16 -> 26):
- Bước 3: Kiểm tra quyền truy cập (aws sts get-caller-identity)
- Bước 4: Thu thập cấu hình thực tế bằng Boto3 & Đánh giá mức độ tuân thủ (PASS / FAIL / ERROR / NOT_APPLICABLE)
- Bước 5: Thực hiện Remediation đối với các tiêu chí chưa đạt (Hỗ trợ Audit-only và Audit-and-remediate)
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

CIS_ID = "2.7"
CIS_TITLE = "Ensure Default EC2 Security groups are not being used."


def check_caller_identity(session: boto3.Session) -> dict:
    """Bước 3: Kiểm tra danh tính AWS trước khi gọi API."""
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    return {
        "UserId": identity.get("UserId"),
        "Account": identity.get("Account"),
        "Arn": identity.get("Arn"),
    }


def audit_default_security_groups(ec2_client) -> list[dict]:
    """
    Bước 4: Thu thập cấu hình thực tế bằng Boto3 và đánh giá tuân thủ CIS 2.7.
    Kiểm tra:
    1. Các EC2 instance hiện có (không tính terminated) có gắn Security Group 'default' hay không.
    2. Các Default Security Group trong region có còn chứa inbound/outbound rules hay không.
    """
    results = []
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        # 1. Kiểm tra tất cả EC2 instances
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
                    vpc_id = instance.get("VpcId", "N/A")
                    security_groups = instance.get("SecurityGroups", [])

                    default_sgs = [
                        sg for sg in security_groups if sg.get("GroupName") == "default"
                    ]

                    if default_sgs:
                        sg_list_str = ", ".join(
                            f"{sg['GroupName']} ({sg['GroupId']})" for sg in default_sgs
                        )
                        status = "FAIL"
                        details = (
                            f"EC2 Instance {instance_id} (VPC: {vpc_id}, State: {state}) "
                            f"đang sử dụng Default Security Group: {sg_list_str}"
                        )
                    else:
                        sg_list_str = ", ".join(
                            f"{sg['GroupName']} ({sg['GroupId']})" for sg in security_groups
                        )
                        status = "PASS"
                        details = (
                            f"EC2 Instance {instance_id} (VPC: {vpc_id}, State: {state}) "
                            f"chỉ sử dụng Custom Security Group: {sg_list_str}"
                        )

                    results.append(
                        {
                            "cis_id": CIS_ID,
                            "check": CIS_TITLE,
                            "resource_type": "EC2_Instance",
                            "resource_id": instance_id,
                            "vpc_id": vpc_id,
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
                    "vpc_id": "N/A",
                    "status": "NOT_APPLICABLE",
                    "details": "Không có EC2 instance nào đang hoạt động trong region này.",
                    "timestamp": timestamp,
                }
            )

        # 2. Kiểm tra cấu hình các Default Security Group theo đúng hướng dẫn Remediation của CIS 2.7
        sg_resp = ec2_client.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": ["default"]}]
        )
        for sg in sg_resp.get("SecurityGroups", []):
            sg_id = sg["GroupId"]
            vpc_id = sg.get("VpcId", "N/A")
            ingress_rules = sg.get("IpPermissions", [])

            if ingress_rules:
                status = "FAIL"
                details = (
                    f"Default Security Group ({sg_id}) trong VPC {vpc_id} "
                    f"đang có {len(ingress_rules)} inbound rule(s) chưa được xoá."
                )
            else:
                status = "PASS"
                details = (
                    f"Default Security Group ({sg_id}) trong VPC {vpc_id} "
                    f"không có inbound rule nào."
                )

            results.append(
                {
                    "cis_id": CIS_ID,
                    "check": f"{CIS_TITLE} (Default SG Inbound Rules Check)",
                    "resource_type": "Default_Security_Group",
                    "resource_id": sg_id,
                    "vpc_id": vpc_id,
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
                "resource_type": "AWS_EC2",
                "resource_id": "UNKNOWN",
                "vpc_id": "N/A",
                "status": "ERROR",
                "details": f"Lỗi khi gọi AWS API: {exc}",
                "timestamp": timestamp,
            }
        )

    return results


def get_or_create_replacement_sg(ec2_client, vpc_id: str) -> str:
    """Tìm hoặc tạo mới một Custom Security Group hạn chế quyền trong VPC để gỡ Default SG."""
    sg_name = "cis-2-7-remediated-custom-sg"
    resp = ec2_client.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": [sg_name]},
        ]
    )
    if resp.get("SecurityGroups"):
        return resp["SecurityGroups"][0]["GroupId"]

    create_resp = ec2_client.create_security_group(
        GroupName=sg_name,
        Description="Custom SG duoc tao tu dong boi kich ban CIS 2.7 Remediation",
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "security-group",
                "Tags": [{"Key": "Name", "Value": sg_name}],
            }
        ],
    )
    return create_resp["GroupId"]


def remediate_default_security_groups(
    ec2_client,
    audit_results: list[dict],
    replacement_sg_id: str | None = None,
    dry_run: bool = False,
) -> list[dict]:
    """
    Bước 5: Khắc phục các tài nguyên bị FAIL ở bước Audit:
    - Với EC2 Instance đang gắn 'default' SG: thay thế 'default' SG bằng Custom SG.
    - Với Default Security Group còn chứa Inbound Rules: thực hiện revoke toàn bộ Inbound Rules
      theo đúng CIS Benchmark 2.7 Remediation Procedure (trang 57 tài liệu CIS).
    """
    actions = []

    for item in audit_results:
        if item["status"] != "FAIL":
            continue

        res_type = item["resource_type"]
        res_id = item["resource_id"]
        vpc_id = item["vpc_id"]

        if res_type == "EC2_Instance":
            try:
                inst_resp = ec2_client.describe_instances(InstanceIds=[res_id])
                instance = inst_resp["Reservations"][0]["Instances"][0]
                current_sgs = instance.get("SecurityGroups", [])

                non_default_sg_ids = [
                    sg["GroupId"]
                    for sg in current_sgs
                    if sg.get("GroupName") != "default"
                ]

                if not non_default_sg_ids:
                    target_sg_id = replacement_sg_id or get_or_create_replacement_sg(
                        ec2_client, vpc_id
                    )
                    non_default_sg_ids = [target_sg_id]

                if not dry_run:
                    ec2_client.modify_instance_attribute(
                        InstanceId=res_id, Groups=non_default_sg_ids
                    )

                actions.append(
                    {
                        "resource_id": res_id,
                        "resource_type": res_type,
                        "action": "replace_default_sg_on_instance",
                        "status": "DRY_RUN" if dry_run else "SUCCESS",
                        "details": (
                            f"Đã gỡ Default SG khỏi instance {res_id}, "
                            f"cập nhật thành Custom SG: {non_default_sg_ids}"
                        ),
                    }
                )
            except (BotoCoreError, ClientError) as exc:
                actions.append(
                    {
                        "resource_id": res_id,
                        "resource_type": res_type,
                        "action": "replace_default_sg_on_instance",
                        "status": "ERROR",
                        "details": f"Không thể cập nhật SG cho instance {res_id}: {exc}",
                    }
                )

        elif res_type == "Default_Security_Group":
            try:
                sg_resp = ec2_client.describe_security_groups(GroupIds=[res_id])
                sg = sg_resp["SecurityGroups"][0]
                inbound_permissions = sg.get("IpPermissions", [])

                if inbound_permissions and not dry_run:
                    ec2_client.revoke_security_group_ingress(
                        GroupId=res_id, IpPermissions=inbound_permissions
                    )

                actions.append(
                    {
                        "resource_id": res_id,
                        "resource_type": res_type,
                        "action": "revoke_default_sg_inbound_rules",
                        "status": "DRY_RUN" if dry_run else "SUCCESS",
                        "details": (
                            f"Đã xoá {len(inbound_permissions)} inbound rule(s) "
                            f"khỏi Default Security Group {res_id}."
                        ),
                        "revoked_rules": inbound_permissions,
                    }
                )
            except (BotoCoreError, ClientError) as exc:
                actions.append(
                    {
                        "resource_id": res_id,
                        "resource_type": res_type,
                        "action": "revoke_default_sg_inbound_rules",
                        "status": "ERROR",
                        "details": f"Không thể xoá inbound rule của Default SG {res_id}: {exc}",
                    }
                )

    return actions


def export_reports(
    report_data: dict, json_path: str, csv_path: str
) -> None:
    """Bước 7: Xuất kết quả kiểm tra ra định dạng JSON và CSV."""
    os.makedirs(os.path.dirname(json_path), exist_ok=True)

    with open(json_path, "w", encoding="utf-8") as f_json:
        json.dump(report_data, f_json, ensure_ascii=False, indent=2)

    # Tổng hợp dữ liệu trước & sau remediation theo đúng yêu cầu Bước 7 (trang 26)
    initial_map = {
        (r["resource_type"], r["resource_id"]): r
        for r in report_data.get("initial_audit", [])
    }
    final_map = {
        (r["resource_type"], r["resource_id"]): r
        for r in report_data.get("post_remediation_audit", [])
    }
    action_map = {
        (a["resource_type"], a["resource_id"]): a
        for a in report_data.get("remediation_actions", [])
    }

    fieldnames = [
        "cis_id",
        "check_name",
        "resource_type",
        "resource_id",
        "vpc_id",
        "initial_status",
        "initial_details",
        "remediation_action",
        "remediation_status",
        "final_status",
        "final_details",
        "timestamp",
    ]

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=fieldnames)
        writer.writeheader()

        for key, init_rec in initial_map.items():
            act_rec = action_map.get(key, {})
            fin_rec = final_map.get(key, {})
            writer.writerow(
                {
                    "cis_id": init_rec.get("cis_id", CIS_ID),
                    "check_name": init_rec.get("check", CIS_TITLE),
                    "resource_type": init_rec.get("resource_type"),
                    "resource_id": init_rec.get("resource_id"),
                    "vpc_id": init_rec.get("vpc_id"),
                    "initial_status": init_rec.get("status"),
                    "initial_details": init_rec.get("details"),
                    "remediation_action": act_rec.get("action", "NONE"),
                    "remediation_status": act_rec.get("status", "NOT_EXECUTED"),
                    "final_status": fin_rec.get("status", init_rec.get("status")),
                    "final_details": fin_rec.get("details", init_rec.get("details")),
                    "timestamp": fin_rec.get("timestamp", init_rec.get("timestamp")),
                }
            )


def main():
    parser = argparse.ArgumentParser(
        description="CIS 2.7 - Audit & Remediation: Ensure Default EC2 Security groups are not being used."
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
        "--replacement-sg-id",
        default=None,
        help="ID của Custom Security Group dùng để thay thế Default SG trên EC2 instance (tùy chọn)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Chạy thử nghiệm Remediation nhưng không thực sự thay đổi cấu hình trên AWS",
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
    initial_audit = audit_default_security_groups(ec2_client)
    for res in initial_audit:
        print(f"    - [{res['status']}] {res['resource_type']} ({res['resource_id']}): {res['details']}")

    remediation_actions = []
    post_remediation_audit = []

    has_failures = any(r["status"] == "FAIL" for r in initial_audit)

    if args.mode == "remediate" and has_failures:
        print(f"\n[*] Bước 5: Thực hiện Remediation cho CIS {CIS_ID} (dry_run={args.dry_run})...")
        remediation_actions = remediate_default_security_groups(
            ec2_client,
            initial_audit,
            replacement_sg_id=args.replacement_sg_id,
            dry_run=args.dry_run,
        )
        for act in remediation_actions:
            print(f"    - [{act['status']}] {act['action']} ({act['resource_id']}): {act['details']}")

        print(f"\n[*] Bước 6: Kiểm tra lại (Verification) sau khi Remediation...")
        post_remediation_audit = audit_default_security_groups(ec2_client)
        for res in post_remediation_audit:
            print(f"    - [{res['status']}] {res['resource_type']} ({res['resource_id']}): {res['details']}")
    elif args.mode == "remediate" and not has_failures:
        print("\n[*] Tất cả tài nguyên đã PASS, không cần thực hiện Remediation.")

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

    json_path = os.path.join(args.output_dir, "cis_2_7_report.json")
    csv_path = os.path.join(args.output_dir, "cis_2_7_report.csv")
    export_reports(report_data, json_path, csv_path)

    print(f"\n[*] Bước 7: Đã xuất báo cáo kết quả tại:")
    print(f"    - JSON: {json_path}")
    print(f"    - CSV : {csv_path}")


if __name__ == "__main__":
    main()
