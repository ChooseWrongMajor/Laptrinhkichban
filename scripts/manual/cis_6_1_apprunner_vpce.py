#!/usr/bin/env python3
"""
CIS AWS Compute Services Benchmark v2.0.0
Recommendation 6.1: Ensure you are using VPC Endpoints for source code access (Manual / Scripted)

Luồng thực hiện theo báo cáo (Mục 2.2.3 - Trang 16 -> 26) và CIS Benchmark (Trang 159-160):
- Bước 3: Kiểm tra quyền truy cập (aws sts get-caller-identity)
- Bước 4: Thu thập danh sách VPC Endpoints trong region bằng Boto3 (describe_vpc_endpoints)
          và kiểm tra xem có Interface VPC Endpoint cho dịch vụ App Runner ('com.amazonaws.<region>.apprunner') hay không:
    + Theo CIS 6.1 (Trang 159):
      1. Service name: com.amazonaws.<region>.apprunner
      2. Status (State): available
      3. VPC ID, Subnets, Security Groups và Policy được liên kết hợp lệ.
    + PASS: Tồn tại VPC Endpoint cho App Runner ở trạng thái 'available' (hoặc 'pending'), có gắn Subnet và Security Group.
    + FAIL: Chưa có VPC Endpoint cho App Runner hoặc cấu hình chưa đầy đủ.
- Bước 5: Thực hiện Remediation khi chưa có VPC Endpoint:
    + Tạo Interface VPC Endpoint cho 'com.amazonaws.<region>.apprunner' trong VPC chỉ định.
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

CIS_ID = "6.1"
CIS_TITLE = "Ensure you are using VPC Endpoints for source code access"


def check_caller_identity(session: boto3.Session) -> dict:
    """Bước 3: Kiểm tra danh tính AWS trước khi gọi API."""
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    return {
        "UserId": identity.get("UserId"),
        "Account": identity.get("Account"),
        "Arn": identity.get("Arn"),
    }


def audit_apprunner_vpc_endpoint(ec2_client, region: str) -> list[dict]:
    """
    Bước 4: Kiểm tra sự tồn tại và cấu hình của VPC Endpoint cho AWS App Runner
    theo đúng 6 tiêu chí ở trang 159 sách CIS Benchmark:
    1. Service name: com.amazonaws.<region>.apprunner
    2. Status: Available
    3. VPC ID: associated
    4. Subnets: associated
    5. Security Groups: associated
    6. Policy: configured
    """
    results = []
    timestamp = datetime.now(timezone.utc).isoformat()
    expected_service = f"com.amazonaws.{region}.apprunner"

    try:
        resp = ec2_client.describe_vpc_endpoints(
            Filters=[{"Name": "service-name", "Values": [expected_service]}]
        )
        endpoints = resp.get("VpcEndpoints", [])

        # Bỏ qua các endpoint đã bị xoá (deleted / deleting)
        active_endpoints = [
            ep
            for ep in endpoints
            if ep.get("State", "").lower() not in ("deleted", "deleting", "failed")
        ]

        if not active_endpoints:
            results.append(
                {
                    "cis_id": CIS_ID,
                    "check": CIS_TITLE,
                    "resource_type": "VPC_Endpoint",
                    "resource_id": "MISSING_APPRUNNER_VPCE",
                    "service_name": expected_service,
                    "vpc_id": "N/A",
                    "state": "NOT_FOUND",
                    "subnet_ids": [],
                    "security_group_ids": [],
                    "status": "FAIL",
                    "details": (
                        f"Chưa cấu hình Interface VPC Endpoint cho dịch vụ '{expected_service}' "
                        f"trong region {region}."
                    ),
                    "timestamp": timestamp,
                }
            )
            return results

        for ep in active_endpoints:
            ep_id = ep["VpcEndpointId"]
            state = ep.get("State", "unknown")
            vpc_id = ep.get("VpcId", "N/A")
            subnets = ep.get("SubnetIds", [])
            sgs = [g["GroupId"] for g in ep.get("Groups", [])]
            has_policy = bool(ep.get("PolicyDocument"))

            if state in ("available", "pending") and vpc_id and subnets and sgs and has_policy:
                status = "PASS"
                details = (
                    f"VPC Endpoint {ep_id} ({expected_service}) đạt chuẩn: "
                    f"State={state}, VpcId={vpc_id}, Subnets={subnets}, SecurityGroups={sgs}."
                )
            else:
                status = "FAIL"
                details = (
                    f"VPC Endpoint {ep_id} ({expected_service}) chưa đáp ứng đủ điều kiện: "
                    f"State={state}, VpcId={vpc_id}, Subnets={subnets}, SecurityGroups={sgs}."
                )

            results.append(
                {
                    "cis_id": CIS_ID,
                    "check": CIS_TITLE,
                    "resource_type": "VPC_Endpoint",
                    "resource_id": ep_id,
                    "service_name": expected_service,
                    "vpc_id": vpc_id,
                    "state": state,
                    "subnet_ids": subnets,
                    "security_group_ids": sgs,
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
                "resource_type": "VPC_Endpoint",
                "resource_id": "UNKNOWN",
                "service_name": expected_service,
                "vpc_id": "N/A",
                "state": "ERROR",
                "subnet_ids": [],
                "security_group_ids": [],
                "status": "ERROR",
                "details": f"Lỗi khi gọi AWS EC2 describe_vpc_endpoints API: {exc}",
                "timestamp": timestamp,
            }
        )

    return results


def remediate_apprunner_vpc_endpoint(
    ec2_client,
    region: str,
    vpc_id: str,
    subnet_id: str,
    security_group_id: str,
    audit_results: list[dict],
    dry_run: bool = False,
) -> list[dict]:
    """
    Bước 5: Tạo Interface VPC Endpoint cho App Runner theo đúng 10 bước trang 160 sách CIS Benchmark.
    """
    actions = []
    service_name = f"com.amazonaws.{region}.apprunner"

    for item in audit_results:
        if item["status"] != "FAIL":
            continue

        try:
            created_vpce_id = "DRY_RUN_VPCE_ID"
            if not dry_run:
                resp = ec2_client.create_vpc_endpoint(
                    VpcEndpointType="Interface",
                    VpcId=vpc_id,
                    ServiceName=service_name,
                    SubnetIds=[subnet_id],
                    SecurityGroupIds=[security_group_id],
                    PrivateDnsEnabled=True,
                    TagSpecifications=[
                        {
                            "ResourceType": "vpc-endpoint",
                            "Tags": [
                                {"Key": "Name", "Value": "cis-6-1-apprunner-vpce"},
                                {"Key": "CIS_Recommendation", "Value": "6.1"},
                            ],
                        }
                    ],
                )
                created_vpce_id = resp["VpcEndpoint"]["VpcEndpointId"]
                # Đợi vài giây hoặc chờ endpoint khả dụng
                waiter_done = False
                for _ in range(18):
                    chk = ec2_client.describe_vpc_endpoints(
                        VpcEndpointIds=[created_vpce_id]
                    )
                    st = chk["VpcEndpoints"][0].get("State", "")
                    if st == "available":
                        waiter_done = True
                        break
                    import time
                    time.sleep(5)

            actions.append(
                {
                    "resource_id": created_vpce_id,
                    "resource_type": "VPC_Endpoint",
                    "action": "create_apprunner_interface_vpc_endpoint",
                    "status": "DRY_RUN" if dry_run else "SUCCESS",
                    "details": (
                        f"Đã khởi tạo Interface VPC Endpoint {created_vpce_id} cho dịch vụ "
                        f"'{service_name}' trong VPC {vpc_id} (Subnet: {subnet_id}, SG: {security_group_id})."
                    ),
                }
            )
        except (BotoCoreError, ClientError) as exc:
            actions.append(
                {
                    "resource_id": item["resource_id"],
                    "resource_type": "VPC_Endpoint",
                    "action": "create_apprunner_interface_vpc_endpoint",
                    "status": "ERROR",
                    "details": f"Không thể tạo VPC Endpoint cho App Runner: {exc}",
                }
            )

    return actions


def export_reports(report_data: dict, json_path: str, csv_path: str) -> None:
    """Bước 7: Xuất kết quả kiểm tra ra định dạng JSON và CSV."""
    os.makedirs(os.path.dirname(json_path), exist_ok=True)

    with open(json_path, "w", encoding="utf-8") as f_json:
        json.dump(report_data, f_json, ensure_ascii=False, indent=2)

    initial_list = report_data.get("initial_audit", [])
    final_list = report_data.get("post_remediation_audit", [])
    actions_list = report_data.get("remediation_actions", [])

    fieldnames = [
        "cis_id",
        "check_name",
        "initial_resource_id",
        "initial_status",
        "initial_details",
        "remediation_action",
        "remediation_status",
        "final_resource_id",
        "final_state",
        "final_status",
        "final_details",
        "timestamp",
    ]

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=fieldnames)
        writer.writeheader()

        init_rec = initial_list[0] if initial_list else {}
        act_rec = actions_list[0] if actions_list else {}
        fin_rec = final_list[0] if final_list else init_rec

        writer.writerow(
            {
                "cis_id": CIS_ID,
                "check_name": CIS_TITLE,
                "initial_resource_id": init_rec.get("resource_id"),
                "initial_status": init_rec.get("status"),
                "initial_details": init_rec.get("details"),
                "remediation_action": act_rec.get("action", "NONE"),
                "remediation_status": act_rec.get("status", "NOT_EXECUTED"),
                "final_resource_id": fin_rec.get("resource_id"),
                "final_state": fin_rec.get("state"),
                "final_status": fin_rec.get("status"),
                "final_details": fin_rec.get("details"),
                "timestamp": fin_rec.get("timestamp", init_rec.get("timestamp")),
            }
        )


def main():
    parser = argparse.ArgumentParser(
        description="CIS 6.1 - Audit & Remediation: Ensure you are using VPC Endpoints for source code access"
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
        "--vpc-id",
        default="vpc-05f31dd1b38d6f1b9",
        help="VPC ID dùng để tạo App Runner VPC Endpoint khi Remediation",
    )
    parser.add_argument(
        "--subnet-id",
        default="subnet-05560be0f1e0a1afc",
        help="Subnet ID dùng để tạo App Runner VPC Endpoint khi Remediation",
    )
    parser.add_argument(
        "--security-group-id",
        default="sg-0e0b641ff9ab2785c",
        help="Security Group ID gắn vào App Runner VPC Endpoint khi Remediation",
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
    initial_audit = audit_apprunner_vpc_endpoint(ec2_client, args.region)
    for res in initial_audit:
        print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")

    remediation_actions = []
    post_remediation_audit = []

    has_failures = any(r["status"] == "FAIL" for r in initial_audit)

    if args.mode == "remediate" and has_failures:
        print(f"\n[*] Bước 5: Thực hiện Remediation cho CIS {CIS_ID} (dry_run={args.dry_run})...")
        remediation_actions = remediate_apprunner_vpc_endpoint(
            ec2_client,
            args.region,
            args.vpc_id,
            args.subnet_id,
            args.security_group_id,
            initial_audit,
            dry_run=args.dry_run,
        )
        for act in remediation_actions:
            print(f"    - [{act['status']}] {act['action']} ({act['resource_id']}): {act['details']}")

        print(f"\n[*] Bước 6: Kiểm tra lại (Verification) sau khi Remediation...")
        post_remediation_audit = audit_apprunner_vpc_endpoint(ec2_client, args.region)
        for res in post_remediation_audit:
            print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")
    elif args.mode == "remediate" and not has_failures:
        print("\n[*] Đã có VPC Endpoint cho App Runner đạt chuẩn CIS 6.1, không cần Remediation.")

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

    json_path = os.path.join(args.output_dir, "cis_6_1_report.json")
    csv_path = os.path.join(args.output_dir, "cis_6_1_report.csv")
    export_reports(report_data, json_path, csv_path)

    print(f"\n[*] Bước 7: Đã xuất báo cáo kết quả tại:")
    print(f"    - JSON: {json_path}")
    print(f"    - CSV : {csv_path}")


if __name__ == "__main__":
    main()
