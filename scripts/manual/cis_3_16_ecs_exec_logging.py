#!/usr/bin/env python3
"""
CIS AWS Compute Services Benchmark v2.0.0
Recommendation 3.16: Ensure ECS Exec sessions have audit logging enabled (Manual / Scripted)

Luồng thực hiện theo báo cáo (Mục 2.2.3 - Trang 16 -> 26) và CIS Benchmark (Trang 121-123):
- Bước 3: Kiểm tra quyền truy cập (aws sts get-caller-identity)
- Bước 4: Thu thập danh sách ECS Clusters và kiểm tra cấu hình executeCommandConfiguration.logging:
    + Theo CIS 3.16 (Trang 121-122):
      * Chỉ chế độ 'OVERRIDE' (gửi log về CloudWatch Logs log group hoặc S3 bucket chuyên biệt) mới đạt chuẩn (PASS).
      * Nếu logging là None, 'NONE', hoặc 'DEFAULT' -> FAIL (nếu có service bật ECS Exec hoặc đánh giá trực tiếp trên Cluster).
- Bước 5: Thực hiện Remediation đối với các ECS Cluster chưa đạt:
    + Tạo CloudWatch Log Group '/ecs/exec-audit-logs' với retention 365 ngày.
    + Cập nhật ECS Cluster sang chế độ logging = 'OVERRIDE' trỏ về '/ecs/exec-audit-logs'.
    + Tự động force-new-deployment cho các ECS Service đang bật enableExecuteCommand=True.
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

CIS_ID = "3.16"
CIS_TITLE = "Ensure ECS Exec sessions have audit logging enabled"
DEFAULT_AUDIT_LOG_GROUP = "/ecs/exec-audit-logs"


def check_caller_identity(session: boto3.Session) -> dict:
    """Bước 3: Kiểm tra danh tính AWS trước khi gọi API."""
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    return {
        "UserId": identity.get("UserId"),
        "Account": identity.get("Account"),
        "Arn": identity.get("Arn"),
    }


def get_exec_enabled_services(ecs_client, cluster_arn: str) -> list[str]:
    """Lấy danh sách các ECS service trong cluster có bật enableExecuteCommand=True."""
    exec_services = []
    paginator = ecs_client.get_paginator("list_services")
    service_arns = []
    for page in paginator.paginate(cluster=cluster_arn):
        service_arns.extend(page.get("serviceArns", []))

    for i in range(0, len(service_arns), 10):
        batch = service_arns[i : i + 10]
        desc = ecs_client.describe_services(cluster=cluster_arn, services=batch)
        for svc in desc.get("services", []):
            if svc.get("enableExecuteCommand") is True:
                exec_services.append(svc["serviceName"])

    return exec_services


def audit_ecs_exec_logging(ecs_client) -> list[dict]:
    """
    Bước 4: Kiểm tra cấu hình ECS Exec audit logging trên tất cả ECS Clusters trong region
    theo đúng hướng dẫn trang 121-122 sách CIS Benchmark:
    - Kiểm tra executeCommandConfiguration.logging của từng Cluster.
    - PASS nếu logging == 'OVERRIDE' và có cấu hình CloudWatchLogGroupName hoặc S3BucketName.
    - FAIL nếu logging là None, 'NONE', hoặc 'DEFAULT'.
    """
    results = []
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        cluster_arns = []
        paginator = ecs_client.get_paginator("list_clusters")
        for page in paginator.paginate():
            cluster_arns.extend(page.get("clusterArns", []))

        if not cluster_arns:
            results.append(
                {
                    "cis_id": CIS_ID,
                    "check": CIS_TITLE,
                    "resource_type": "ECS_Cluster",
                    "resource_id": "NONE",
                    "cluster_name": "N/A",
                    "logging_mode": "N/A",
                    "exec_enabled_services": [],
                    "status": "NOT_APPLICABLE",
                    "details": "Không có ECS Cluster nào trong region này.",
                    "timestamp": timestamp,
                }
            )
            return results

        desc_resp = ecs_client.describe_clusters(
            clusters=cluster_arns, include=["CONFIGURATIONS"]
        )

        for cluster in desc_resp.get("clusters", []):
            cluster_arn = cluster["clusterArn"]
            cluster_name = cluster["clusterName"]
            exec_services = get_exec_enabled_services(ecs_client, cluster_arn)

            exec_cfg = cluster.get("configuration", {}).get(
                "executeCommandConfiguration", {}
            )
            logging_mode = exec_cfg.get("logging", "NONE_OR_DEFAULT")
            log_cfg = exec_cfg.get("logConfiguration", {})
            cw_log_group = log_cfg.get("cloudWatchLogGroupName")
            s3_bucket = log_cfg.get("s3BucketName")

            if logging_mode == "OVERRIDE" and (cw_log_group or s3_bucket):
                status = "PASS"
                dest = cw_log_group or s3_bucket
                details = (
                    f"ECS Cluster '{cluster_name}' đã cấu hình ECS Exec audit logging = OVERRIDE "
                    f"(Destination: {dest}, Exec-enabled services: {len(exec_services)})."
                )
            else:
                status = "FAIL"
                details = (
                    f"ECS Cluster '{cluster_name}' có executeCommandConfiguration.logging = {logging_mode} "
                    f"(chưa đặt thành OVERRIDE với CloudWatch/S3 log destination chuyên biệt)."
                )

            results.append(
                {
                    "cis_id": CIS_ID,
                    "check": CIS_TITLE,
                    "resource_type": "ECS_Cluster",
                    "resource_id": cluster_arn,
                    "cluster_name": cluster_name,
                    "logging_mode": logging_mode,
                    "log_destination": cw_log_group or s3_bucket or "None",
                    "exec_enabled_services": exec_services,
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
                "resource_type": "ECS_Cluster",
                "resource_id": "UNKNOWN",
                "cluster_name": "UNKNOWN",
                "logging_mode": "N/A",
                "log_destination": "N/A",
                "exec_enabled_services": [],
                "status": "ERROR",
                "details": f"Lỗi khi gọi AWS ECS API: {exc}",
                "timestamp": timestamp,
            }
        )

    return results


def ensure_audit_log_group(logs_client, log_group_name: str = DEFAULT_AUDIT_LOG_GROUP):
    """
    Bước 1 trong CIS 3.16 Remediation (Trang 122):
    aws logs create-log-group --log-group-name /ecs/exec-audit-logs
    aws logs put-retention-policy --log-group-name /ecs/exec-audit-logs --retention-in-days 365
    """
    try:
        logs_client.create_log_group(logGroupName=log_group_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
            raise

    logs_client.put_retention_policy(
        logGroupName=log_group_name, retentionInDays=365
    )


def remediate_ecs_exec_logging(
    ecs_client,
    logs_client,
    audit_results: list[dict],
    log_group_name: str = DEFAULT_AUDIT_LOG_GROUP,
    dry_run: bool = False,
) -> list[dict]:
    """
    Bước 5: Khắc phục các ECS Cluster bị FAIL theo đúng 3 bước trang 122-123 sách CIS Benchmark:
    1. Tạo CloudWatch Log Group /ecs/exec-audit-logs với retention 365 ngày.
    2. Gọi update_cluster để bật executeCommandConfiguration.logging = 'OVERRIDE'.
    3. Gọi update_service(forceNewDeployment=True) cho các service đang bật ECS Exec.
    """
    actions = []

    if not dry_run:
        ensure_audit_log_group(logs_client, log_group_name)

    for item in audit_results:
        if item["status"] != "FAIL":
            continue

        cluster_name = item["cluster_name"]
        cluster_arn = item["resource_id"]
        exec_services = item.get("exec_enabled_services", [])

        try:
            if not dry_run:
                ecs_client.update_cluster(
                    cluster=cluster_name,
                    configuration={
                        "executeCommandConfiguration": {
                            "logging": "OVERRIDE",
                            "logConfiguration": {
                                "cloudWatchLogGroupName": log_group_name
                            },
                        }
                    },
                )

                for svc_name in exec_services:
                    ecs_client.update_service(
                        cluster=cluster_name,
                        service=svc_name,
                        forceNewDeployment=True,
                    )

            actions.append(
                {
                    "resource_id": cluster_arn,
                    "cluster_name": cluster_name,
                    "resource_type": "ECS_Cluster",
                    "action": "enable_ecs_exec_override_logging",
                    "status": "DRY_RUN" if dry_run else "SUCCESS",
                    "details": (
                        f"Đã cấu hình logging='OVERRIDE' (CloudWatch Log Group: {log_group_name}) "
                        f"cho ECS Cluster '{cluster_name}'."
                    ),
                }
            )
        except (BotoCoreError, ClientError) as exc:
            actions.append(
                {
                    "resource_id": cluster_arn,
                    "cluster_name": cluster_name,
                    "resource_type": "ECS_Cluster",
                    "action": "enable_ecs_exec_override_logging",
                    "status": "ERROR",
                    "details": f"Không thể cập nhật ECS Cluster '{cluster_name}': {exc}",
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
        "cluster_name",
        "initial_logging_mode",
        "initial_status",
        "initial_details",
        "remediation_action",
        "remediation_status",
        "final_logging_mode",
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
                    "cluster_name": init_rec.get("cluster_name"),
                    "initial_logging_mode": init_rec.get("logging_mode"),
                    "initial_status": init_rec.get("status"),
                    "initial_details": init_rec.get("details"),
                    "remediation_action": act_rec.get("action", "NONE"),
                    "remediation_status": act_rec.get("status", "NOT_EXECUTED"),
                    "final_logging_mode": fin_rec.get(
                        "logging_mode", init_rec.get("logging_mode")
                    ),
                    "final_status": fin_rec.get("status", init_rec.get("status")),
                    "final_details": fin_rec.get("details", init_rec.get("details")),
                    "timestamp": fin_rec.get("timestamp", init_rec.get("timestamp")),
                }
            )


def main():
    parser = argparse.ArgumentParser(
        description="CIS 3.16 - Audit & Remediation: Ensure ECS Exec sessions have audit logging enabled"
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
        "--log-group-name",
        default=DEFAULT_AUDIT_LOG_GROUP,
        help="Tên CloudWatch Log Group lưu audit log cho ECS Exec (mặc định: /ecs/exec-audit-logs)",
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
    ecs_client = session.client("ecs")
    logs_client = session.client("logs")

    print(f"[*] Bước 3: Kiểm tra danh tính kết nối AWS (Region: {args.region})...")
    try:
        caller_identity = check_caller_identity(session)
        print(f"    -> Đã xác thực với ARN: {caller_identity['Arn']}")
    except (BotoCoreError, ClientError) as exc:
        print(f"[!] Lỗi xác thực AWS CLI/Boto3: {exc}")
        return

    print(f"\n[*] Bước 4: Thu thập cấu hình và đánh giá tuân thủ CIS {CIS_ID}...")
    initial_audit = audit_ecs_exec_logging(ecs_client)
    for res in initial_audit:
        print(f"    - [{res['status']}] {res['cluster_name']} ({res['resource_id']}): {res['details']}")

    remediation_actions = []
    post_remediation_audit = []

    has_failures = any(r["status"] == "FAIL" for r in initial_audit)

    if args.mode == "remediate" and has_failures:
        print(f"\n[*] Bước 5: Thực hiện Remediation cho CIS {CIS_ID} (dry_run={args.dry_run})...")
        remediation_actions = remediate_ecs_exec_logging(
            ecs_client,
            logs_client,
            initial_audit,
            log_group_name=args.log_group_name,
            dry_run=args.dry_run,
        )
        for act in remediation_actions:
            print(f"    - [{act['status']}] {act['action']} ({act['cluster_name']}): {act['details']}")

        print(f"\n[*] Bước 6: Kiểm tra lại (Verification) sau khi Remediation...")
        post_remediation_audit = audit_ecs_exec_logging(ecs_client)
        for res in post_remediation_audit:
            print(f"    - [{res['status']}] {res['cluster_name']} ({res['resource_id']}): {res['details']}")
    elif args.mode == "remediate" and not has_failures:
        print("\n[*] Tất cả ECS Clusters đã đạt chuẩn CIS 3.16, không cần Remediation.")

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

    json_path = os.path.join(args.output_dir, "cis_3_16_report.json")
    csv_path = os.path.join(args.output_dir, "cis_3_16_report.csv")
    export_reports(report_data, json_path, csv_path)

    print(f"\n[*] Bước 7: Đã xuất báo cáo kết quả tại:")
    print(f"    - JSON: {json_path}")
    print(f"    - CSV : {csv_path}")


if __name__ == "__main__":
    main()
