#!/usr/bin/env python3
"""
Trình điều phối trung tâm (Central Orchestrator) cho phương pháp Tự động hóa (Automated)
CIS AWS Compute Services Benchmark v2.0.0 - Nhóm 04 (21 Tiêu chí Automated)

Cách sử dụng:
  1. Khởi tạo môi trường mẫu chứa lỗi vi phạm (Seed Non-Compliant State - $0 Cost):
     python scripts/automated/main_automated.py --mode seed

  2. Chạy kiểm tra tự động (Audit-only):
     python scripts/automated/main_automated.py --mode audit

  3. Chạy kiểm tra + khắc phục tự động + xác minh lại (Audit-and-Remediate):
     python scripts/automated/main_automated.py --mode remediate

  4. Dọn dẹp KMS Customer-Managed Key sau khi chụp ảnh báo cáo (tránh phí KMS $1/tháng):
     python scripts/automated/main_automated.py --mode cleanup-kms
"""

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List
import boto3
from botocore.exceptions import ClientError

from common import (
    CheckResult,
    export_reports,
    print_audit_table,
    verify_caller_identity,
    BOLD,
    CYAN,
    GREEN,
    RED,
    RESET,
    YELLOW,
)
from ec2_automated import run_ec2_audit, run_ec2_remediation
from ecs_automated import run_ecs_audit, run_ecs_remediation
from fargate_automated import KMS_ALIAS_NAME, run_fargate_audit, run_fargate_remediation
from lambda_automated import run_lambda_audit, run_lambda_remediation

BASE_DIR = Path(__file__).resolve().parents[2]
REPORTS_DIR = BASE_DIR / "reports" / "automated"


def ensure_ecs_task_exec_role(session: boto3.Session, account_id: str) -> str:
    iam = session.client("iam")
    role_name = "cis-compute-benchmark-ecs-task-exec-role"
    try:
        return iam.get_role(RoleName=role_name)["Role"]["Arn"]
    except ClientError:
        assume_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_policy),
            Description="ECS Task Execution Role for CIS Compute Benchmark",
        )["Role"]["Arn"]
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
        )
        return role_arn


def seed_non_compliant_environment(session: boto3.Session, account_id: str) -> None:
    """
    Thiết lập trạng thái ban đầu cân bằng (13 PASS / 8 FAIL - Compliance Score: 61.90%)
    trên các tài nguyên Metadata hoàn toàn miễn phí ($0.00):
      - EC2 FAIL (2): 2.2.1 (EBS Encryption by Default = False), 2.2.2 (Snapshot Block Public Access = unblocked)
      - ECS FAIL (4): 3.2 & 3.14 (assignPublicIp = ENABLED), 3.5 (readonlyRootFilesystem = False), 3.9 (containerInsights = disabled)
      - Fargate FAIL (1): 11.1 (Chưa gắn KMS CMK cho Ephemeral Storage)
      - Lambda FAIL (1): 12.16 (Function URL AuthType = NONE)
      - 13 tiêu chí còn lại (2.1.2, 2.1.4, 2.2.3, 3.1, 3.3, 3.4, 3.6, 3.7, 3.8, 3.10, 3.11, 3.12, 3.13) đạt PASS sẵn.
    """
    print(f"\n{YELLOW}{BOLD}[SEED] Đang thiết lập trạng thái kiểm thử ban đầu (13 PASS / 8 FAIL - 61.90%) trên AWS...{RESET}")
    ec2 = session.client("ec2")
    ecs = session.client("ecs")
    lmb = session.client("lambda")
    region = session.region_name or "ap-southeast-1"

    # 1. EC2: Tắt EBS Encryption by Default (2.2.1 FAIL) & mở Snapshot Block Public Access (2.2.2 FAIL)
    ec2.disable_ebs_encryption_by_default()
    ec2.disable_snapshot_block_public_access()
    print("  [+] EC2: Đã đặt EbsEncryptionByDefault=False (2.2.1) & SnapshotBlockPublicAccess=unblocked (2.2.2)")

    # 2. ECS Task Definition: Đạt chuẩn 3.1, 3.3, 3.4, 3.6, 3.7, 3.12, 3.13; chỉ để readonlyRootFilesystem=False (3.5 FAIL)
    exec_role_arn = ensure_ecs_task_exec_role(session, account_id)
    for old_arn in ecs.list_task_definitions(status="ACTIVE").get("taskDefinitionArns", []):
        ecs.deregister_task_definition(taskDefinition=old_arn)

    trusted_image = f"{account_id}.dkr.ecr.{region}.amazonaws.com/cis-compute-benchmark-private-repo:latest"
    fargate_td_arn = ecs.register_task_definition(
        family="cis-compute-benchmark-task",
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        pidMode="task",
        containerDefinitions=[
            {
                "name": "app-container",
                "image": trusted_image,
                "essential": True,
                "user": "1000:1000",
                "privileged": False,
                "readonlyRootFilesystem": False,  # Cố tình để False -> Vi phạm CIS 3.5
                "environment": [{"name": "APP_ENV", "value": "production"}],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": "/ecs/exec-audit-logs",
                        "awslogs-region": region,
                        "awslogs-stream-prefix": "ecs-app",
                    },
                },
            }
        ],
        tags=[
            {"key": "Name", "value": "cis-compute-benchmark-task"},
            {"key": "Project", "value": "cis-compute-benchmark"},
            {"key": "Environment", "value": "lab"},
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    print("  [+] ECS Task Definition: Đạt chuẩn 3.1, 3.3, 3.4, 3.6, 3.7, 3.12, 3.13; để readonlyRootFilesystem=False (3.5 FAIL)")

    # 3. ECS Cluster: Giữ nguyên Tags (3.11 PASS), tắt Container Insights (3.9 FAIL), bỏ KMS Key (11.1 FAIL)
    cluster_name = "cis-compute-benchmark-cluster"
    cluster_arn = f"arn:aws:ecs:{region}:{account_id}:cluster/{cluster_name}"
    ecs.update_cluster_settings(
        cluster=cluster_name,
        settings=[{"name": "containerInsights", "value": "disabled"}],
    )
    ecs.update_cluster(
        cluster=cluster_name,
        configuration={
            "executeCommandConfiguration": {
                "logging": "OVERRIDE",
                "logConfiguration": {
                    "cloudWatchLogGroupName": "/ecs/exec-audit-logs",
                    "cloudWatchEncryptionEnabled": False,
                },
            },
            "managedStorageConfiguration": {},
        },
    )
    ecs.tag_resource(
        resourceArn=cluster_arn,
        tags=[
            {"key": "Name", "value": cluster_name},
            {"key": "Project", "value": "cis-compute-benchmark"},
            {"key": "Environment", "value": "lab"},
        ],
    )
    print("  [+] ECS Cluster: Đạt chuẩn 3.11 (Tagged); để containerInsights=disabled (3.9 FAIL) và chưa gắn KMS CMK (11.1 FAIL)")

    # 4. ECS Service (desiredCount=0 -> $0 cost): Giữ platformVersion=LATEST (3.8 PASS) & Tags (3.10 PASS), để assignPublicIp=ENABLED (3.2 & 3.14 FAIL)
    svc_name = "cis-compute-benchmark-service"
    s_arns = ecs.list_services(cluster=cluster_name).get("serviceArns", [])
    svc_exists = any(a.endswith(f"/{svc_name}") for a in s_arns)

    if not svc_exists:
        svc_resp = ecs.create_service(
            cluster=cluster_name,
            serviceName=svc_name,
            taskDefinition=fargate_td_arn,
            desiredCount=0,
            launchType="FARGATE",
            platformVersion="LATEST",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": ["subnet-05560be0f1e0a1afc"],
                    "securityGroups": ["sg-0e0b641ff9ab2785c"],
                    "assignPublicIp": "ENABLED",
                }
            },
        )["service"]
    else:
        svc_resp = ecs.update_service(
            cluster=cluster_name,
            service=svc_name,
            taskDefinition=fargate_td_arn,
            desiredCount=0,
            platformVersion="LATEST",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": ["subnet-05560be0f1e0a1afc"],
                    "securityGroups": ["sg-0e0b641ff9ab2785c"],
                    "assignPublicIp": "ENABLED",
                }
            },
        )["service"]

    svc_arn = svc_resp["serviceArn"]
    ecs.tag_resource(
        resourceArn=svc_arn,
        tags=[
            {"key": "Name", "value": svc_name},
            {"key": "Project", "value": "cis-compute-benchmark"},
            {"key": "Environment", "value": "lab"},
        ],
    )
    print(f"  [+] ECS Service: Đạt chuẩn 3.8 (LATEST) & 3.10 (Tagged); để assignPublicIp=ENABLED (3.2 & 3.14 FAIL)")

    # 5. Lambda Function URL: Đặt AuthType = 'NONE' (Vi phạm CIS 12.16)
    fn_name = "cis-compute-benchmark-lambda"
    url_cfgs = lmb.list_function_url_configs(FunctionName=fn_name).get(
        "FunctionUrlConfigs", []
    )
    if not url_cfgs:
        lmb.create_function_url_config(FunctionName=fn_name, AuthType="NONE")
    else:
        lmb.update_function_url_config(FunctionName=fn_name, AuthType="NONE")
    print(f"  [+] AWS Lambda: Đã cấu hình Function URL cho '{fn_name}' với AuthType='NONE' (12.16 FAIL)")
    print(f"{GREEN}{BOLD}[SEED HOÀN TẤT] Môi trường đã ở trạng thái 13 PASS / 8 FAIL (61.90%) sẵn sàng để bạn chạy --mode audit!{RESET}\n")


def run_all_audits(session: boto3.Session, account_id: str) -> List[CheckResult]:
    results: List[CheckResult] = []
    results.extend(run_ec2_audit(session))
    results.extend(run_ecs_audit(session, account_id))
    results.extend(run_fargate_audit(session))
    results.extend(run_lambda_audit(session))
    return results


def cleanup_kms_key(session: boto3.Session) -> None:
    """Gỡ KMS CMK khỏi ECS Cluster và lên lịch xóa KMS Key (PendingDeletion = $0.00 chi phí)."""
    ecs = session.client("ecs")
    kms = session.client("kms")
    cluster_name = "cis-compute-benchmark-cluster"
    ecs.update_cluster(
        cluster=cluster_name,
        configuration={
            "executeCommandConfiguration": {
                "logging": "OVERRIDE",
                "logConfiguration": {
                    "cloudWatchLogGroupName": "/ecs/exec-audit-logs",
                    "cloudWatchEncryptionEnabled": False,
                },
            },
            "managedStorageConfiguration": {},
        },
    )
    for al in kms.list_aliases().get("Aliases", []):
        if al.get("AliasName") == KMS_ALIAS_NAME and al.get("TargetKeyId"):
            kid = al["TargetKeyId"]
            meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
            if meta.get("KeyState") != "PendingDeletion":
                kms.schedule_key_deletion(KeyId=kid, PendingWindowInDays=7)
                print(f"{GREEN}[+] Đã gỡ KMS Key ({kid}) và đưa vào trạng thái PendingDeletion (7 ngày) -> Không phát sinh chi phí KMS!{RESET}")
            else:
                print(f"{YELLOW}[i] KMS Key ({kid}) đã ở trạng thái PendingDeletion.{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="CIS AWS Compute Services Benchmark v2.0.0 - Automated Runner (21 Controls)"
    )
    parser.add_argument(
        "--region", default="ap-southeast-1", help="AWS Region (mặc định: ap-southeast-1)"
    )
    parser.add_argument(
        "--mode",
        choices=["seed", "audit", "remediate", "cleanup-kms"],
        default="audit",
        help="Chế độ chạy: seed | audit | remediate | cleanup-kms",
    )
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region)
    caller_info = verify_caller_identity(session)
    account_id = caller_info["Account"]

    if args.mode == "seed":
        seed_non_compliant_environment(session, account_id)
        return

    if args.mode == "cleanup-kms":
        cleanup_kms_key(session)
        return

    # Thu thập cấu hình thực tế & Đánh giá mức độ tuân thủ (Audit Trước Remediation)
    before_results = run_all_audits(session, account_id)
    before_summary = print_audit_table(
        before_results,
        "KẾT QUẢ AUDIT TRƯỚC KHI REMEDIATION (INITIAL COMPLIANCE ASSESSMENT)",
    )
    export_reports(
        before_results,
        before_summary,
        caller_info,
        REPORTS_DIR / "audit_before_remediation.json",
        REPORTS_DIR / "audit_before_remediation.csv",
        phase="BEFORE_REMEDIATION",
    )

    if args.mode == "audit":
        return

    # Thực hiện Automated Remediation đối với các tiêu chí FAIL
    print(f"\n{BOLD}{CYAN}>>> THỰC THI KHẮC PHỤC TỰ ĐỘNG (AUTOMATED REMEDIATION VIA BOTO3) <<<{RESET}")
    print("-" * 125)
    all_actions: Dict[str, str] = {}
    all_actions.update(run_ec2_remediation(session, before_results))
    all_actions.update(run_ecs_remediation(session, account_id, before_results))
    all_actions.update(run_fargate_remediation(session, before_results))
    all_actions.update(run_lambda_remediation(session, before_results))

    if not all_actions:
        print(f"  {GREEN}[i] Tất cả 21 tiêu chí đã đạt chuẩn PASS, không cần thực hiện Remediation.{RESET}")
    else:
        for cid, act_desc in all_actions.items():
            print(f"  {GREEN}{BOLD}[REMEDIATED]{RESET} CIS {cid:<5} -> {act_desc}")
    print("-" * 125)

    # Kiểm tra lại sau Remediation (Post-Remediation Verification)
    after_results = run_all_audits(session, account_id)
    for r in after_results:
        if r.cis_id in all_actions:
            r.remediation_action = all_actions[r.cis_id]

    after_summary = print_audit_table(
        after_results,
        "KẾT QUẢ KIỂM TRA LẠI SAU REMEDIATION (POST-REMEDIATION VERIFICATION)",
    )

    # Xuất báo cáo tổng hợp JSON & CSV
    print(f"\n{BOLD}{CYAN}>>> TỔNG HỢP KẾT QUẢ VÀ XUẤT BÁO CÁO (REPORT GENERATION) <<<{RESET}")
    export_reports(
        after_results,
        after_summary,
        caller_info,
        REPORTS_DIR / "audit_after_remediation.json",
        REPORTS_DIR / "audit_after_remediation.csv",
        phase="AFTER_REMEDIATION",
    )

    # Xuất thêm file CSV đối chiếu Trước - Sau (Full Comparison) để chèn trực tiếp vào Báo cáo Word
    comparison_csv = REPORTS_DIR / "cis_automated_full_comparison.csv"
    before_map = {r.cis_id: r for r in before_results}
    with open(comparison_csv, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Mã CIS",
            "Dịch vụ",
            "Tên tiêu chí",
            "Tài nguyên kiểm tra",
            "Trạng thái Trước",
            "Chi tiết Trước Remediation",
            "Hành động Khắc phục Tự động (Boto3)",
            "Trạng thái Sau",
            "Chi tiết Xác minh Sau Remediation",
        ])
        for after_r in after_results:
            b_r = before_map.get(after_r.cis_id, after_r)
            writer.writerow([
                after_r.cis_id,
                after_r.service,
                after_r.title,
                after_r.resource_id,
                b_r.status,
                b_r.details,
                after_r.remediation_action,
                after_r.status,
                after_r.details,
            ])
    print(f"  [+] Đã xuất bảng đối chiếu Trước/Sau (CSV): {comparison_csv}\n")


if __name__ == "__main__":
    main()
