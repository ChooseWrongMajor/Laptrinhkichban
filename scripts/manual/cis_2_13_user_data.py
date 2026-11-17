#!/usr/bin/env python3
"""
CIS AWS Compute Services Benchmark v2.0.0
Recommendation 2.13: Ensure Secrets and Sensitive Data are not stored directly in EC2 User Data (Manual / Scripted)

Luồng thực hiện theo báo cáo (Mục 2.2.3 - Trang 16 -> 26) và CIS Benchmark (Trang 72-73):
- Bước 3: Kiểm tra quyền truy cập (aws sts get-caller-identity)
- Bước 4: Thu thập thuộc tính userData của từng EC2 instance bằng Boto3 (describe_instance_attribute),
          giải mã Base64 và quét tìm các mẫu thông tin nhạy cảm (mật khẩu, AWS Access Key, Secret Key, API Token, Private Key):
    + PASS: Không có User Data hoặc nội dung User Data không chứa thông tin nhạy cảm.
    + FAIL: Phát hiện từ khóa/mẫu thông tin bí mật trực tiếp trong User Data.
- Bước 5: Thực hiện Remediation đối với các EC2 instance chứa bí mật trong User Data:
    + Dừng instance (nếu đang running và được phép), sau đó xoá hoặc làm sạch các dòng chứa thông tin nhạy cảm trong User Data
      bằng modify_instance_attribute(InstanceId=..., UserData={'Value': ...}).
- Bước 6: Kiểm tra lại sau Remediation (Verification)
- Bước 7: Tổng hợp kết quả và xuất báo cáo (JSON & CSV)
"""

import argparse
import base64
import csv
import json
import os
import re
from datetime import datetime, timezone
import boto3
from botocore.exceptions import BotoCoreError, ClientError

CIS_ID = "2.13"
CIS_TITLE = "Ensure Secrets and Sensitive Data are not stored directly in EC2 User Data"

# Các mẫu Regex nhận diện thông tin nhạy cảm / bí mật phổ biến trong EC2 User Data
SECRET_PATTERNS = [
    (
        "AWS_ACCESS_KEY_ID",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "AWS_SECRET_ACCESS_KEY",
        re.compile(
            r"(?i)(aws_secret_access_key|secret_key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{20,}['\"]?"
        ),
    ),
    (
        "HARDCODED_PASSWORD",
        re.compile(
            r"(?i)(password|passwd|pwd|db_pass|db_password|mysql_root_password)\s*[:=]\s*['\"]?[^\s'\"]{4,}['\"]?"
        ),
    ),
    (
        "API_TOKEN_OR_SECRET",
        re.compile(
            r"(?i)(api_key|apikey|api_secret|access_token|auth_token|bearer_token|secret_token)\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?"
        ),
    ),
    (
        "PRIVATE_KEY_BLOCK",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
]


def check_caller_identity(session: boto3.Session) -> dict:
    """Bước 3: Kiểm tra danh tính AWS trước khi gọi API."""
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    return {
        "UserId": identity.get("UserId"),
        "Account": identity.get("Account"),
        "Arn": identity.get("Arn"),
    }


def decode_user_data(encoded_value: str | None) -> str:
    """Giải mã Base64 nội dung User Data của EC2."""
    if not encoded_value:
        return ""
    try:
        raw_bytes = base64.b64decode(encoded_value)
        return raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        return ""


def scan_secrets_in_text(text: str) -> list[str]:
    """Quét nội dung văn bản User Data để phát hiện các mẫu bí mật."""
    findings = []
    if not text:
        return findings

    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            matched_str = match.group(0)
            # Ẩn bớt giá trị nhạy cảm khi ghi log
            masked = matched_str[:12] + "***" if len(matched_str) > 12 else matched_str
            findings.append(f"{label} ({masked})")
    return findings


def sanitize_user_data(text: str) -> str:
    """Loại bỏ hoặc thay thế các dòng chứa thông tin nhạy cảm trong User Data."""
    cleaned_lines = []
    for line in text.splitlines():
        if scan_secrets_in_text(line):
            cleaned_lines.append(
                "# [REDACTED BY CIS 2.13 REMEDIATION] Secret moved to AWS Secrets Manager / SSM Parameter Store"
            )
        else:
            cleaned_lines.append(line)
    return "\n".join(cleaned_lines) + "\n"


def audit_ec2_user_data(ec2_client) -> list[dict]:
    """
    Bước 4: Thu thập User Data của tất cả EC2 instances (theo đúng trang 72 sách CIS Benchmark:
    1. aws ec2 describe-instances
    2. aws ec2 describe-instance-attribute --instance-id <id> --attribute userData
    3. Giải mã Base64 và kiểm tra có chứa secrets/sensitive data hay không).
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

                    attr_resp = ec2_client.describe_instance_attribute(
                        InstanceId=instance_id, Attribute="userData"
                    )
                    b64_val = attr_resp.get("UserData", {}).get("Value")
                    decoded_text = decode_user_data(b64_val)
                    findings = scan_secrets_in_text(decoded_text)

                    if not decoded_text.strip():
                        status = "PASS"
                        details = (
                            f"EC2 Instance {instance_id} (State: {state}) không cấu hình User Data "
                            f"(trống), không có thông tin nhạy cảm."
                        )
                    elif findings:
                        status = "FAIL"
                        details = (
                            f"EC2 Instance {instance_id} (State: {state}) phát hiện thông tin nhạy cảm "
                            f"trong User Data: {', '.join(findings)}"
                        )
                    else:
                        status = "PASS"
                        preview = " | ".join(
                            line.strip()
                            for line in decoded_text.splitlines()
                            if line.strip()
                        )[:160]
                        details = (
                            f"EC2 Instance {instance_id} (State: {state}) có User Data hợp lệ (không chứa "
                            f"mật khẩu/khóa bí mật). Nội dung: {preview}"
                        )

                    results.append(
                        {
                            "cis_id": CIS_ID,
                            "check": CIS_TITLE,
                            "resource_type": "EC2_Instance",
                            "resource_id": instance_id,
                            "instance_state": state,
                            "has_user_data": bool(decoded_text.strip()),
                            "findings": findings,
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
                    "has_user_data": False,
                    "findings": [],
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
                "has_user_data": False,
                "findings": [],
                "status": "ERROR",
                "details": f"Lỗi khi gọi AWS API: {exc}",
                "timestamp": timestamp,
            }
        )

    return results


def remediate_ec2_user_data(
    ec2_client, audit_results: list[dict], dry_run: bool = False
) -> list[dict]:
    """
    Bước 5: Khắc phục các EC2 instance có chứa thông tin nhạy cảm trong User Data
    theo trang 73 sách CIS Benchmark:
    - Nếu instance đang running: phải stop instance trước khi sửa User Data.
    - Cập nhật lại User Data đã loại bỏ thông tin nhạy cảm.
    """
    actions = []

    for item in audit_results:
        if item["status"] != "FAIL":
            continue

        instance_id = item["resource_id"]
        state = item["instance_state"]

        try:
            attr_resp = ec2_client.describe_instance_attribute(
                InstanceId=instance_id, Attribute="userData"
            )
            b64_val = attr_resp.get("UserData", {}).get("Value")
            decoded_text = decode_user_data(b64_val)
            sanitized_text = sanitize_user_data(decoded_text)

            if not dry_run:
                was_running = state == "running"
                if was_running:
                    ec2_client.stop_instances(InstanceIds=[instance_id])
                    waiter = ec2_client.get_waiter("instance_stopped")
                    waiter.wait(InstanceIds=[instance_id])

                ec2_client.modify_instance_attribute(
                    InstanceId=instance_id,
                    UserData={"Value": sanitized_text.encode("utf-8")},
                )

                if was_running:
                    ec2_client.start_instances(InstanceIds=[instance_id])

            actions.append(
                {
                    "resource_id": instance_id,
                    "resource_type": "EC2_Instance",
                    "action": "sanitize_secrets_from_user_data",
                    "status": "DRY_RUN" if dry_run else "SUCCESS",
                    "details": (
                        f"Đã làm sạch các dòng chứa thông tin nhạy cảm khỏi User Data "
                        f"của EC2 Instance {instance_id}."
                    ),
                }
            )
        except (BotoCoreError, ClientError) as exc:
            actions.append(
                {
                    "resource_id": instance_id,
                    "resource_type": "EC2_Instance",
                    "action": "sanitize_secrets_from_user_data",
                    "status": "ERROR",
                    "details": f"Không thể cập nhật User Data cho {instance_id}: {exc}",
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
        "has_user_data",
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

        for res_id, init_rec in initial_map.items():
            act_rec = action_map.get(res_id, {})
            fin_rec = final_map.get(res_id, {})
            writer.writerow(
                {
                    "cis_id": init_rec.get("cis_id", CIS_ID),
                    "check_name": init_rec.get("check", CIS_TITLE),
                    "resource_id": res_id,
                    "instance_state": init_rec.get("instance_state"),
                    "has_user_data": init_rec.get("has_user_data"),
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
        description="CIS 2.13 - Audit & Remediation: Ensure Secrets and Sensitive Data are not stored directly in EC2 User Data"
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
    initial_audit = audit_ec2_user_data(ec2_client)
    for res in initial_audit:
        print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")

    remediation_actions = []
    post_remediation_audit = []

    has_failures = any(r["status"] == "FAIL" for r in initial_audit)

    if args.mode == "remediate" and has_failures:
        print(f"\n[*] Bước 5: Thực hiện Remediation cho CIS {CIS_ID} (dry_run={args.dry_run})...")
        remediation_actions = remediate_ec2_user_data(
            ec2_client, initial_audit, dry_run=args.dry_run
        )
        for act in remediation_actions:
            print(f"    - [{act['status']}] {act['action']} ({act['resource_id']}): {act['details']}")

        print(f"\n[*] Bước 6: Kiểm tra lại (Verification) sau khi Remediation...")
        post_remediation_audit = audit_ec2_user_data(ec2_client)
        for res in post_remediation_audit:
            print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")
    elif args.mode == "remediate" and not has_failures:
        print("\n[*] Tất cả EC2 instances đều có User Data an toàn (PASS), không cần Remediation.")

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

    json_path = os.path.join(args.output_dir, "cis_2_13_report.json")
    csv_path = os.path.join(args.output_dir, "cis_2_13_report.csv")
    export_reports(report_data, json_path, csv_path)

    print(f"\n[*] Bước 7: Đã xuất báo cáo kết quả tại:")
    print(f"    - JSON: {json_path}")
    print(f"    - CSV : {csv_path}")


if __name__ == "__main__":
    main()
