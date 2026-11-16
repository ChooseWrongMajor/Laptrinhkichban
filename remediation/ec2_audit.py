import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# =========================
# Configuration
# =========================

REGION = "us-east-1"

# Security Group được phát hiện FAIL trong báo cáo audit
TARGET_SG_ID = "sg-055c7152a7a2dbded"

# True: chỉ kiểm tra và mô phỏng, không thay đổi AWS
# False: thực hiện remediation thật
DRY_RUN = False

ec2 = boto3.client("ec2", region_name=REGION)


def find_ssh_open_rules(group_id):
    """
    Tìm các inbound rule cho phép TCP port 22
    từ toàn bộ IPv4 (0.0.0.0/0).
    """

    response = ec2.describe_security_groups(
        GroupIds=[group_id]
    )

    security_groups = response["SecurityGroups"]

    if not security_groups:
        raise RuntimeError(
            f"Không tìm thấy Security Group {group_id}"
        )

    security_group = security_groups[0]
    matching_permissions = []

    for permission in security_group.get("IpPermissions", []):

        # Chỉ xét TCP
        if permission.get("IpProtocol") != "tcp":
            continue

        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        # Chỉ xử lý rule có phạm vi bao gồm port 22
        if from_port is None or to_port is None:
            continue

        if not (from_port <= 22 <= to_port):
            continue

        # Chỉ xóa rule có CIDR IPv4 0.0.0.0/0
        matching_ranges = [
            ip_range
            for ip_range in permission.get("IpRanges", [])
            if ip_range.get("CidrIp") == "0.0.0.0/0"
        ]

        if matching_ranges:
            # Chỉ giữ CIDR cần xóa trong bản sao của permission
            permission_to_revoke = {
                **permission,
                "IpRanges": matching_ranges
            }

            matching_permissions.append(
                permission_to_revoke
            )

    return matching_permissions


def verify_remediation(group_id):
    """
    Kiểm tra lại Security Group sau remediation.
    """

    remaining_rules = find_ssh_open_rules(group_id)

    if not remaining_rules:
        return {
            "status": "PASS",
            "details": (
                "Không còn inbound rule TCP port 22 "
                "từ 0.0.0.0/0."
            )
        }

    return {
        "status": "FAIL",
        "details": (
            "Vẫn còn inbound rule TCP port 22 "
            "từ 0.0.0.0/0."
        )
    }


def remediate():
    report = {
        "region": REGION,
        "target_security_group": TARGET_SG_ID,
        "remediation_time": datetime.now(
            timezone.utc
        ).isoformat(),
        "dry_run": DRY_RUN,
        "actions": []
    }

    try:
        rules = find_ssh_open_rules(TARGET_SG_ID)

        if not rules:
            print(
                "PASS: Không tìm thấy rule SSH "
                "mở cho toàn bộ Internet."
            )

            report["actions"].append({
                "action": "revoke_ssh_from_world",
                "status": "PASS",
                "details": "Không cần sửa cấu hình."
            })

        else:
            for rule in rules:
                if DRY_RUN:
                    print(
                        "[DRY RUN] Sẽ xóa rule SSH "
                        f"mở cho toàn bộ Internet "
                        f"trong {TARGET_SG_ID}"
                    )

                    report["actions"].append({
                        "action": "revoke_ssh_from_world",
                        "status": "DRY_RUN",
                        "details": (
                            "Đã tìm thấy rule cần xử lý; "
                            "chưa thay đổi AWS."
                        ),
                        "rule": rule
                    })

                else:
                    response = ec2.revoke_security_group_ingress(
                        GroupId=TARGET_SG_ID,
                        IpPermissions=[rule]
                    )

                    success = response.get(
                        "Return", False
                    )

                    report["actions"].append({
                        "action": "revoke_ssh_from_world",
                        "status": (
                            "SUCCESS" if success else "ERROR"
                        ),
                        "details": (
                            "Đã gửi yêu cầu xóa rule SSH."
                            if success else
                            "AWS chưa xác nhận xóa rule."
                        ),
                        "rule": rule
                    })

                    print(
                        "Đã gửi yêu cầu xóa rule SSH "
                        f"trong {TARGET_SG_ID}"
                    )

        # Chỉ xác minh trạng thái thực tế khi không phải DRY RUN
        if not DRY_RUN:
            verification = verify_remediation(
                TARGET_SG_ID
            )

            report["verification"] = verification

            print(
                f"Verification: {verification['status']}"
            )
            print(verification["details"])

    except ClientError as error:
        error_message = error.response.get(
            "Error", {}
        ).get("Message", str(error))

        print(f"ERROR: {error_message}")

        report["actions"].append({
            "action": "revoke_ssh_from_world",
            "status": "ERROR",
            "details": error_message
        })

    except Exception as error:
        print(f"ERROR: {error}")

        report["actions"].append({
            "action": "revoke_ssh_from_world",
            "status": "ERROR",
            "details": str(error)
        })

    # Xuất báo cáo remediation
    with open(
        "remediation_report.json",
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(
        "\nĐã lưu kết quả vào remediation_report.json"
    )


if __name__ == "__main__":
    remediate()