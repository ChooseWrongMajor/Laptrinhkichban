import boto3
import json
from datetime import datetime, timezone

REGION = "us-east-1"

# Tạo các AWS clients
ec2 = boto3.client("ec2", region_name=REGION)

# Lưu kết quả audit
audit_results = []


def add_result(check_name, resource_id, status, details):
    """Thêm một kết quả audit vào danh sách."""
    audit_results.append({
        "check": check_name,
        "resource_id": resource_id,
        "status": status,
        "details": details
    })


def audit_security_groups():

    response = ec2.describe_security_groups()

    for sg in response["SecurityGroups"]:
        sg_id = sg["GroupId"]
        sg_name = sg["GroupName"]

        ssh_open_to_world = False

        for rule in sg.get("IpPermissions", []):
            # Chỉ xét rule TCP có port 22
            if rule.get("IpProtocol") == "tcp":
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                if from_port <= 22 <= to_port:
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            ssh_open_to_world = True

        if ssh_open_to_world:
            status = "FAIL"
            details = (
                f"Security Group {sg_name} ({sg_id}) "
                "cho phép SSH từ 0.0.0.0/0"
            )
        else:
            status = "PASS"
            details = (
                f"Không phát hiện rule IPv4 0.0.0.0/0 "
                f"cho phép TCP port 22 trong {sg_name} ({sg_id})"
            )

        add_result(
            "SSH restricted from internet",
            sg_id,
            status,
            details
        )


def audit_ec2_instances():
    """Kiểm tra trạng thái, Public IP và EBS encryption của EC2."""

    response = ec2.describe_instances()

    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instance_id = instance["InstanceId"]
            state = instance["State"]["Name"]
            public_ip = instance.get("PublicIpAddress")

            # Kiểm tra trạng thái instance
            if state == "running":
                add_result(
                    "EC2 instance state",
                    instance_id,
                    "PASS",
                    "Instance đang ở trạng thái running"
                )
            else:
                add_result(
                    "EC2 instance state",
                    instance_id,
                    "INFO",
                    f"Instance đang ở trạng thái {state}"
                )

            # Ghi nhận Public IP, chưa kết luận vi phạm CIS
            if public_ip:
                add_result(
                    "EC2 public IP",
                    instance_id,
                    "INFO",
                    f"Instance có Public IP: {public_ip}"
                )
            else:
                add_result(
                    "EC2 public IP",
                    instance_id,
                    "INFO",
                    "Instance không có Public IP"
                )

            # Kiểm tra các EBS volumes gắn vào instance
            for mapping in instance.get("BlockDeviceMappings", []):
                ebs = mapping.get("Ebs")

                if not ebs:
                    continue

                volume_id = ebs["VolumeId"]

                volume_response = ec2.describe_volumes(
                    VolumeIds=[volume_id]
                )

                for volume in volume_response["Volumes"]:
                    encrypted = volume["Encrypted"]

                    if encrypted:
                        status = "PASS"
                        details = "EBS volume đã được mã hóa"
                    else:
                        status = "FAIL"
                        details = "EBS volume chưa được mã hóa"

                    add_result(
                        "EBS volume encryption",
                        volume_id,
                        status,
                        details
                    )


def main():
    print(f"Bắt đầu audit AWS region: {REGION}")

    audit_security_groups()
    audit_ec2_instances()

    report = {
        "region": REGION,
        "audit_time": datetime.now(timezone.utc).isoformat(),
        "results": audit_results
    }

    # Xuất báo cáo JSON
    with open("audit_report.json", "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    # In kết quả ra terminal
    for result in audit_results:
        print(
            f"[{result['status']}] "
            f"{result['check']} | "
            f"{result['resource_id']} | "
            f"{result['details']}"
        )

    print("\nĐã lưu báo cáo vào audit_report.json")


if __name__ == "__main__":
    main()