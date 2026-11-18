"""
CIS ID -> hành động remediation. Tier của từng control lấy từ audit/registry.py.

Thứ tự thực thi được cố định:
  - 2.2.2 trước 2.2.3: đóng public snapshot trước khi copy/xoá
  - 3.3 trước 3.4: cả hai tạo revision mới, mỗi bước dựa trên revision mới nhất
  - 2.2.1 cuối cùng: thay đổi cấp account, ảnh hưởng rộng nhất
"""
from remediation.actions import ebs, ec2, ecs, lambda_

ACTIONS = {
    "2.2.2": ebs.make_snapshot_private,
    "2.2.3": ebs.encrypt_snapshot,
    "2.1.2": ec2.encrypt_ami,
    "2.14": ec2.propagate_asg_tags,
    "3.2": ecs.disable_service_public_ip,
    "3.3": ecs.remove_host_pid_mode,
    "3.4": ecs.disable_privileged,
    "3.9": ecs.enable_container_insights,
    "3.11": ecs.tag_cluster,
    "12.16": lambda_.require_iam_auth,
    "2.2.1": ebs.enable_ebs_default_encryption,
}

EXECUTION_ORDER = list(ACTIONS)


def ordered(controls):
    """Sắp control theo thứ tự thực thi; control không có action (audit-only) xếp cuối."""
    rank = {cid: i for i, cid in enumerate(EXECUTION_ORDER)}
    return sorted(controls, key=lambda c: rank.get(c.cis_id, len(rank)))
