"""
Danh sách 15 khuyến nghị Automated được triển khai, theo CIS AWS Compute
Services Benchmark v2.0.0. Thứ tự trong CONTROLS là thứ tự in trong báo cáo.
"""
from audit.checks import ebs, ec2, ecs, lambda_
from core.models import TIER_APPROVAL, TIER_AUDIT_ONLY, TIER_AUTO, Control

CONTROLS = [
    Control("2.1.2", "AMIs are encrypted", "AMI", 1,
            "images", ec2.ami_encrypted, TIER_APPROVAL,
            "Copy AMI có mã hóa; deregister AMI cũ cần duyệt"),
    Control("2.1.4", "AMIs not older than 90 days", "AMI", 1,
            "images", ec2.ami_not_older_than_90_days, TIER_AUDIT_ONLY,
            "Cần build lại AMI (launch, patch, create image)"),
    Control("2.2.1", "EBS encryption by default enabled", "EBS", 1,
            "ebs_default_encryption", ebs.ebs_encryption_by_default, TIER_AUTO),
    Control("2.2.2", "EBS snapshots not public", "EBS", 1,
            "snapshots", ebs.snapshot_not_public, TIER_AUTO),
    Control("2.2.3", "EBS snapshots are encrypted", "EBS", 1,
            "snapshots", ebs.snapshot_encrypted, TIER_APPROVAL,
            "Copy snapshot có mã hóa; xoá snapshot cũ cần duyệt"),
    Control("2.14", "ASG propagates tags to instances", "EC2", 1,
            "auto_scaling_groups", ec2.asg_propagates_tags, TIER_AUTO),
    Control("3.2", "ECS service assignPublicIp DISABLED", "ECS", 1,
            "ecs_services", ecs.service_no_public_ip, TIER_AUTO),
    Control("3.3", "Task def pidMode not host", "ECS", 1,
            "ecs_task_definitions", ecs.task_def_no_host_pid, TIER_AUTO),
    Control("3.4", "Task def not privileged", "ECS", 1,
            "ecs_task_definitions", ecs.task_def_not_privileged, TIER_AUTO),
    Control("3.5", "Task def readonlyRootFilesystem", "ECS", 1,
            "ecs_task_definitions", ecs.task_def_readonly_root, TIER_AUDIT_ONLY,
            "Ứng dụng có thể cần ghi vào filesystem, phải kiểm thử trước"),
    Control("3.6", "No secrets in task def env vars", "ECS", 1,
            "ecs_task_definitions", ecs.task_def_no_secret_env, TIER_AUDIT_ONLY,
            "Phải chuyển secret sang Secrets Manager/SSM trước khi xoá biến"),
    Control("3.7", "Task def logging configured", "ECS", 1,
            "ecs_task_definitions", ecs.task_def_logging, TIER_AUDIT_ONLY,
            "Cần quyết định log driver và log group"),
    Control("3.9", "ECS cluster Container Insights", "ECS", 2,
            "ecs_clusters", ecs.cluster_container_insights, TIER_AUTO),
    Control("3.11", "ECS cluster tagged", "ECS", 1,
            "ecs_clusters", ecs.cluster_tagged, TIER_AUTO),
    Control("12.16", "Lambda Function URL uses AWS_IAM", "Lambda", 1,
            "lambda_function_urls", lambda_.function_url_iam_auth, TIER_AUTO),
]

CONTROLS_BY_ID = {c.cis_id: c for c in CONTROLS}


def select_controls(only=None):
    """Lọc control theo danh sách CIS ID (vd: ['2.2.1', '3.4'])."""
    if not only:
        return list(CONTROLS)
    unknown = [cid for cid in only if cid not in CONTROLS_BY_ID]
    if unknown:
        raise ValueError(f"CIS ID không có trong registry: {', '.join(unknown)}")
    return [c for c in CONTROLS if c.cis_id in only]
