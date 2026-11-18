from dataclasses import dataclass, field

from botocore.exceptions import ClientError

from core.models import PENDING_APPROVAL, PLANNED, REMEDIATED

# Tag gắn vào mọi tài nguyên do remediation tạo ra, để cleanup.py tìm và dọn
CREATED_BY_KEY = "CreatedBy"
CREATED_BY_VALUE = "cis-remediation"

# Chờ AMI/snapshot copy xong: kiểm tra mỗi 15 giây, tối đa 30 phút
WAITER_CONFIG = {"Delay": 15, "MaxAttempts": 120}


@dataclass
class ActionContext:
    """Thông tin chung cho mọi hành động remediation trong một region."""
    aws: object
    region: str
    account_id: str
    collector: object          # Collector mới (đã lọc scope) để tra cứu tài nguyên liên quan
    dry_run: bool = True
    allow_destructive: bool = False

    def client(self, service):
        return self.aws.client(service, self.region)


@dataclass
class ActionOutcome:
    """Kết quả một hành động, engine sẽ chuyển thành RemediationResult."""
    status: str
    action: str
    message: str
    rollback: str = ""
    created_resources: list = field(default_factory=list)
    verify_ids: list = field(default_factory=list)  # rỗng = kiểm tra lại chính tài nguyên gốc
    details: dict = field(default_factory=dict)


def planned(action, message, rollback="", **details):
    return ActionOutcome(PLANNED, action, message, rollback, details=details)


def remediated(action, message, rollback="", verify_ids=None, created=None, **details):
    return ActionOutcome(REMEDIATED, action, message, rollback,
                         created_resources=created or [], verify_ids=verify_ids or [],
                         details=details)


def pending_approval(action, message, rollback="", verify_ids=None, created=None, **details):
    return ActionOutcome(PENDING_APPROVAL, action, message, rollback,
                         created_resources=created or [], verify_ids=verify_ids or [],
                         details=details)


def ec2_dry_run(method, **params):
    """
    Gọi API EC2 với DryRun=True: AWS kiểm tra quyền và tham số nhưng không thay đổi gì.
    Thành công trả về DryRunOperation; thiếu quyền trả về UnauthorizedOperation (ném lỗi).
    """
    try:
        method(DryRun=True, **params)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DryRunOperation":
            return "DryRun OK: đủ quyền và tham số hợp lệ"
        raise
    return "DryRun OK"


def remediation_tags(cis_id, source_id, existing=None, key_style="Key"):
    """
    Bộ tag cho tài nguyên mới: giữ tag của tài nguyên gốc (trừ tag 'aws:' do AWS quản lý)
    và thêm tag đánh dấu nguồn gốc. key_style = "Key" (EC2) hoặc "key" (ECS).
    """
    value_style = "Value" if key_style == "Key" else "value"
    tags = {}
    for tag in existing or []:
        key = tag.get("Key", tag.get("key"))
        if key and not key.startswith("aws:"):
            tags[key] = tag.get("Value", tag.get("value", ""))
    tags.update({CREATED_BY_KEY: CREATED_BY_VALUE, "SourceResource": source_id, "CisId": cis_id})
    return [{key_style: k, value_style: v} for k, v in tags.items()]
