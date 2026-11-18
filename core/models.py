from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# Trạng thái audit
PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"
NOT_APPLICABLE = "NOT_APPLICABLE"

# Mức remediation của từng khuyến nghị
TIER_AUTO = "AUTO"              # tự động sửa an toàn
TIER_APPROVAL = "APPROVAL"      # tạo bản thay thế, xoá tài nguyên cũ cần duyệt
TIER_AUDIT_ONLY = "AUDIT_ONLY"  # chỉ audit, sửa thủ công


# Trạng thái remediation
PLANNED = "PLANNED"                          # dry-run: mới lập kế hoạch
REMEDIATED = "REMEDIATED"                    # đã sửa và verify PASS
PENDING_APPROVAL = "PENDING_APPROVAL"        # đã tạo bản thay thế, tài nguyên cũ chờ duyệt xoá
SKIPPED_AUDIT_ONLY = "SKIPPED_AUDIT_ONLY"    # tier C, không tự động sửa
SKIPPED_COMPLIANT = "SKIPPED_COMPLIANT"      # kiểm tra lại trước khi sửa thì đã PASS
SKIPPED_OUT_OF_SCOPE = "SKIPPED_OUT_OF_SCOPE"  # không còn tồn tại hoặc ngoài phạm vi tag
REMEDIATION_FAILED = "FAILED"                # gọi API lỗi hoặc verify vẫn FAIL


@dataclass
class AuditContext:
    """Thông tin chung truyền cho mọi hàm đánh giá."""
    account_id: str
    region: str
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Finding:
    """Kết quả kiểm tra một khuyến nghị CIS trên một tài nguyên."""
    cis_id: str
    resource_id: str
    status: str
    message: str
    resource_name: str = ""
    region: str = ""
    evidence: dict = field(default_factory=dict)
    checked_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self):
        return asdict(self)


@dataclass
class RemediationResult:
    """Kết quả remediation một tài nguyên FAIL."""
    cis_id: str
    resource_id: str
    status: str
    action: str
    message: str
    tier: str = ""
    resource_name: str = ""
    region: str = ""
    before: str = FAIL
    after: str = ""
    rollback: str = ""                                    # lệnh CLI để hoàn tác
    created_resources: list = field(default_factory=list)  # tài nguyên mới do remediation tạo ra
    verify_ids: list = field(default_factory=list)          # tài nguyên cần kiểm tra lại sau khi sửa
    details: dict = field(default_factory=dict)
    executed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class Control:
    """Metadata của một khuyến nghị CIS và cách kiểm tra nó."""
    cis_id: str
    title: str
    service: str
    level: int
    source: str          # tên phương thức của Collector trả về danh sách tài nguyên
    evaluate: object     # hàm (resource, ctx) -> Finding
    remediation: str     # TIER_AUTO / TIER_APPROVAL / TIER_AUDIT_ONLY
    note: str = ""       # lý do khi không tự động sửa
