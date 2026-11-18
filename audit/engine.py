from botocore.exceptions import BotoCoreError, ClientError

from audit.collectors import Collector, error_text
from core.models import ERROR, AuditContext, Finding


def audit_control(collector, control, ctx):
    """Chạy một control trên toàn bộ tài nguyên mà collector thu thập được."""
    try:
        resources = getattr(collector, control.source)
    except (ClientError, BotoCoreError) as exc:
        # Không thu thập được (thiếu quyền, service không khả dụng...) -> ERROR cho cả control
        return [Finding(
            cis_id=control.cis_id, resource_id="*", region=ctx.region, status=ERROR,
            message=f"Không thu thập được dữ liệu: {error_text(exc)}",
        )]
    return [control.evaluate(resource, ctx) for resource in resources]


def run_audit(aws, regions, controls, scope=None, progress=None):
    """
    Audit các control trên nhiều region, trả về danh sách Finding.
    Remediation cũng dùng hàm này để kiểm tra lại sau khi sửa.
    """
    findings = []
    for region in regions:
        collector = Collector(aws, region, scope)
        ctx = AuditContext(account_id=aws.account_id, region=region)
        for control in controls:
            if progress:
                progress(region, control)
            findings.extend(audit_control(collector, control, ctx))
    return findings
