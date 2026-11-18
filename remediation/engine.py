from collections import defaultdict

from botocore.exceptions import BotoCoreError, ClientError, WaiterError

from audit.collectors import Collector, error_text
from audit.engine import audit_control
from core.models import (
    FAIL, PASS, PENDING_APPROVAL, REMEDIATED, REMEDIATION_FAILED, SKIPPED_AUDIT_ONLY,
    SKIPPED_COMPLIANT, SKIPPED_OUT_OF_SCOPE, TIER_AUDIT_ONLY, AuditContext, Finding,
    RemediationResult,
)
from remediation.actions.base import ActionContext
from remediation.registry import ACTIONS, ordered


def load_findings(details):
    """Chuyển audit_details.json thành danh sách Finding."""
    return [Finding(**item) for item in details["findings"]]


def _result(finding, control, status, action, message, **extra):
    return RemediationResult(
        cis_id=finding.cis_id, resource_id=finding.resource_id,
        resource_name=finding.resource_name, region=finding.region,
        tier=control.remediation, status=status, action=action, message=message,
        before=finding.status, **extra,
    )


def match_key(resource_id):
    """
    Khoá đối chiếu tài nguyên giữa lần audit và hiện tại.
    Task definition so theo family (bỏ ':revision'), vì CIS chỉ xét revision mới nhất
    và một bước remediation trước đó có thể đã tạo revision mới.
    """
    if ":task-definition/" in resource_id:
        return resource_id.rsplit(":", 1)[0]
    return resource_id


def _current_resources(collector, control, ctx):
    """
    Thu thập lại tài nguyên (trong scope) và đánh giá lại ngay trước khi sửa,
    phòng trường hợp trạng thái đã thay đổi kể từ lần audit.
    Trả về {match_key: (resource, finding hiện tại)}.
    """
    resources = getattr(collector, control.source)
    current = {}
    for resource in resources:
        finding = control.evaluate(resource, ctx)
        current[match_key(finding.resource_id)] = (resource, finding)
    return current


def remediate(aws, findings, controls, scope, dry_run=True, allow_destructive=False, progress=None):
    """
    Remediation cho các Finding FAIL của audit.
    dry_run=True: chỉ lập kế hoạch (EC2 dùng DryRun=True để kiểm tra quyền).
    """
    targets = defaultdict(list)
    for f in findings:
        if f.status == FAIL:
            targets[(f.cis_id, f.region)].append(f)

    results = []
    for control in ordered(controls):
        regions = sorted({region for (cid, region) in targets if cid == control.cis_id})
        for region in regions:
            fails = targets[(control.cis_id, region)]

            if control.remediation == TIER_AUDIT_ONLY or control.cis_id not in ACTIONS:
                results += [_result(f, control, SKIPPED_AUDIT_ONLY, "-", control.note) for f in fails]
                continue

            # Collector mới cho mỗi control: tránh dùng cache cũ sau khi bước trước đã sửa
            collector = Collector(aws, region, scope)
            audit_ctx = AuditContext(account_id=aws.account_id, region=region)
            action_ctx = ActionContext(aws, region, aws.account_id, collector, dry_run, allow_destructive)

            try:
                current = _current_resources(collector, control, audit_ctx)
            except (ClientError, BotoCoreError) as exc:
                results += [_result(f, control, REMEDIATION_FAILED, "-",
                                    f"Không thu thập lại được: {error_text(exc)}") for f in fails]
                continue

            for f in fails:
                if progress:
                    progress(control, f)
                key = match_key(f.resource_id)
                if key not in current:
                    results.append(_result(f, control, SKIPPED_OUT_OF_SCOPE, "-",
                                           "Tài nguyên không còn tồn tại hoặc nằm ngoài scope tag"))
                    continue
                resource, now = current[key]
                if now.status != FAIL:
                    results.append(_result(f, control, SKIPPED_COMPLIANT, "-",
                                           f"Kiểm tra lại trước khi sửa: {now.status}"))
                    continue
                try:
                    outcome = ACTIONS[control.cis_id](resource, action_ctx)
                except (ClientError, BotoCoreError, WaiterError) as exc:
                    results.append(_result(f, control, REMEDIATION_FAILED, "-", error_text(exc)))
                    continue
                results.append(_result(
                    f, control, outcome.status, outcome.action, outcome.message,
                    rollback=outcome.rollback, created_resources=outcome.created_resources,
                    verify_ids=outcome.verify_ids or [now.resource_id], details=outcome.details,
                ))
    return results


def verify(aws, results, controls, scope):
    """
    Bước kiểm tra lại: chạy lại đúng hàm check của audit trên tài nguyên đã sửa.
    Không tin vào việc API trả về thành công, mà xác minh trạng thái thực tế trên AWS.
    """
    by_id = {c.cis_id: c for c in controls}
    groups = defaultdict(list)
    for r in results:
        if r.status in (REMEDIATED, PENDING_APPROVAL):
            groups[(r.cis_id, r.region)].append(r)

    for (cis_id, region), items in groups.items():
        collector = Collector(aws, region, scope)
        ctx = AuditContext(account_id=aws.account_id, region=region)
        status_of = {f.resource_id: f.status for f in audit_control(collector, by_id[cis_id], ctx)}

        for r in items:
            checks = {vid: status_of.get(vid, "NOT_FOUND") for vid in r.verify_ids}
            r.details["verify"] = checks
            fixed = all(s == PASS for s in checks.values())

            if r.status == PENDING_APPROVAL:
                # Bản thay thế đã đạt, tài nguyên gốc vẫn FAIL cho tới khi được duyệt xoá
                r.after = status_of.get(r.resource_id, "NOT_FOUND")
                if not fixed:
                    r.status = REMEDIATION_FAILED
                    r.message += f" | Verify bản thay thế không đạt: {checks}"
            else:
                r.after = PASS if fixed else FAIL
                if not fixed:
                    r.status = REMEDIATION_FAILED
                    r.message += f" | Verify không đạt: {checks}"
    return results
