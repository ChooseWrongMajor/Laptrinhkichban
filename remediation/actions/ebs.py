from remediation.actions.base import (
    WAITER_CONFIG, ec2_dry_run, pending_approval, planned, remediated, remediation_tags,
)


def enable_ebs_default_encryption(setting, ctx):
    """CIS 2.2.1 (tier A): bật EBS encryption by default cho region."""
    ec2 = ctx.client("ec2")
    action = "ec2.enable_ebs_encryption_by_default()"
    rollback = f"aws ec2 disable-ebs-encryption-by-default --region {ctx.region}"

    if ctx.dry_run:
        check = ec2_dry_run(ec2.enable_ebs_encryption_by_default)
        return planned(action, f"Sẽ bật mã hóa mặc định cho mọi volume mới trong {ctx.region}. {check}",
                       rollback, scope="account-level")

    ec2.enable_ebs_encryption_by_default()
    return remediated(action, "Đã bật EBS encryption by default", rollback)


def make_snapshot_private(snap, ctx):
    """CIS 2.2.2 (tier A): gỡ quyền createVolumePermission của group 'all'."""
    ec2 = ctx.client("ec2")
    snapshot_id = snap["SnapshotId"]
    params = {
        "SnapshotId": snapshot_id,
        "Attribute": "createVolumePermission",
        "OperationType": "remove",
        "GroupNames": ["all"],
    }
    action = f"ec2.modify_snapshot_attribute({snapshot_id}, remove group=all)"
    rollback = (f"aws ec2 modify-snapshot-attribute --region {ctx.region} --snapshot-id {snapshot_id} "
                f"--attribute createVolumePermission --operation-type add --group-names all")

    if ctx.dry_run:
        check = ec2_dry_run(ec2.modify_snapshot_attribute, **params)
        return planned(action, f"Sẽ chuyển snapshot về private. {check}", rollback)

    ec2.modify_snapshot_attribute(**params)
    return remediated(action, "Đã gỡ quyền public của snapshot", rollback)


def encrypt_snapshot(snap, ctx):
    """
    CIS 2.2.3 (tier B): snapshot không mã hóa tại chỗ được -> copy với Encrypted=True.
    Chỉ xoá snapshot gốc khi có --allow-destructive.
    """
    ec2 = ctx.client("ec2")
    source_id = snap["SnapshotId"]
    tags = remediation_tags("2.2.3", source_id, snap.get("Tags"))
    for tag in tags:
        if tag["Key"] == "Name":
            tag["Value"] = f"{tag['Value']}-encrypted"

    params = {
        "SourceSnapshotId": source_id,
        "SourceRegion": ctx.region,
        "Encrypted": True,
        "Description": f"Encrypted copy of {source_id} (CIS 2.2.3 remediation)",
        "TagSpecifications": [{"ResourceType": "snapshot", "Tags": tags}],
    }
    action = f"ec2.copy_snapshot({source_id}, Encrypted=True)"

    if ctx.dry_run:
        check = ec2_dry_run(ec2.copy_snapshot, **params)
        step2 = ("rồi xoá snapshot gốc" if ctx.allow_destructive
                 else "snapshot gốc giữ lại chờ duyệt (--allow-destructive để xoá)")
        return planned(action, f"Sẽ tạo bản copy mã hóa, {step2}. {check}")

    new_id = ec2.copy_snapshot(**params)["SnapshotId"]
    ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[new_id], WaiterConfig=WAITER_CONFIG)

    if ctx.allow_destructive:
        ec2.delete_snapshot(SnapshotId=source_id)
        return remediated(
            f"{action} -> {new_id}; delete_snapshot({source_id})",
            f"Đã tạo {new_id} (mã hóa) và xoá snapshot gốc",
            rollback="Không hoàn tác được việc xoá snapshot; dùng bản copy mã hóa thay thế",
            verify_ids=[new_id], created=[new_id], deleted=[source_id],
        )
    return pending_approval(
        f"{action} -> {new_id}",
        f"Đã tạo {new_id} (mã hóa); snapshot gốc chờ duyệt xoá",
        rollback=f"aws ec2 delete-snapshot --region {ctx.region} --snapshot-id {new_id}",
        verify_ids=[new_id], created=[new_id],
    )
