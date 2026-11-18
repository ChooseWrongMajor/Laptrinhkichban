from audit.checks.base import evaluator
from core.models import FAIL, PASS
from core.scope import normalize_tags


def _snapshot_id(snap):
    return snap["SnapshotId"]


def _snapshot_name(snap):
    return normalize_tags(snap.get("Tags")).get("Name", "")


@evaluator("2.2.1", lambda r: f"ebs-encryption-by-default/{r['region']}")
def ebs_encryption_by_default(setting, ctx):
    """CIS 2.2.1: bật 'Always encrypt new EBS volumes' cho region."""
    enabled = setting["EbsEncryptionByDefault"]
    evidence = {"EbsEncryptionByDefault": enabled}

    if enabled:
        return PASS, "EBS encryption by default đang bật", evidence
    return FAIL, "EBS encryption by default đang tắt, volume mới có thể không được mã hóa", evidence


@evaluator("2.2.2", _snapshot_id, _snapshot_name)
def snapshot_not_public(snap, ctx):
    """CIS 2.2.2: snapshot không chia sẻ cho group 'all'."""
    permissions = snap["_create_volume_permissions"]
    is_public = any(p.get("Group") == "all" for p in permissions)
    shared_accounts = [p["UserId"] for p in permissions if "UserId" in p]
    evidence = {"public": is_public, "shared_with_accounts": shared_accounts}

    if is_public:
        return FAIL, "Snapshot đang public (createVolumePermission group=all)", evidence
    return PASS, "Snapshot không public", evidence


@evaluator("2.2.3", _snapshot_id, _snapshot_name)
def snapshot_encrypted(snap, ctx):
    """CIS 2.2.3: snapshot phải được mã hóa."""
    evidence = {"encrypted": snap["Encrypted"], "kms_key_id": snap.get("KmsKeyId", "")}

    if snap["Encrypted"]:
        return PASS, "Snapshot đã mã hóa", evidence
    return FAIL, f"Snapshot chưa mã hóa (volume nguồn {snap.get('VolumeId')})", evidence
