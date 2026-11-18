from datetime import datetime

from audit.checks.base import evaluator
from core.models import FAIL, NOT_APPLICABLE, PASS

MAX_AMI_AGE_DAYS = 90


def _image_id(img):
    return img["ImageId"]


def _image_name(img):
    return img.get("Name", "")


@evaluator("2.1.2", _image_id, _image_name)
def ami_encrypted(img, ctx):
    """CIS 2.1.2: mọi EBS snapshot của AMI phải được mã hóa."""
    devices = [
        {
            "device": bdm.get("DeviceName"),
            "snapshot_id": bdm["Ebs"].get("SnapshotId"),
            "encrypted": bdm["Ebs"].get("Encrypted") is True,
        }
        for bdm in img.get("BlockDeviceMappings", [])
        if "Ebs" in bdm
    ]
    if not devices:
        return NOT_APPLICABLE, "AMI không dùng EBS (instance-store)", {}

    unencrypted = [d["device"] for d in devices if not d["encrypted"]]
    if unencrypted:
        return FAIL, f"Snapshot chưa mã hóa ở device: {', '.join(unencrypted)}", {"devices": devices}
    return PASS, "Toàn bộ EBS snapshot của AMI đã mã hóa", {"devices": devices}


@evaluator("2.1.4", _image_id, _image_name)
def ami_not_older_than_90_days(img, ctx):
    """CIS 2.1.4: AMI không quá 90 ngày tuổi."""
    created = datetime.fromisoformat(img["CreationDate"].replace("Z", "+00:00"))
    age_days = (ctx.now - created).days
    evidence = {"creation_date": img["CreationDate"], "age_days": age_days}

    if age_days > MAX_AMI_AGE_DAYS:
        return FAIL, f"AMI đã {age_days} ngày tuổi (> {MAX_AMI_AGE_DAYS})", evidence
    return PASS, f"AMI {age_days} ngày tuổi", evidence


@evaluator("2.14", lambda g: g["AutoScalingGroupARN"], lambda g: g["AutoScalingGroupName"])
def asg_propagates_tags(group, ctx):
    """CIS 2.14: mọi tag của ASG phải có PropagateAtLaunch = true."""
    tags = group.get("Tags", [])
    not_propagated = [t["Key"] for t in tags if not t.get("PropagateAtLaunch")]
    evidence = {"tag_count": len(tags), "not_propagated": not_propagated}

    if not_propagated:
        return FAIL, f"Tag không propagate xuống instance: {', '.join(not_propagated)}", evidence
    if not tags:
        return PASS, "ASG không có tag nào cần propagate", evidence
    return PASS, f"Cả {len(tags)} tag đều propagate xuống instance", evidence
