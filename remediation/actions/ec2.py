from remediation.actions.base import (
    WAITER_CONFIG, ec2_dry_run, pending_approval, planned, remediated, remediation_tags,
)


def encrypt_ami(img, ctx):
    """
    CIS 2.1.2 (tier B): copy AMI với Encrypted=True.
    Chỉ deregister AMI gốc (kèm snapshot) khi có --allow-destructive, vì launch template
    hoặc ASG có thể vẫn tham chiếu tới ID cũ.
    """
    ec2 = ctx.client("ec2")
    source_id = img["ImageId"]
    new_name = f"{img['Name']}-encrypted"
    params = {
        "Name": new_name,
        "SourceImageId": source_id,
        "SourceRegion": ctx.region,
        "Encrypted": True,
        "CopyImageTags": True,
        "Description": f"Encrypted copy of {source_id} (CIS 2.1.2 remediation)",
    }
    action = f"ec2.copy_image({source_id}, Encrypted=True)"

    if ctx.dry_run:
        check = ec2_dry_run(ec2.copy_image, **params)
        step2 = ("rồi deregister AMI gốc" if ctx.allow_destructive
                 else "AMI gốc giữ lại chờ duyệt (--allow-destructive để deregister)")
        return planned(action, f"Sẽ tạo '{new_name}' có mã hóa, {step2}. {check}")

    new_id = ec2.copy_image(**params)["ImageId"]
    tags = remediation_tags("2.1.2", source_id, img.get("Tags"))
    tags = [t for t in tags if t["Key"] != "Name"] + [{"Key": "Name", "Value": new_name}]
    ec2.create_tags(Resources=[new_id], Tags=tags)
    ec2.get_waiter("image_available").wait(ImageIds=[new_id], WaiterConfig=WAITER_CONFIG)

    if ctx.allow_destructive:
        ec2.deregister_image(ImageId=source_id, DeleteAssociatedSnapshots=True)
        return remediated(
            f"{action} -> {new_id}; deregister_image({source_id})",
            f"Đã tạo {new_id} (mã hóa) và deregister AMI gốc",
            rollback="Không hoàn tác được việc deregister; dùng AMI copy mã hóa thay thế",
            verify_ids=[new_id], created=[new_id], deleted=[source_id],
        )
    return pending_approval(
        f"{action} -> {new_id}",
        f"Đã tạo {new_id} '{new_name}' (mã hóa); AMI gốc chờ duyệt deregister",
        rollback=(f"aws ec2 deregister-image --region {ctx.region} --image-id {new_id} "
                  f"--delete-associated-snapshots"),
        verify_ids=[new_id], created=[new_id],
    )


def propagate_asg_tags(group, ctx):
    """CIS 2.14 (tier A): bật PropagateAtLaunch cho các tag chưa propagate."""
    name = group["AutoScalingGroupName"]
    fixes = [
        {
            "ResourceId": name,
            "ResourceType": "auto-scaling-group",
            "Key": tag["Key"],
            "Value": tag.get("Value", ""),
            "PropagateAtLaunch": True,
        }
        for tag in group.get("Tags", [])
        if not tag.get("PropagateAtLaunch")
    ]
    keys = [t["Key"] for t in fixes]
    action = f"autoscaling.create_or_update_tags({name}, {keys}, PropagateAtLaunch=True)"
    rollback = f"Đặt lại PropagateAtLaunch=false cho các tag: {', '.join(keys)}"

    if ctx.dry_run:
        return planned(action, f"Sẽ bật propagate cho tag: {', '.join(keys)}", rollback)

    ctx.client("autoscaling").create_or_update_tags(Tags=fixes)
    return remediated(action, f"Đã bật propagate cho {len(keys)} tag", rollback)
