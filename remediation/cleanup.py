"""
Dọn các tài nguyên do remediation tạo ra (tag CreatedBy=cis-remediation).
Chúng nằm ngoài Terraform state nên `terraform destroy` không xoá, vẫn tính phí.

Mặc định chỉ liệt kê. Thêm --apply để xoá.
    python -m remediation.cleanup
    python -m remediation.cleanup --apply
    python -m remediation.cleanup --apply --reset-ebs-default   # tắt lại EBS encryption by default
"""
import argparse

from botocore.exceptions import ClientError

from audit.collectors import error_text
from core.session import AwsSession, paginate
from remediation.actions.base import CREATED_BY_KEY, CREATED_BY_VALUE

TAG_FILTER = [{"Name": f"tag:{CREATED_BY_KEY}", "Values": [CREATED_BY_VALUE]}]


def find_created(aws, region):
    ec2 = aws.client("ec2", region)
    ecs = aws.client("ecs", region)
    images = list(paginate(ec2, "describe_images", "Images", Owners=["self"], Filters=TAG_FILTER))
    snapshots = list(paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"], Filters=TAG_FILTER))

    task_defs = []
    for arn in paginate(ecs, "list_task_definitions", "taskDefinitionArns", status="ACTIVE"):
        tags = ecs.list_tags_for_resource(resourceArn=arn).get("tags", [])
        if any(t["key"] == CREATED_BY_KEY and t["value"] == CREATED_BY_VALUE for t in tags):
            task_defs.append(arn)
    return images, snapshots, task_defs


def run(action, label, apply):
    """In hành động; chỉ thực thi khi --apply. Lỗi một tài nguyên không làm dừng cả quá trình."""
    if not apply:
        print(f"  [plan] {label}")
        return
    try:
        action()
        print(f"  [done] {label}")
    except ClientError as exc:
        print(f"  [fail] {label}: {error_text(exc)}")


def main():
    parser = argparse.ArgumentParser(description="Dọn tài nguyên do CIS remediation tạo ra")
    parser.add_argument("--regions", help="Danh sách region, phân tách bằng dấu phẩy")
    parser.add_argument("--apply", action="store_true", help="Thực sự xoá (mặc định chỉ liệt kê)")
    parser.add_argument("--reset-ebs-default", action="store_true",
                        help="Tắt EBS encryption by default (để dựng lại lab với 2.2.1 FAIL)")
    parser.add_argument("--profile", help="AWS CLI profile")
    args = parser.parse_args()

    aws = AwsSession(profile=args.profile)
    regions = args.regions.split(",") if args.regions else [aws.default_region]

    for region in regions:
        ec2 = aws.client("ec2", region)
        ecs = aws.client("ecs", region)
        images, snapshots, task_defs = find_created(aws, region)
        print(f"[{region}] AMI: {len(images)} | Snapshot: {len(snapshots)} | Task definition: {len(task_defs)}")

        # AMI trước (kèm snapshot của nó), sau đó mới tới snapshot độc lập
        ami_snapshots = set()
        for img in images:
            ami_snapshots |= {b["Ebs"]["SnapshotId"] for b in img.get("BlockDeviceMappings", []) if "Ebs" in b}
            run(lambda i=img: ec2.deregister_image(ImageId=i["ImageId"], DeleteAssociatedSnapshots=True),
                f"deregister AMI {img['ImageId']} ({img.get('Name')}) + snapshot", args.apply)
        for snap in snapshots:
            if snap["SnapshotId"] in ami_snapshots:
                continue
            run(lambda s=snap: ec2.delete_snapshot(SnapshotId=s["SnapshotId"]),
                f"delete snapshot {snap['SnapshotId']}", args.apply)
        for arn in task_defs:
            run(lambda a=arn: ecs.deregister_task_definition(taskDefinition=a),
                f"deregister task definition {arn.split('/')[-1]}", args.apply)

        if args.reset_ebs_default:
            run(ec2.disable_ebs_encryption_by_default,
                f"disable EBS encryption by default ({region})", args.apply)

    if not args.apply:
        print("\nChưa xoá gì. Thêm --apply để thực thi.")


if __name__ == "__main__":
    main()
