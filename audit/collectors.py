from functools import cached_property

from botocore.exceptions import ClientError

from core.scope import in_scope
from core.session import chunks, paginate


def error_text(exc):
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return f"{err.get('Code')}: {err.get('Message')}"
    return str(exc)


class Collector:
    """
    Thu thập cấu hình thực tế của một region.
    Mỗi API chỉ gọi một lần rồi cache lại, các check dùng chung kết quả.
    Lỗi ở cấp tài nguyên được ghi vào khoá "_error" để check trả về ERROR
    thay vì dừng cả chương trình.
    """

    def __init__(self, aws, region, scope=None):
        self.aws = aws
        self.region = region
        self.scope = scope or {}
        self.ec2 = aws.client("ec2", region)
        self.ecs = aws.client("ecs", region)
        self.autoscaling = aws.client("autoscaling", region)
        self.lambda_ = aws.client("lambda", region)

    # ------------------------------------------------------------------
    # EC2 / AMI / EBS
    # ------------------------------------------------------------------
    @cached_property
    def images(self):
        images = paginate(self.ec2, "describe_images", "Images", Owners=["self"])
        return [img for img in images if in_scope(img.get("Tags"), self.scope)]

    @cached_property
    def snapshots(self):
        snapshots = []
        for snap in paginate(self.ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]):
            if not in_scope(snap.get("Tags"), self.scope):
                continue
            try:
                attr = self.ec2.describe_snapshot_attribute(
                    SnapshotId=snap["SnapshotId"], Attribute="createVolumePermission"
                )
                snap["_create_volume_permissions"] = attr.get("CreateVolumePermissions", [])
            except ClientError as exc:
                snap["_error"] = error_text(exc)
            snapshots.append(snap)
        return snapshots

    @cached_property
    def ebs_default_encryption(self):
        # Cài đặt cấp account/region nên không áp dụng tag scope
        resp = self.ec2.get_ebs_encryption_by_default()
        return [{
            "EbsEncryptionByDefault": resp["EbsEncryptionByDefault"],
            "region": self.region,
        }]

    @cached_property
    def auto_scaling_groups(self):
        groups = paginate(
            self.autoscaling, "describe_auto_scaling_groups", "AutoScalingGroups"
        )
        return [g for g in groups if in_scope(g.get("Tags"), self.scope)]

    # ------------------------------------------------------------------
    # ECS
    # ------------------------------------------------------------------
    @cached_property
    def _all_ecs_clusters(self):
        arns = list(paginate(self.ecs, "list_clusters", "clusterArns"))
        clusters = []
        for group in chunks(arns, 100):
            resp = self.ecs.describe_clusters(clusters=group, include=["SETTINGS", "TAGS"])
            clusters.extend(resp["clusters"])
        return clusters

    @cached_property
    def ecs_clusters(self):
        return [c for c in self._all_ecs_clusters if in_scope(c.get("tags"), self.scope)]

    @cached_property
    def ecs_services(self):
        # Duyệt mọi cluster (không lọc) vì service có tag riêng của nó
        services = []
        for cluster in self._all_ecs_clusters:
            arns = list(paginate(
                self.ecs, "list_services", "serviceArns", cluster=cluster["clusterArn"]
            ))
            for group in chunks(arns, 10):
                resp = self.ecs.describe_services(
                    cluster=cluster["clusterArn"], services=group, include=["TAGS"]
                )
                services.extend(
                    s for s in resp["services"] if in_scope(s.get("tags"), self.scope)
                )
        return services

    @cached_property
    def ecs_task_definitions(self):
        """
        Revision ACTIVE mới nhất của mỗi family (đúng phạm vi CIS mục 3.x).
        Gọi describe theo tên family sẽ trả về revision mới nhất.
        """
        task_defs = []
        families = paginate(
            self.ecs, "list_task_definition_families", "families", status="ACTIVE"
        )
        for family in families:
            try:
                resp = self.ecs.describe_task_definition(
                    taskDefinition=family, include=["TAGS"]
                )
            except ClientError as exc:
                task_defs.append({"family": family, "taskDefinitionArn": family,
                                  "_error": error_text(exc)})
                continue
            if in_scope(resp.get("tags"), self.scope):
                task_defs.append({**resp["taskDefinition"], "tags": resp.get("tags", [])})
        return task_defs

    # ------------------------------------------------------------------
    # Lambda
    # ------------------------------------------------------------------
    @cached_property
    def lambda_function_urls(self):
        """Mỗi phần tử là một Function URL config, kèm tên function."""
        urls = []
        for fn in paginate(self.lambda_, "list_functions", "Functions"):
            if self.scope:
                tags = self.lambda_.list_tags(Resource=fn["FunctionArn"]).get("Tags", {})
                if not in_scope(tags, self.scope):
                    continue
            try:
                configs = list(paginate(
                    self.lambda_, "list_function_url_configs", "FunctionUrlConfigs",
                    FunctionName=fn["FunctionName"],
                ))
            except ClientError as exc:
                urls.append({"FunctionName": fn["FunctionName"],
                             "FunctionArn": fn["FunctionArn"], "_error": error_text(exc)})
                continue
            for cfg in configs:
                urls.append({**cfg, "FunctionName": fn["FunctionName"]})
        return urls
