import copy

from remediation.actions.base import planned, remediated, remediation_tags

# Tag thêm vào cluster thiếu tag (CIS 3.11)
DEFAULT_CLUSTER_TAGS = {"Owner": "unassigned", "ManagedBy": "cis-remediation"}


# ----------------------------------------------------------------------
# Service
# ----------------------------------------------------------------------
def disable_service_public_ip(service, ctx):
    """CIS 3.2 (tier A): giữ nguyên subnet và SG, chỉ đổi assignPublicIp sang DISABLED."""
    awsvpc = dict(service["networkConfiguration"]["awsvpcConfiguration"])
    awsvpc["assignPublicIp"] = "DISABLED"
    name = service["serviceName"]
    action = f"ecs.update_service({name}, assignPublicIp=DISABLED)"
    rollback = (f"aws ecs update-service --region {ctx.region} --cluster {service['clusterArn']} "
                f"--service {name} --network-configuration "
                f"'awsvpcConfiguration={{subnets=[{','.join(awsvpc['subnets'])}],"
                f"securityGroups=[{','.join(awsvpc.get('securityGroups', []))}],assignPublicIp=ENABLED}}'")

    if ctx.dry_run:
        return planned(action, f"Sẽ tắt public IP cho service {name} (task chạy sau đó cần NAT/VPC endpoint để ra Internet)",
                       rollback)

    ctx.client("ecs").update_service(
        cluster=service["clusterArn"], service=service["serviceArn"],
        networkConfiguration={"awsvpcConfiguration": awsvpc},
    )
    return remediated(action, "Đã tắt assignPublicIp", rollback)


# ----------------------------------------------------------------------
# Task definition: bất biến -> tạo revision mới đã sửa
# ----------------------------------------------------------------------
def _registrable_fields(ecs):
    """Danh sách tham số RegisterTaskDefinition chấp nhận, lấy từ service model của boto3."""
    shape = ecs.meta.service_model.operation_model("RegisterTaskDefinition").input_shape
    return set(shape.members) - {"tags"}


def _services_using(ctx, task_def_arn):
    return [s for s in ctx.collector.ecs_services if s.get("taskDefinition") == task_def_arn]


def _register_fixed_revision(td, ctx, cis_id, change, fix):
    """
    Tạo revision mới từ revision hiện tại sau khi áp dụng hàm fix(spec),
    rồi cập nhật các service đang dùng revision cũ. Revision cũ giữ nguyên để rollback.
    """
    old_arn = td["taskDefinitionArn"]
    label = f"{td['family']}:{td['revision']}"
    services = _services_using(ctx, old_arn)
    service_names = [s["serviceName"] for s in services]
    action = f"ecs.register_task_definition({td['family']}, {change})"
    if service_names:
        action += f"; update_service({', '.join(service_names)})"

    if ctx.dry_run:
        target = f"cập nhật service: {', '.join(service_names)}" if service_names else "không service nào đang dùng"
        return planned(action, f"Sẽ tạo revision mới từ {label} với {change}; {target}")

    ecs = ctx.client("ecs")
    allowed = _registrable_fields(ecs)
    spec = copy.deepcopy({k: v for k, v in td.items() if k in allowed})
    fix(spec)
    tags = remediation_tags(cis_id, old_arn, td.get("tags"), key_style="key")
    new_td = ecs.register_task_definition(**spec, tags=tags)["taskDefinition"]
    new_arn = new_td["taskDefinitionArn"]

    for svc in services:
        ecs.update_service(cluster=svc["clusterArn"], service=svc["serviceArn"], taskDefinition=new_arn)

    rollback = f"Chuyển service về revision cũ: aws ecs update-service --task-definition {label}"
    if not service_names:
        rollback = f"aws ecs deregister-task-definition --region {ctx.region} --task-definition {new_td['family']}:{new_td['revision']}"
    return remediated(
        action, f"Đã tạo revision {new_td['family']}:{new_td['revision']} ({change})",
        rollback, verify_ids=[new_arn], created=[new_arn], updated_services=service_names,
    )


def remove_host_pid_mode(td, ctx):
    """CIS 3.3 (tier A): bỏ pidMode=host (về mặc định private namespace)."""
    return _register_fixed_revision(
        td, ctx, "3.3", "pidMode bị gỡ bỏ", lambda spec: spec.pop("pidMode", None),
    )


def disable_privileged(td, ctx):
    """CIS 3.4 (tier A): đặt privileged=false cho mọi container."""
    names = [c["name"] for c in td["containerDefinitions"] if c.get("privileged") is True]

    def fix(spec):
        for container in spec["containerDefinitions"]:
            if container.get("privileged") is True:
                container["privileged"] = False

    return _register_fixed_revision(td, ctx, "3.4", f"privileged=false cho {', '.join(names)}", fix)


# ----------------------------------------------------------------------
# Cluster
# ----------------------------------------------------------------------
def enable_container_insights(cluster, ctx):
    """CIS 3.9 (tier A): bật Container Insights."""
    name = cluster["clusterName"]
    action = f"ecs.update_cluster_settings({name}, containerInsights=enabled)"
    rollback = (f"aws ecs update-cluster-settings --region {ctx.region} --cluster {name} "
                f"--settings name=containerInsights,value=disabled")

    if ctx.dry_run:
        return planned(action, "Sẽ bật Container Insights (phát sinh chi phí CloudWatch)", rollback)

    ctx.client("ecs").update_cluster_settings(
        cluster=cluster["clusterArn"], settings=[{"name": "containerInsights", "value": "enabled"}],
    )
    return remediated(action, "Đã bật Container Insights", rollback)


def tag_cluster(cluster, ctx):
    """CIS 3.11 (tier A): gắn bộ tag mặc định để chủ sở hữu bổ sung thông tin sau."""
    name = cluster["clusterName"]
    tags = [{"key": k, "value": v} for k, v in DEFAULT_CLUSTER_TAGS.items()]
    action = f"ecs.tag_resource({name}, {DEFAULT_CLUSTER_TAGS})"
    rollback = (f"aws ecs untag-resource --region {ctx.region} --resource-arn {cluster['clusterArn']} "
                f"--tag-keys {' '.join(DEFAULT_CLUSTER_TAGS)}")

    if ctx.dry_run:
        return planned(action, f"Sẽ gắn tag {DEFAULT_CLUSTER_TAGS}", rollback)

    ctx.client("ecs").tag_resource(resourceArn=cluster["clusterArn"], tags=tags)
    return remediated(action, "Đã gắn tag mặc định cho cluster", rollback)
