from audit.checks.base import evaluator
from core.models import FAIL, NOT_APPLICABLE, PASS
from core.scope import normalize_tags

# CIS 3.6: các biến môi trường chứa credential không được truyền qua "environment"
SENSITIVE_ENV_NAMES = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ECS_ENGINE_AUTH_DATA"}

CONTAINER_INSIGHTS_OK = {"enabled", "enhanced"}


def _td_id(td):
    return td["taskDefinitionArn"]


def _td_name(td):
    if "revision" in td:
        return f"{td['family']}:{td['revision']}"
    return td.get("family", "")


def _containers(td):
    return td.get("containerDefinitions", [])


# ----------------------------------------------------------------------
# Service
# ----------------------------------------------------------------------
@evaluator("3.2", lambda s: s["serviceArn"], lambda s: s["serviceName"])
def service_no_public_ip(service, ctx):
    """CIS 3.2: assignPublicIp của ECS service phải là DISABLED."""
    awsvpc = service.get("networkConfiguration", {}).get("awsvpcConfiguration")
    if not awsvpc:
        return NOT_APPLICABLE, "Service không dùng network mode awsvpc", {}

    value = awsvpc.get("assignPublicIp", "DISABLED")
    evidence = {"assignPublicIp": value, "subnets": awsvpc.get("subnets", [])}
    if value == "ENABLED":
        return FAIL, "Service tự động gán Public IP cho task", evidence
    return PASS, "assignPublicIp = DISABLED", evidence


# ----------------------------------------------------------------------
# Task definition (revision ACTIVE mới nhất)
# ----------------------------------------------------------------------
@evaluator("3.3", _td_id, _td_name)
def task_def_no_host_pid(td, ctx):
    """CIS 3.3: pidMode không được là 'host'."""
    pid_mode = td.get("pidMode")
    evidence = {"pidMode": pid_mode}
    if pid_mode == "host":
        return FAIL, "Task chia sẻ PID namespace với host", evidence
    return PASS, f"pidMode = {pid_mode or 'không đặt (mặc định private)'}", evidence


@evaluator("3.4", _td_id, _td_name)
def task_def_not_privileged(td, ctx):
    """CIS 3.4: không container nào có privileged = true."""
    privileged = [c["name"] for c in _containers(td) if c.get("privileged") is True]
    evidence = {"privileged_containers": privileged}
    if privileged:
        return FAIL, f"Container privileged: {', '.join(privileged)}", evidence
    return PASS, "Không có container privileged", evidence


@evaluator("3.5", _td_id, _td_name)
def task_def_readonly_root(td, ctx):
    """CIS 3.5: mọi container phải có readonlyRootFilesystem = true."""
    writable = [c["name"] for c in _containers(td) if c.get("readonlyRootFilesystem") is not True]
    evidence = {"writable_root_containers": writable}
    if writable:
        return FAIL, f"Root filesystem cho phép ghi: {', '.join(writable)}", evidence
    return PASS, "Mọi container dùng root filesystem chỉ đọc", evidence


@evaluator("3.6", _td_id, _td_name)
def task_def_no_secret_env(td, ctx):
    """CIS 3.6: không truyền credential qua biến môi trường."""
    leaks = [
        {"container": c["name"], "variable": env["name"]}
        for c in _containers(td)
        for env in c.get("environment", [])
        if env.get("name") in SENSITIVE_ENV_NAMES
    ]
    # Chỉ ghi tên biến, không bao giờ ghi giá trị secret vào report
    evidence = {
        "sensitive_env": leaks,
        "uses_secrets_block": any(c.get("secrets") for c in _containers(td)),
    }
    if leaks:
        names = ", ".join(f"{l['container']}/{l['variable']}" for l in leaks)
        return FAIL, f"Credential trong environment: {names}", evidence
    return PASS, "Không có credential trong biến môi trường", evidence


@evaluator("3.7", _td_id, _td_name)
def task_def_logging(td, ctx):
    """CIS 3.7: ít nhất một container có logConfiguration với logDriver."""
    drivers = {
        c["name"]: c["logConfiguration"]["logDriver"]
        for c in _containers(td)
        if c.get("logConfiguration", {}).get("logDriver")
    }
    evidence = {"log_drivers": drivers}
    if not drivers:
        return FAIL, "Không container nào cấu hình logging", evidence
    return PASS, f"Logging: {', '.join(f'{k}={v}' for k, v in drivers.items())}", evidence


# ----------------------------------------------------------------------
# Cluster
# ----------------------------------------------------------------------
@evaluator("3.9", lambda c: c["clusterArn"], lambda c: c["clusterName"])
def cluster_container_insights(cluster, ctx):
    """CIS 3.9: containerInsights = enabled hoặc enhanced."""
    settings = {s["name"]: s["value"] for s in cluster.get("settings", [])}
    value = settings.get("containerInsights", "disabled")
    evidence = {"containerInsights": value}
    if value in CONTAINER_INSIGHTS_OK:
        return PASS, f"Container Insights = {value}", evidence
    return FAIL, f"Container Insights = {value}", evidence


@evaluator("3.11", lambda c: c["clusterArn"], lambda c: c["clusterName"])
def cluster_tagged(cluster, ctx):
    """CIS 3.11: cluster có ít nhất một tag không bắt đầu bằng 'aws:'."""
    keys = [k for k in normalize_tags(cluster.get("tags")) if not k.startswith("aws:")]
    evidence = {"user_tag_keys": keys}
    if keys:
        return PASS, f"Cluster có {len(keys)} tag", evidence
    return FAIL, "Cluster không có tag do người dùng đặt", evidence
