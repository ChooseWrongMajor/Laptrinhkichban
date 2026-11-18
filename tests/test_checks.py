"""Test logic đánh giá của từng check bằng dữ liệu mẫu, không gọi AWS."""
import json
from datetime import datetime, timezone

import pytest

from audit.checks import ebs, ec2, ecs, lambda_
from audit.registry import CONTROLS, select_controls
from core.models import ERROR, FAIL, NOT_APPLICABLE, PASS, AuditContext, Finding
from core.report import control_status, load_expected, summarize, totals
from core.scope import in_scope, normalize_tags, parse_scope

CTX = AuditContext(account_id="123456789012", region="us-east-1",
                   now=datetime(2026, 11, 17, tzinfo=timezone.utc))


def task_def(**container):
    base = {"name": "app", "image": "nginx"}
    return {
        "taskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/web:1",
        "family": "web", "revision": 1,
        "containerDefinitions": [{**base, **container}],
    }


# ---------------------------------------------------------------- AMI / EC2
def image(encrypted=True, created="2026-11-01T00:00:00.000Z"):
    return {
        "ImageId": "ami-1", "Name": "computebench-dev-v1.0.0", "CreationDate": created,
        "BlockDeviceMappings": [{"DeviceName": "/dev/xvda",
                                 "Ebs": {"SnapshotId": "snap-1", "Encrypted": encrypted}}],
    }


def test_2_1_2_ami_encrypted():
    assert ec2.ami_encrypted(image(True), CTX).status == PASS
    finding = ec2.ami_encrypted(image(False), CTX)
    assert finding.status == FAIL
    assert finding.resource_name == "computebench-dev-v1.0.0"


def test_2_1_2_instance_store_ami_not_applicable():
    img = {**image(), "BlockDeviceMappings": [{"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0"}]}
    assert ec2.ami_encrypted(img, CTX).status == NOT_APPLICABLE


def test_2_1_4_ami_age():
    assert ec2.ami_not_older_than_90_days(image(created="2026-10-01T00:00:00.000Z"), CTX).status == PASS
    old = ec2.ami_not_older_than_90_days(image(created="2026-01-01T00:00:00.000Z"), CTX)
    assert old.status == FAIL
    assert old.evidence["age_days"] > 90


def test_2_14_asg_tags():
    group = {"AutoScalingGroupARN": "arn:asg", "AutoScalingGroupName": "asg",
             "Tags": [{"Key": "Name", "PropagateAtLaunch": True},
                      {"Key": "Owner", "PropagateAtLaunch": False}]}
    finding = ec2.asg_propagates_tags(group, CTX)
    assert finding.status == FAIL
    assert finding.evidence["not_propagated"] == ["Owner"]
    group["Tags"][1]["PropagateAtLaunch"] = True
    assert ec2.asg_propagates_tags(group, CTX).status == PASS


# ---------------------------------------------------------------- EBS
def test_2_2_1_ebs_default():
    assert ebs.ebs_encryption_by_default({"EbsEncryptionByDefault": True, "region": "us-east-1"}, CTX).status == PASS
    finding = ebs.ebs_encryption_by_default({"EbsEncryptionByDefault": False, "region": "us-east-1"}, CTX)
    assert finding.status == FAIL
    assert finding.resource_id == "ebs-encryption-by-default/us-east-1"


def snapshot(encrypted=False, permissions=()):
    return {"SnapshotId": "snap-1", "VolumeId": "vol-1", "Encrypted": encrypted,
            "Tags": [{"Key": "Name", "Value": "snap-plain"}],
            "_create_volume_permissions": list(permissions)}


def test_2_2_2_snapshot_public():
    assert ebs.snapshot_not_public(snapshot(permissions=[{"Group": "all"}]), CTX).status == FAIL
    private = ebs.snapshot_not_public(snapshot(permissions=[{"UserId": "111122223333"}]), CTX)
    assert private.status == PASS
    assert private.evidence["shared_with_accounts"] == ["111122223333"]


def test_2_2_3_snapshot_encrypted():
    assert ebs.snapshot_encrypted(snapshot(encrypted=True), CTX).status == PASS
    finding = ebs.snapshot_encrypted(snapshot(encrypted=False), CTX)
    assert finding.status == FAIL
    assert finding.resource_name == "snap-plain"


def test_collector_error_becomes_error_finding():
    snap = {**snapshot(), "_error": "AccessDenied: not authorized"}
    finding = ebs.snapshot_not_public(snap, CTX)
    assert finding.status == ERROR
    assert "AccessDenied" in finding.message


def test_missing_field_becomes_error_finding():
    finding = ebs.snapshot_not_public({"SnapshotId": "snap-x"}, CTX)
    assert finding.status == ERROR


# ---------------------------------------------------------------- ECS
def service(assign_public_ip=None, awsvpc=True):
    svc = {"serviceArn": "arn:svc", "serviceName": "web-svc"}
    if awsvpc:
        cfg = {"subnets": ["subnet-1"]}
        if assign_public_ip:
            cfg["assignPublicIp"] = assign_public_ip
        svc["networkConfiguration"] = {"awsvpcConfiguration": cfg}
    return svc


def test_3_2_service_public_ip():
    assert ecs.service_no_public_ip(service("ENABLED"), CTX).status == FAIL
    assert ecs.service_no_public_ip(service("DISABLED"), CTX).status == PASS
    assert ecs.service_no_public_ip(service(awsvpc=False), CTX).status == NOT_APPLICABLE


def test_3_3_pid_mode():
    assert ecs.task_def_no_host_pid({**task_def(), "pidMode": "host"}, CTX).status == FAIL
    assert ecs.task_def_no_host_pid(task_def(), CTX).status == PASS


def test_3_4_privileged():
    finding = ecs.task_def_not_privileged(task_def(privileged=True), CTX)
    assert finding.status == FAIL
    assert finding.resource_name == "web:1"
    assert ecs.task_def_not_privileged(task_def(privileged=False), CTX).status == PASS
    assert ecs.task_def_not_privileged(task_def(), CTX).status == PASS


def test_3_5_readonly_root():
    assert ecs.task_def_readonly_root(task_def(readonlyRootFilesystem=True), CTX).status == PASS
    assert ecs.task_def_readonly_root(task_def(readonlyRootFilesystem=False), CTX).status == FAIL
    # Không khai báo = mặc định false -> FAIL
    assert ecs.task_def_readonly_root(task_def(), CTX).status == FAIL


def test_3_6_secret_env_does_not_leak_value():
    td = task_def(environment=[{"name": "AWS_SECRET_ACCESS_KEY", "value": "super-secret"}])
    finding = ecs.task_def_no_secret_env(td, CTX)
    assert finding.status == FAIL
    assert "super-secret" not in json.dumps(finding.to_dict())

    ok = task_def(environment=[{"name": "APP_ENV", "value": "dev"}],
                  secrets=[{"name": "DB_PASSWORD", "valueFrom": "arn:ssm"}])
    finding = ecs.task_def_no_secret_env(ok, CTX)
    assert finding.status == PASS
    assert finding.evidence["uses_secrets_block"] is True


def test_3_7_logging():
    td = task_def(logConfiguration={"logDriver": "awslogs", "options": {}})
    assert ecs.task_def_logging(td, CTX).status == PASS
    assert ecs.task_def_logging(task_def(), CTX).status == FAIL


def cluster(insights=None, tags=()):
    settings = [{"name": "containerInsights", "value": insights}] if insights else []
    return {"clusterArn": "arn:cluster", "clusterName": "c1", "settings": settings, "tags": list(tags)}


def test_3_9_container_insights():
    assert ecs.cluster_container_insights(cluster("enabled"), CTX).status == PASS
    assert ecs.cluster_container_insights(cluster("enhanced"), CTX).status == PASS
    assert ecs.cluster_container_insights(cluster("disabled"), CTX).status == FAIL
    assert ecs.cluster_container_insights(cluster(), CTX).status == FAIL


def test_3_11_cluster_tagged_ignores_aws_prefix():
    assert ecs.cluster_tagged(cluster(tags=[{"key": "aws:cloudformation:stack", "value": "x"}]), CTX).status == FAIL
    assert ecs.cluster_tagged(cluster(tags=[{"key": "Owner", "value": "nhom04"}]), CTX).status == PASS


# ---------------------------------------------------------------- Lambda
def test_12_16_function_url_auth():
    url = {"FunctionArn": "arn:fn", "FunctionName": "fn", "AuthType": "NONE"}
    assert lambda_.function_url_iam_auth(url, CTX).status == FAIL
    assert lambda_.function_url_iam_auth({**url, "AuthType": "AWS_IAM"}, CTX).status == PASS


# ---------------------------------------------------------------- core
def test_registry_has_15_unique_controls():
    ids = [c.cis_id for c in CONTROLS]
    assert len(ids) == 15
    assert len(set(ids)) == 15


def test_select_controls_rejects_unknown_id():
    assert [c.cis_id for c in select_controls(["3.4", "2.2.1"])] == ["2.2.1", "3.4"]
    with pytest.raises(ValueError):
        select_controls(["9.9"])


def f(status, cis_id="3.4"):
    return Finding(cis_id=cis_id, resource_id="r", status=status, message="")


@pytest.mark.parametrize("statuses, expected", [
    ([PASS, FAIL], FAIL),
    ([PASS, ERROR], ERROR),
    ([FAIL, ERROR], FAIL),
    ([PASS, NOT_APPLICABLE], PASS),
    ([NOT_APPLICABLE], NOT_APPLICABLE),
    ([], NOT_APPLICABLE),
])
def test_control_status(statuses, expected):
    assert control_status([f(s) for s in statuses]) == expected


def test_summarize_and_expected_match():
    controls = select_controls(["2.2.1", "3.4"])
    findings = [f(FAIL, "2.2.1"), f(PASS, "3.4"), f(FAIL, "3.4")]
    rows = summarize(findings, controls, {"2.2.1": {"expected": "FAIL"}, "3.4": {"expected": "PASS"}})

    assert [r["status"] for r in rows] == [FAIL, FAIL]
    assert [r["match"] for r in rows] == ["YES", "NO"]
    assert rows[1]["checked"] == 2 and rows[1]["fail"] == 1

    stats = totals(rows)
    assert stats["fail"] == 2 and stats["compliance_pct"] == 0.0
    assert stats["expected_matched"] == 1


def test_load_expected_accepts_both_terraform_formats(tmp_path):
    matrix = {"2.2.1": {"expected": "FAIL"}}
    single = tmp_path / "single.json"
    single.write_text(json.dumps(matrix))
    full = tmp_path / "full.json"
    full.write_text(json.dumps({"cis_automated_matrix": {"sensitive": False, "value": matrix}}))

    assert load_expected(str(single)) == matrix
    assert load_expected(str(full)) == matrix


def test_scope_helpers():
    assert normalize_tags([{"Key": "Project", "Value": "computebench"}]) == {"Project": "computebench"}
    assert normalize_tags([{"key": "Project", "value": "computebench"}]) == {"Project": "computebench"}
    scope = parse_scope(["Project=computebench"])
    assert in_scope({"Project": "computebench", "Env": "dev"}, scope)
    assert not in_scope([{"Key": "Project", "Value": "other"}], scope)
    assert in_scope(None, {})
