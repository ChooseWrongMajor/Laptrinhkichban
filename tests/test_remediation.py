"""
Test remediation không cần AWS:
  - action: dùng botocore Stubber để kiểm tra đúng tham số gửi lên API
  - engine: dùng collector giả để kiểm tra luồng skip / dry-run / verify
"""
import boto3
import pytest
from botocore.stub import ANY, Stubber

from audit.registry import CONTROLS_BY_ID, select_controls
from core.models import (
    FAIL, PASS, PENDING_APPROVAL, PLANNED, REMEDIATED, REMEDIATION_FAILED, SKIPPED_AUDIT_ONLY,
    SKIPPED_COMPLIANT, SKIPPED_OUT_OF_SCOPE, Finding, RemediationResult,
)
from remediation import engine
from remediation.actions import ebs, ecs, lambda_
from remediation.actions.base import ActionContext
from remediation.registry import EXECUTION_ORDER, ordered

REGION = "us-east-1"
TD_BASE = "arn:aws:ecs:us-east-1:123456789012:task-definition/computebench-worker"
TD_ARN = f"{TD_BASE}:1"


class FakeAws:
    """Thay AwsSession: trả về client boto3 thật đã gắn Stubber."""

    def __init__(self):
        session = boto3.Session(aws_access_key_id="x", aws_secret_access_key="x", region_name=REGION)
        self.clients = {s: session.client(s) for s in ("ec2", "ecs", "lambda", "autoscaling")}
        self.stubs = {s: Stubber(c) for s, c in self.clients.items()}
        self.account_id = "123456789012"

    def client(self, service, region=None):
        return self.clients[service]


class FakeCollector:
    def __init__(self, **sources):
        self.__dict__.update(sources)


@pytest.fixture
def aws():
    fake = FakeAws()
    for stub in fake.stubs.values():
        stub.activate()
    yield fake
    for stub in fake.stubs.values():
        stub.assert_no_pending_responses()


def ctx(aws, dry_run=False, services=(), destructive=False):
    return ActionContext(aws, REGION, aws.account_id, FakeCollector(ecs_services=list(services)),
                         dry_run=dry_run, allow_destructive=destructive)


def worker_td():
    return {
        "taskDefinitionArn": TD_ARN, "family": "computebench-worker", "revision": 1,
        "status": "ACTIVE", "registeredAt": "2026-11-18", "registeredBy": "arn:user",
        "compatibilities": ["EC2"], "requiresAttributes": [{"name": "x"}],
        "requiresCompatibilities": ["EC2"], "networkMode": "bridge",
        "containerDefinitions": [{"name": "worker", "image": "busybox", "memory": 128, "privileged": True}],
        "tags": [{"key": "Project", "value": "computebench"}, {"key": "aws:cloudformation:x", "value": "y"}],
    }


# ---------------------------------------------------------------- actions
def test_3_4_registers_clean_revision_without_read_only_fields(aws):
    new_td = {"taskDefinitionArn": f"{TD_BASE}:2", "family": "computebench-worker", "revision": 2}
    aws.stubs["ecs"].add_response(
        "register_task_definition", {"taskDefinition": new_td},
        expected_params={
            "family": "computebench-worker",
            "requiresCompatibilities": ["EC2"],
            "networkMode": "bridge",
            "containerDefinitions": [{"name": "worker", "image": "busybox", "memory": 128, "privileged": False}],
            "tags": [
                {"key": "Project", "value": "computebench"},
                {"key": "CreatedBy", "value": "cis-remediation"},
                {"key": "SourceResource", "value": TD_ARN},
                {"key": "CisId", "value": "3.4"},
            ],
        },
    )
    outcome = ecs.disable_privileged(worker_td(), ctx(aws))
    assert outcome.status == REMEDIATED
    assert outcome.verify_ids == [new_td["taskDefinitionArn"]]


def test_3_4_updates_services_using_old_revision(aws):
    svc = {"serviceName": "worker-svc", "serviceArn": "arn:svc", "clusterArn": "arn:cluster",
           "taskDefinition": TD_ARN}
    other = {**svc, "serviceName": "other", "taskDefinition": "arn:other:1"}
    new_arn = f"{TD_BASE}:2"
    aws.stubs["ecs"].add_response("register_task_definition",
                                  {"taskDefinition": {"taskDefinitionArn": new_arn, "family": "f", "revision": 2}})
    aws.stubs["ecs"].add_response("update_service", {},
                                  {"cluster": "arn:cluster", "service": "arn:svc", "taskDefinition": new_arn})
    outcome = ecs.disable_privileged(worker_td(), ctx(aws, services=[svc, other]))
    assert outcome.details["updated_services"] == ["worker-svc"]


def test_3_4_dry_run_calls_nothing(aws):
    outcome = ecs.disable_privileged(worker_td(), ctx(aws, dry_run=True))
    assert outcome.status == PLANNED


def test_3_2_keeps_subnets_and_security_groups(aws):
    service = {
        "serviceName": "web-public-svc", "serviceArn": "arn:svc", "clusterArn": "arn:cluster",
        "networkConfiguration": {"awsvpcConfiguration": {
            "subnets": ["subnet-1", "subnet-2"], "securityGroups": ["sg-1"], "assignPublicIp": "ENABLED"}},
    }
    aws.stubs["ecs"].add_response("update_service", {}, {
        "cluster": "arn:cluster", "service": "arn:svc",
        "networkConfiguration": {"awsvpcConfiguration": {
            "subnets": ["subnet-1", "subnet-2"], "securityGroups": ["sg-1"], "assignPublicIp": "DISABLED"}},
    })
    outcome = ecs.disable_service_public_ip(service, ctx(aws))
    assert outcome.status == REMEDIATED
    assert "ENABLED" in outcome.rollback
    # Không sửa trực tiếp dict của collector
    assert service["networkConfiguration"]["awsvpcConfiguration"]["assignPublicIp"] == "ENABLED"


def test_2_2_2_dry_run_uses_ec2_dryrun_flag(aws):
    aws.stubs["ec2"].add_client_error(
        "modify_snapshot_attribute", service_error_code="DryRunOperation",
        expected_params={"DryRun": True, "SnapshotId": "snap-1", "Attribute": "createVolumePermission",
                         "OperationType": "remove", "GroupNames": ["all"]},
    )
    outcome = ebs.make_snapshot_private({"SnapshotId": "snap-1"}, ctx(aws, dry_run=True))
    assert outcome.status == PLANNED
    assert "DryRun OK" in outcome.message


def test_dry_run_permission_error_is_raised(aws):
    aws.stubs["ec2"].add_client_error("enable_ebs_encryption_by_default",
                                      service_error_code="UnauthorizedOperation")
    with pytest.raises(Exception):
        ebs.enable_ebs_default_encryption({"region": REGION}, ctx(aws, dry_run=True))


def test_2_2_3_without_destructive_keeps_source_snapshot(aws):
    snap = {"SnapshotId": "snap-old", "Tags": [{"Key": "Name", "Value": "snap-plain"},
                                               {"Key": "Project", "Value": "computebench"}]}
    aws.stubs["ec2"].add_response("copy_snapshot", {"SnapshotId": "snap-new"}, {
        "SourceSnapshotId": "snap-old", "SourceRegion": REGION, "Encrypted": True,
        "Description": ANY, "TagSpecifications": [{"ResourceType": "snapshot", "Tags": [
            {"Key": "Name", "Value": "snap-plain-encrypted"},
            {"Key": "Project", "Value": "computebench"},
            {"Key": "CreatedBy", "Value": "cis-remediation"},
            {"Key": "SourceResource", "Value": "snap-old"},
            {"Key": "CisId", "Value": "2.2.3"},
        ]}],
    })
    aws.stubs["ec2"].add_response("describe_snapshots",
                                  {"Snapshots": [{"SnapshotId": "snap-new", "State": "completed"}]})
    outcome = ebs.encrypt_snapshot(snap, ctx(aws))
    assert outcome.status == PENDING_APPROVAL
    assert outcome.created_resources == ["snap-new"]  # không có delete_snapshot trong stub


def test_12_16_apply(aws):
    aws.stubs["lambda"].add_response("update_function_url_config",
                                     {"FunctionUrl": "https://abcdefghijklmnop.lambda-url.us-east-1.on.aws/",
                                      "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:computebench-public-fn", "AuthType": "AWS_IAM",
                                      "CreationTime": "2026-11-18T00:00:00Z", "LastModifiedTime": "2026-11-18T00:00:00Z"},
                                     {"FunctionName": "computebench-public-fn", "AuthType": "AWS_IAM"})
    outcome = lambda_.require_iam_auth({"FunctionName": "computebench-public-fn"}, ctx(aws))
    assert outcome.status == REMEDIATED


# ---------------------------------------------------------------- engine
class FakeAwsNoApi:
    account_id = "123456789012"


def finding(cis_id, resource_id, status=FAIL):
    return Finding(cis_id=cis_id, resource_id=resource_id, status=status, message="", region=REGION)


def url(name, auth):
    return {"FunctionArn": f"arn:fn:{name}", "FunctionName": name, "AuthType": auth}


def patch_collector(monkeypatch, **sources):
    monkeypatch.setattr(engine, "Collector", lambda aws, region, scope: FakeCollector(**sources))


def test_engine_skips_audit_only_compliant_and_missing(monkeypatch):
    patch_collector(monkeypatch, lambda_function_urls=[url("a", "NONE"), url("b", "AWS_IAM")])
    findings = [
        finding("12.16", "arn:fn:a"),            # còn FAIL -> PLANNED
        finding("12.16", "arn:fn:b"),            # đã PASS khi kiểm tra lại
        finding("12.16", "arn:fn:deleted"),      # không còn tồn tại
        finding("3.5", "arn:td:web:1"),          # tier C
        finding("3.9", "arn:cluster", PASS),     # không phải FAIL -> bỏ qua
    ]
    results = engine.remediate(FakeAwsNoApi(), findings, select_controls(None), scope={}, dry_run=True)
    status = {r.resource_id: r.status for r in results}
    assert status == {
        "arn:fn:a": PLANNED,
        "arn:fn:b": SKIPPED_COMPLIANT,
        "arn:fn:deleted": SKIPPED_OUT_OF_SCOPE,
        "arn:td:web:1": SKIPPED_AUDIT_ONLY,
    }


def test_engine_matches_task_definition_by_family(monkeypatch):
    latest = {**worker_td(), "taskDefinitionArn": f"{TD_BASE}:3", "revision": 3}
    patch_collector(monkeypatch, ecs_task_definitions=[latest], ecs_services=[])
    results = engine.remediate(FakeAwsNoApi(), [finding("3.4", TD_ARN)],
                               select_controls(["3.4"]), scope={}, dry_run=True)
    assert results[0].status == PLANNED
    assert ":3" in results[0].message.split("từ ")[1]


def test_verify_marks_failed_when_still_non_compliant(monkeypatch):
    patch_collector(monkeypatch, lambda_function_urls=[url("a", "AWS_IAM"), url("b", "NONE")])
    results = [
        RemediationResult("12.16", "arn:fn:a", REMEDIATED, "x", "ok", verify_ids=["arn:fn:a"], region=REGION),
        RemediationResult("12.16", "arn:fn:b", REMEDIATED, "x", "ok", verify_ids=["arn:fn:b"], region=REGION),
    ]
    engine.verify(FakeAwsNoApi(), results, select_controls(["12.16"]), scope={})
    assert (results[0].status, results[0].after) == (REMEDIATED, PASS)
    assert (results[1].status, results[1].after) == (REMEDIATION_FAILED, FAIL)


def test_verify_pending_approval_checks_replacement(monkeypatch):
    snaps = [
        {"SnapshotId": "snap-old", "Encrypted": False, "_create_volume_permissions": []},
        {"SnapshotId": "snap-new", "Encrypted": True, "_create_volume_permissions": []},
    ]
    patch_collector(monkeypatch, snapshots=snaps)
    r = RemediationResult("2.2.3", "snap-old", PENDING_APPROVAL, "copy", "ok",
                          verify_ids=["snap-new"], region=REGION)
    engine.verify(FakeAwsNoApi(), [r], select_controls(["2.2.3"]), scope={})
    assert r.status == PENDING_APPROVAL
    assert r.after == FAIL              # bản gốc vẫn FAIL tới khi được duyệt xoá
    assert r.details["verify"] == {"snap-new": PASS}


def test_execution_order():
    ids = [c.cis_id for c in ordered(select_controls(None))]
    assert ids.index("2.2.2") < ids.index("2.2.3")
    assert ids.index("3.3") < ids.index("3.4")
    assert ids.index("2.2.1") == len(EXECUTION_ORDER) - 1
    # Mọi action đều có control tương ứng trong registry audit
    assert set(EXECUTION_ORDER) <= set(CONTROLS_BY_ID)


def test_match_key():
    assert engine.match_key(TD_ARN) == engine.match_key(f"{TD_BASE}:7")
    assert engine.match_key("snap-1") == "snap-1"
