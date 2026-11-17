#!/usr/bin/env python3
"""
Module 3: Tự động hóa kiểm tra (Audit) và khắc phục (Remediation) cho dịch vụ AWS Fargate
Bao gồm tiêu chí Automated trong CIS AWS Compute Services Benchmark v2.0.0:
  - CIS 11.1: Ensure customer-managed keys are used to encrypt AWS Fargate ephemeral storage data for Amazon ECS
"""

import json
import time
from typing import Dict, List
import boto3
from botocore.exceptions import ClientError
from common import CheckResult

KMS_ALIAS_NAME = "alias/cis-11-1-fargate-ephemeral-key"


def audit_cis_11_1(session: boto3.Session) -> CheckResult:
    ecs = session.client("ecs")
    kms = session.client("kms")
    try:
        cluster_arns = ecs.list_clusters().get("clusterArns", [])
        if not cluster_arns:
            return CheckResult(
                cis_id="11.1",
                title="Ensure customer-managed keys are used to encrypt AWS Fargate ephemeral storage data",
                service="AWS Fargate",
                resource_id="No ECS Clusters",
                status="NOT_APPLICABLE",
                details="Không có ECS Cluster nào trong Region.",
            )

        clusters = ecs.describe_clusters(
            clusters=cluster_arns, include=["CONFIGURATIONS"]
        ).get("clusters", [])

        violating = []
        compliant = []
        for c in clusters:
            cname = c["clusterName"]
            kms_id = (
                c.get("configuration", {})
                .get("managedStorageConfiguration", {})
                .get("fargateEphemeralStorageKmsKeyId")
            )
            if not kms_id:
                violating.append(cname)
            else:
                key_meta = kms.describe_key(KeyId=kms_id)["KeyMetadata"]
                if key_meta.get("KeyManager") == "CUSTOMER" and key_meta.get("Enabled"):
                    compliant.append(f"{cname} (CMK: {key_meta['KeyId']})")
                else:
                    violating.append(f"{cname} (KeyManager={key_meta.get('KeyManager')})")

        if violating:
            return CheckResult(
                cis_id="11.1",
                title="Ensure customer-managed keys are used to encrypt AWS Fargate ephemeral storage data",
                service="AWS Fargate",
                resource_id=clusters[0]["clusterName"],
                status="FAIL",
                details=f"Fargate Ephemeral Storage chưa mã hóa bằng KMS CMK trên cluster: {', '.join(violating)}",
            )

        return CheckResult(
            cis_id="11.1",
            title="Ensure customer-managed keys are used to encrypt AWS Fargate ephemeral storage data",
            service="AWS Fargate",
            resource_id=clusters[0]["clusterName"],
            status="PASS",
            details=f"Đã mã hóa Fargate Ephemeral Storage bằng KMS CMK: {', '.join(compliant)}",
        )
    except ClientError as e:
        return CheckResult(
            cis_id="11.1",
            title="Ensure customer-managed keys are used to encrypt AWS Fargate ephemeral storage data",
            service="AWS Fargate",
            resource_id="Fargate-Ephemeral-Storage",
            status="ERROR",
            details=str(e),
        )


def _build_fargate_key_policy(account_id: str) -> str:
    """Chính sách KMS Key Policy cho phép dịch vụ fargate.amazonaws.com mã hóa Ephemeral Storage (CIS 11.1)."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowFargateServicePrincipalToUseKey",
                "Effect": "Allow",
                "Principal": {"Service": "fargate.amazonaws.com"},
                "Action": [
                    "kms:GenerateDataKeyWithoutPlaintext",
                    "kms:CreateGrant",
                    "kms:DescribeKey",
                    "kms:Decrypt",
                ],
                "Resource": "*",
            },
        ],
    }
    return json.dumps(policy)


def _get_or_create_cmk(kms, account_id: str) -> str:
    """Tìm hoặc tạo KMS Customer-Managed Key kèm Key Policy cho fargate.amazonaws.com."""
    key_policy_str = _build_fargate_key_policy(account_id)
    aliases = kms.list_aliases().get("Aliases", [])
    for al in aliases:
        if al.get("AliasName") == KMS_ALIAS_NAME and al.get("TargetKeyId"):
            kid = al["TargetKeyId"]
            meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
            if meta.get("KeyState") == "PendingDeletion":
                kms.cancel_key_deletion(KeyId=kid)
                kms.enable_key(KeyId=kid)
            elif not meta.get("Enabled"):
                kms.enable_key(KeyId=kid)
            kms.put_key_policy(KeyId=kid, PolicyName="default", Policy=key_policy_str)
            return meta["Arn"]

    created = kms.create_key(
        Description="CIS 11.1 Customer Managed Key for AWS Fargate Ephemeral Storage",
        KeyUsage="ENCRYPT_DECRYPT",
        Origin="AWS_KMS",
        Policy=key_policy_str,
        Tags=[
            {"TagKey": "Name", "TagValue": "cis-11-1-fargate-cmk"},
            {"TagKey": "Project", "TagValue": "cis-compute-benchmark"},
        ],
    )["KeyMetadata"]
    kms.create_alias(AliasName=KMS_ALIAS_NAME, TargetKeyId=created["KeyId"])
    return created["Arn"]


def remediate_cis_11_1(session: boto3.Session) -> str:
    ecs = session.client("ecs")
    kms = session.client("kms")
    account_id = session.client("sts").get_caller_identity()["Account"]
    cmk_arn = _get_or_create_cmk(kms, account_id)
    time.sleep(2)

    cluster_name = "cis-compute-benchmark-cluster"
    ecs.update_cluster(
        cluster=cluster_name,
        configuration={
            "executeCommandConfiguration": {
                "logging": "OVERRIDE",
                "logConfiguration": {
                    "cloudWatchLogGroupName": "/ecs/exec-audit-logs",
                    "cloudWatchEncryptionEnabled": False,
                },
            },
            "managedStorageConfiguration": {
                "fargateEphemeralStorageKmsKeyId": cmk_arn,
            },
        },
    )
    return f"Đã gắn KMS Customer-Managed Key ({cmk_arn.split('/')[-1]}) vào managedStorageConfiguration của cluster '{cluster_name}'."


def run_fargate_audit(session: boto3.Session) -> List[CheckResult]:
    return [audit_cis_11_1(session)]


def run_fargate_remediation(
    session: boto3.Session, audit_results: List[CheckResult]
) -> Dict[str, str]:
    actions = {}
    for r in audit_results:
        if r.cis_id == "11.1" and r.status == "FAIL":
            actions["11.1"] = remediate_cis_11_1(session)
    return actions
