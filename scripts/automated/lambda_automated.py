#!/usr/bin/env python3
"""
Module 4: Tự động hóa kiểm tra (Audit) và khắc phục (Remediation) cho dịch vụ AWS Lambda
Bao gồm tiêu chí Automated trong CIS AWS Compute Services Benchmark v2.0.0:
  - CIS 12.16: Ensure AWS Lambda Function URLs are configured to use AWS IAM authentication
"""

from typing import Dict, List
import boto3
from botocore.exceptions import ClientError
from common import CheckResult


def audit_cis_12_16(session: boto3.Session) -> CheckResult:
    lmb = session.client("lambda")
    try:
        functions = lmb.list_functions().get("Functions", [])
        if not functions:
            return CheckResult(
                cis_id="12.16",
                title="Ensure AWS Lambda Function URLs are configured to use AWS IAM authentication",
                service="AWS Lambda",
                resource_id="No Lambda Functions",
                status="NOT_APPLICABLE",
                details="Không có Lambda Function nào trong Region.",
            )

        violating = []
        compliant = []
        for fn in functions:
            fname = fn["FunctionName"]
            url_cfgs = lmb.list_function_url_configs(FunctionName=fname).get(
                "FunctionUrlConfigs", []
            )
            for cfg in url_cfgs:
                auth_type = cfg.get("AuthType", "NONE")
                if auth_type != "AWS_IAM":
                    violating.append(f"{fname}(AuthType={auth_type})")
                else:
                    compliant.append(f"{fname}(AuthType={auth_type})")

        if not violating and not compliant:
            return CheckResult(
                cis_id="12.16",
                title="Ensure AWS Lambda Function URLs are configured to use AWS IAM authentication",
                service="AWS Lambda",
                resource_id="No Function URLs",
                status="NOT_APPLICABLE",
                details="Không có Lambda Function URL nào được cấu hình.",
            )

        if violating:
            return CheckResult(
                cis_id="12.16",
                title="Ensure AWS Lambda Function URLs are configured to use AWS IAM authentication",
                service="AWS Lambda",
                resource_id=functions[0]["FunctionName"],
                status="FAIL",
                details=f"Lambda Function URL đang mở công khai không xác thực: {', '.join(violating)}",
            )

        return CheckResult(
            cis_id="12.16",
            title="Ensure AWS Lambda Function URLs are configured to use AWS IAM authentication",
            service="AWS Lambda",
            resource_id=functions[0]["FunctionName"],
            status="PASS",
            details=f"Tất cả Lambda Function URL đều bắt buộc xác thực IAM: {', '.join(compliant)}",
        )
    except ClientError as e:
        return CheckResult(
            cis_id="12.16",
            title="Ensure AWS Lambda Function URLs are configured to use AWS IAM authentication",
            service="AWS Lambda",
            resource_id="Lambda-Function-URL",
            status="ERROR",
            details=str(e),
        )


def remediate_cis_12_16(session: boto3.Session) -> str:
    lmb = session.client("lambda")
    functions = lmb.list_functions().get("Functions", [])
    updated = []
    for fn in functions:
        fname = fn["FunctionName"]
        url_cfgs = lmb.list_function_url_configs(FunctionName=fname).get(
            "FunctionUrlConfigs", []
        )
        for cfg in url_cfgs:
            if cfg.get("AuthType") != "AWS_IAM":
                lmb.update_function_url_config(
                    FunctionName=fname, AuthType="AWS_IAM"
                )
                updated.append(fname)
    return f"Đã cập nhật Lambda Function URL sang AuthType='AWS_IAM' cho: {', '.join(updated)}"


def run_lambda_audit(session: boto3.Session) -> List[CheckResult]:
    return [audit_cis_12_16(session)]


def run_lambda_remediation(
    session: boto3.Session, audit_results: List[CheckResult]
) -> Dict[str, str]:
    actions = {}
    for r in audit_results:
        if r.cis_id == "12.16" and r.status == "FAIL":
            actions["12.16"] = remediate_cis_12_16(session)
    return actions
