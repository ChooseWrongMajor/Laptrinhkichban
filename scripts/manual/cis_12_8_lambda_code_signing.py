#!/usr/bin/env python3
"""
CIS AWS Compute Services Benchmark v2.0.0
Recommendation 12.8: Ensure that Code Signing is enabled for Lambda functions. (Manual / Scripted)

Luồng thực hiện theo báo cáo (Mục 2.2.3 - Trang 16 -> 26) và CIS Benchmark (Trang 200-203):
- Bước 3: Kiểm tra quyền truy cập (aws sts get-caller-identity)
- Bước 4: Thu thập danh sách tất cả Lambda functions trong region bằng Boto3,
          kiểm tra cấu hình Code Signing của từng hàm (theo đúng các bước trang 200-201 sách CIS):
    1. Gọi get_function_code_signing_config(FunctionName=...) để lấy CodeSigningConfigArn.
       - Nếu không có CodeSigningConfigArn -> FAIL.
    2. Nếu có CodeSigningConfigArn, gọi get_code_signing_config(CodeSigningConfigArn=...)
       để kiểm tra CodeSigningPolicies.UntrustedArtifactOnDeployment:
       - Nếu giá trị là 'Warn' -> FAIL (sách CIS yêu cầu bắt buộc là 'Enforce').
       - Nếu giá trị là 'Enforce' -> PASS.
- Bước 5: Thực hiện Remediation đối với các Lambda function bị FAIL:
    + Tạo AWS Signer Signing Profile (platformId='AWSLambda-SHA384-ECDSA') nếu chưa có.
    + Tạo Lambda Code Signing Configuration với UntrustedArtifactOnDeployment='Enforce'.
    + Gắn Code Signing Configuration vào Lambda function bằng put_function_code_signing_config.
- Bước 6: Kiểm tra lại sau Remediation (Verification)
- Bước 7: Tổng hợp kết quả và xuất báo cáo (JSON & CSV)
"""

import argparse
import csv
import io
import json
import os
import time
import zipfile
from datetime import datetime, timezone
import boto3
from botocore.exceptions import BotoCoreError, ClientError

CIS_ID = "12.8"
CIS_TITLE = "Ensure that Code Signing is enabled for Lambda functions."
DEFAULT_SIGNING_PROFILE_NAME = "cis128lambdasigningprofile"
DEFAULT_FUNCTION_NAME = "cis-compute-benchmark-lambda"


def check_caller_identity(session: boto3.Session) -> dict:
    """Bước 3: Kiểm tra danh tính AWS trước khi gọi API."""
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    return {
        "UserId": identity.get("UserId"),
        "Account": identity.get("Account"),
        "Arn": identity.get("Arn"),
    }


def ensure_demo_lambda_function(
    lambda_client, iam_client, function_name: str = DEFAULT_FUNCTION_NAME
) -> str:
    """Đảm bảo tồn tại ít nhất 1 Lambda function trên tài khoản để thực hiện kiểm thử CIS 12.8."""
    try:
        resp = lambda_client.get_function(FunctionName=function_name)
        return resp["Configuration"]["FunctionArn"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

    role_name = f"{function_name}-exec-role"
    assume_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    try:
        role_resp = iam_client.get_role(RoleName=role_name)
        role_arn = role_resp["Role"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            create_role = iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_policy),
                Description="Execution role for CIS 12.8 demo Lambda function",
            )
            role_arn = create_role["Role"]["Arn"]
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
            time.sleep(10)
        else:
            raise

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            "def lambda_handler(event, context):\n    return {'statusCode': 200, 'body': 'CIS Benchmark Lambda'}\n",
        )
    zip_buffer.seek(0)

    fn_resp = lambda_client.create_function(
        FunctionName=function_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": zip_buffer.read()},
        Description="Demo Lambda function for CIS AWS Compute Services Benchmark v2.0.0",
        Timeout=10,
        MemorySize=128,
    )
    return fn_resp["FunctionArn"]


def audit_lambda_code_signing(lambda_client) -> list[dict]:
    """
    Bước 4: Kiểm tra Code Signing cho tất cả Lambda functions trong region
    theo đúng hướng dẫn CLI ở trang 200-201 sách CIS Benchmark:
    1. aws lambda list-functions
    2. aws lambda get-function-code-signing-config --function-name <name> --query "CodeSigningConfigArn"
    3. aws lambda get-code-signing-config --code-signing-config-arn <ARN> --query "CodeSigningConfig.CodeSigningPolicies.UntrustedArtifactOnDeployment"
    """
    results = []
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        paginator = lambda_client.get_paginator("list_functions")
        functions = []
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))

        if not functions:
            results.append(
                {
                    "cis_id": CIS_ID,
                    "check": CIS_TITLE,
                    "resource_type": "Lambda_Function",
                    "resource_id": "NONE",
                    "code_signing_config_arn": "None",
                    "validation_policy": "N/A",
                    "last_modified": "N/A",
                    "status": "NOT_APPLICABLE",
                    "details": "Không có Lambda function nào trong region này.",
                    "timestamp": timestamp,
                }
            )
            return results

        for fn in functions:
            fn_name = fn["FunctionName"]
            last_modified = fn.get("LastModified", "")

            csc_resp = lambda_client.get_function_code_signing_config(
                FunctionName=fn_name
            )
            csc_arn = csc_resp.get("CodeSigningConfigArn")

            if not csc_arn:
                status = "FAIL"
                policy_mode = "NONE"
                details = (
                    f"Lambda function '{fn_name}' chưa được gắn Code Signing Configuration "
                    f"(CodeSigningConfigArn=null)."
                )
            else:
                cfg_detail = lambda_client.get_code_signing_config(
                    CodeSigningConfigArn=csc_arn
                )
                csc_obj = cfg_detail.get("CodeSigningConfig", {})
                policy_mode = csc_obj.get("CodeSigningPolicies", {}).get(
                    "UntrustedArtifactOnDeployment", "Warn"
                )
                csc_last_modified = csc_obj.get("LastModified", "")

                if policy_mode != "Enforce":
                    status = "FAIL"
                    details = (
                        f"Lambda function '{fn_name}' đã gắn Code Signing Config ({csc_arn}) "
                        f"nhưng UntrustedArtifactOnDeployment='{policy_mode}' (yêu cầu 'Enforce')."
                    )
                else:
                    status = "PASS"
                    details = (
                        f"Lambda function '{fn_name}' đã bật Code Signing đạt chuẩn: "
                        f"CodeSigningConfigArn={csc_arn}, UntrustedArtifactOnDeployment='Enforce' "
                        f"(Function LastModified: {last_modified}, Config LastModified: {csc_last_modified})."
                    )

            results.append(
                {
                    "cis_id": CIS_ID,
                    "check": CIS_TITLE,
                    "resource_type": "Lambda_Function",
                    "resource_id": fn_name,
                    "code_signing_config_arn": csc_arn or "None",
                    "validation_policy": policy_mode,
                    "last_modified": last_modified,
                    "status": status,
                    "details": details,
                    "timestamp": timestamp,
                }
            )

    except (BotoCoreError, ClientError) as exc:
        results.append(
            {
                "cis_id": CIS_ID,
                "check": CIS_TITLE,
                "resource_type": "Lambda_Function",
                "resource_id": "UNKNOWN",
                "code_signing_config_arn": "N/A",
                "validation_policy": "N/A",
                "last_modified": "N/A",
                "status": "ERROR",
                "details": f"Lỗi khi gọi AWS Lambda API: {exc}",
                "timestamp": timestamp,
            }
        )

    return results


def ensure_code_signing_config(
    signer_client,
    lambda_client,
    profile_name: str = DEFAULT_SIGNING_PROFILE_NAME,
) -> str:
    """
    Bước 1-8 trong CIS 12.8 Remediation (Trang 201-202):
    1. Tạo AWS Signer Signing Profile cho Lambda (platformId='AWSLambda-SHA384-ECDSA').
    2. Tạo Lambda Code Signing Configuration với UntrustedArtifactOnDeployment='Enforce'.
    """
    # Kiểm tra xem đã có Code Signing Config nào đạt chuẩn Enforce chưa
    existing_cscs = lambda_client.list_code_signing_configs().get(
        "CodeSigningConfigs", []
    )
    for csc in existing_cscs:
        if (
            csc.get("CodeSigningPolicies", {}).get("UntrustedArtifactOnDeployment")
            == "Enforce"
        ):
            return csc["CodeSigningConfigArn"]

    # Tạo hoặc lấy AWS Signer Signing Profile
    try:
        prof = signer_client.get_signing_profile(profileName=profile_name)
        profile_version_arn = prof["profileVersionArn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            put_prof = signer_client.put_signing_profile(
                profileName=profile_name,
                platformId="AWSLambda-SHA384-ECDSA",
                signatureValidityPeriod={"value": 12, "type": "MONTHS"},
            )
            profile_version_arn = put_prof["profileVersionArn"]
        else:
            raise

    create_csc = lambda_client.create_code_signing_config(
        Description="CIS 12.8 Enforced Code Signing Configuration for Lambda",
        AllowedPublishers={
            "SigningProfileVersionArns": [profile_version_arn]
        },
        CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"},
    )
    return create_csc["CodeSigningConfig"]["CodeSigningConfigArn"]


def remediate_lambda_code_signing(
    lambda_client,
    signer_client,
    audit_results: list[dict],
    dry_run: bool = False,
) -> list[dict]:
    """
    Bước 5: Gắn Code Signing Configuration (chế độ Enforce) vào các Lambda function bị FAIL.
    """
    actions = []
    csc_arn = "DRY_RUN_CSC_ARN"

    if not dry_run:
        csc_arn = ensure_code_signing_config(signer_client, lambda_client)

    for item in audit_results:
        if item["status"] != "FAIL":
            continue

        fn_name = item["resource_id"]
        try:
            if not dry_run:
                lambda_client.put_function_code_signing_config(
                    CodeSigningConfigArn=csc_arn,
                    FunctionName=fn_name,
                )

            actions.append(
                {
                    "resource_id": fn_name,
                    "resource_type": "Lambda_Function",
                    "action": "attach_enforced_code_signing_config",
                    "status": "DRY_RUN" if dry_run else "SUCCESS",
                    "details": (
                        f"Đã gắn Code Signing Configuration ({csc_arn}, Policy=Enforce) "
                        f"cho Lambda function '{fn_name}'."
                    ),
                }
            )
        except (BotoCoreError, ClientError) as exc:
            actions.append(
                {
                    "resource_id": fn_name,
                    "resource_type": "Lambda_Function",
                    "action": "attach_enforced_code_signing_config",
                    "status": "ERROR",
                    "details": f"Không thể gắn Code Signing Config cho '{fn_name}': {exc}",
                }
            )

    return actions


def export_reports(report_data: dict, json_path: str, csv_path: str) -> None:
    """Bước 7: Xuất kết quả kiểm tra ra định dạng JSON và CSV."""
    os.makedirs(os.path.dirname(json_path), exist_ok=True)

    with open(json_path, "w", encoding="utf-8") as f_json:
        json.dump(report_data, f_json, ensure_ascii=False, indent=2)

    initial_map = {
        r["resource_id"]: r for r in report_data.get("initial_audit", [])
    }
    final_map = {
        r["resource_id"]: r for r in report_data.get("post_remediation_audit", [])
    }
    action_map = {
        a["resource_id"]: a for a in report_data.get("remediation_actions", [])
    }

    fieldnames = [
        "cis_id",
        "check_name",
        "resource_id",
        "initial_csc_arn",
        "initial_policy",
        "initial_status",
        "initial_details",
        "remediation_action",
        "remediation_status",
        "final_csc_arn",
        "final_policy",
        "final_status",
        "final_details",
        "timestamp",
    ]

    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=fieldnames)
        writer.writeheader()

        for res_id, init_rec in initial_map.items():
            act_rec = action_map.get(res_id, {})
            fin_rec = final_map.get(res_id, {})
            writer.writerow(
                {
                    "cis_id": init_rec.get("cis_id", CIS_ID),
                    "check_name": init_rec.get("check", CIS_TITLE),
                    "resource_id": res_id,
                    "initial_csc_arn": init_rec.get("code_signing_config_arn"),
                    "initial_policy": init_rec.get("validation_policy"),
                    "initial_status": init_rec.get("status"),
                    "initial_details": init_rec.get("details"),
                    "remediation_action": act_rec.get("action", "NONE"),
                    "remediation_status": act_rec.get("status", "NOT_EXECUTED"),
                    "final_csc_arn": fin_rec.get(
                        "code_signing_config_arn",
                        init_rec.get("code_signing_config_arn"),
                    ),
                    "final_policy": fin_rec.get(
                        "validation_policy", init_rec.get("validation_policy")
                    ),
                    "final_status": fin_rec.get("status", init_rec.get("status")),
                    "final_details": fin_rec.get("details", init_rec.get("details")),
                    "timestamp": fin_rec.get("timestamp", init_rec.get("timestamp")),
                }
            )


def main():
    parser = argparse.ArgumentParser(
        description="CIS 12.8 - Audit & Remediation: Ensure that Code Signing is enabled for Lambda functions."
    )
    parser.add_argument(
        "--region",
        default="ap-southeast-1",
        help="AWS Region cần kiểm tra (mặc định: ap-southeast-1)",
    )
    parser.add_argument(
        "--mode",
        choices=["audit", "remediate"],
        default="audit",
        help="Chế độ chạy: 'audit' (Audit-only) hoặc 'remediate' (Audit-and-remediate)",
    )
    parser.add_argument(
        "--ensure-demo-function",
        action="store_true",
        help="Tự động tạo 1 Lambda function mẫu (miễn phí) nếu tài khoản chưa có hàm nào",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Chạy thử nghiệm Remediation nhưng không thay đổi thực tế trên AWS",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Thư mục xuất file báo cáo JSON/CSV",
    )
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region)
    lambda_client = session.client("lambda")
    signer_client = session.client("signer")
    iam_client = session.client("iam")

    print(f"[*] Bước 3: Kiểm tra danh tính kết nối AWS (Region: {args.region})...")
    try:
        caller_identity = check_caller_identity(session)
        print(f"    -> Đã xác thực với ARN: {caller_identity['Arn']}")
    except (BotoCoreError, ClientError) as exc:
        print(f"[!] Lỗi xác thực AWS CLI/Boto3: {exc}")
        return

    if args.ensure_demo_function:
        print(f"[*] Khởi tạo Lambda function mẫu '{DEFAULT_FUNCTION_NAME}' để kiểm thử...")
        ensure_demo_lambda_function(lambda_client, iam_client, DEFAULT_FUNCTION_NAME)

    print(f"\n[*] Bước 4: Thu thập cấu hình và đánh giá tuân thủ CIS {CIS_ID}...")
    initial_audit = audit_lambda_code_signing(lambda_client)
    for res in initial_audit:
        print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")

    remediation_actions = []
    post_remediation_audit = []

    has_failures = any(r["status"] == "FAIL" for r in initial_audit)

    if args.mode == "remediate" and has_failures:
        print(f"\n[*] Bước 5: Thực hiện Remediation cho CIS {CIS_ID} (dry_run={args.dry_run})...")
        remediation_actions = remediate_lambda_code_signing(
            lambda_client, signer_client, initial_audit, dry_run=args.dry_run
        )
        for act in remediation_actions:
            print(f"    - [{act['status']}] {act['action']} ({act['resource_id']}): {act['details']}")

        print(f"\n[*] Bước 6: Kiểm tra lại (Verification) sau khi Remediation...")
        post_remediation_audit = audit_lambda_code_signing(lambda_client)
        for res in post_remediation_audit:
            print(f"    - [{res['status']}] {res['resource_id']}: {res['details']}")
    elif args.mode == "remediate" and not has_failures:
        print("\n[*] Tất cả Lambda functions đã bật Code Signing (PASS), không cần Remediation.")

    report_data = {
        "cis_benchmark": "CIS AWS Compute Services Benchmark v2.0.0",
        "cis_id": CIS_ID,
        "title": CIS_TITLE,
        "region": args.region,
        "mode": args.mode,
        "caller_identity": caller_identity,
        "execution_time": datetime.now(timezone.utc).isoformat(),
        "initial_audit": initial_audit,
        "remediation_actions": remediation_actions,
        "post_remediation_audit": post_remediation_audit,
    }

    json_path = os.path.join(args.output_dir, "cis_12_8_report.json")
    csv_path = os.path.join(args.output_dir, "cis_12_8_report.csv")
    export_reports(report_data, json_path, csv_path)

    print(f"\n[*] Bước 7: Đã xuất báo cáo kết quả tại:")
    print(f"    - JSON: {json_path}")
    print(f"    - CSV : {csv_path}")


if __name__ == "__main__":
    main()
