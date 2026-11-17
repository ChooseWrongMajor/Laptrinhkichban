#!/usr/bin/env python3
"""
Module 2: Tự động hóa kiểm tra (Audit) và khắc phục (Remediation) cho dịch vụ Amazon ECS
Bao gồm 14 tiêu chí Automated trong CIS AWS Compute Services Benchmark v2.0.0:
  - CIS 3.1 : Ensure Amazon ECS task definitions using 'host' network mode do not allow privileged or root user access to the host
  - CIS 3.2 : Ensure 'assignPublicIp' is set to 'DISABLED' for Amazon ECS services
  - CIS 3.3 : Ensure Amazon ECS task definitions do not have 'pidMode' set to 'host'
  - CIS 3.4 : Ensure Amazon ECS task definitions do not have 'privileged' set to 'true'
  - CIS 3.5 : Ensure 'readonlyRootFilesystem' is set to 'true' for Amazon ECS task definitions
  - CIS 3.6 : Ensure secrets are not passed as container environment variables in Amazon ECS task definitions
  - CIS 3.7 : Ensure logging is configured for Amazon ECS task definitions
  - CIS 3.8 : Ensure Amazon ECS Fargate services are using the latest Fargate platform version
  - CIS 3.9 : Ensure monitoring is enabled for Amazon ECS clusters
  - CIS 3.10: Ensure Amazon ECS services are tagged
  - CIS 3.11: Ensure Amazon ECS clusters are tagged
  - CIS 3.12: Ensure Amazon ECS task definitions are tagged
  - CIS 3.13: Ensure only trusted images are used with Amazon ECS
  - CIS 3.14: Ensure 'assignPublicIp' is set to 'DISABLED' for Amazon ECS task sets
"""

import re
from typing import Any, Dict, List, Tuple
import boto3
from botocore.exceptions import ClientError
from common import CheckResult

SECRET_ENV_PATTERN = re.compile(
    r"(PASSWORD|PASSWD|SECRET|API_KEY|ACCESS_KEY|PRIVATE_KEY|TOKEN|DB_PASS)",
    re.IGNORECASE,
)


def _get_active_task_definitions(ecs) -> List[Tuple[Dict[str, Any], List[Dict[str, str]]]]:
    """Lấy danh sách toàn bộ Task Definition đang ACTIVE kèm danh sách Tags."""
    arns = ecs.list_task_definitions(status="ACTIVE").get("taskDefinitionArns", [])
    items = []
    for arn in arns:
        resp = ecs.describe_task_definition(taskDefinition=arn, include=["TAGS"])
        items.append((resp["taskDefinition"], resp.get("tags", [])))
    return items


def _get_clusters_and_services(ecs) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Lấy danh sách toàn bộ ECS Cluster và ECS Service kèm cấu hình, Settings và Tags."""
    cluster_arns = ecs.list_clusters().get("clusterArns", [])
    if not cluster_arns:
        return [], []
    clusters = ecs.describe_clusters(
        clusters=cluster_arns, include=["SETTINGS", "CONFIGURATIONS", "TAGS"]
    ).get("clusters", [])

    all_services = []
    for c in clusters:
        c_arn = c["clusterArn"]
        s_arns = ecs.list_services(cluster=c_arn).get("serviceArns", [])
        if s_arns:
            svcs = ecs.describe_services(
                cluster=c_arn, services=s_arns, include=["TAGS"]
            ).get("services", [])
            all_services.extend([s for s in svcs if s.get("status") == "ACTIVE"])
    return clusters, all_services


def run_ecs_audit(session: boto3.Session, account_id: str) -> List[CheckResult]:
    ecs = session.client("ecs")
    region = session.region_name or "ap-southeast-1"
    task_defs = _get_active_task_definitions(ecs)
    clusters, services = _get_clusters_and_services(ecs)
    results: List[CheckResult] = []

    # ------------------------------------------------------------------
    # CIS 3.1: host networkMode + privileged or root user
    # ------------------------------------------------------------------
    if not task_defs:
        results.append(
            CheckResult("3.1", "Ensure ECS task definitions using 'host' network mode do not allow privileged/root", "Amazon ECS", "No Active TaskDefs", "NOT_APPLICABLE", "Không có ECS Task Definition đang ACTIVE.")
        )
    else:
        violating_3_1 = []
        for td, _ in task_defs:
            td_id = f"{td['family']}:{td['revision']}"
            if td.get("networkMode") == "host":
                for c in td.get("containerDefinitions", []):
                    user_val = str(c.get("user", "")).strip()
                    if c.get("privileged") is True or user_val in ("", "root", "0"):
                        violating_3_1.append(f"{td_id}({c['name']})")
        if violating_3_1:
            results.append(
                CheckResult("3.1", "Ensure ECS task definitions using 'host' network mode do not allow privileged/root", "Amazon ECS", ", ".join(violating_3_1), "FAIL", f"Task Definition dùng networkMode='host' với quyền root/privileged: {', '.join(violating_3_1)}")
            )
        else:
            td_names = [f"{td['family']}:{td['revision']}" for td, _ in task_defs]
            results.append(
                CheckResult("3.1", "Ensure ECS task definitions using 'host' network mode do not allow privileged/root", "Amazon ECS", ", ".join(td_names), "PASS", f"Tất cả Task Definition ({', '.join(td_names)}) không vi phạm host network + root/privileged.")
            )

    # ------------------------------------------------------------------
    # CIS 3.2: assignPublicIp is DISABLED for ECS services
    # ------------------------------------------------------------------
    if not services:
        results.append(
            CheckResult("3.2", "Ensure 'assignPublicIp' is set to 'DISABLED' for Amazon ECS services", "Amazon ECS", "No Active Services", "NOT_APPLICABLE", "Không có ECS Service đang ACTIVE.")
        )
    else:
        violating_3_2 = []
        compliant_3_2 = []
        for s in services:
            sname = s["serviceName"]
            pub_ip = (
                s.get("networkConfiguration", {})
                .get("awsvpcConfiguration", {})
                .get("assignPublicIp", "DISABLED")
            )
            if pub_ip == "ENABLED":
                violating_3_2.append(sname)
            else:
                compliant_3_2.append(sname)
        if violating_3_2:
            results.append(
                CheckResult("3.2", "Ensure 'assignPublicIp' is set to 'DISABLED' for Amazon ECS services", "Amazon ECS", ", ".join(violating_3_2), "FAIL", f"ECS Service đang cấu hình assignPublicIp='ENABLED': {', '.join(violating_3_2)}")
            )
        else:
            results.append(
                CheckResult("3.2", "Ensure 'assignPublicIp' is set to 'DISABLED' for Amazon ECS services", "Amazon ECS", ", ".join(compliant_3_2), "PASS", f"ECS Service ({', '.join(compliant_3_2)}) có assignPublicIp='DISABLED'.")
            )

    # ------------------------------------------------------------------
    # CIS 3.3: pidMode is not set to 'host'
    # ------------------------------------------------------------------
    violating_3_3 = [
        f"{td['family']}:{td['revision']}"
        for td, _ in task_defs
        if td.get("pidMode") == "host"
    ]
    if violating_3_3:
        results.append(
            CheckResult("3.3", "Ensure Amazon ECS task definitions do not have 'pidMode' set to 'host'", "Amazon ECS", ", ".join(violating_3_3), "FAIL", f"Task Definition có pidMode='host': {', '.join(violating_3_3)}")
        )
    else:
        td_names = [f"{td['family']}:{td['revision']}" for td, _ in task_defs]
        results.append(
            CheckResult("3.3", "Ensure Amazon ECS task definitions do not have 'pidMode' set to 'host'", "Amazon ECS", ", ".join(td_names) or "N/A", "PASS", f"Không có Task Definition nào đặt pidMode='host' ({', '.join(td_names)}).")
        )

    # ------------------------------------------------------------------
    # CIS 3.4: privileged is not set to 'true'
    # ------------------------------------------------------------------
    violating_3_4 = []
    for td, _ in task_defs:
        td_id = f"{td['family']}:{td['revision']}"
        for c in td.get("containerDefinitions", []):
            if c.get("privileged") is True:
                violating_3_4.append(f"{td_id}({c['name']})")
    if violating_3_4:
        results.append(
            CheckResult("3.4", "Ensure Amazon ECS task definitions do not have 'privileged' set to 'true'", "Amazon ECS", ", ".join(violating_3_4), "FAIL", f"Container bật privileged=True: {', '.join(violating_3_4)}")
        )
    else:
        td_names = [f"{td['family']}:{td['revision']}" for td, _ in task_defs]
        results.append(
            CheckResult("3.4", "Ensure Amazon ECS task definitions do not have 'privileged' set to 'true'", "Amazon ECS", ", ".join(td_names) or "N/A", "PASS", f"Tất cả container trong ({', '.join(td_names)}) đều đặt privileged=False.")
        )

    # ------------------------------------------------------------------
    # CIS 3.5: readonlyRootFilesystem is set to 'true'
    # ------------------------------------------------------------------
    violating_3_5 = []
    for td, _ in task_defs:
        td_id = f"{td['family']}:{td['revision']}"
        for c in td.get("containerDefinitions", []):
            if c.get("readonlyRootFilesystem") is not True:
                violating_3_5.append(td_id)
    if violating_3_5:
        results.append(
            CheckResult("3.5", "Ensure 'readonlyRootFilesystem' is set to 'true' for Amazon ECS task definitions", "Amazon ECS", ", ".join(violating_3_5), "FAIL", f"Container chưa bật readonlyRootFilesystem=True ({', '.join(violating_3_5)})")
        )
    else:
        td_names = [f"{td['family']}:{td['revision']}" for td, _ in task_defs]
        results.append(
            CheckResult("3.5", "Ensure 'readonlyRootFilesystem' is set to 'true' for Amazon ECS task definitions", "Amazon ECS", ", ".join(td_names) or "N/A", "PASS", f"Tất cả container trong ({', '.join(td_names)}) đều có readonlyRootFilesystem=True")
        )

    # ------------------------------------------------------------------
    # CIS 3.6: secrets are not passed as container environment variables
    # ------------------------------------------------------------------
    violating_3_6 = []
    for td, _ in task_defs:
        td_id = f"{td['family']}:{td['revision']}"
        for c in td.get("containerDefinitions", []):
            for env in c.get("environment", []):
                ename = env.get("name", "")
                if SECRET_ENV_PATTERN.search(ename):
                    violating_3_6.append(f"{td_id}({ename})")
    if violating_3_6:
        results.append(
            CheckResult("3.6", "Ensure secrets are not passed as container environment variables in ECS task definitions", "Amazon ECS", ", ".join(violating_3_6), "FAIL", f"Phát hiện biến môi trường nhạy cảm dạng plaintext: {', '.join(violating_3_6)}")
        )
    else:
        td_names = [f"{td['family']}:{td['revision']}" for td, _ in task_defs]
        results.append(
            CheckResult("3.6", "Ensure secrets are not passed as container environment variables in ECS task definitions", "Amazon ECS", ", ".join(td_names) or "N/A", "PASS", f"Không có biến môi trường chứa secret plaintext trong ({', '.join(td_names)}).")
        )

    # ------------------------------------------------------------------
    # CIS 3.7: logging is configured for Amazon ECS task definitions
    # ------------------------------------------------------------------
    violating_3_7 = []
    for td, _ in task_defs:
        td_id = f"{td['family']}:{td['revision']}"
        for c in td.get("containerDefinitions", []):
            log_cfg = c.get("logConfiguration", {})
            if not log_cfg or not log_cfg.get("logDriver"):
                violating_3_7.append(f"{td_id}({c['name']})")
    if violating_3_7:
        results.append(
            CheckResult("3.7", "Ensure logging is configured for Amazon ECS task definitions", "Amazon ECS", ", ".join(violating_3_7), "FAIL", f"Container chưa cấu hình logConfiguration: {', '.join(violating_3_7)}")
        )
    else:
        td_names = [f"{td['family']}:{td['revision']}" for td, _ in task_defs]
        results.append(
            CheckResult("3.7", "Ensure logging is configured for Amazon ECS task definitions", "Amazon ECS", ", ".join(td_names) or "N/A", "PASS", f"Tất cả container trong ({', '.join(td_names)}) đã bật logDriver='awslogs'.")
        )

    # ------------------------------------------------------------------
    # CIS 3.8: ECS Fargate services are using the latest Fargate platform version
    # ------------------------------------------------------------------
    fargate_svcs = [s for s in services if s.get("launchType") == "FARGATE" or s.get("platformVersion")]
    if not fargate_svcs:
        results.append(
            CheckResult("3.8", "Ensure Amazon ECS Fargate services are using the latest Fargate platform version", "Amazon ECS", "No Fargate Services", "NOT_APPLICABLE", "Không có ECS Fargate Service đang ACTIVE.")
        )
    else:
        violating_3_8 = []
        compliant_3_8 = []
        for s in fargate_svcs:
            pv = s.get("platformVersion", "")
            # Trên AWS Fargate Linux, LATEST tương ứng với phiên bản 1.4.0; các bản 1.3.0 trở xuống là cũ (FAIL)
            if pv not in ("LATEST", "1.4.0"):
                violating_3_8.append(f"{s['serviceName']}({pv})")
            else:
                compliant_3_8.append(f"{s['serviceName']}({pv})")
        if violating_3_8:
            results.append(
                CheckResult("3.8", "Ensure Amazon ECS Fargate services are using the latest Fargate platform version", "Amazon ECS", fargate_svcs[0]["serviceName"], "FAIL", f"Fargate Service dùng Platform Version cũ: {', '.join(violating_3_8)}")
            )
        else:
            results.append(
                CheckResult("3.8", "Ensure Amazon ECS Fargate services are using the latest Fargate platform version", "Amazon ECS", fargate_svcs[0]["serviceName"], "PASS", f"Fargate Service đang dùng Platform Version mới nhất: {', '.join(compliant_3_8)}")
            )

    # ------------------------------------------------------------------
    # CIS 3.9: Ensure monitoring (containerInsights) is enabled for ECS clusters
    # ------------------------------------------------------------------
    violating_3_9 = []
    compliant_3_9 = []
    for c in clusters:
        cname = c["clusterName"]
        settings = {st["name"]: st["value"] for st in c.get("settings", [])}
        ci_val = settings.get("containerInsights", "disabled")
        if ci_val not in ("enabled", "enhanced"):
            violating_3_9.append(f"{cname} (containerInsights={ci_val})")
        else:
            compliant_3_9.append(f"{cname} (containerInsights={ci_val})")
    if violating_3_9:
        results.append(
            CheckResult("3.9", "Ensure monitoring is enabled for Amazon ECS clusters", "Amazon ECS", clusters[0]["clusterName"], "FAIL", f"ECS Cluster chưa bật Container Insights: {', '.join(violating_3_9)}")
        )
    else:
        results.append(
            CheckResult("3.9", "Ensure monitoring is enabled for Amazon ECS clusters", "Amazon ECS", clusters[0]["clusterName"], "PASS", f"ECS Cluster đã bật giám sát Container Insights: {', '.join(compliant_3_9)}")
        )

    # ------------------------------------------------------------------
    # CIS 3.10: Ensure Amazon ECS services are tagged
    # ------------------------------------------------------------------
    violating_3_10 = [s["serviceName"] for s in services if not s.get("tags")]
    if violating_3_10:
        results.append(
            CheckResult("3.10", "Ensure Amazon ECS services are tagged", "Amazon ECS", ", ".join(violating_3_10), "FAIL", f"ECS Service chưa được gắn thẻ (tags=[]): {', '.join(violating_3_10)}")
        )
    else:
        s_names = [f"{s['serviceName']} ({len(s.get('tags', []))} tags)" for s in services]
        results.append(
            CheckResult("3.10", "Ensure Amazon ECS services are tagged", "Amazon ECS", services[0]["serviceName"] if services else "N/A", "PASS", f"Tất cả ECS Service đều đã gắn thẻ quản lý: {', '.join(s_names)}")
        )

    # ------------------------------------------------------------------
    # CIS 3.11: Ensure Amazon ECS clusters are tagged
    # ------------------------------------------------------------------
    violating_3_11 = [c["clusterName"] for c in clusters if not c.get("tags")]
    if violating_3_11:
        results.append(
            CheckResult("3.11", "Ensure Amazon ECS clusters are tagged", "Amazon ECS", ", ".join(violating_3_11), "FAIL", f"ECS Cluster chưa được gắn thẻ (tags=[]): {', '.join(violating_3_11)}")
        )
    else:
        c_names = [f"{c['clusterName']} ({len(c.get('tags', []))} tags)" for c in clusters]
        results.append(
            CheckResult("3.11", "Ensure Amazon ECS clusters are tagged", "Amazon ECS", clusters[0]["clusterName"], "PASS", f"Tất cả ECS Cluster đều đã gắn thẻ quản lý: {', '.join(c_names)}")
        )

    # ------------------------------------------------------------------
    # CIS 3.12: Ensure Amazon ECS task definitions are tagged
    # ------------------------------------------------------------------
    violating_3_12 = [
        f"{td['family']}:{td['revision']}" for td, tags in task_defs if not tags
    ]
    if violating_3_12:
        results.append(
            CheckResult("3.12", "Ensure Amazon ECS task definitions are tagged", "Amazon ECS", ", ".join(violating_3_12), "FAIL", f"Task Definition chưa được gắn thẻ (tags=[]): {', '.join(violating_3_12)}")
        )
    else:
        td_tagged = [f"{td['family']}:{td['revision']} ({len(tags)} tags)" for td, tags in task_defs]
        td_short = f"{task_defs[0][0]['family']}:{task_defs[0][0]['revision']}" if task_defs else "N/A"
        results.append(
            CheckResult("3.12", "Ensure Amazon ECS task definitions are tagged", "Amazon ECS", td_short, "PASS", f"Tất cả Task Definition đều đã gắn thẻ: {', '.join(td_tagged)}")
        )

    # ------------------------------------------------------------------
    # CIS 3.13: Ensure only trusted images are used with Amazon ECS
    # ------------------------------------------------------------------
    trusted_prefix = f"{account_id}.dkr.ecr.{region}.amazonaws.com/"
    violating_3_13 = []
    compliant_3_13 = []
    for td, _ in task_defs:
        td_id = f"{td['family']}:{td['revision']}"
        for c in td.get("containerDefinitions", []):
            img = c.get("image", "")
            if not (img.startswith(trusted_prefix) or img.startswith("public.ecr.aws/")):
                violating_3_13.append(f"{td_id} ({img})")
            else:
                compliant_3_13.append(f"{td_id} ({img.split('/')[-1]})")
    td_short = f"{task_defs[0][0]['family']}:{task_defs[0][0]['revision']}" if task_defs else "N/A"
    if violating_3_13:
        results.append(
            CheckResult("3.13", "Ensure only trusted images are used with Amazon ECS", "Amazon ECS", td_short, "FAIL", f"Container dùng image ngoài kho ECR đáng tin cậy: {', '.join(violating_3_13)}")
        )
    else:
        results.append(
            CheckResult("3.13", "Ensure only trusted images are used with Amazon ECS", "Amazon ECS", td_short, "PASS", f"Chỉ sử dụng container image từ kho ECR nội bộ đáng tin cậy: {', '.join(compliant_3_13)}")
        )

    # ------------------------------------------------------------------
    # CIS 3.14: Ensure 'assignPublicIp' is set to 'DISABLED' for Amazon ECS task sets
    # ------------------------------------------------------------------
    violating_3_14 = []
    compliant_3_14 = []
    for s in services:
        sname = s["serviceName"]
        task_sets = s.get("taskSets", [])
        if task_sets:
            for ts in task_sets:
                ts_id = ts.get("id", "task-set")
                pub_ip = (
                    ts.get("networkConfiguration", {})
                    .get("awsvpcConfiguration", {})
                    .get("assignPublicIp", "DISABLED")
                )
                if pub_ip == "ENABLED":
                    violating_3_14.append(f"{sname}/{ts_id}")
                else:
                    compliant_3_14.append(f"{sname}/{ts_id}")
        else:
            pub_ip = (
                s.get("networkConfiguration", {})
                .get("awsvpcConfiguration", {})
                .get("assignPublicIp", "DISABLED")
            )
            if pub_ip == "ENABLED":
                violating_3_14.append(f"{sname}/primary-taskset")
            else:
                compliant_3_14.append(f"{sname}/primary-taskset")

    svc_short = services[0]["serviceName"] if services else "N/A"
    if violating_3_14:
        results.append(
            CheckResult("3.14", "Ensure 'assignPublicIp' is set to 'DISABLED' for Amazon ECS task sets", "Amazon ECS", svc_short, "FAIL", f"ECS Task Set đang đặt assignPublicIp='ENABLED' ({', '.join(violating_3_14)})")
        )
    else:
        results.append(
            CheckResult("3.14", "Ensure 'assignPublicIp' is set to 'DISABLED' for Amazon ECS task sets", "Amazon ECS", svc_short, "PASS", f"Tất cả ECS Task Set ({', '.join(compliant_3_14)}) đều có assignPublicIp='DISABLED'")
        )

    return results


def run_ecs_remediation(
    session: boto3.Session,
    account_id: str,
    audit_results: List[CheckResult],
    subnet_id: str = "subnet-05560be0f1e0a1afc",
    sg_id: str = "sg-0e0b641ff9ab2785c",
) -> Dict[str, str]:
    """
    Tự động khắc phục toàn bộ các lỗi cấu hình ECS (Task Definition, Cluster, Service, Task Set)
    """
    ecs = session.client("ecs")
    region = session.region_name or "ap-southeast-1"
    failed_ids = {r.cis_id for r in audit_results if r.status == "FAIL"}
    actions: Dict[str, str] = {}

    # 1. Khắc phục nhóm lỗi ECS Task Definition (3.1, 3.3, 3.4, 3.5, 3.6, 3.7, 3.12, 3.13)
    td_cis_set = {"3.1", "3.3", "3.4", "3.5", "3.6", "3.7", "3.12", "3.13"}
    if failed_ids.intersection(td_cis_set):
        old_arns = ecs.list_task_definitions(status="ACTIVE").get(
            "taskDefinitionArns", []
        )
        trusted_image = f"{account_id}.dkr.ecr.{region}.amazonaws.com/cis-compute-benchmark-private-repo:latest"
        exec_role_arn = f"arn:aws:iam::{account_id}:role/cis-compute-benchmark-ecs-task-exec-role"

        new_td = ecs.register_task_definition(
            family="cis-compute-benchmark-task",
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",
            executionRoleArn=exec_role_arn,
            pidMode="task",
            containerDefinitions=[
                {
                    "name": "app-container",
                    "image": trusted_image,
                    "essential": True,
                    "user": "1000:1000",
                    "privileged": False,
                    "readonlyRootFilesystem": True,
                    "environment": [{"name": "APP_ENV", "value": "production"}],
                    "logConfiguration": {
                        "logDriver": "awslogs",
                        "options": {
                            "awslogs-group": "/ecs/exec-audit-logs",
                            "awslogs-region": region,
                            "awslogs-stream-prefix": "ecs-app",
                        },
                    },
                }
            ],
            tags=[
                {"key": "Name", "value": "cis-compute-benchmark-task"},
                {"key": "Project", "value": "cis-compute-benchmark"},
                {"key": "Environment", "value": "lab"},
            ],
        )["taskDefinition"]
        new_td_arn = new_td["taskDefinitionArn"]
        new_td_short = f"{new_td['family']}:{new_td['revision']}"

        # Hủy đăng ký (deregister) các revision cũ không tuân thủ
        for old_arn in old_arns:
            if old_arn != new_td_arn:
                ecs.deregister_task_definition(taskDefinition=old_arn)

        for cid in sorted(failed_ids.intersection(td_cis_set)):
            actions[cid] = (
                f"Đã đăng ký Task Definition chuẩn CIS ({new_td_short}) và hủy các revision vi phạm cũ."
            )

    # 2. Khắc phục lỗi ECS Cluster (3.9 Container Insights & 3.11 Cluster Tags)
    cluster_name = "cis-compute-benchmark-cluster"
    cluster_arn = f"arn:aws:ecs:{region}:{account_id}:cluster/{cluster_name}"

    if "3.9" in failed_ids:
        ecs.update_cluster_settings(
            cluster=cluster_name,
            settings=[{"name": "containerInsights", "value": "enabled"}],
        )
        actions["3.9"] = (
            f"Đã bật Container Insights (value='enabled') cho cluster '{cluster_name}'."
        )

    if "3.11" in failed_ids:
        ecs.tag_resource(
            resourceArn=cluster_arn,
            tags=[
                {"key": "Name", "value": cluster_name},
                {"key": "Project", "value": "cis-compute-benchmark"},
                {"key": "Environment", "value": "lab"},
            ],
        )
        actions["3.11"] = f"Đã gắn thẻ (Tags) chuẩn quản trị cho cluster '{cluster_name}'."

    # 3. Khắc phục lỗi ECS Service & Task Set (3.2, 3.8, 3.10, 3.14)
    svc_cis_set = {"3.2", "3.8", "3.10", "3.14"}
    if failed_ids.intersection(svc_cis_set):
        s_arns = ecs.list_services(cluster=cluster_name).get("serviceArns", [])
        latest_tds = ecs.list_task_definitions(
            familyPrefix="cis-compute-benchmark-task", status="ACTIVE", sort="DESC"
        ).get("taskDefinitionArns", [])
        target_td = latest_tds[0] if latest_tds else "cis-compute-benchmark-task"

        for s_arn in s_arns:
            ecs.update_service(
                cluster=cluster_name,
                service=s_arn,
                taskDefinition=target_td,
                platformVersion="LATEST",
                networkConfiguration={
                    "awsvpcConfiguration": {
                        "subnets": [subnet_id],
                        "securityGroups": [sg_id],
                        "assignPublicIp": "DISABLED",
                    }
                },
            )
            ecs.tag_resource(
                resourceArn=s_arn,
                tags=[
                    {"key": "Name", "value": "cis-compute-benchmark-service"},
                    {"key": "Project", "value": "cis-compute-benchmark"},
                    {"key": "Environment", "value": "lab"},
                ],
            )

        if "3.2" in failed_ids:
            actions["3.2"] = "Đã cập nhật ECS Service với assignPublicIp='DISABLED'."
        if "3.8" in failed_ids:
            actions["3.8"] = "Đã nâng cấp ECS Fargate Service lên platformVersion='LATEST' (1.4.0)."
        if "3.10" in failed_ids:
            actions["3.10"] = "Đã gắn thẻ (Tags) cho ECS Service qua ecs.tag_resource()."
        if "3.14" in failed_ids:
            actions["3.14"] = "Đã cập nhật ECS Task Set / Deployment với assignPublicIp='DISABLED'."

    return actions
