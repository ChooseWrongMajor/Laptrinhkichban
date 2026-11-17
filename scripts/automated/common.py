#!/usr/bin/env python3
"""
Module dùng chung cho hệ thống đánh giá và khắc phục tự động (Automated)
CIS AWS Compute Services Benchmark v2.0.0 - Nhóm 04
"""

import csv
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
import boto3
from botocore.exceptions import ClientError

# Mã màu ANSI hiển thị trực quan trên Terminal (Windows PowerShell / Terminal)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


@dataclass
class CheckResult:
    cis_id: str
    title: str
    service: str
    resource_id: str
    status: str  # PASS | FAIL | ERROR | NOT_APPLICABLE
    details: str
    remediation_action: str = "NONE"
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


def verify_caller_identity(session: boto3.Session) -> Dict[str, str]:
    """
    Kiểm tra danh tính và quyền truy cập AWS CLI / Boto3 qua STS GetCallerIdentity
    """
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    info = {
        "UserId": identity.get("UserId", ""),
        "Account": identity.get("Account", ""),
        "Arn": identity.get("Arn", ""),
        "Region": session.region_name or "ap-southeast-1",
    }
    print(f"{CYAN}{BOLD}========================================================================================{RESET}")
    print(f"{CYAN}{BOLD}   CIS AWS COMPUTE SERVICES BENCHMARK v2.0.0 - AUTOMATED AUDIT & REMEDIATION SYSTEM{RESET}")
    print(f"{CYAN}{BOLD}========================================================================================{RESET}")
    print(f"[*] Xác thực danh tính phiên làm việc AWS STS (Caller Identity):")
    print(f"  - Account ID : {BOLD}{info['Account']}{RESET}")
    print(f"  - IAM ARN    : {BOLD}{info['Arn']}{RESET}")
    print(f"  - Region     : {BOLD}{info['Region']}{RESET}")
    print(f"{CYAN}----------------------------------------------------------------------------------------{RESET}")
    return info


def print_audit_table(results: List[CheckResult], phase_title: str) -> Dict[str, Any]:
    """
    In bảng kết quả kiểm tra (Audit) ra màn hình Terminal kèm thống kê Compliance Score %
    """
    print(f"\n{BOLD}{CYAN}>>> {phase_title.upper()} <<<{RESET}")
    header = f"{'CIS ID':<7} | {'Dịch vụ':<11} | {'Trạng thái':<10} | {'Tài nguyên (Resource ID)':<36} | {'Chi tiết cấu hình thực tế'}"
    print("-" * 125)
    print(BOLD + header + RESET)
    print("-" * 125)

    counts = {"PASS": 0, "FAIL": 0, "ERROR": 0, "NOT_APPLICABLE": 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
        if r.status == "PASS":
            status_str = f"{GREEN}{BOLD}[PASS]{RESET}    "
        elif r.status == "FAIL":
            status_str = f"{RED}{BOLD}[FAIL]{RESET}    "
        elif r.status == "ERROR":
            status_str = f"{YELLOW}{BOLD}[ERROR]{RESET}   "
        else:
            status_str = f"{YELLOW}[N/A]{RESET}     "

        print(f"{r.cis_id:<7} | {r.service:<11} | {status_str} | {r.resource_id:<36} | {r.details}")

    print("-" * 125)
    applicable = counts["PASS"] + counts["FAIL"]
    score = (counts["PASS"] / applicable * 100.0) if applicable > 0 else 100.0
    score_color = GREEN if score == 100.0 else (YELLOW if score >= 50.0 else RED)

    print(
        f"{BOLD}TỔNG KẾT:{RESET} Tổng số tiêu chí: {BOLD}{len(results)}{RESET} | "
        f"{GREEN}{BOLD}PASS: {counts['PASS']}{RESET} | "
        f"{RED}{BOLD}FAIL: {counts['FAIL']}{RESET} | "
        f"{YELLOW}ERROR: {counts['ERROR']}{RESET} | "
        f"N/A: {counts['NOT_APPLICABLE']} | "
        f"Điểm tuân thủ (Compliance Score): {score_color}{BOLD}{score:.2f}% ({counts['PASS']}/{applicable}){RESET}"
    )
    print("-" * 125)
    return {
        "total": len(results),
        "pass": counts["PASS"],
        "fail": counts["FAIL"],
        "error": counts["ERROR"],
        "not_applicable": counts["NOT_APPLICABLE"],
        "compliance_score": round(score, 2),
    }


def export_reports(
    results: List[CheckResult],
    summary: Dict[str, Any],
    caller_info: Dict[str, str],
    json_path: Path,
    csv_path: Path,
    phase: str,
) -> None:
    """
    Xuất kết quả ra định dạng chuẩn JSON và CSV phục vụ đối chiếu và lưu trữ báo cáo
    """
    json_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "benchmark": "CIS AWS Compute Services Benchmark v2.0.0",
        "assessment_method": "Automated",
        "phase": phase,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "caller_identity": caller_info,
        "summary": summary,
        "results": [asdict(r) for r in results],
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    fieldnames = [
        "cis_id",
        "service",
        "title",
        "resource_id",
        "status",
        "details",
        "remediation_action",
        "timestamp",
    ]
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))

    print(f"  [+] Đã xuất báo cáo JSON : {json_path}")
    print(f"  [+] Đã xuất báo cáo CSV  : {csv_path}")
