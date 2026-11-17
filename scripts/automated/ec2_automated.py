#!/usr/bin/env python3
"""
Module 1: Tự động hóa kiểm tra (Audit) và khắc phục (Remediation) cho dịch vụ Amazon EC2
Bao gồm 5 tiêu chí Automated trong CIS AWS Compute Services Benchmark v2.0.0:
  - CIS 2.1.2: Ensure Amazon Machine Images (AMIs) are encrypted
  - CIS 2.1.4: Ensure Images (AMI) are not older than 90 days
  - CIS 2.2.1: Ensure EBS volume encryption is enabled
  - CIS 2.2.2: Ensure Public Access to EBS Snapshots is Disabled
  - CIS 2.2.3: Ensure EBS volume snapshots are encrypted
"""

from datetime import datetime, timezone
from typing import Dict, List
import boto3
from botocore.exceptions import ClientError
from common import CheckResult, GREEN, RED, YELLOW, BOLD, RESET


# ==============================================================================
# CIS 2.1.2: Ensure Amazon Machine Images (AMIs) are encrypted
# ==============================================================================
def audit_cis_2_1_2(session: boto3.Session) -> CheckResult:
    ec2 = session.client("ec2")
    try:
        images = ec2.describe_images(Owners=["self"]).get("Images", [])
        if not images:
            return CheckResult(
                cis_id="2.1.2",
                title="Ensure Amazon Machine Images (AMIs) are encrypted",
                service="Amazon EC2",
                resource_id="N/A (No AMIs)",
                status="NOT_APPLICABLE",
                details="Không có AMI nào thuộc sở hữu của tài khoản (Owners=self).",
            )

        unencrypted_amis = []
        encrypted_amis = []
        for img in images:
            ami_id = img["ImageId"]
            ebs_mappings = [
                b["Ebs"] for b in img.get("BlockDeviceMappings", []) if "Ebs" in b
            ]
            if any(not ebs.get("Encrypted", False) for ebs in ebs_mappings):
                unencrypted_amis.append(ami_id)
            else:
                encrypted_amis.append(ami_id)

        if unencrypted_amis:
            return CheckResult(
                cis_id="2.1.2",
                title="Ensure Amazon Machine Images (AMIs) are encrypted",
                service="Amazon EC2",
                resource_id=", ".join(unencrypted_amis),
                status="FAIL",
                details=f"Phát hiện {len(unencrypted_amis)} AMI chưa mã hóa EBS: {', '.join(unencrypted_amis)}",
            )

        return CheckResult(
            cis_id="2.1.2",
            title="Ensure Amazon Machine Images (AMIs) are encrypted",
            service="Amazon EC2",
            resource_id=f"{len(encrypted_amis)} AMIs ({encrypted_amis[0]})",
            status="PASS",
            details=f"Tất cả {len(encrypted_amis)} AMI đều có Encrypted=True ({', '.join(encrypted_amis)})",
        )
    except ClientError as e:
        return CheckResult(
            cis_id="2.1.2",
            title="Ensure Amazon Machine Images (AMIs) are encrypted",
            service="Amazon EC2",
            resource_id="EC2-AMI",
            status="ERROR",
            details=str(e),
        )


# ==============================================================================
# CIS 2.1.4: Ensure Images (AMI) are not older than 90 days
# ==============================================================================
def audit_cis_2_1_4(session: boto3.Session) -> CheckResult:
    ec2 = session.client("ec2")
    try:
        images = ec2.describe_images(Owners=["self"]).get("Images", [])
        if not images:
            return CheckResult(
                cis_id="2.1.4",
                title="Ensure Images (AMI) are not older than 90 days",
                service="Amazon EC2",
                resource_id="N/A (No AMIs)",
                status="NOT_APPLICABLE",
                details="Không có AMI nào thuộc sở hữu của tài khoản.",
            )

        now = datetime.now(timezone.utc)
        old_amis = []
        valid_amis = []
        max_age_days = 0

        for img in images:
            ami_id = img["ImageId"]
            creation_str = img.get("CreationDate", "")
            creation_dt = datetime.fromisoformat(creation_str.replace("Z", "+00:00"))
            age_days = (now - creation_dt).days
            max_age_days = max(max_age_days, age_days)
            if age_days > 90:
                old_amis.append(f"{ami_id} ({age_days}d)")
            else:
                valid_amis.append(f"{ami_id} ({age_days}d)")

        if old_amis:
            return CheckResult(
                cis_id="2.1.4",
                title="Ensure Images (AMI) are not older than 90 days",
                service="Amazon EC2",
                resource_id=", ".join(old_amis),
                status="FAIL",
                details=f"Phát hiện AMI quá 90 ngày tuổi: {', '.join(old_amis)}",
            )

        return CheckResult(
            cis_id="2.1.4",
            title="Ensure Images (AMI) are not older than 90 days",
            service="Amazon EC2",
            resource_id=f"{len(valid_amis)} AMIs (max {max_age_days} days)",
            status="PASS",
            details=f"Tất cả {len(valid_amis)} AMI đều <= 90 ngày tuổi (tuổi tối đa: {max_age_days} ngày)",
        )
    except ClientError as e:
        return CheckResult(
            cis_id="2.1.4",
            title="Ensure Images (AMI) are not older than 90 days",
            service="Amazon EC2",
            resource_id="EC2-AMI",
            status="ERROR",
            details=str(e),
        )


# ==============================================================================
# CIS 2.2.1: Ensure EBS volume encryption is enabled
# ==============================================================================
def audit_cis_2_2_1(session: boto3.Session) -> CheckResult:
    ec2 = session.client("ec2")
    region = session.region_name or "ap-southeast-1"
    try:
        default_enc = ec2.get_ebs_encryption_by_default().get(
            "EbsEncryptionByDefault", False
        )
        volumes = ec2.describe_volumes().get("Volumes", [])
        unenc_vols = [v["VolumeId"] for v in volumes if not v.get("Encrypted", False)]

        if not default_enc or unenc_vols:
            reasons = []
            if not default_enc:
                reasons.append("EbsEncryptionByDefault=False")
            if unenc_vols:
                reasons.append(f"Volume chưa mã hóa: {', '.join(unenc_vols)}")
            return CheckResult(
                cis_id="2.2.1",
                title="Ensure EBS volume encryption is enabled",
                service="Amazon EC2",
                resource_id=f"Region {region} (EBS Default)",
                status="FAIL",
                details=f"Chưa bật mã hóa EBS mặc định: {'; '.join(reasons)}",
            )

        vol_ids = [v["VolumeId"] for v in volumes]
        return CheckResult(
            cis_id="2.2.1",
            title="Ensure EBS volume encryption is enabled",
            service="Amazon EC2",
            resource_id=f"Region {region} ({len(vol_ids)} volume)",
            status="PASS",
            details=f"EbsEncryptionByDefault=True và EBS Volume ({', '.join(vol_ids)}) có Encrypted=True",
        )
    except ClientError as e:
        return CheckResult(
            cis_id="2.2.1",
            title="Ensure EBS volume encryption is enabled",
            service="Amazon EC2",
            resource_id=f"Region {region}",
            status="ERROR",
            details=str(e),
        )


def remediate_cis_2_2_1(session: boto3.Session) -> str:
    ec2 = session.client("ec2")
    ec2.enable_ebs_encryption_by_default()
    return "Đã gọi ec2.enable_ebs_encryption_by_default() -> EbsEncryptionByDefault = True"


# ==============================================================================
# CIS 2.2.2: Ensure Public Access to EBS Snapshots is Disabled
# ==============================================================================
def audit_cis_2_2_2(session: boto3.Session) -> CheckResult:
    ec2 = session.client("ec2")
    region = session.region_name or "ap-southeast-1"
    try:
        bpa_state = ec2.get_snapshot_block_public_access_state().get(
            "State", "unblocked"
        )
        snapshots = ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
        public_snaps = []
        for snap in snapshots:
            sid = snap["SnapshotId"]
            perms = ec2.describe_snapshot_attribute(
                SnapshotId=sid, Attribute="createVolumePermission"
            ).get("CreateVolumePermissions", [])
            if any(p.get("Group") == "all" for p in perms):
                public_snaps.append(sid)

        if bpa_state not in ("block-all-sharing", "block-new-sharing") or public_snaps:
            return CheckResult(
                cis_id="2.2.2",
                title="Ensure Public Access to EBS Snapshots is Disabled",
                service="Amazon EC2",
                resource_id=f"Region {region} ({bpa_state})",
                status="FAIL",
                details=f"Snapshot Block Public Access đang ở trạng thái '{bpa_state}' (Public={len(public_snaps)})",
            )

        return CheckResult(
            cis_id="2.2.2",
            title="Ensure Public Access to EBS Snapshots is Disabled",
            service="Amazon EC2",
            resource_id=f"Region {region} (blocked)",
            status="PASS",
            details=f"Snapshot Block Public Access='{bpa_state}' và 0/{len(snapshots)} snapshot công khai",
        )
    except ClientError as e:
        return CheckResult(
            cis_id="2.2.2",
            title="Ensure Public Access to EBS Snapshots is Disabled",
            service="Amazon EC2",
            resource_id=f"Region {region}",
            status="ERROR",
            details=str(e),
        )


def remediate_cis_2_2_2(session: boto3.Session) -> str:
    ec2 = session.client("ec2")
    ec2.enable_snapshot_block_public_access(State="block-all-sharing")
    return "Đã gọi ec2.enable_snapshot_block_public_access(State='block-all-sharing')"


# ==============================================================================
# CIS 2.2.3: Ensure EBS volume snapshots are encrypted
# ==============================================================================
def audit_cis_2_2_3(session: boto3.Session) -> CheckResult:
    ec2 = session.client("ec2")
    try:
        snapshots = ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
        if not snapshots:
            return CheckResult(
                cis_id="2.2.3",
                title="Ensure EBS volume snapshots are encrypted",
                service="Amazon EC2",
                resource_id="N/A (No Snapshots)",
                status="NOT_APPLICABLE",
                details="Không có EBS Snapshot nào thuộc sở hữu của tài khoản.",
            )

        unenc_snaps = [
            s["SnapshotId"] for s in snapshots if not s.get("Encrypted", False)
        ]
        enc_snaps = [s["SnapshotId"] for s in snapshots if s.get("Encrypted", False)]

        if unenc_snaps:
            return CheckResult(
                cis_id="2.2.3",
                title="Ensure EBS volume snapshots are encrypted",
                service="Amazon EC2",
                resource_id=", ".join(unenc_snaps),
                status="FAIL",
                details=f"Phát hiện {len(unenc_snaps)} EBS Snapshot chưa được mã hóa: {', '.join(unenc_snaps)}",
            )

        return CheckResult(
            cis_id="2.2.3",
            title="Ensure EBS volume snapshots are encrypted",
            service="Amazon EC2",
            resource_id=f"{len(enc_snaps)} Snapshots ({enc_snaps[0]})",
            status="PASS",
            details=f"Tất cả {len(enc_snaps)} EBS Snapshot đều có Encrypted=True ({', '.join(enc_snaps)})",
        )
    except ClientError as e:
        return CheckResult(
            cis_id="2.2.3",
            title="Ensure EBS volume snapshots are encrypted",
            service="Amazon EC2",
            resource_id="EC2-Snapshots",
            status="ERROR",
            details=str(e),
        )


def run_ec2_audit(session: boto3.Session) -> List[CheckResult]:
    return [
        audit_cis_2_1_2(session),
        audit_cis_2_1_4(session),
        audit_cis_2_2_1(session),
        audit_cis_2_2_2(session),
        audit_cis_2_2_3(session),
    ]


def run_ec2_remediation(
    session: boto3.Session, audit_results: List[CheckResult]
) -> Dict[str, str]:
    actions = {}
    for r in audit_results:
        if r.status != "FAIL":
            continue
        if r.cis_id == "2.2.1":
            actions["2.2.1"] = remediate_cis_2_2_1(session)
        elif r.cis_id == "2.2.2":
            actions["2.2.2"] = remediate_cis_2_2_2(session)
    return actions
