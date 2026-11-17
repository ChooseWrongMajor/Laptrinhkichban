# Hạ tầng kiểm thử CIS 2.1.2 (Ensure AMIs are encrypted), CIS 2.1.4 (AMI age <= 90 days),
# CIS 2.2.1 (EBS encryption by default), CIS 2.2.2 (Block public access to EBS snapshots),
# và CIS 2.2.3 (Ensure EBS volume snapshots are encrypted)

# CIS 2.2.1: Bật mã hóa mặc định cho tất cả EBS Volume tạo mới trong Region
resource "aws_ebs_encryption_by_default" "cis_2_2_1" {
  enabled = true
}

# CIS 2.2.2: Chặn chia sẻ công khai toàn bộ EBS Snapshot trong Region
resource "aws_ebs_snapshot_block_public_access" "cis_2_2_2" {
  state = "block-all-sharing"
}

# CIS 2.1.2 & 2.1.4 & 2.2.3: Tạo bản sao AMI được mã hóa (Encrypted = true) từ AMI hiện có
data "aws_ami" "existing_org_ami" {
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = ["sportmate-test-v1.0.0"]
  }
}
