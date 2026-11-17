# =====================================================================
# AMI - phục vụ Manual 2.1.1 và Automated 2.1.2, 2.1.4
# Quy ước đặt tên của nhóm: <project>-<environment>-<version>
#
#   AMI                         | 2.1.1 tên | 2.1.2 mã hóa | 2.1.4 tuổi
#   computebench-dev-v1.0.0     | PASS      | FAIL         | PASS
#   computebench-dev-v1.0.1     | PASS      | PASS         | PASS
#   my-test-image               | FAIL      | FAIL         | PASS
# =====================================================================

resource "aws_ami_from_instance" "base_unencrypted" {
  name                    = "${local.name}-v1.0.0"
  source_instance_id      = aws_instance.hardened.id
  snapshot_without_reboot = true

  tags = {
    Name        = "${local.name}-v1.0.0"
    CisControls = "2.1.1 2.1.2 2.1.4"
    Expected    = "2.1.2=FAIL"
  }
}

# Bản copy có mã hóa EBS snapshot (KMS key mặc định aws/ebs)
resource "aws_ami_copy" "base_encrypted" {
  name              = "${local.name}-v1.0.1"
  source_ami_id     = aws_ami_from_instance.base_unencrypted.id
  source_ami_region = local.region
  encrypted         = true

  tags = {
    Name        = "${local.name}-v1.0.1"
    CisControls = "2.1.1 2.1.2 2.1.4"
    Expected    = "PASS"
  }
}

# Tên không theo quy ước, không mã hóa
resource "aws_ami_from_instance" "bad_name" {
  name                    = "my-test-image"
  source_instance_id      = aws_instance.legacy.id
  snapshot_without_reboot = true

  tags = {
    Name        = "my-test-image"
    CisControls = "2.1.1 2.1.2 2.1.4"
    Expected    = "2.1.1=FAIL 2.1.2=FAIL"
  }
}
