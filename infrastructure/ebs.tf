# =====================================================================
# EBS - phục vụ Automated 2.2.1, 2.2.2, 2.2.3
#
# 2.2.1 (EBS encryption by default) là cài đặt cấp account/region nên
# KHÔNG quản lý bằng Terraform. Lab yêu cầu cài đặt này đang TẮT (FAIL),
# remediation sẽ bật nó lên. Xem README.
#
#   Snapshot                 | 2.2.2 public | 2.2.3 mã hóa
#   snap-plain (public)      | FAIL         | FAIL
#   snap-encrypted (private) | PASS         | PASS
# =====================================================================

resource "aws_ebs_volume" "plain" {
  availability_zone = local.azs[0]
  size              = 1
  type              = "gp3"
  encrypted         = false

  tags = {
    Name = "${local.name}-vol-plain"
  }
}

resource "aws_ebs_volume" "encrypted" {
  availability_zone = local.azs[0]
  size              = 1
  type              = "gp3"
  encrypted         = true

  tags = {
    Name = "${local.name}-vol-encrypted"
  }
}

resource "aws_ebs_snapshot" "plain" {
  volume_id   = aws_ebs_volume.plain.id
  description = "Unencrypted snapshot shared publicly (CIS 2.2.2, 2.2.3 FAIL)"

  tags = {
    Name        = "${local.name}-snap-plain"
    CisControls = "2.2.2 2.2.3"
    Expected    = "FAIL"
  }
}

resource "aws_ebs_snapshot" "encrypted" {
  volume_id   = aws_ebs_volume.encrypted.id
  description = "Encrypted private snapshot (CIS 2.2.2, 2.2.3 PASS)"

  tags = {
    Name        = "${local.name}-snap-encrypted"
    CisControls = "2.2.2 2.2.3"
    Expected    = "PASS"
  }
}

# CIS 2.2.2 FAIL: chia sẻ snapshot cho group "all" (public).
# Provider không hỗ trợ group "all" nên dùng AWS CLI. Snapshot là volume
# 1 GiB rỗng, không chứa dữ liệu.
resource "terraform_data" "make_snapshot_public" {
  triggers_replace = [aws_ebs_snapshot.plain.id]

  provisioner "local-exec" {
    command = "aws ec2 modify-snapshot-attribute --region ${local.region} --snapshot-id ${aws_ebs_snapshot.plain.id} --attribute createVolumePermission --operation-type add --group-names all"
  }
}
