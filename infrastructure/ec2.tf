# Lấy AMI Amazon Linux 2023 mới nhất (trang 18 báo cáo)
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# IAM Role và Instance Profile phục vụ AWS Systems Manager (CIS 2.9 - Trang 63 tài liệu CIS)
resource "aws_iam_role" "ssm_ec2_role" {
  name = "${var.project_name}-ssm-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-ssm-ec2-role"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "ssm_managed_instance_core" {
  role       = aws_iam_role.ssm_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = "${var.project_name}-ssm-instance-profile"
  role = aws_iam_role.ssm_ec2_role.name
}

# EC2 Instance cố tình gắn Default Security Group (vi phạm CIS 2.7),
# cấu hình IMDSv2 là optional (vi phạm CIS 2.8),
# và không gắn iam_instance_profile (vi phạm CIS 2.9)
resource "aws_instance" "my_ec2_non_compliant_2_7" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t2.micro"
  subnet_id                   = data.aws_subnet.existing_subnet.id
  vpc_security_group_ids      = [var.existing_default_sg_id]
  associate_public_ip_address = true

  # Để đạt chuẩn CIS 2.9: bỏ comment dòng dưới để gắn IAM Instance Profile cho Systems Manager
  # iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name

  # Cố tình để http_tokens = "optional" (cho phép IMDSv1 -> vi phạm CIS 2.8)
  # Để đạt chuẩn CIS 2.8: cần đổi thành http_tokens = "required"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
  }

  # Cố tình nhúng thông tin nhạy cảm trực tiếp trong User Data (vi phạm CIS 2.13)
  # Để đạt chuẩn CIS 2.13: không lưu trực tiếp password/key mà lấy từ AWS Secrets Manager / SSM Parameter Store
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="SuperSecretPassword123!"
    export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    echo "Initializing application..."
  EOF

  tags = {
    Name        = "my-terraform-ec2-cis-2-7-2-8-2-9-2-13-fail"
    Project     = var.project_name
    Environment = var.environment
  }
}

