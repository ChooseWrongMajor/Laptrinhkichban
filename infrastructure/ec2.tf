# =====================================================================
# EC2 - phục vụ Manual 2.7, 2.8, 2.9, 2.13 và Automated 2.14
#   ec2-legacy   : cấu hình SAI có chủ đích  -> FAIL
#   ec2-hardened : cấu hình ĐÚNG             -> PASS (đối chứng)
# =====================================================================

# --- IAM instance profile cho SSM (CIS 2.9) ---
resource "aws_iam_role" "ec2_ssm" {
  name = "${local.name}-ec2-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_ssm_core" {
  role       = aws_iam_role.ec2_ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_ssm" {
  name = "${local.name}-ec2-ssm-profile"
  role = aws_iam_role.ec2_ssm.name
}

# --- Instance cấu hình sai ---
resource "aws_instance" "legacy" {
  ami           = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type
  subnet_id     = aws_subnet.public[0].id

  # CIS 2.7 FAIL: dùng Security Group mặc định của VPC
  vpc_security_group_ids = [aws_vpc.main.default_security_group_id]

  # CIS 2.9 FAIL: không có instance profile -> không được SSM quản lý

  # CIS 2.8 FAIL: cho phép IMDSv1
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  # CIS 2.13 FAIL: secret nằm trực tiếp trong user data (giá trị giả lập)
  user_data = <<-EOF
    #!/bin/bash
    export DB_HOST="db.internal.computebench.local"
    export DB_USER="admin"
    export DB_PASSWORD="Lab-Fake-Passw0rd-2026"
    export API_TOKEN="lab-demo-token-not-real-123456"
    echo "app configured" > /tmp/app.log
  EOF

  # Root volume không mã hóa -> AMI tạo ra sẽ FAIL CIS 2.1.2
  root_block_device {
    volume_type = "gp3"
    encrypted   = false
  }

  tags = {
    Name        = "${local.name}-ec2-legacy"
    CisControls = "2.7 2.8 2.9 2.13"
    Expected    = "FAIL"
  }
}

# --- Instance cấu hình đúng ---
resource "aws_instance" "hardened" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.workload.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_ssm.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # Không chứa secret, chỉ lấy tham số từ Parameter Store khi cần
  user_data = <<-EOF
    #!/bin/bash
    echo "app configured, secrets loaded from SSM Parameter Store at runtime" > /tmp/app.log
  EOF

  root_block_device {
    volume_type = "gp3"
    encrypted   = false # giữ không mã hóa để AMI gốc FAIL 2.1.2, bản copy mã hóa sẽ PASS
  }

  tags = {
    Name        = "${local.name}-ec2-hardened"
    CisControls = "2.7 2.8 2.9 2.13"
    Expected    = "PASS"
  }
}

# =====================================================================
# Auto Scaling Group - CIS 2.14 (Automated) -> PASS
# desired_capacity = 0 nên không phát sinh instance/chi phí
# =====================================================================
resource "aws_launch_template" "app" {
  name_prefix   = "${local.name}-lt-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type

  vpc_security_group_ids = [aws_security_group.workload.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_ssm.name
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}

resource "aws_autoscaling_group" "app" {
  name                = "${local.name}-asg"
  min_size            = 0
  max_size            = 1
  desired_capacity    = 0
  vpc_zone_identifier = aws_subnet.public[*].id

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  # CIS 2.14 PASS: mọi tag đều propagate xuống instance
  tag {
    key                 = "Name"
    value               = "${local.name}-asg-instance"
    propagate_at_launch = true
  }

  tag {
    key                 = "Project"
    value               = var.project
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }

  tag {
    key                 = "CisControls"
    value               = "2.14"
    propagate_at_launch = true
  }
}
