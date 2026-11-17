# Hạ tầng Amazon ECR kiểm thử tiêu chí CIS 18.4 (Trang 243-245 tài liệu CIS)

data "aws_caller_identity" "ecr_current" {}

resource "aws_ecr_repository" "private_repo" {
  name                 = "${var.project_name}-private-repo"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name        = "${var.project_name}-private-repo"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Resource Policy chuẩn CIS 18.4: Chỉ cho phép tài khoản AWS nội bộ được phê duyệt, không mở Principal = "*"
# (Nếu muốn test trạng thái FAIL: đặt Principal = "*" và không có Condition giới hạn)
resource "aws_ecr_repository_policy" "private_repo_policy" {
  repository = aws_ecr_repository.private_repo.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowOnlyTrustedInternalAccount"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.ecr_current.account_id}:root"
        }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability"
        ]
      }
    ]
  })
}
