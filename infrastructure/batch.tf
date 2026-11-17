# Hạ tầng AWS Batch IAM Role kiểm thử tiêu chí CIS 8.2 (Trang 165-167 tài liệu CIS)

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "batch_service_role" {
  name = "${var.project_name}-batch-service-role"

  # Cấu hình Trust Policy chống lỗ hổng Cross-Service Confused Deputy theo chuẩn CIS 8.2 (Trang 166)
  # (Nếu muốn test trạng thái FAIL: bỏ khối Condition hoặc đặt aws:SourceArn chứa dấu '*')
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "batch.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnLike = {
            "aws:SourceArn" = [
              "arn:aws:batch:${var.aws_region}:${data.aws_caller_identity.current.account_id}:compute-environment/testCE"
            ]
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-batch-service-role"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "batch_service_role_policy" {
  role       = aws_iam_role.batch_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
}
