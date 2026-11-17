# =====================================================================
# ECR - phục vụ Manual 18.4
#   computebench-leaky   : policy Principal "*" không Condition -> FAIL
#   computebench-private : policy chỉ cho account của tổ chức  -> PASS
# =====================================================================

resource "aws_ecr_repository" "leaky" {
  name         = "${var.project}-leaky"
  force_delete = true

  tags = {
    CisControls = "18.4"
    Expected    = "FAIL"
  }
}

resource "aws_ecr_repository_policy" "leaky" {
  repository = aws_ecr_repository.leaky.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicPull"
      Effect    = "Allow"
      Principal = "*"
      Action = [
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchCheckLayerAvailability",
      ]
    }]
  })
}

resource "aws_ecr_repository" "private" {
  name         = "${var.project}-private"
  force_delete = true

  tags = {
    CisControls = "18.4"
    Expected    = "PASS"
  }
}

resource "aws_ecr_repository_policy" "private" {
  repository = aws_ecr_repository.private.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OrgAccountPull"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action = [
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchCheckLayerAvailability",
      ]
    }]
  })
}
