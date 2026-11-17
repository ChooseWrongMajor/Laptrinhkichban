# =====================================================================
# AWS Batch - phục vụ Manual 8.2 (confused deputy)
#   ce-unsafe : service role trust batch.amazonaws.com không Condition   -> FAIL
#   ce-safe   : trust policy có aws:SourceArn = ARN đầy đủ của compute env -> PASS
# Compute environment FARGATE không chạy job thì không tốn phí.
# =====================================================================

locals {
  batch_ce_names = {
    unsafe = "${local.name}-ce-unsafe"
    safe   = "${local.name}-ce-safe"
  }
}

resource "aws_iam_role" "batch_unsafe" {
  name = "${local.name}-batch-service-unsafe"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "batch.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    CisControls = "8.2"
    Expected    = "FAIL"
  }
}

resource "aws_iam_role" "batch_safe" {
  name = "${local.name}-batch-service-safe"

  # ARN được dựng từ tên nên không tạo vòng phụ thuộc với compute environment
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "batch.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = local.account_id
        }
        ArnLike = {
          "aws:SourceArn" = "arn:aws:batch:${local.region}:${local.account_id}:compute-environment/${local.batch_ce_names.safe}"
        }
      }
    }]
  })

  tags = {
    CisControls = "8.2"
    Expected    = "PASS"
  }
}

resource "aws_iam_role_policy_attachment" "batch" {
  for_each = {
    unsafe = aws_iam_role.batch_unsafe.name
    safe   = aws_iam_role.batch_safe.name
  }

  role       = each.value
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"
}

resource "aws_batch_compute_environment" "unsafe" {
  compute_environment_name = local.batch_ce_names.unsafe
  type                     = "MANAGED"
  service_role             = aws_iam_role.batch_unsafe.arn

  compute_resources {
    type               = "FARGATE"
    max_vcpus          = 2
    subnets            = aws_subnet.public[*].id
    security_group_ids = [aws_security_group.workload.id]
  }

  depends_on = [aws_iam_role_policy_attachment.batch]
}

resource "aws_batch_compute_environment" "safe" {
  compute_environment_name = local.batch_ce_names.safe
  type                     = "MANAGED"
  service_role             = aws_iam_role.batch_safe.arn

  compute_resources {
    type               = "FARGATE"
    max_vcpus          = 2
    subnets            = aws_subnet.public[*].id
    security_group_ids = [aws_security_group.workload.id]
  }

  depends_on = [aws_iam_role_policy_attachment.batch]
}
