# Hạ tầng AWS Lambda kiểm thử các tiêu chí CIS 12.8, 12.10, 12.16

# 1. IAM Execution Role cho Lambda Function
resource "aws_iam_role" "lambda_exec_role" {
  name = "${var.project_name}-lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-lambda-exec-role"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# 2. AWS Signer Signing Profile & Lambda Code Signing Config (CIS 12.8 - Trang 200-203 tài liệu CIS)
resource "aws_signer_signing_profile" "lambda_signing_profile" {
  name_prefix = "cis128lambda"
  platform_id = "AWSLambda-SHA384-ECDSA"

  signature_validity_period {
    value = 12
    type  = "MONTHS"
  }

  tags = {
    Name        = "${var.project_name}-signing-profile"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_lambda_code_signing_config" "lambda_csc" {
  description = "CIS 12.8 Code Signing Config for Lambda functions"

  allowed_publishers {
    signing_profile_version_arns = [
      aws_signer_signing_profile.lambda_signing_profile.version_arn
    ]
  }

  policies {
    # Theo CIS 12.8 (Trang 200-201): bắt buộc đặt là Enforce (nếu là Warn sẽ bị tính là FAIL)
    untrusted_artifact_on_deployment = "Enforce"
  }

  tags = {
    Name        = "${var.project_name}-csc"
    Project     = var.project_name
    Environment = var.environment
  }
}

# 3. Lambda Function & Resource-based Permission Policy (CIS 12.10 - Trang 207-208 tài liệu CIS)
data "aws_caller_identity" "lambda_current" {}

# Quyền truy cập hợp lệ chỉ cấp cho chính AWS Account được phê duyệt (CIS 12.10)
# (Nếu muốn test trạng thái FAIL: đặt principal = "*" hoặc một AWS Account ID lạ "111122223333")
resource "aws_lambda_permission" "allow_trusted_account" {
  statement_id  = "AllowTrustedOrganizationAccount"
  action        = "lambda:InvokeFunction"
  function_name = "cis-compute-benchmark-lambda"
  principal     = data.aws_caller_identity.lambda_current.account_id
}

# 4. Lambda Function URL với cơ chế xác thực AWS_IAM (CIS 12.16 - Automated)
# (Nếu muốn test trạng thái FAIL: đặt authorization_type = "NONE")
resource "aws_lambda_function_url" "cis_12_16_url" {
  function_name      = "cis-compute-benchmark-lambda"
  authorization_type = "AWS_IAM"
}


