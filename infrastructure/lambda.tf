# =====================================================================
# Lambda - phục vụ Automated 12.16 và Manual 12.8, 12.10
#
#   Function               | 12.16 URL auth | 12.8 code signing | 12.10 cross-account
#   computebench-public-fn | FAIL (NONE)    | FAIL (không có)   | FAIL (account lạ)
#   computebench-secure-fn | PASS (AWS_IAM) | PASS (Enforce)    | PASS (chính account)
# =====================================================================

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda_src/handler.py"
  output_path = "${path.module}/build/lambda.zip"
}

resource "aws_iam_role" "lambda" {
  name = "${local.name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ---------------------------------------------------------------------
# Function cấu hình sai: deploy zip trực tiếp, không ký code
# ---------------------------------------------------------------------
resource "aws_lambda_function" "public" {
  function_name    = "${var.project}-public-fn"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  tags = {
    CisControls = "12.8 12.10 12.16"
    Expected    = "FAIL"
  }
}

# CIS 12.16 FAIL: Function URL không yêu cầu xác thực.
# Provider tự thêm statement "FunctionURLAllowPublicAccess" (lambda:InvokeFunctionUrl
# cho Principal "*"), nhưng AWS còn yêu cầu quyền lambda:InvokeFunction nên URL
# thực tế vẫn trả 403.
resource "aws_lambda_function_url" "public" {
  function_name      = aws_lambda_function.public.function_name
  authorization_type = "NONE"
}

# CIS 12.10 FAIL: cho phép tài nguyên thuộc account ngoài tổ chức invoke function.
# Lambda từ chối principal là account không tồn tại (vd 111122223333), nên dùng
# service principal kèm SourceAccount/SourceArn của account lạ: S3 bucket của
# account đó được quyền kích hoạt function -> cross-account access không được phê duyệt.
resource "aws_lambda_permission" "public_cross_account" {
  statement_id   = "AllowUnknownAccountInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.public.function_name
  principal      = "s3.amazonaws.com"
  source_account = var.untrusted_account_id
  source_arn     = "arn:aws:s3:::partner-uploads-${var.untrusted_account_id}"
}

# ---------------------------------------------------------------------
# Function cấu hình đúng: code được ký bằng AWS Signer, CSC = Enforce
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "lambda_artifacts" {
  bucket_prefix = "${var.project}-lambda-artifacts-"
  force_destroy = true
}

# Signer yêu cầu bucket nguồn bật versioning
resource "aws_s3_bucket_versioning" "lambda_artifacts" {
  bucket = aws_s3_bucket.lambda_artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "lambda_unsigned" {
  bucket      = aws_s3_bucket.lambda_artifacts.id
  key         = "unsigned/lambda.zip"
  source      = data.archive_file.lambda.output_path
  source_hash = data.archive_file.lambda.output_base64sha256

  depends_on = [aws_s3_bucket_versioning.lambda_artifacts]
}

# Tên signing profile chỉ cho phép chữ, số và "_"
resource "aws_signer_signing_profile" "lambda" {
  platform_id = "AWSLambda-SHA384-ECDSA"
  name_prefix = "${var.project}_${var.environment}_"
}

resource "aws_signer_signing_job" "lambda" {
  profile_name = aws_signer_signing_profile.lambda.name

  source {
    s3 {
      bucket  = aws_s3_bucket.lambda_artifacts.id
      key     = aws_s3_object.lambda_unsigned.key
      version = aws_s3_object.lambda_unsigned.version_id
    }
  }

  destination {
    s3 {
      bucket = aws_s3_bucket.lambda_artifacts.id
      prefix = "signed/"
    }
  }

  ignore_signing_job_failure = false
}

resource "aws_lambda_code_signing_config" "enforce" {
  description = "Only allow code signed by the lab signing profile"

  allowed_publishers {
    signing_profile_version_arns = [aws_signer_signing_profile.lambda.version_arn]
  }

  policies {
    untrusted_artifact_on_deployment = "Enforce"
  }
}

resource "aws_lambda_function" "secure" {
  function_name           = "${var.project}-secure-fn"
  role                    = aws_iam_role.lambda.arn
  runtime                 = "python3.12"
  handler                 = "handler.lambda_handler"
  s3_bucket               = aws_s3_bucket.lambda_artifacts.id
  s3_key                  = aws_signer_signing_job.lambda.signed_object[0].s3[0].key
  code_signing_config_arn = aws_lambda_code_signing_config.enforce.arn

  tags = {
    CisControls = "12.8 12.10 12.16"
    Expected    = "PASS"
  }
}

# CIS 12.16 PASS
resource "aws_lambda_function_url" "secure" {
  function_name      = aws_lambda_function.secure.function_name
  authorization_type = "AWS_IAM"
}

# CIS 12.10 PASS: chỉ account của tổ chức được invoke
resource "aws_lambda_permission" "secure_same_account" {
  statement_id  = "AllowOwnAccountInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.secure.function_name
  principal     = "arn:aws:iam::${local.account_id}:root" # AWS lưu dạng ARN, khai báo đúng dạng để không bị replace mỗi lần apply
}
