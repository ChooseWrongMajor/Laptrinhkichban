# Hạ tầng Amazon ECS & AWS Fargate kiểm thử các tiêu chí CIS Benchmark:
# Manual: 3.16
# Automated: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13, 3.14 và 11.1

# 1. CloudWatch Log Group lưu trữ nhật ký kiểm toán ECS Exec (CIS 3.16) và Container Logs (CIS 3.7)
resource "aws_cloudwatch_log_group" "ecs_exec_audit_logs" {
  name              = "/ecs/exec-audit-logs"
  retention_in_days = 365

  tags = {
    Name        = "ecs-exec-audit-logs"
    Project     = var.project_name
    Environment = var.environment
  }
}

# 2. Customer-Managed KMS Key để mã hóa dữ liệu Ephemeral Storage của AWS Fargate (CIS 11.1)
resource "aws_kms_key" "fargate_ephemeral_kms" {
  description             = "CIS 11.1 Customer Managed Key for AWS Fargate Ephemeral Storage"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name        = "${var.project_name}-fargate-kms"
    Project     = var.project_name
    Environment = var.environment
  }
}

# 3. ECS Cluster cấu hình đạt chuẩn CIS 3.9 (Container Insights), CIS 3.11 (Cluster Tagged),
# CIS 3.16 (ECS Exec Audit Logging), và CIS 11.1 (Fargate Ephemeral Storage CMK Encryption)
resource "aws_ecs_cluster" "cis_ecs_cluster" {
  name = "${var.project_name}-cluster"

  # CIS 3.9: Ensure monitoring is enabled for Amazon ECS clusters
  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  configuration {
    # CIS 3.16: Ensure ECS Exec sessions have audit logging enabled
    execute_command_configuration {
      logging = "OVERRIDE"

      log_configuration {
        cloud_watch_encryption_enabled = false
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.ecs_exec_audit_logs.name
      }
    }

    # CIS 11.1: Ensure customer-managed keys are used to encrypt AWS Fargate ephemeral storage data
    managed_storage_configuration {
      fargate_ephemeral_storage_kms_key_id = aws_kms_key.fargate_ephemeral_kms.arn
    }
  }

  # CIS 3.11: Ensure Amazon ECS clusters are tagged
  tags = {
    Name        = "${var.project_name}-cluster"
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform-CIS-Benchmark"
  }
}

# 4. IAM Task Execution Role cho ECS Task Definition
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.project_name}-ecs-task-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-ecs-task-exec-role"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# 5. ECS Task Definition đạt chuẩn CIS 3.1, 3.3, 3.4, 3.5, 3.6, 3.7, 3.12, 3.13
resource "aws_ecs_task_definition" "cis_compliant_task" {
  family                   = "${var.project_name}-task"
  network_mode             = "awsvpc" # CIS 3.1: Không dùng host network mode với quyền root/privileged
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  pid_mode                 = "task"   # CIS 3.3: Không đặt pidMode = "host"

  container_definitions = jsonencode([
    {
      name                   = "app-container"
      # CIS 3.13: Chỉ sử dụng container image từ kho ECR nội bộ đáng tin cậy (Trusted Registry)
      image                  = "${aws_ecr_repository.private_repo.repository_url}:latest"
      essential              = true
      user                   = "1000:1000" # CIS 3.1: Không chạy bằng root
      privileged             = false       # CIS 3.4: Không bật privileged = true
      readonlyRootFilesystem = true        # CIS 3.5: Bật readonlyRootFilesystem = true
      # CIS 3.6: Không truyền secret trực tiếp qua biến môi trường (environment)
      environment = [
        {
          name  = "APP_ENV"
          value = "production"
        }
      ]
      # CIS 3.7: Cấu hình logging cho container trong Task Definition
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_exec_audit_logs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs-app"
        }
      }
    }
  ])

  # CIS 3.12: Ensure Amazon ECS task definitions are tagged
  tags = {
    Name        = "${var.project_name}-task"
    Project     = var.project_name
    Environment = var.environment
  }
}

# 6. ECS Service đạt chuẩn CIS 3.2 (assignPublicIp = DISABLED), CIS 3.8 (platform_version = LATEST),
# và CIS 3.10 (ECS Service Tagged)
resource "aws_ecs_service" "cis_compliant_service" {
  name             = "${var.project_name}-service"
  cluster          = aws_ecs_cluster.cis_ecs_cluster.id
  task_definition  = aws_ecs_task_definition.cis_compliant_task.arn
  desired_count    = 0 # Đặt = 0 để kiểm thử cấu hình mà không phát sinh chi phí chạy Fargate Task
  launch_type      = "FARGATE"
  platform_version = "LATEST" # CIS 3.8: Sử dụng phiên bản nền tảng Fargate mới nhất

  network_configuration {
    subnets          = [data.aws_subnet.existing_subnet.id]
    security_groups  = [var.existing_custom_sg_id]
    assign_public_ip = false # CIS 3.2: assignPublicIp = DISABLED
  }

  # CIS 3.10: Ensure Amazon ECS services are tagged
  tags = {
    Name        = "${var.project_name}-service"
    Project     = var.project_name
    Environment = var.environment
  }
}
