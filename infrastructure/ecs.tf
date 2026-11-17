# =====================================================================
# ECS - phục vụ Automated 3.2 - 3.7, 3.9, 3.11 và Manual 3.16
#
#   Task definition     | 3.3 pid | 3.4 priv | 3.5 rofs | 3.6 secret | 3.7 log
#   computebench-web    | PASS    | PASS     | FAIL     | PASS       | PASS
#   computebench-worker | PASS    | FAIL     | PASS     | PASS       | PASS
#
#   Service             | 3.2 assignPublicIp | 3.16 exec logging
#   web-public-svc      | FAIL (ENABLED)     | exec bật, cluster DEFAULT -> FAIL
#   web-private-svc     | PASS (DISABLED)    | exec tắt
#
#   Cluster: 3.9 Container Insights PASS, 3.11 tagged PASS
# Mọi service để desired_count = 0 nên không có task chạy, không tốn phí.
# =====================================================================

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${local.name}"
  retention_in_days = 7
}

resource "aws_ecs_cluster" "main" {
  name = "${local.name}-cluster"

  # CIS 3.9 PASS
  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  # CIS 3.16 FAIL: ECS Exec logging = DEFAULT (không có đích audit riêng)
  configuration {
    execute_command_configuration {
      logging = "DEFAULT"
    }
  }

  # CIS 3.11 PASS: có tag do người dùng đặt (ngoài default_tags)
  tags = {
    Name        = "${local.name}-cluster"
    Owner       = "nhom04"
    CisControls = "3.9 3.11 3.16"
  }
}

# --- Secret đúng cách cho CIS 3.6: lưu ở Parameter Store, inject qua "secrets" ---
resource "aws_ssm_parameter" "db_password" {
  name  = "/${var.project}/${var.environment}/db_password"
  type  = "SecureString"
  value = "lab-demo-secret-${random_id.db_password.hex}"
}

resource "random_id" "db_password" {
  byte_length = 8
}

# --- IAM roles cho ECS ---
data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_execution" {
  name               = "${local.name}-ecs-execution-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_execution_ssm" {
  name = "read-db-password"
  role = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ssm:GetParameters"]
      Resource = aws_ssm_parameter.db_password.arn
    }]
  })
}

# Task role cần quyền ssmmessages để ECS Exec hoạt động
resource "aws_iam_role" "ecs_task" {
  name               = "${local.name}-ecs-task-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy" "ecs_task_exec" {
  name = "ecs-exec"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel",
      ]
      Resource = "*"
    }]
  })
}

# --- Task definition 1: Fargate web ---
resource "aws_ecs_task_definition" "web" {
  family                   = "${var.project}-web"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([{
    name      = "web"
    image     = "public.ecr.aws/nginx/nginx:stable"
    essential = true

    portMappings = [{ containerPort = 80, protocol = "tcp" }]

    # CIS 3.5 FAIL: root filesystem cho phép ghi
    readonlyRootFilesystem = false

    # CIS 3.6 PASS: env không chứa AWS_ACCESS_KEY_ID/SECRET, secret lấy từ SSM
    environment = [
      { name = "APP_ENV", value = var.environment },
    ]
    secrets = [
      { name = "DB_PASSWORD", valueFrom = aws_ssm_parameter.db_password.arn },
    ]

    # CIS 3.7 PASS
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.ecs.name
        awslogs-region        = local.region
        awslogs-stream-prefix = "web"
      }
    }
  }])

  tags = {
    CisControls = "3.3 3.4 3.5 3.6 3.7"
    Expected    = "3.5=FAIL"
  }
}

# --- Task definition 2: EC2 worker (privileged chỉ hỗ trợ trên EC2 launch type) ---
resource "aws_ecs_task_definition" "worker" {
  family                   = "${var.project}-worker"
  requires_compatibilities = ["EC2"]
  network_mode             = "bridge"
  execution_role_arn       = aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([{
    name      = "worker"
    image     = "public.ecr.aws/docker/library/busybox:stable"
    essential = true
    memory    = 128
    command   = ["sh", "-c", "while true; do echo working; sleep 60; done"]

    # CIS 3.4 FAIL
    privileged = true

    # CIS 3.5 PASS
    readonlyRootFilesystem = true

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.ecs.name
        awslogs-region        = local.region
        awslogs-stream-prefix = "worker"
      }
    }
  }])

  tags = {
    CisControls = "3.3 3.4 3.5 3.6 3.7"
    Expected    = "3.4=FAIL"
  }
}

# --- Services ---
resource "aws_ecs_service" "web_public" {
  name                   = "web-public-svc"
  cluster                = aws_ecs_cluster.main.id
  task_definition        = aws_ecs_task_definition.web.arn
  launch_type            = "FARGATE"
  platform_version       = "LATEST"
  desired_count          = 0
  enable_execute_command = true # CIS 3.16: Exec bật trên cluster logging DEFAULT
  propagate_tags         = "SERVICE"

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.workload.id]
    assign_public_ip = true # CIS 3.2 FAIL
  }

  tags = {
    CisControls = "3.2 3.16"
    Expected    = "FAIL"
  }
}

resource "aws_ecs_service" "web_private" {
  name             = "web-private-svc"
  cluster          = aws_ecs_cluster.main.id
  task_definition  = aws_ecs_task_definition.web.arn
  launch_type      = "FARGATE"
  platform_version = "LATEST"
  desired_count    = 0
  propagate_tags   = "SERVICE"

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.workload.id]
    assign_public_ip = false # CIS 3.2 PASS
  }

  tags = {
    CisControls = "3.2"
    Expected    = "PASS"
  }
}
