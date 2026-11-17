# =====================================================================
# App Runner - phục vụ Manual 6.1 (VPC endpoint cho App Runner)
# Mặc định không tạo endpoint -> FAIL.
# Đặt enable_apprunner_vpc_endpoint = true để tạo endpoint -> PASS.
# Interface endpoint tính phí theo giờ cho mỗi AZ, nên chỉ bật khi demo.
# =====================================================================

data "aws_vpc_endpoint_service" "apprunner" {
  count   = var.enable_apprunner_vpc_endpoint ? 1 : 0
  service = "apprunner"
}

locals {
  # Chỉ đặt endpoint ở các subnet có AZ mà dịch vụ hỗ trợ
  apprunner_subnet_ids = var.enable_apprunner_vpc_endpoint ? [
    for s in aws_subnet.public : s.id
    if contains(data.aws_vpc_endpoint_service.apprunner[0].availability_zones, s.availability_zone)
  ] : []
}

resource "aws_security_group" "apprunner_endpoint" {
  count = var.enable_apprunner_vpc_endpoint ? 1 : 0

  name        = "${local.name}-apprunner-endpoint-sg"
  description = "HTTPS from inside the VPC to the App Runner endpoint"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }
}

resource "aws_vpc_endpoint" "apprunner" {
  count = var.enable_apprunner_vpc_endpoint ? 1 : 0

  vpc_id              = aws_vpc.main.id
  service_name        = data.aws_vpc_endpoint_service.apprunner[0].service_name
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.apprunner_subnet_ids
  security_group_ids  = [aws_security_group.apprunner_endpoint[0].id]
  private_dns_enabled = true

  tags = {
    Name        = "${local.name}-apprunner-endpoint"
    CisControls = "6.1"
    Expected    = "PASS"
  }
}
