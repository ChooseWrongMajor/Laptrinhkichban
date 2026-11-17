# Hạ tầng AWS App Runner VPC Endpoint kiểm thử tiêu chí CIS 6.1 (Trang 159-160 tài liệu CIS)

resource "aws_vpc_endpoint" "apprunner" {
  vpc_id              = data.aws_vpc.existing_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.apprunner"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [data.aws_subnet.existing_subnet.id]
  security_group_ids  = [var.existing_custom_sg_id]
  private_dns_enabled = true

  tags = {
    Name        = "${var.project_name}-apprunner-vpce"
    Project     = var.project_name
    Environment = var.environment
  }
}
