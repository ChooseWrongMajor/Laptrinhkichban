# Sử dụng hạ tầng VPC và Subnet đã có sẵn trên AWS Account (206489185820)
# để tương thích với quyền của IAM User cis-benchmark-ansible (không cần quyền ec2:CreateVpc)

data "aws_vpc" "existing_vpc" {
  id = var.existing_vpc_id
}

data "aws_subnet" "existing_subnet" {
  id = var.existing_subnet_id
}
