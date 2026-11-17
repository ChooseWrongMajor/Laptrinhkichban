variable "aws_region" {
  description = "AWS Region triển khai hạ tầng kiểm thử CIS Benchmark"
  type        = string
  default     = "ap-southeast-1"
}

variable "project_name" {
  description = "Tên dự án dùng để đặt tag"
  type        = string
  default     = "cis-compute-benchmark"
}

variable "environment" {
  description = "Môi trường triển khai (dev/test/prod)"
  type        = string
  default     = "test"
}

variable "existing_vpc_id" {
  description = "ID của VPC có sẵn trên AWS Account"
  type        = string
  default     = "vpc-05f31dd1b38d6f1b9"
}

variable "existing_subnet_id" {
  description = "ID của Subnet có sẵn trong VPC"
  type        = string
  default     = "subnet-05560be0f1e0a1afc"
}

variable "existing_default_sg_id" {
  description = "ID của Default Security Group trong VPC"
  type        = string
  default     = "sg-026a4e7f95cb008af"
}

variable "existing_custom_sg_id" {
  description = "ID của Custom Security Group chuẩn (sportmate-app-sg)"
  type        = string
  default     = "sg-0e0b641ff9ab2785c"
}
