variable "region" {
  description = "Region triển khai lab"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Tên dự án, dùng làm prefix và theo quy ước đặt tên AMI (CIS 2.1.1)"
  type        = string
  default     = "computebench"
}

variable "environment" {
  description = "Môi trường triển khai"
  type        = string
  default     = "dev"
}

variable "instance_type" {
  description = "Loại EC2 instance cho lab"
  type        = string
  default     = "t3.micro"
}

variable "untrusted_account_id" {
  description = "Account ID ngoài tổ chức, dùng để tạo lỗi cross-account cho CIS 12.10"
  type        = string
  default     = "111122223333"
}

variable "enable_apprunner_vpc_endpoint" {
  description = "CIS 6.1: false = không có endpoint (FAIL), true = tạo interface endpoint (PASS, có tính phí theo giờ)"
  type        = bool
  default     = false
}
