output "vpc_id" {
  description = "ID của VPC kiểm thử"
  value       = data.aws_vpc.existing_vpc.id
}

output "default_security_group_id" {
  description = "ID của Default Security Group trong VPC"
  value       = var.existing_default_sg_id
}

output "custom_security_group_id" {
  description = "ID của Custom Security Group dùng để thay thế Default SG"
  value       = var.existing_custom_sg_id
}

output "ec2_instance_id_cis_2_7" {
  description = "ID của EC2 Instance đang dùng Default Security Group (vi phạm CIS 2.7)"
  value       = aws_instance.my_ec2_non_compliant_2_7.id
}
