output "account_id" {
  value = local.account_id
}

output "region" {
  value = local.region
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "ec2_instances" {
  value = {
    legacy   = aws_instance.legacy.id
    hardened = aws_instance.hardened.id
  }
}

output "amis" {
  value = {
    base_unencrypted = aws_ami_from_instance.base_unencrypted.id
    base_encrypted   = aws_ami_copy.base_encrypted.id
    bad_name         = aws_ami_from_instance.bad_name.id
  }
}

output "snapshots" {
  value = {
    plain_public      = aws_ebs_snapshot.plain.id
    encrypted_private = aws_ebs_snapshot.encrypted.id
  }
}

output "ecs" {
  value = {
    cluster          = aws_ecs_cluster.main.name
    services         = [aws_ecs_service.web_public.name, aws_ecs_service.web_private.name]
    task_definitions = [aws_ecs_task_definition.web.arn, aws_ecs_task_definition.worker.arn]
  }
}

output "lambda_functions" {
  value = {
    public = aws_lambda_function.public.function_name
    secure = aws_lambda_function.secure.function_name
  }
}
