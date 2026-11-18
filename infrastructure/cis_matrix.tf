# =====================================================================
# Ma trận kết quả kỳ vọng của lab: CIS ID -> tài nguyên PASS / FAIL.
# Dùng để đối chiếu với kết quả của script audit và đưa vào báo cáo.
# =====================================================================

locals {
  automated_controls = {
    "2.1.2" = { service = "AMI", expected = "FAIL", fail = [aws_ami_from_instance.base_unencrypted.id, aws_ami_from_instance.bad_name.id], pass = [aws_ami_copy.base_encrypted.id] }
    "2.1.4" = { service = "AMI", expected = "PASS", fail = [], pass = [aws_ami_from_instance.base_unencrypted.id, aws_ami_copy.base_encrypted.id, aws_ami_from_instance.bad_name.id] }
    "2.2.1" = { service = "EBS", expected = "FAIL", fail = ["account-setting:${local.region}"], pass = [] }
    "2.2.2" = { service = "EBS", expected = "FAIL", fail = [aws_ebs_snapshot.plain.id], pass = [aws_ebs_snapshot.encrypted.id] }
    "2.2.3" = { service = "EBS", expected = "FAIL", fail = [aws_ebs_snapshot.plain.id], pass = [aws_ebs_snapshot.encrypted.id] }
    "2.14"  = { service = "EC2", expected = "PASS", fail = [], pass = [aws_autoscaling_group.app.name] }
    "3.2"   = { service = "ECS", expected = "FAIL", fail = [aws_ecs_service.web_public.name], pass = [aws_ecs_service.web_private.name] }
    "3.3"   = { service = "ECS", expected = "PASS", fail = [], pass = [aws_ecs_task_definition.web.family, aws_ecs_task_definition.worker.family] }
    "3.4"   = { service = "ECS", expected = "FAIL", fail = [aws_ecs_task_definition.worker.family], pass = [aws_ecs_task_definition.web.family] }
    "3.5"   = { service = "ECS", expected = "FAIL", fail = [aws_ecs_task_definition.web.family], pass = [aws_ecs_task_definition.worker.family] }
    "3.6"   = { service = "ECS", expected = "PASS", fail = [], pass = [aws_ecs_task_definition.web.family, aws_ecs_task_definition.worker.family] }
    "3.7"   = { service = "ECS", expected = "PASS", fail = [], pass = [aws_ecs_task_definition.web.family, aws_ecs_task_definition.worker.family] }
    "3.9"   = { service = "ECS", expected = "PASS", fail = [], pass = [aws_ecs_cluster.main.name] }
    "3.11"  = { service = "ECS", expected = "PASS", fail = [], pass = [aws_ecs_cluster.main.name] }
    "12.16" = { service = "Lambda", expected = "FAIL", fail = [aws_lambda_function.public.function_name], pass = [aws_lambda_function.secure.function_name] }
  }

  manual_controls = {
    "2.1.1" = { service = "AMI", expected = "FAIL", fail = [aws_ami_from_instance.bad_name.name], pass = [aws_ami_from_instance.base_unencrypted.name, aws_ami_copy.base_encrypted.name] }
    "2.7"   = { service = "EC2", expected = "FAIL", fail = [aws_instance.legacy.id], pass = [aws_instance.hardened.id] }
    "2.8"   = { service = "EC2", expected = "FAIL", fail = [aws_instance.legacy.id], pass = [aws_instance.hardened.id] }
    "2.9"   = { service = "EC2", expected = "FAIL", fail = [aws_instance.legacy.id], pass = [aws_instance.hardened.id] }
    "2.13"  = { service = "EC2", expected = "FAIL", fail = [aws_instance.legacy.id], pass = [aws_instance.hardened.id] }
    "3.16"  = { service = "ECS", expected = "FAIL", fail = [aws_ecs_cluster.main.name], pass = [] }
    "8.2"   = { service = "Batch", expected = "FAIL", fail = [aws_iam_role.batch_unsafe.name], pass = [aws_iam_role.batch_safe.name] }
    "12.8"  = { service = "Lambda", expected = "FAIL", fail = [aws_lambda_function.public.function_name], pass = [aws_lambda_function.secure.function_name] }
    "12.10" = { service = "Lambda", expected = "FAIL", fail = [aws_lambda_function.public.function_name], pass = [aws_lambda_function.secure.function_name] }
    "18.4"  = { service = "ECR", expected = "FAIL", fail = [aws_ecr_repository.leaky.name], pass = [aws_ecr_repository.private.name] }
  }
}

output "cis_automated_matrix" {
  description = "15 khuyến nghị Automated: kết quả kỳ vọng và tài nguyên tương ứng"
  value       = local.automated_controls
}

output "cis_manual_matrix" {
  description = "Các khuyến nghị Manual: kết quả kỳ vọng và tài nguyên tương ứng"
  value       = local.manual_controls
}
