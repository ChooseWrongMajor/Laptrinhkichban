# Hạ tầng lab CIS AWS Compute Services v2.0.0

Hạ tầng được **cố ý cấu hình sai một phần** để mỗi khuyến nghị đều có tài nguyên PASS và FAIL đối chứng.

## Cấu trúc

| File | Nội dung | CIS |
|---|---|---|
| `provider.tf`, `variables.tf`, `main.tf` | Provider, biến, data source dùng chung | – |
| `network.tf` | VPC, 2 public subnet, IGW, SG workload (không inbound) | – |
| `ec2.tf` | `ec2-legacy` (sai), `ec2-hardened` (đúng), launch template + ASG | 2.7, 2.8, 2.9, 2.13 (M) · 2.14 (A) |
| `ami.tf` | 3 AMI: đúng tên/không mã hóa, đúng tên/mã hóa, sai tên | 2.1.1 (M) · 2.1.2, 2.1.4 (A) |
| `ebs.tf` | Snapshot không mã hóa + public, snapshot mã hóa + private | 2.2.1, 2.2.2, 2.2.3 (A) |
| `ecs.tf` | Cluster, 2 task definition, 2 service (`desired_count = 0`) | 3.2–3.7, 3.9, 3.11 (A) · 3.16 (M) |
| `lambda.tf` | `public-fn` (sai), `secure-fn` (ký code bằng AWS Signer) | 12.16 (A) · 12.8, 12.10 (M) |
| `ecr.tf` | Repo policy `Principal: "*"` và repo chỉ cho account nội bộ | 18.4 (M) |
| `batch.tf` | 2 compute environment Fargate, trust policy có/không `aws:SourceArn` | 8.2 (M) |
| `apprunner.tf` | VPC endpoint App Runner (bật bằng biến) | 6.1 (M) |
| `cis_matrix.tf` | Output kết quả kỳ vọng cho từng CIS ID | – |

## Kết quả kỳ vọng

**Automated (15): 8 FAIL / 7 PASS**

| CIS | Kỳ vọng | Tài nguyên FAIL | Tài nguyên PASS |
|---|---|---|---|
| 2.1.2 | FAIL | AMI `v1.0.0`, `my-test-image` | AMI `v1.0.1` (encrypted) |
| 2.1.4 | PASS | – | cả 3 AMI (mới tạo) |
| 2.2.1 | FAIL | cài đặt account (đang tắt) | – |
| 2.2.2 | FAIL | `snap-plain` (public) | `snap-encrypted` |
| 2.2.3 | FAIL | `snap-plain` | `snap-encrypted` |
| 2.14 | PASS | – | ASG |
| 3.2 | FAIL | `web-public-svc` | `web-private-svc` |
| 3.3 | PASS | – | `web`, `worker` |
| 3.4 | FAIL | `worker` (privileged) | `web` |
| 3.5 | FAIL | `web` | `worker` |
| 3.6 | PASS | – | `web` (secret qua SSM), `worker` |
| 3.7 | PASS | – | `web`, `worker` |
| 3.9 | PASS | – | cluster |
| 3.11 | PASS | – | cluster |
| 12.16 | FAIL | `public-fn` (`NONE`) | `secure-fn` (`AWS_IAM`) |

**Manual (11): đều có cặp đối chứng đúng/sai**

| CIS | FAIL | PASS |
|---|---|---|
| 2.1.1 | `my-test-image` | `computebench-dev-v1.0.0`, `v1.0.1` |
| 2.7 | `ec2-legacy` (default SG) | `ec2-hardened` |
| 2.8 | `ec2-legacy` (IMDSv1) | `ec2-hardened` |
| 2.9 | `ec2-legacy` (không SSM) | `ec2-hardened` |
| 2.13 | `ec2-legacy` (secret giả trong user data) | `ec2-hardened` |
| 3.16 | cluster (logging `DEFAULT`, service bật Exec) | – |
| 6.1 | không có endpoint | bật `enable_apprunner_vpc_endpoint` |
| 8.2 | `batch-service-unsafe` | `batch-service-safe` |
| 12.8 | `public-fn` | `secure-fn` (CSC `Enforce`) |
| 12.10 | `public-fn` (account `111122223333`) | `secure-fn` |
| 18.4 | `computebench-leaky` | `computebench-private` |

## Điều kiện tiên quyết

```bash
aws ec2 get-ebs-encryption-by-default        # phải là false (để 2.2.1 FAIL và tạo được volume không mã hóa)
aws ec2 get-snapshot-block-public-access-state  # phải là unblocked (để tạo được snapshot public cho 2.2.2)
```

AWS CLI phải có sẵn vì `ebs.tf` dùng nó để chia sẻ snapshot public.

## Chạy

```bash
terraform init
terraform plan
terraform apply
terraform output cis_automated_matrix
terraform destroy
```

Sau khi demo remediation 2.2.1 (bật EBS encryption by default), nếu muốn dựng lại lab từ đầu thì phải tắt lại:
`aws ec2 disable-ebs-encryption-by-default`.

## Chi phí

Phần tốn phí chính là 2 instance `t3.micro` chạy liên tục, cộng với snapshot của AMI/EBS (vài GB). ECS service, ASG và Batch đều để 0 task/instance nên không tốn phí. VPC endpoint App Runner mặc định tắt. Nên `terraform destroy` sau mỗi buổi làm.
