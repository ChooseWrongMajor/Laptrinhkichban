# Hướng dẫn & Nội dung Báo cáo Mục 3.3. Automated (21 Tiêu chí CIS AWS Compute Services Benchmark v2.0.0)

## I. Các lệnh chạy chụp ảnh màn hình Terminal cho Báo cáo

Khi mở PowerShell tại thư mục gốc `c:\Users\Dell\School\LapTrinhKichBan\DoAnCuoiKy`:

### 1. Chạy Audit lần 1 (Trước khi Remediation - 13 PASS / 8 FAIL, Điểm tuân thủ 61.90%):
```powershell
python scripts/automated/main_automated.py --mode audit
```
*(Nếu lỡ chạy remediate rồi mà muốn quay lại trạng thái 13 PASS / 8 FAIL thì gõ `python scripts/automated/main_automated.py --mode seed` trước).*

### 2. Chạy Tự động Khắc phục & Kiểm tra lại (Remediation + Verification -> 21/21 PASS, 100.00%):
```powershell
python scripts/automated/main_automated.py --mode remediate
```

### 3. (Quan trọng) Lệnh dọn dẹp KMS Key sau khi chụp ảnh xong để không tốn phí KMS ($1/tháng):
```powershell
python scripts/automated/main_automated.py --mode cleanup-kms
```

---

## II. Nội dung Copy-Paste trực tiếp vào Báo cáo Word – Mục `3.3. Automated`

### a) Kết quả kiểm tra tự động trước khi khắc phục (Initial Audit)

Thực hiện chạy kịch bản kiểm tra tự động trên toàn bộ 21 tiêu chí thuộc nhóm Automated bằng lệnh:
`python scripts/automated/main_automated.py --mode audit`

*(Chèn ảnh chụp màn hình Terminal phần `KẾT QUẢ AUDIT TRƯỚC KHI REMEDIATION` vào đây)*

**Bảng tổng hợp kết quả kiểm tra tự động trước khi khắc phục (21 tiêu chí):**

| Mã CIS | Dịch vụ | Tên chính sách | Tài nguyên kiểm tra | Trạng thái | Chi tiết cấu hình thực tế thu thập qua Boto3 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **2.1.2** | Amazon EC2 | Ensure Amazon Machine Images (AMIs) are encrypted | `ami-0e8ae9b21ed993cb6`, `ami-0033a375ab8f52dab`, `ami-0b17c5bcd55b17b96` | **PASS** | Tất cả 3 AMI thuộc sở hữu của tài khoản đều có `BlockDeviceMappings.Ebs.Encrypted = True`. |
| **2.1.4** | Amazon EC2 | Ensure Images (AMI) are not older than 90 days | 3 AMIs (tối đa 28 ngày tuổi) | **PASS** | Tất cả 3 AMI đều được tạo trong vòng 28 ngày (`<= 90 ngày` theo chuẩn CIS). |
| **2.2.1** | Amazon EC2 | Ensure EBS volume encryption is enabled | Region `ap-southeast-1` | **FAIL** | Cấu hình mã hóa EBS mặc định của Region đang tắt (`EbsEncryptionByDefault = False`). |
| **2.2.2** | Amazon EC2 | Ensure Public Access to EBS Snapshots is Disabled | Region `ap-southeast-1` | **FAIL** | Trạng thái chặn chia sẻ công khai EBS Snapshot đang mở (`State = 'unblocked'`). |
| **2.2.3** | Amazon EC2 | Ensure EBS volume snapshots are encrypted | `snap-0477a67c12d14ca67`, `snap-04003fbd64d5dca76`, `snap-0e52cef71fd051a00` | **PASS** | Tất cả 3 EBS Snapshot hiện có đều được mã hóa (`Encrypted = True`). |
| **3.1** | Amazon ECS | Ensure ECS task definitions using 'host' network mode do not allow privileged or root user access | `cis-compute-benchmark-task:5` | **PASS** | Task Definition sử dụng `networkMode='awsvpc'`, `user='1000:1000'` và `privileged=False`. |
| **3.2** | Amazon ECS | Ensure 'assignPublicIp' is set to 'DISABLED' for Amazon ECS services | `cis-compute-benchmark-service` | **FAIL** | ECS Service đang cấu hình `awsvpcConfiguration.assignPublicIp = 'ENABLED'`. |
| **3.3** | Amazon ECS | Ensure Amazon ECS task definitions do not have 'pidMode' set to 'host' | `cis-compute-benchmark-task:5` | **PASS** | Task Definition đặt `pidMode = 'task'` (không chia sẻ tiến trình host). |
| **3.4** | Amazon ECS | Ensure Amazon ECS task definitions do not have 'privileged' set to 'true' | `cis-compute-benchmark-task:5` | **PASS** | Container trong Task Definition đã tắt quyền đặc quyền (`privileged = False`). |
| **3.5** | Amazon ECS | Ensure 'readonlyRootFilesystem' is set to 'true' for Amazon ECS task definitions | `cis-compute-benchmark-task:5` | **FAIL** | Container chưa bật chế độ hệ thống tệp gốc chỉ đọc (`readonlyRootFilesystem = False`). |
| **3.6** | Amazon ECS | Ensure secrets are not passed as container environment variables in ECS task definitions | `cis-compute-benchmark-task:5` | **PASS** | Biến môi trường không chứa mật khẩu, khóa truy cập hoặc token dạng rõ. |
| **3.7** | Amazon ECS | Ensure logging is configured for Amazon ECS task definitions | `cis-compute-benchmark-task:5` | **PASS** | Container đã cấu hình `logDriver='awslogs'` ghi nhật ký về `/ecs/exec-audit-logs`. |
| **3.8** | Amazon ECS | Ensure Amazon ECS Fargate services are using the latest Fargate platform version | `cis-compute-benchmark-service` | **PASS** | ECS Fargate Service đang sử dụng phiên bản nền tảng mới nhất (`platformVersion = '1.4.0' / LATEST`). |
| **3.9** | Amazon ECS | Ensure monitoring is enabled for Amazon ECS clusters | `cis-compute-benchmark-cluster` | **FAIL** | Tính năng giám sát Container Insights trên ECS Cluster đang tắt (`containerInsights = 'disabled'`). |
| **3.10** | Amazon ECS | Ensure Amazon ECS services are tagged | `cis-compute-benchmark-service` | **PASS** | ECS Service đã được gắn đầy đủ bộ thẻ quản lý tài nguyên (3 tags). |
| **3.11** | Amazon ECS | Ensure Amazon ECS clusters are tagged | `cis-compute-benchmark-cluster` | **PASS** | ECS Cluster đã được gắn đầy đủ bộ thẻ quản lý tài nguyên (3 tags). |
| **3.12** | Amazon ECS | Ensure Amazon ECS task definitions are tagged | `cis-compute-benchmark-task:5` | **PASS** | ECS Task Definition đã được gắn đầy đủ bộ thẻ quản lý tài nguyên (3 tags). |
| **3.13** | Amazon ECS | Ensure only trusted images are used with Amazon ECS | `cis-compute-benchmark-task:5` | **PASS** | Container chỉ sử dụng image từ kho ECR nội bộ đáng tin cậy (`206489185820.dkr.ecr...`). |
| **3.14** | Amazon ECS | Ensure 'assignPublicIp' is set to 'DISABLED' for Amazon ECS task sets | `cis-compute-benchmark-service/primary-deployment` | **FAIL** | Cấu hình mạng của Task Set / Deployment đang đặt `assignPublicIp = 'ENABLED'`. |
| **11.1** | AWS Fargate | Ensure customer-managed keys are used to encrypt AWS Fargate ephemeral storage data | `cis-compute-benchmark-cluster` | **FAIL** | ECS Cluster chưa cấu hình khóa KMS CMK cho `fargateEphemeralStorageKmsKeyId`. |
| **12.16** | AWS Lambda | Ensure AWS Lambda Function URLs are configured to use AWS IAM authentication | `cis-compute-benchmark-lambda` | **FAIL** | Lambda Function URL đang mở truy cập công khai không xác thực (`AuthType = 'NONE'`). |

* **Tổng kết trước khi khắc phục:** Tổng số tiêu chí: **21** | Đạt (**PASS**): **13** | Chưa đạt (**FAIL**): **8** | Điểm tuân thủ (**Compliance Score**): **61.90% (13/21)**.

---

### b) Thực hiện khắc phục tự động (Remediation) và Kiểm tra lại (Verification)

Thực hiện chạy kịch bản ở chế độ tự động khắc phục và xác minh lại đối với 8 tiêu chí chưa đạt:
`python scripts/automated/main_automated.py --mode remediate`

*(Chèn ảnh chụp màn hình Terminal phần `THỰC THI KHẮC PHỤC TỰ ĐỘNG` và `KẾT QUẢ KIỂM TRA LẠI SAU REMEDIATION` vào đây)*

**Bảng tổng hợp các hành động khắc phục tự động bằng Boto3 (8 tiêu chí FAIL $\rightarrow$ PASS):**

| Nhóm dịch vụ | Mã CIS | Hàm Boto3 API thực thi | Hành động khắc phục tự động trên AWS |
| :--- | :--- | :--- | :--- |
| **Amazon EC2** | `2.2.1` | `ec2.enable_ebs_encryption_by_default()` | Bật tính năng mã hóa EBS mặc định trên toàn Region `ap-southeast-1` (`EbsEncryptionByDefault = True`). |
| **Amazon EC2** | `2.2.2` | `ec2.enable_snapshot_block_public_access(State='block-all-sharing')` | Chuyển trạng thái chặn chia sẻ công khai EBS Snapshot từ `unblocked` sang `block-all-sharing`. |
| **Amazon ECS** | `3.5` | `ecs.register_task_definition()`, `ecs.deregister_task_definition()` | Đăng ký revision mới của Task Definition với `readonlyRootFilesystem = True` và hủy revision cũ. |
| **Amazon ECS** | `3.9` | `ecs.update_cluster_settings()` | Bật chế độ giám sát `containerInsights = 'enabled'` cho `cis-compute-benchmark-cluster`. |
| **Amazon ECS** | `3.2`, `3.14` | `ecs.update_service()` | Cập nhật cấu hình mạng của ECS Service và Task Set sang `assignPublicIp = 'DISABLED'`. |
| **AWS Fargate** | `11.1` | `kms.create_key()`, `kms.put_key_policy()`, `ecs.update_cluster()` | Gắn khóa KMS Customer-Managed Key (`7fff66f0-a18c-4f46-9e0a-a51a33d9e037`) vào `managedStorageConfiguration` của ECS Cluster. |
| **AWS Lambda** | `12.16` | `lambda.update_function_url_config(AuthType='AWS_IAM')` | Đổi cơ chế xác thực của Lambda Function URL từ `AuthType='NONE'` sang `AuthType='AWS_IAM'`. |

**Bảng kết quả kiểm tra lại sau khi khắc phục tự động (Post-Remediation Verification):**

| Mã CIS | Dịch vụ | Tài nguyên sau khắc phục | Trạng thái Trước | Trạng thái Sau | Chi tiết xác minh thực tế sau Remediation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **2.1.2** | Amazon EC2 | 3 AMIs (`ami-0e8ae9b21ed993cb6`, ...) | PASS | **PASS** | Tất cả 3 AMI đều có `Encrypted=True`. |
| **2.1.4** | Amazon EC2 | 3 AMIs (max 28 days) | PASS | **PASS** | Tất cả 3 AMI đều `<= 90` ngày tuổi (28 ngày). |
| **2.2.1** | Amazon EC2 | Region `ap-southeast-1` (`vol-0ce1688c6b1af63c3`) | **FAIL** | **PASS** | `EbsEncryptionByDefault=True` và EBS Volume hiện có đạt `Encrypted=True`. |
| **2.2.2** | Amazon EC2 | Region `ap-southeast-1` (`block-all-sharing`) | **FAIL** | **PASS** | `SnapshotBlockPublicAccess='block-all-sharing'` và 0/3 snapshot công khai. |
| **2.2.3** | Amazon EC2 | 3 Snapshots (`snap-0477a67c12d14ca67`, ...) | PASS | **PASS** | Tất cả 3 EBS Snapshot đều có `Encrypted=True`. |
| **3.1** | Amazon ECS | `cis-compute-benchmark-task:6` | PASS | **PASS** | Task Definition dùng `networkMode='awsvpc'`, `user='1000:1000'`, `privileged=False`. |
| **3.2** | Amazon ECS | `cis-compute-benchmark-service` | **FAIL** | **PASS** | ECS Service đã đặt `assignPublicIp='DISABLED'`. |
| **3.3** | Amazon ECS | `cis-compute-benchmark-task:6` | PASS | **PASS** | Task Definition đặt `pidMode='task'` (không dùng `'host'`). |
| **3.4** | Amazon ECS | `cis-compute-benchmark-task:6` | PASS | **PASS** | Container trong Task Definition đặt `privileged=False`. |
| **3.5** | Amazon ECS | `cis-compute-benchmark-task:6` | **FAIL** | **PASS** | Container trong Task Definition đã bật `readonlyRootFilesystem=True`. |
| **3.6** | Amazon ECS | `cis-compute-benchmark-task:6` | PASS | **PASS** | Biến môi trường không chứa mật khẩu hay khóa bí mật dạng rõ. |
| **3.7** | Amazon ECS | `cis-compute-benchmark-task:6` | PASS | **PASS** | Container đã cấu hình `logDriver='awslogs'` ghi về `/ecs/exec-audit-logs`. |
| **3.8** | Amazon ECS | `cis-compute-benchmark-service(1.4.0)` | PASS | **PASS** | Fargate Service sử dụng phiên bản nền tảng mới nhất (`1.4.0` / `LATEST`). |
| **3.9** | Amazon ECS | `cis-compute-benchmark-cluster(enabled)` | **FAIL** | **PASS** | ECS Cluster đã bật giám sát `containerInsights='enabled'`. |
| **3.10** | Amazon ECS | `cis-compute-benchmark-service(3 tags)` | PASS | **PASS** | ECS Service đã được gắn đầy đủ 3 thẻ quản trị. |
| **3.11** | Amazon ECS | `cis-compute-benchmark-cluster(3 tags)` | PASS | **PASS** | ECS Cluster đã được gắn đầy đủ 3 thẻ quản trị. |
| **3.12** | Amazon ECS | `cis-compute-benchmark-task:6(3 tags)` | PASS | **PASS** | Task Definition đã được gắn đầy đủ 3 thẻ quản trị. |
| **3.13** | Amazon ECS | `cis-compute-benchmark-task:6` | PASS | **PASS** | Chỉ sử dụng container image từ kho ECR nội bộ (`206489185820.dkr.ecr...`). |
| **3.14** | Amazon ECS | `cis-compute-benchmark-service/primary-deployment` | **FAIL** | **PASS** | ECS Task Set / Deployment đã đặt `assignPublicIp='DISABLED'`. |
| **11.1** | AWS Fargate | `cis-compute-benchmark-cluster(CMK:7fff66f0...)` | **FAIL** | **PASS** | Đã mã hóa Fargate Ephemeral Storage bằng KMS Customer-Managed Key. |
| **12.16** | AWS Lambda | `cis-compute-benchmark-lambda(AuthType=AWS_IAM)` | **FAIL** | **PASS** | Lambda Function URL đã bắt buộc xác thực qua `AuthType='AWS_IAM'`. |

* **Tổng kết sau khi khắc phục:** Tổng số tiêu chí: **21** | Đạt (**PASS**): **21** | Chưa đạt (**FAIL**): **0** | Điểm tuân thủ (**Compliance Score**): **100.00% (21/21)**.
