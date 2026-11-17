# Hướng dẫn Kiểm tra & Khắc phục Tiêu chí CIS 12.8 (Manual & Scripted)

## 1. Thông tin chung
- **Mã tiêu chí**: CIS 12.8
- **Tên tiêu chí**: Ensure that Code Signing is enabled for Lambda functions. (Manual)
- **Mức độ (Profile)**: Level 1
- **Dịch vụ áp dụng**: AWS Lambda / AWS Signer
- **Mục đích**: Đảm bảo tất cả các hàm AWS Lambda đều được gắn cấu hình ký mã (**Code Signing Configuration**) với chính sách kiểm tra chữ ký số đặt ở mức **`Enforce`** (`UntrustedArtifactOnDeployment = "Enforce"`), nhằm ngăn chặn triển khai gói mã chưa được ký hoặc đã bị chỉnh sửa trái phép.

---

## 2. Quy trình Kiểm tra & Khắc phục bằng AWS CLI (Trang 200–203 tài liệu CIS Benchmark)

### 2.1. Audit Procedure – Kiểm tra (Nguyên văn trang 200–201 sách CIS)
1. Liệt kê các Lambda functions trong region:
   ```powershell
   aws lambda list-functions --region ap-southeast-1 --output table --query "Functions[*].FunctionName"
   ```
2. Kiểm tra ARN của Code Signing Configuration gắn với hàm:
   ```powershell
   aws lambda get-function-code-signing-config --region ap-southeast-1 --function-name "cis-compute-benchmark-lambda" --query "CodeSigningConfigArn"
   ```
3. Kiểm tra chính sách xác thực chữ ký (`UntrustedArtifactOnDeployment` phải trả về `"Enforce"`):
   ```powershell
   aws lambda get-code-signing-config --region ap-southeast-1 --code-signing-config-arn <CSC_ARN> --query "CodeSigningConfig.CodeSigningPolicies.UntrustedArtifactOnDeployment"
   ```

---

### 2.2. Remediation Procedure – Khắc phục (Trang 201–203 sách CIS)
Chạy kịch bản Python tự động tạo AWS Signer Signing Profile, tạo Code Signing Configuration (`Enforce`) và gắn vào Lambda function:
```powershell
python scripts/manual/cis_12_8_lambda_code_signing.py --region ap-southeast-1 --ensure-demo-function --mode remediate
```

---

## 3. Biểu mẫu trình bày Phần 3.2. Manual trong Báo cáo (Giống mẫu nhóm NGINX)

| Tên chính sách | Key (Lệnh) | Kết quả (screenshot) | Kết quả thực tế so với kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **12.8 - Đảm bảo bật tính năng Code Signing cho các Lambda functions** | `aws lambda get-function-code-signing-config --region ap-southeast-1 --function-name "cis-compute-benchmark-lambda" --query "CodeSigningConfigArn"`<br><br>`aws lambda get-code-signing-config --region ap-southeast-1 --code-signing-config-arn <CSC_ARN> --query "CodeSigningConfig.CodeSigningPolicies.UntrustedArtifactOnDeployment"` | *(Dán ảnh chụp màn hình chạy 2 lệnh trên PowerShell trả về ARN của CodeSigningConfig và chữ `"Enforce"`)* | Hàm Lambda đã được gắn `CodeSigningConfigArn` và chính sách kiểm tra chữ ký `UntrustedArtifactOnDeployment` được đặt thành `"Enforce"`, đúng chuẩn CIS $\rightarrow$ **TRUE** |
