# Hướng dẫn Kiểm tra & Khắc phục Tiêu chí CIS 12.10 (Manual & Scripted)

## 1. Thông tin chung
- **Mã tiêu chí**: CIS 12.10
- **Tên tiêu chí**: Ensure Lambda functions do not allow unknown cross account access via permission policies. (Manual)
- **Mức độ (Profile)**: Level 1
- **Dịch vụ áp dụng**: AWS Lambda
- **Mục đích**: Đảm bảo các hàm AWS Lambda không cấp quyền truy cập liên tài khoản (`Resource-based policy`) cho những tài khoản AWS lạ hoặc Principal không được xác định và phê duyệt.

---

## 2. Quy trình Kiểm tra & Khắc phục bằng AWS CLI (Trang 207–208 tài liệu CIS Benchmark)

### 2.1. Audit Procedure – Kiểm tra (Nguyên văn trang 207–208 sách CIS)
1. Liệt kê các hàm Lambda trong region:
   ```powershell
   aws lambda list-functions --region ap-southeast-1 --output table --query "Functions[*].FunctionName"
   ```
2. Xem chính sách quyền (`Policy`) gắn với hàm Lambda:
   ```powershell
   aws lambda get-policy --region ap-southeast-1 --function-name "cis-compute-benchmark-lambda" --output text --query "Policy"
   ```
3. Kiểm tra phần tử `"Principal"` trong kết quả trả về:
   - **PASS (`TRUE`)**: `"Principal"` chỉ chứa ARN của tài khoản AWS đã được phê duyệt trong tổ chức (ví dụ: `"arn:aws:iam::206489185820:root"`).
   - **FAIL**: `"Principal"` chứa `"*"` hoặc chứa ARN của một tài khoản AWS lạ không thuộc tổ chức.

---

### 2.2. Remediation Procedure – Khắc phục (Trang 208 sách CIS)
Xoá statement cấp quyền cho tài khoản lạ và chỉ cấp quyền cho tài khoản đã được phê duyệt:
```powershell
python scripts/manual/cis_12_10_lambda_cross_account.py --region ap-southeast-1 --mode remediate
```

---

## 3. Biểu mẫu trình bày Phần 3.2. Manual trong Báo cáo (Giống mẫu nhóm NGINX)

| Tên chính sách | Key (Lệnh) | Kết quả (screenshot) | Kết quả thực tế so với kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **12.10 - Đảm bảo Lambda functions không cho phép truy cập liên tài khoản trái phép qua Permission Policies** | `aws lambda get-policy --region ap-southeast-1 --function-name "cis-compute-benchmark-lambda" --output text --query "Policy"` | *(Dán ảnh chụp màn hình hiển thị JSON Policy có `"Principal":{"AWS":"arn:aws:iam::206489185820:root"}`)* | Chính sách `Resource-based policy` của hàm Lambda chỉ cấp quyền `lambda:InvokeFunction` cho duy nhất tài khoản AWS đã được phê duyệt (`206489185820`), không có tài khoản lạ, đúng chuẩn CIS $\rightarrow$ **TRUE** |
