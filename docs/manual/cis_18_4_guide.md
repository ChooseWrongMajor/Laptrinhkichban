# Hướng dẫn Kiểm tra & Khắc phục Tiêu chí CIS 18.4 (Manual & Scripted)

## 1. Thông tin chung
- **Mã tiêu chí**: CIS 18.4
- **Tên tiêu chí**: Ensure private ECR repositories do not allow public access via resource policies (Manual)
- **Mức độ (Profile)**: Level 1
- **Dịch vụ áp dụng**: Amazon Elastic Container Registry (ECR)
- **Mục đích**: Đảm bảo các kho lưu trữ container riêng tư (Private ECR Repositories) không có `Resource-based policy` cho phép truy cập công khai (`Principal: "*"` hoặc `"AWS": "*"`) mà không có điều kiện giới hạn tài khoản/tổ chức.

---

## 2. Quy trình Kiểm tra & Khắc phục bằng AWS CLI (Trang 243–245 tài liệu CIS Benchmark)

### 2.1. Audit Procedure – Kiểm tra (Nguyên văn trang 243–244 sách CIS)
1. Liệt kê tất cả các Private ECR Repositories trong region:
   ```powershell
   aws ecr describe-repositories --region ap-southeast-1 --query "repositories[].repositoryName" --output table
   ```
2. Kiểm tra chính sách tài nguyên (`policyText`) của từng Repository:
   ```powershell
   aws ecr get-repository-policy --repository-name cis-compute-benchmark-private-repo --region ap-southeast-1 --query "policyText" --output text
   ```
   - **PASS (`TRUE`)**: Không có policy (`RepositoryPolicyNotFoundException`) hoặc `Principal` trong policy chỉ cấp quyền cho các tài khoản AWS cụ thể (`"arn:aws:iam::206489185820:root"`).
   - **FAIL**: Policy có `Effect: "Allow"` và `Principal: "*"` (hoặc `"AWS": "*"`) mà không có `Condition` giới hạn.

---

### 2.2. Remediation Procedure – Khắc phục (Trang 244–245 sách CIS)
Chạy kịch bản Python tự động sửa `Principal: "*"` thành tài khoản AWS nội bộ cụ thể:
```powershell
python scripts/manual/cis_18_4_ecr_private_policy.py --region ap-southeast-1 --mode remediate
```

---

## 3. Biểu mẫu trình bày Phần 3.2. Manual trong Báo cáo (Giống mẫu nhóm NGINX)

| Tên chính sách | Key (Lệnh) | Kết quả (screenshot) | Kết quả thực tế so với kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **18.4 - Đảm bảo các kho lưu trữ ECR riêng tư không cho phép truy cập công khai qua Resource Policies** | `aws ecr get-repository-policy --repository-name cis-compute-benchmark-private-repo --region ap-southeast-1 --query "policyText" --output text` | *(Dán ảnh chụp màn hình hiển thị JSON Policy có `"Principal":{"AWS":"arn:aws:iam::206489185820:root"}`)* | Chính sách tài nguyên (`Repository Policy`) của ECR Repository chỉ cấp quyền cho tài khoản nội bộ (`arn:aws:iam::206489185820:root`), không mở `Principal: "*"`, đúng chuẩn CIS $\rightarrow$ **TRUE** |
