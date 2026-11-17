# Hướng dẫn Kiểm tra & Khắc phục Tiêu chí CIS 8.2 (Manual & Scripted)

## 1. Thông tin chung
- **Mã tiêu chí**: CIS 8.2
- **Tên tiêu chí**: Ensure Batch roles are configured for cross-service confused deputy prevention (Manual)
- **Mức độ (Profile)**: Level 1
- **Dịch vụ áp dụng**: AWS Batch / AWS IAM
- **Mục đích**: Đảm bảo các IAM Role được sử dụng bởi AWS Batch (`batch.amazonaws.com`) có cấu hình điều kiện `aws:SourceArn` (với ARN cụ thể, không dùng ký tự đại diện `*`) và `aws:SourceAccount` trong Trust Policy (`AssumeRolePolicyDocument`) nhằm ngăn chặn lỗ hổng Cross-Service Confused Deputy.

---

## 2. Quy trình Kiểm tra & Khắc phục (Trang 165–167 tài liệu CIS Benchmark)

### 2.1. Audit Procedure – Kiểm tra
1. Xem chính sách tin cậy (`AssumeRolePolicyDocument`) của IAM Role dành cho AWS Batch:
   ```powershell
   aws iam get-role --role-name cis-compute-benchmark-batch-service-role --query "Role.AssumeRolePolicyDocument" --output json
   ```
2. Đánh giá theo trang 166 sách CIS Benchmark:
   - **PASS (`TRUE`)**: Trong `Statement` có `Principal.Service = "batch.amazonaws.com"`, `Action = "sts:AssumeRole"` và khối `Condition.ArnLike.aws:SourceArn` chứa đầy đủ ARN của Batch Compute Environment (ví dụ: `"arn:aws:batch:ap-southeast-1:206489185820:compute-environment/testCE"`), không chứa dấu `*`.
   - **FAIL**: Không có `Condition` hoặc `aws:SourceArn` chứa dấu `*`.

---

### 2.2. Remediation Procedure – Khắc phục
Chạy kịch bản tự động cập nhật `AssumeRolePolicyDocument` của Role theo đúng mẫu trang 166–167 sách CIS:
```powershell
python scripts/manual/cis_8_2_batch_confused_deputy.py --region ap-southeast-1 --mode remediate
```

---

## 3. Biểu mẫu trình bày Phần 3.2. Manual trong Báo cáo (Giống mẫu nhóm NGINX)

| Tên chính sách | Key (Lệnh) | Kết quả (screenshot) | Kết quả thực tế so với kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **8.2 - Đảm bảo IAM Role của AWS Batch được cấu hình chống lỗ hổng Cross-Service Confused Deputy** | `aws iam get-role --role-name cis-compute-benchmark-batch-service-role --query "Role.AssumeRolePolicyDocument" --output json` | *(Dán ảnh chụp màn hình JSON hiển thị `AssumeRolePolicyDocument` có `aws:SourceArn` và `aws:SourceAccount`)* | Chính sách tin cậy (`Trust Policy`) của Batch Role đã giới hạn chặt chẽ `aws:SourceAccount` và `aws:SourceArn` tới ARN cụ thể (không chứa `*`), đúng chuẩn CIS $\rightarrow$ **TRUE** |

---

## 4. Thực thi Kịch bản Python Boto3

```powershell
# Chế độ chỉ kiểm tra (Audit-only)
python scripts/manual/cis_8_2_batch_confused_deputy.py --region ap-southeast-1 --mode audit

# Chế độ kiểm tra và tự động khắc phục (Audit-and-remediate)
python scripts/manual/cis_8_2_batch_confused_deputy.py --region ap-southeast-1 --mode remediate
```

Báo cáo đầu ra được lưu tự động tại:
- `reports/cis_8_2_report.json`
- `reports/cis_8_2_report.csv`
