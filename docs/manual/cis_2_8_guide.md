# Hướng dẫn Kiểm tra & Khắc phục Tiêu chí CIS 2.8 (Manual & Scripted)

## 1. Thông tin chung
- **Mã tiêu chí**: CIS 2.8
- **Tên tiêu chí**: Ensure the Use of IMDSv2 is Enforced on All Existing Instances (Manual)
- **Mức độ (Profile)**: Level 2
- **Dịch vụ áp dụng**: Amazon EC2
- **Mục đích**: Đảm bảo tất cả các EC2 instance hiện có bắt buộc sử dụng Instance Metadata Service Version 2 (`IMDSv2`, tức thuộc tính `HttpTokens = required`), giúp chống lại các cuộc tấn công SSRF đánh cắp thông tin xác thực tạm thời từ metadata.

---

## 2. Quy trình Kiểm tra & Khắc phục bằng AWS CLI (Theo tài liệu CIS trang 58-59)

### 2.1. Audit Procedure – Kiểm tra
*Lưu ý của CIS Benchmark: Có thể kiểm tra bằng lệnh AWS CLI để lọc các instance vẫn còn để `http-tokens = optional` hoặc xem trực tiếp giá trị `HttpTokens` của từng instance.*

#### Lệnh 1: Lệnh chuẩn trong sách CIS (Tìm các instance vi phạm - có `http-tokens = optional`)
```powershell
aws ec2 describe-instances --region ap-southeast-1 --output text --filters "Name=metadata-options.http-tokens,Values=optional" --query "Reservations[*].Instances[*].{Instance:InstanceId}"
```
- Nếu kết quả **trống** -> Không có instance nào dùng `optional` -> **PASS (TRUE)**.

#### Lệnh 2: Lệnh hiển thị trực tiếp cấu hình `HttpTokens` của EC2 instance (Rất trực quan khi chụp ảnh báo cáo)
```powershell
aws ec2 describe-instances --region ap-southeast-1 --query "Reservations[*].Instances[*].{InstanceId:InstanceId,HttpTokens:MetadataOptions.HttpTokens,HttpEndpoint:MetadataOptions.HttpEndpoint}" --output table
```
- Kết quả hiển thị rõ `HttpTokens = required` và `HttpEndpoint = enabled` -> **PASS (TRUE)**.

---

### 2.2. Remediation Procedure – Khắc phục
Nếu phát hiện instance nào có `HttpTokens = optional`, chạy lệnh sau để bắt buộc sử dụng IMDSv2:

```powershell
aws ec2 modify-instance-metadata-options `
  --region ap-southeast-1 `
  --instance-id <INSTANCE_ID> `
  --http-tokens required `
  --http-endpoint enabled
```

---

## 3. Biểu mẫu trình bày Phần 3.2. Manual trong Báo cáo (Giống mẫu nhóm NGINX)

| Tên chính sách | Key (Lệnh) | Kết quả (screenshot) | Kết quả thực tế so với kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **2.8 - Đảm bảo bắt buộc sử dụng IMDSv2 trên tất cả EC2 Instances** | `aws ec2 describe-instances --region ap-southeast-1 --query "Reservations[*].Instances[*].{InstanceId:InstanceId,HttpTokens:MetadataOptions.HttpTokens,HttpEndpoint:MetadataOptions.HttpEndpoint}" --output table` | *(Chụp màn hình bảng kết quả trên PowerShell)* | `HttpTokens: required`, `HttpEndpoint: enabled` — Instance đã bắt buộc sử dụng IMDSv2 theo chuẩn CIS $\rightarrow$ **TRUE** |

---

## 4. Thực thi Kịch bản Python Boto3

```powershell
# Chế độ chỉ kiểm tra (Audit-only)
python scripts/manual/cis_2_8_imdsv2.py --region ap-southeast-1 --mode audit

# Chế độ kiểm tra và tự động khắc phục (Audit-and-remediate)
python scripts/manual/cis_2_8_imdsv2.py --region ap-southeast-1 --mode remediate
```

Báo cáo đầu ra được lưu tự động tại:
- `reports/cis_2_8_report.json`
- `reports/cis_2_8_report.csv`
