# Hướng dẫn Kiểm tra & Khắc phục Tiêu chí CIS 2.13 (Manual & Scripted)

## 1. Thông tin chung
- **Mã tiêu chí**: CIS 2.13
- **Tên tiêu chí**: Ensure Secrets and Sensitive Data are not stored directly in EC2 User Data (Manual)
- **Mức độ (Profile)**: Level 1
- **Dịch vụ áp dụng**: Amazon EC2
- **Mục đích**: Đảm bảo không lưu mật khẩu, khóa truy cập (`AWS_SECRET_ACCESS_KEY`), token hoặc dữ liệu nhạy cảm trực tiếp trong EC2 User Data.

---

## 2. Quy trình Kiểm tra & Khắc phục bằng AWS CLI (Trang 72–73 tài liệu CIS Benchmark)

### 2.1. Audit Procedure – Kiểm tra (`From the Command line` - Trang 72 sách CIS)
1. Lấy danh sách các EC2 instance trong region:
   ```powershell
   aws ec2 describe-instances --region ap-southeast-1 --query "Reservations[*].Instances[*].InstanceId" --output text
   ```
2. Kiểm tra thuộc tính `userData` của từng EC2 instance và giải mã Base64 (đúng theo ghi chú trong sách CIS: *"Note: User Data may be Base64 encoded. Decode the output as necessary."*):
   ```powershell
   # Lệnh 1: Xem thuộc tính userData gốc (dạng Base64) theo nguyên văn sách CIS
   aws ec2 describe-instance-attribute --region ap-southeast-1 --instance-id i-019d25d6c06d427a4 --attribute userData

   # Lệnh 2: Giải mã Base64 ngay trên PowerShell để xem nội dung script thực tế
   [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((aws ec2 describe-instance-attribute --region ap-southeast-1 --instance-id i-019d25d6c06d427a4 --attribute userData --query "UserData.Value" --output text)))
   ```
3. Đánh giá nội dung:
   - Trên máy `i-019d25d6c06d427a4`, nội dung User Data giải mã ra chỉ chứa các lệnh cài đặt gói phần mềm (`apt-get update`, `apt-get install -y docker.io docker-compose-v2 git curl nginx...`), **hoàn toàn không chứa mật khẩu, khóa bí mật hay token** -> **Kết quả: PASS (TRUE)**.

---

### 2.2. Remediation Procedure – Khắc phục (Trang 73 sách CIS)
Nếu phát hiện có thông tin nhạy cảm trong User Data:
1. Dừng (Stop) EC2 instance:
   ```powershell
   aws ec2 stop-instances --region ap-southeast-1 --instance-ids <INSTANCE_ID>
   ```
2. Chuyển mật khẩu/khóa bí mật sang **AWS Secrets Manager** hoặc **AWS Systems Manager Parameter Store**, sau đó cập nhật lại User Data đã làm sạch:
   ```powershell
   aws ec2 modify-instance-attribute --region ap-southeast-1 --instance-id <INSTANCE_ID> --user-data Value=<BASE64_CLEAN_SCRIPT>
   ```
3. Khởi động lại (Start) EC2 instance.

---

## 3. Biểu mẫu trình bày Phần 3.2. Manual trong Báo cáo (Giống mẫu nhóm NGINX)

| Tên chính sách | Key (Lệnh) | Kết quả (screenshot) | Kết quả thực tế so với kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **2.13 - Đảm bảo không lưu thông tin bí mật trực tiếp trong EC2 User Data** | `aws ec2 describe-instance-attribute --region ap-southeast-1 --instance-id i-019d25d6c06d427a4 --attribute userData`<br><br>*(Kèm giải mã Base64)* | *(Dán ảnh chụp màn hình chạy lệnh trên PowerShell)* | Nội dung User Data sau khi giải mã Base64 chỉ chứa kịch bản cài đặt môi trường (`apt-get install docker, nginx`), không chứa mật khẩu hay khóa truy cập nhạy cảm, đúng chuẩn CIS $\rightarrow$ **TRUE** |

---

## 4. Thực thi Kịch bản Python Boto3

```powershell
# Chế độ chỉ kiểm tra (Audit-only)
python scripts/manual/cis_2_13_user_data.py --region ap-southeast-1 --mode audit

# Chế độ kiểm tra và tự động khắc phục (Audit-and-remediate)
python scripts/manual/cis_2_13_user_data.py --region ap-southeast-1 --mode remediate
```

Báo cáo đầu ra được lưu tự động tại:
- `reports/cis_2_13_report.json`
- `reports/cis_2_13_report.csv`
