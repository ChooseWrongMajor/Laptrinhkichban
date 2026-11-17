# Hướng dẫn Kiểm tra & Khắc phục Tiêu chí CIS 3.16 (Manual & Scripted)

## 1. Thông tin chung
- **Mã tiêu chí**: CIS 3.16
- **Tên tiêu chí**: Ensure ECS Exec sessions have audit logging enabled (Manual)
- **Mức độ (Profile)**: Level 1
- **Dịch vụ áp dụng**: Amazon Elastic Container Service (ECS)
- **Mục đích**: Khi ECS Exec được sử dụng để truy cập shell trực tiếp vào container, toàn bộ phiên làm việc phải được ghi nhật ký kiểm toán ở chế độ **`OVERRIDE`** và gửi về CloudWatch Logs log group (`/ecs/exec-audit-logs`) hoặc S3 bucket chuyên biệt.

---

## 2. Quy trình Kiểm tra & Khắc phục bằng AWS CLI (Trang 121–123 tài liệu CIS Benchmark)

### 2.1. Audit Procedure – Kiểm tra (Nguyên văn trang 121–122 sách CIS)
1. Liệt kê các ECS Cluster trong region:
   ```powershell
   aws ecs list-clusters --region ap-southeast-1 --query "clusterArns[]" --output table
   ```
2. Kiểm tra chế độ ghi nhật ký phiên (`executeCommandConfiguration.logging`) và cấu hình chi tiết của Cluster (Bước 3 trang 122 & Bước 4 trang 123 sách CIS):
   ```powershell
   # Kiểm tra giá trị logging (Phải trả về OVERRIDE)
   aws ecs describe-clusters --clusters cis-compute-benchmark-cluster --include CONFIGURATIONS --region ap-southeast-1 --query "clusters[].configuration.executeCommandConfiguration.logging" --output text

   # Xem chi tiết đối tượng executeCommandConfiguration (Bước 4 trang 123 sách CIS)
   aws ecs describe-clusters --clusters cis-compute-benchmark-cluster --include CONFIGURATIONS --region ap-southeast-1 --query "clusters[].configuration.executeCommandConfiguration" --output json
   ```
- **Đánh giá**:
  - Nếu `logging` là **`OVERRIDE`** và có `cloudWatchLogGroupName: "/ecs/exec-audit-logs"` -> **PASS (TRUE)**.
  - Nếu `logging` là `None`, `NONE` hoặc `DEFAULT` -> **FAIL**.

---

### 2.2. Remediation Procedure – Khắc phục (Trang 122–123 sách CIS)
1. Tạo CloudWatch Log Group `/ecs/exec-audit-logs` với thời hạn lưu trữ 365 ngày:
   ```powershell
   aws logs create-log-group --log-group-name /ecs/exec-audit-logs --region ap-southeast-1
   aws logs put-retention-policy --log-group-name /ecs/exec-audit-logs --region ap-southeast-1 --retention-in-days 365
   ```
2. Cập nhật ECS Cluster sang chế độ `OVERRIDE`:
   ```powershell
   python scripts/manual/cis_3_16_ecs_exec_logging.py --region ap-southeast-1 --mode remediate
   ```

---

## 3. Biểu mẫu trình bày Phần 3.2. Manual trong Báo cáo (Giống mẫu nhóm NGINX)

| Tên chính sách | Key (Lệnh) | Kết quả (screenshot) | Kết quả thực tế so với kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **3.16 - Đảm bảo các phiên ECS Exec được bật ghi nhật ký kiểm toán (Audit Logging)** | `aws ecs describe-clusters --clusters cis-compute-benchmark-cluster --include CONFIGURATIONS --region ap-southeast-1 --query "clusters[].configuration.executeCommandConfiguration" --output json` | *(Dán ảnh chụp màn hình JSON trả về `logging: OVERRIDE` và `/ecs/exec-audit-logs`)* | `logging: "OVERRIDE"`, `cloudWatchLogGroupName: "/ecs/exec-audit-logs"` — Đã bật ghi nhật ký kiểm toán phiên ECS Exec về CloudWatch Logs đúng chuẩn CIS $\rightarrow$ **TRUE** |

---

## 4. Thực thi Kịch bản Python Boto3

```powershell
# Chế độ chỉ kiểm tra (Audit-only)
python scripts/manual/cis_3_16_ecs_exec_logging.py --region ap-southeast-1 --mode audit

# Chế độ kiểm tra và tự động khắc phục (Audit-and-remediate)
python scripts/manual/cis_3_16_ecs_exec_logging.py --region ap-southeast-1 --mode remediate
```

Báo cáo đầu ra được lưu tự động tại:
- `reports/cis_3_16_report.json`
- `reports/cis_3_16_report.csv`
