# Hướng dẫn Kiểm tra & Khắc phục Tiêu chí CIS 2.9 (Manual & Scripted)

## 1. Thông tin chung
- **Mã tiêu chí**: CIS 2.9
- **Tên tiêu chí**: Ensure use of AWS Systems Manager to manage EC2 instances (Manual)
- **Mức độ (Profile)**: Level 2
- **Dịch vụ áp dụng**: Amazon EC2 / AWS Systems Manager (SSM)
- **Mục đích**: Đảm bảo các EC2 instance được quản lý tập trung thông qua AWS Systems Manager (thay vì mở cổng SSH/RDP trực tiếp). Để EC2 kết nối được vào Systems Manager, instance bắt buộc phải được gắn **IAM Instance Profile** có quyền `AmazonSSMManagedInstanceCore`.

---

## 2. Quy trình Kiểm tra & Khắc phục (Audit & Remediation)

### 2.1. Audit Procedure – Kiểm tra

#### Cách 1: Kiểm tra trên AWS Management Console (Trang 61 tài liệu CIS)
1. Truy cập **AWS Systems Manager Console**: https://console.aws.amazon.com/systems-manager/
2. Ở menu bên trái, mục **Node Management**, chọn **Inventory** (hoặc **Fleet Manager**).
3. Kiểm tra danh sách các EC2 instance:
   - Nếu tất cả EC2 instance đều xuất hiện trong danh sách Managed Instances -> **PASS**.
   - Nếu có EC2 instance chưa xuất hiện hoặc chưa gắn IAM Instance Profile -> **FAIL**.

#### Cách 2: Kiểm tra bằng AWS CLI
Kiểm tra xem EC2 instance đã được gắn `IamInstanceProfile` phục vụ Systems Manager hay chưa:

```powershell
aws ec2 describe-instances --region ap-southeast-1 --query "Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,IamInstanceProfile:IamInstanceProfile.Arn}" --output table
```

*(Nếu tài khoản có quyền `ssm:DescribeInstanceInformation`, có thể kiểm tra thêm danh sách Managed Instances trực tiếp từ SSM)*:
```powershell
aws ssm describe-instance-information --region ap-southeast-1 --query "InstanceInformationList[*].{InstanceId:InstanceId,PingStatus:PingStatus,AgentVersion:AgentVersion}" --output table
```

---

### 2.2. Remediation Procedure – Khắc phục (Trang 61–64 tài liệu CIS)

1. **Tạo IAM Role cho Systems Manager** (nếu chưa có):
   - Vào **IAM Console** -> **Roles** -> **Create role**.
   - Chọn Trusted entity là **AWS service** -> **EC2**.
   - Gắn quyền (Policy): `AmazonSSMManagedInstanceCore`.
   - Đặt tên Role, ví dụ: `EC2-SSM-Managed-Role`.
2. **Gắn IAM Role vào EC2 Instance**:
   - Vào **EC2 Console** -> **Instances**, chọn EC2 instance (`i-019d25d6c06d427a4`).
   - Chọn **Actions** -> **Security** -> **Modify IAM role**.
   - Chọn IAM Role vừa tạo (`EC2-SSM-Managed-Role`) và nhấn **Update IAM role**.
   - Hoặc thực hiện bằng AWS CLI:
     ```powershell
     aws ec2 associate-iam-instance-profile --region ap-southeast-1 --instance-id <INSTANCE_ID> --iam-instance-profile Name=<INSTANCE_PROFILE_NAME>
     ```

---

## 3. Biểu mẫu trình bày Phần 3.2. Manual trong Báo cáo (Giống mẫu nhóm NGINX)

### Trường hợp 1: Ghi nhận kết quả thực tế hiện tại (Phát hiện lỗi chưa gắn IAM Profile cho SSM -> FAIL/FALSE)
| Tên chính sách | Key (Lệnh) | Kết quả (screenshot) | Kết quả thực tế so với kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **2.9 - Đảm bảo sử dụng AWS Systems Manager để quản lý EC2 instances** | `aws ec2 describe-instances --region ap-southeast-1 --query "Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,IamInstanceProfile:IamInstanceProfile.Arn}" --output table` | *(Chụp màn hình bảng kết quả trên PowerShell)* | `IamInstanceProfile: None` — EC2 instance chưa được gắn IAM Instance Profile cho Systems Manager $\rightarrow$ **FAIL (Cần gắn IAM Role `AmazonSSMManagedInstanceCore`)** |

### Trường hợp 2: Sau khi bạn gắn IAM Role trên AWS Console (Đạt chuẩn -> TRUE)
| Tên chính sách | Key (Lệnh) | Kết quả (screenshot) | Kết quả thực tế so với kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **2.9 - Đảm bảo sử dụng AWS Systems Manager để quản lý EC2 instances** | `aws ec2 describe-instances --region ap-southeast-1 --query "Reservations[*].Instances[*].{InstanceId:InstanceId,State:State.Name,IamInstanceProfile:IamInstanceProfile.Arn}" --output table` | *(Chụp màn hình bảng kết quả sau khi gắn IAM Role)* | `IamInstanceProfile` hiển thị ARN của SSM Role — Instance đã được cấu hình quản lý qua AWS Systems Manager $\rightarrow$ **TRUE** |

---

## 4. Thực thi Kịch bản Python Boto3

```powershell
# Chế độ chỉ kiểm tra (Audit-only)
python scripts/manual/cis_2_9_ssm.py --region ap-southeast-1 --mode audit

# Chế độ kiểm tra và tự động khắc phục (Audit-and-remediate)
python scripts/manual/cis_2_9_ssm.py --region ap-southeast-1 --mode remediate
```

Báo cáo đầu ra được lưu tự động tại:
- `reports/cis_2_9_report.json`
- `reports/cis_2_9_report.csv`
