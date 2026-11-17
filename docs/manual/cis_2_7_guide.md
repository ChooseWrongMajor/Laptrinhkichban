# Hướng dẫn Kiểm tra & Khắc phục Tiêu chí CIS 2.7 (Manual & Scripted)

## 1. Thông tin chung
- **Mã tiêu chí**: CIS 2.7
- **Tên tiêu chí**: Ensure Default EC2 Security groups are not being used. (Manual)
- **Mức độ (Profile)**: Level 1
- **Dịch vụ áp dụng**: Amazon EC2 / VPC Security Group
- **Mục đích**: Đảm bảo các EC2 instance không sử dụng Security Group mặc định (`default`) của VPC và các Default Security Group không mở sẵn các luồng lưu lượng mạng không cần thiết.

---

## 2. Khởi tạo môi trường kiểm thử bằng Terraform (Bước 1)

Di chuyển vào thư mục `infrastructure` và khởi tạo hạ tầng mạng + EC2 instance cố tình gắn `default` Security Group:

```powershell
cd infrastructure
terraform init
terraform plan
terraform apply -auto-approve
```

Sau khi `apply` thành công, Terraform sẽ xuất ra:
- `vpc_id`: ID của VPC vừa tạo.
- `default_security_group_id`: ID của Default SG (đang mở inbound rule).
- `custom_security_group_id`: ID của Custom SG chuẩn.
- `ec2_instance_id_cis_2_7`: ID của EC2 instance đang gắn Default SG (dùng để test trạng thái `FAIL`).

---

## 3. Quy trình thực hiện Manual (AWS Console & AWS CLI)

### 3.1. Audit Procedure – Kiểm tra

#### Cách 1: Kiểm tra trên AWS Management Console
1. Đăng nhập vào **AWS EC2 Console**: https://console.aws.amazon.com/ec2/
2. Ở thanh điều hướng bên trái, chọn **Instances** -> **Instances**.
3. Tại ô tìm kiếm thuộc tính (Filter attributes), chọn **Security Group Name** và nhập `default`.
4. Nếu danh sách trả về bất kỳ EC2 Instance nào đang sử dụng Security Group `default` -> **Kết quả: FAIL**.

#### Cách 2: Kiểm tra bằng AWS CLI (Kiểm tra chéo)
Chạy lệnh sau trên PowerShell/Terminal để liệt kê các EC2 instance đang gắn Default Security Group:

```powershell
aws ec2 describe-instances `
  --region ap-southeast-1 `
  --output json `
  --filters "Name=instance.group-name,Values=default" `
  --query "Reservations[*].Instances[*].{Instance:InstanceId,State:State.Name,VpcId:VpcId}"
```
- **Đánh giá**:
  - Nếu kết quả trả về mảng rỗng `[]` -> **PASS**.
  - Nếu trả về danh sách các `InstanceId` -> **FAIL**.

Kiểm tra thêm xem Default Security Group có đang mở Inbound Rule nào hay không:
```powershell
aws ec2 describe-security-groups `
  --region ap-southeast-1 `
  --filters "Name=group-name,Values=default" `
  --query "SecurityGroups[*].{GroupId:GroupId,VpcId:VpcId,InboundRules:IpPermissions}"
```

---

### 3.2. Remediation Procedure – Khắc phục

#### Cách 1: Thực hiện trên AWS Management Console
1. **Đổi Security Group cho EC2 Instance**:
   - Vào **EC2 Console** -> **Instances**, chọn Instance bị phát hiện dùng `default` SG.
   - Chọn **Actions** -> **Security** -> **Change security groups**.
   - Gỡ bỏ `default` Security Group, thêm Custom Security Group (`cis-compute-benchmark-custom-sg`) và nhấn **Save**.
2. **Xoá các Rule trong Default Security Group** (Theo trang 56 tài liệu CIS Benchmark):
   - Vào **Network & Security** -> **Security Groups**.
   - Chọn Default Security Group (`default`), vào tab **Inbound rules** -> **Edit inbound rules**.
   - Nhấn **Delete** toàn bộ các rule đang có và nhấn **Save rules**.

#### Cách 2: Thực hiện bằng AWS CLI
```powershell
# 1. Thay thế Default SG trên EC2 instance bằng Custom SG
aws ec2 modify-instance-attribute `
  --region ap-southeast-1 `
  --instance-id <EC2_INSTANCE_ID> `
  --groups <CUSTOM_SECURITY_GROUP_ID>
```

---

## 4. Thực thi Kịch bản Python Boto3 (Audit + Remediation + Xuất báo cáo JSON/CSV)

Kịch bản `scripts/manual/cis_2_7_default_sg.py` tự động hóa đầy đủ các bước từ Bước 3 đến Bước 7 trong báo cáo:

### Chế độ 1: Chỉ kiểm tra (Audit-only)
```powershell
python scripts/manual/cis_2_7_default_sg.py --region ap-southeast-1 --mode audit
```

### Chế độ 2: Kiểm tra và tự động khắc phục (Audit-and-remediate)
```powershell
python scripts/manual/cis_2_7_default_sg.py --region ap-southeast-1 --mode remediate
```

Sau khi chạy xong, kết quả trước và sau khi khắc phục được lưu tại:
- `reports/cis_2_7_report.json`
- `reports/cis_2_7_report.csv`

---

## 5. Dọn dẹp hạ tầng sau khi kiểm thử
```powershell
cd infrastructure
terraform destroy -auto-approve
```
