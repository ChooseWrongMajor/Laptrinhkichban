# Hướng dẫn Kiểm tra & Khắc phục Tiêu chí CIS 6.1 (Manual & Scripted)

## 1. Thông tin chung
- **Mã tiêu chí**: CIS 6.1
- **Tên tiêu chí**: Ensure you are using VPC Endpoints for source code access (Manual)
- **Mức độ (Profile)**: Level 1
- **Dịch vụ áp dụng**: AWS App Runner / Amazon VPC
- **Mục đích**: Đảm bảo kết nối giữa môi trường VPC triển khai mã nguồn và dịch vụ AWS App Runner đi qua mạng riêng (AWS PrivateLink) thông qua Interface VPC Endpoint (`com.amazonaws.<region>.apprunner`), thay vì đi qua Internet công cộng.

---

## 2. Quy trình Kiểm tra & Khắc phục (Trang 159–160 tài liệu CIS Benchmark)

### 2.1. Audit Procedure – Kiểm tra
Theo trang 159 sách CIS Benchmark, cần xác nhận VPC Endpoint của App Runner thỏa mãn 6 thông số:
1. `Service name`: `com.amazonaws.<region>.apprunner`
2. `Status`: `Available`
3. `VPC ID`: Được gắn đúng VPC
4. `Subnets`: Được gắn Subnet
5. `Security Groups`: Được gắn Security Group
6. `Policy`: Được cấu hình hợp lệ

#### Lệnh kiểm tra bằng AWS CLI:
```powershell
aws ec2 describe-vpc-endpoints --region ap-southeast-1 --filters "Name=service-name,Values=com.amazonaws.ap-southeast-1.apprunner" --query "VpcEndpoints[*].{VpcEndpointId:VpcEndpointId,ServiceName:ServiceName,State:State,VpcId:VpcId,Subnets:SubnetIds,SecurityGroups:Groups[*].GroupId}" --output json
```

---

### 2.2. Remediation Procedure – Khắc phục (Trang 160 sách CIS)
Tạo Interface VPC Endpoint cho `com.amazonaws.ap-southeast-1.apprunner` bằng kịch bản tự động:
```powershell
python scripts/manual/cis_6_1_apprunner_vpce.py --region ap-southeast-1 --mode remediate
```

*(Lưu ý chi phí: Interface VPC Endpoint có tính phí theo giờ (~$0.01/giờ), nên ngay sau khi bạn chạy lệnh kiểm tra và chụp ảnh màn hình xong, hãy xóa VPC Endpoint bằng lệnh `aws ec2 delete-vpc-endpoints --region ap-southeast-1 --vpc-endpoint-ids <VPCE_ID>` để không tốn tiền).*

---

## 3. Biểu mẫu trình bày Phần 3.2. Manual trong Báo cáo (Giống mẫu nhóm NGINX)

| Tên chính sách | Key (Lệnh) | Kết quả (screenshot) | Kết quả thực tế so với kết quả kỳ vọng |
| :--- | :--- | :--- | :--- |
| **6.1 - Đảm bảo sử dụng VPC Endpoints cho việc truy cập mã nguồn trong AWS App Runner** | `aws ec2 describe-vpc-endpoints --region ap-southeast-1 --filters "Name=service-name,Values=com.amazonaws.ap-southeast-1.apprunner" --query "VpcEndpoints[*].{VpcEndpointId:VpcEndpointId,ServiceName:ServiceName,State:State,VpcId:VpcId,Subnets:SubnetIds,SecurityGroups:Groups[*].GroupId}" --output json` | *(Dán ảnh chụp màn hình JSON trả về `ServiceName: com.amazonaws.ap-southeast-1.apprunner`, `State: available`)* | Đã cấu hình Interface VPC Endpoint `com.amazonaws.ap-southeast-1.apprunner` ở trạng thái `available`, gắn đầy đủ VPC, Subnet và Security Group đúng chuẩn CIS $\rightarrow$ **TRUE** |
