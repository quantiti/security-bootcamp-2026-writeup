# Team17 — Write-up K3S và ArgoCD sau sự cố Palimpsest

**Sự kiện:** Security Bootcamp 2026  
**Máy:** K3S/ArgoCD `172.16.202.106`  
**Phạm vi:** Giải mã file host, phục hồi control plane và các pod ArgoCD.

## Kết quả chính

Frame PRI1 lấy từ Edge-proxy **không** xác thực được container K3S; bộ đọc không phát hành plaintext khi AEAD thất bại. Nhóm tìm frame riêng trong `Team24_k3s-argocd-Snapshot6.vmem` tại offset `0x1405484b0`; kết hợp định danh K3S để xác thực **113 file**. Sau thay file và khởi động K3S, node `k3s-argocd` ở trạng thái Ready. Ban đầu nhiều pod ArgoCD bị `ErrImagePull`/`CrashLoopBackOff` vì registry ngoài không truy cập được. Sau sửa `imagePullPolicy`, **7 pod ArgoCD 1/1 Running**; ứng dụng `app-runner` báo Synced/Healthy; HTTP 200 qua ClusterIP.

## Chuỗi xử lý

1. Kiểm tra frame Edge với host K3S và giữ nguyên dữ liệu khi xác thực thất bại. Tìm frame host-specific trong RAM K3S; lập kế hoạch 113 file không lỗi.
2. Sao lưu các container mã hóa, đọc lại archive và đối chiếu SHA256; thay bằng plaintext đã xác thực, giữ quyền/chủ sở hữu.
3. Gắn NFS theo `fstab`, khởi động K3S và xác minh node Ready. Bản kiểm tra đầu vẫn thấy ArgoCD chưa sẵn sàng và một số pod không kéo được image.
4. Lưu workload spec trước sửa; chuyển `imagePullPolicy` của container/initContainer từ `Always` sang `IfNotPresent` để dùng image đã cache, cho controller tái tạo pod lỗi. Không thay image version, không đổi Service ClusterIP và không mở thêm cổng public.
5. Kiểm tra lại 7 pod ArgoCD, trạng thái ứng dụng và HTTP ở ClusterIP.

## Bài học an ninh và giới hạn

GitOps tự đồng bộ manifest là đường đưa thay đổi từ repository vào cluster; báo cáo Purple Team ghi nhận nhánh tấn công qua token Gitea và manifest ArgoCD. Sau phục hồi cần rà Git history, quyền sync, nguồn image, audit log K3S và secret mount. “Synced/Healthy” không chứng minh manifest an toàn. Chưa thử toàn bộ deployment, chưa reboot host sau giải mã và chưa kiểm chứng truy cập ArgoCD từ bên ngoài ClusterIP.

Bằng chứng: [kế hoạch giải mã](recovery-fleet/k3s-recovery-plan-summary.json), [trạng thái ban đầu](recovery-fleet/k3s-cluster.txt), [trạng thái sau sửa](recovery-fleet/k3s-argocd-health.txt), [hồ sơ thay file](recovery-fleet/k3s-applied.txt), [báo cáo Purple Team](BAO_CAO_IR_PURPLE_TEAM_20260911.md).
