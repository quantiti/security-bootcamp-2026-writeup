# Team17 — Write-up Gitea sau sự cố Palimpsest

**Sự kiện:** Security Bootcamp 2026  
**Máy:** Gitea `172.16.201.103`  
**Phạm vi:** Phục hồi dịch vụ Git nội bộ và đối chiếu rủi ro lộ bí mật trong chuỗi CI/CD.

## Kết quả chính

Host khởi đầu với root filesystem chỉ đọc và nhiều unit lỗi. Frame PRI1 từ RAM Edge-proxy được kiểm thử với định danh riêng của Gitea, xác thực **110 file** bằng ChaCha20-Poly1305. Các file mã hóa được sao lưu trước khi thay; Gitea và Nginx sau đó chạy, giao diện qua cổng 3000 trả HTTP 200. `gitea.service` được enable để tự khởi động. Kiểm tra cuối còn `fwupd-refresh` failed do metadata Internet, không phải lỗi Gitea đã được ghi nhận.

## Chuỗi xử lý

1. Thu trạng thái boot, mount, service, tiến trình và đường dẫn bị ảnh hưởng; xác thực vật liệu giải mã trước khi phát hành plaintext.
2. Lập kế hoạch phục hồi 110 file không lỗi; sao lưu các container mã hóa vào archive trên host và đọc lại để đối chiếu SHA256. Giữ quyền/chủ sở hữu khi thay bằng bản rõ đã xác thực.
3. Khởi động các unit hệ thống liên quan, gắn lại NFS `/shared/secrets` theo `fstab`, bật Gitea và Nginx. Không chạy lại script init/seed hoặc tạo database/secret giả.
4. Xác minh tiến trình Gitea, Nginx, listener `127.0.0.1:3000` và Nginx tại IP host `:3000`; log khởi động ghi Gitea 1.21.11 dùng `/etc/gitea/app.ini`. HTTP 200 chứng minh endpoint hoạt động, không tương đương kiểm thử mọi repository hay workflow CI.

## Bài học an ninh

Báo cáo Purple Team ghi nhận token `GITEA_CI_TOKEN` và credential Jenkins nằm trong material triển khai/repository, tạo đường từ truy cập Gitea sang Jenkins, ArgoCD và registry. Đây là **sự cố lộ bí mật/phân quyền**, tách biệt với việc phục hồi file mã hóa. Sau phục hồi cần rà lịch sử Git và object còn chứa secret, thu hồi/rotate token, giảm quyền tài khoản CI, bảo vệ private repository và theo dõi Git write/API bất thường. Không đưa giá trị token hoặc mật khẩu vào write-up.

## Giới hạn và chứng cứ

Không thử đầy đủ từng repo, Git push hoặc pipeline. Chưa reboot lại host sau lượt giải mã để kiểm chứng boot end-to-end. Bằng chứng: [kế hoạch giải mã](recovery-fleet/gitea-recovery-plan-summary.json), [hồ sơ thay file](recovery-fleet/gitea-applied.txt), [trạng thái ứng dụng](recovery-fleet/gitea-app-status.txt), [báo cáo Purple Team](BAO_CAO_IR_PURPLE_TEAM_20260911.md).
