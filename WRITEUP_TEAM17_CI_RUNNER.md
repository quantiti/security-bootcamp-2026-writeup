# Team17 — Write-up CI-runner sau sự cố Palimpsest

**Sự kiện:** Security Bootcamp 2026  
**Máy:** CI-runner `172.16.201.104`  
**Phạm vi:** Phục hồi Docker/Gitea act_runner và kiểm tra khả năng kết nối Gitea.

## Kết quả chính

Máy ban đầu có root filesystem chỉ đọc và nhiều unit lỗi. Bộ giải mã xác thực **116 file** với định danh riêng của CI-runner; các file mã hóa được sao lưu và thay bằng plaintext đã xác thực. Docker và `act_runner` hoạt động. Runner kết nối được Gitea, nhận diện bản đăng ký `.runner` có sẵn, **không đăng ký mới**, và khai báo thành công tên `ci-runner` với label `ubuntu-latest` trên act_runner v0.2.11. `act_runner.service` được enable.

## Chuỗi xử lý

1. Ghi nhận boot, mount, tool và service. Kiểm thử xác thực trước khi sử dụng plaintext, tránh áp vật liệu của host khác mà không kiểm tra AEAD.
2. Lưu container mã hóa vào `/root/fleet-recovery-20260911/encrypted-before-repair.tar`, đọc lại và đối chiếu SHA256; phục hồi 116 file với quyền/chủ sở hữu cũ.
3. Phục hồi các unit nền, Docker và NFS theo cấu hình hiện có; sau đó khởi động `act_runner` mà không chạy lại script seed/registration.
4. Đối chiếu journal: Gitea reachable qua `internal-app.megacorp.local:3000`, `.runner` tồn tại, daemon khởi động và `declare successfully`.

## Bài học an ninh và giới hạn

Runner là điểm thực thi job do Gitea điều khiển. Token có quyền ghi repo, workflow hoặc manifest độc hại có thể chuyển từ Git sang runner/ArgoCD. Cần giới hạn quyền token, bảo vệ runner registration, tách secret khỏi job không tin cậy và giám sát job bất thường. Kết quả “declare successfully” **không chứng minh một pipeline thực tế đã chạy thành công**. Kiểm tra cuối còn `fwupd-refresh` failed; chưa reboot host sau giải mã.

Bằng chứng: [kế hoạch giải mã](recovery-fleet/ci-recovery-plan-summary.json), [hồ sơ thay file](recovery-fleet/ci-applied.txt), [journal runner](recovery-fleet/ci-runner-check.txt), [báo cáo phục hồi toàn đội](recovery-fleet/BAO_CAO_KHOI_PHUC_TEAM17.md).
