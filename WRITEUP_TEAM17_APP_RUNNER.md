# Team17 — Write-up app-runner sau sự cố Palimpsest

**Sự kiện:** Security Bootcamp 2026  
**Máy:** app-runner `172.16.203.110`  
**Phạm vi:** Phục hồi watcher tiêu thụ package từ Verdaccio và phân tích rủi ro thực thi mã qua NPM.

## Kết quả chính

Bộ giải mã xác thực **105 file**; các container được sao lưu và thay bằng plaintext đã xác thực. `app-runner.service` được enable/khởi động. Journal ghi watcher kết nối registry `npm.internal.megacorp.local:4873`, ping thành công và cài ban đầu `@megacorp/utils` **phiên bản 1.0.0**. Bản kiểm tra này chứng minh watcher hoạt động tại thời điểm phục hồi, không chứng minh mọi vòng poll sau đó an toàn.

## Chuỗi xử lý

1. Kiểm tra boot, mount, service và các file mã hóa; xác thực frame với identity riêng của app-runner.
2. Sao lưu file mã hóa vào archive trên host, kiểm tra lại SHA256, thay 105 file hợp lệ và giữ quyền/chủ sở hữu.
3. Phục hồi unit nền, NFS và kết nối Verdaccio; bật service theo cấu hình hiện có, không chạy lại seed ứng dụng tùy tiện.
4. Đối chiếu journal: entrypoint ghi secret lab vào đường dẫn ứng dụng, watcher thấy registry up và phiên bản 1.0.0 được cài. Giá trị secret không được đưa vào write-up.

## Bài học an ninh và giới hạn

Báo cáo Purple Team chứng minh đường tấn công qua package `@megacorp/utils@1.0.1` có lifecycle `postinstall` trên app-runner chạy quyền root. Vì vậy việc phục hồi service **không đủ** để kết luận đã loại bỏ nguy cơ supply-chain. Cần ghim version/digest, kiểm soát publish trên Verdaccio, tránh `npm install -g --unsafe-perm` dưới root, kiểm tra tarball và theo dõi process/file/network của watcher. Chưa kiểm thử mọi vòng poll hoặc reboot host sau giải mã; `fwupd-refresh` còn failed do metadata Internet.

Bằng chứng: [kế hoạch giải mã](recovery-fleet/app-recovery-plan-summary.json), [hồ sơ thay file](recovery-fleet/app-applied.txt), [journal watcher](recovery-fleet/app-app-final.txt), [báo cáo Purple Team](BAO_CAO_IR_PURPLE_TEAM_20260911.md).
