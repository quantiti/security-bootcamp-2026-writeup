# Team17 — Write-up Edge-proxy sau sự cố Palimpsest

**Sự kiện:** Security Bootcamp 2026  
**Máy:** Edge-proxy `172.16.201.102`  
**Phạm vi:** Điều tra mã hóa, phục hồi CMS/Nginx và đánh giá đường đi từ WAN vào dịch vụ nội bộ. Không công bố khóa, token hoặc dữ liệu nhạy cảm.

## Kết quả chính

Edge-proxy ban đầu có root filesystem chỉ đọc, cổng web từ chối kết nối và `/etc/nginx/nginx.conf` mang header `SBC2026\0`. Nhóm bảo toàn chứng cứ, tìm lại cấu hình Nginx gốc từ dữ liệu đĩa còn sót, phục hồi chương trình/unit và đưa CMS hoạt động trở lại. Sau đó, frame PRI1 đầy đủ được tìm trong RAM Snapshot6 ở dạng văn bản; kết hợp định danh riêng của host và vật liệu từ `archivist.svg`, bộ đọc xác thực ChaCha20-Poly1305 thành công **101/101 container** trong `pre-recovery.tar`. Nginx/CMS trả HTTP 200; kiểm tra sau reboot ghi nhận Nginx tự chạy.

## Điều tra và phục hồi

1. Sao lưu có phạm vi các đường dẫn cấu hình, chương trình, web và log trước khi ghi thay đổi. Kiểm tra mẫu Palimpsest/SVG và định dạng container; không suy ra khóa dùng chung chỉ vì mẫu nhị phân trùng Jenkins.
2. Khi chưa có frame, quét block device còn đọc được để lấy bản rõ Nginx; cấu hình lab dài 4.775 byte tại offset `0x68ee04000`. Phục hồi 63 file chương trình/unit bằng gói Ubuntu đúng phiên bản, kiểm tra `nginx -t`, `dpkg --audit` và `apt-get check`.
3. Tìm frame PRI1 đầy đủ 48 byte trong Snapshot6 VMEM tại offset `0xeca0a000` bằng cách quét biểu diễn hex/base64. Bản trích RAM có 44/103 container xác thực; 59 bản thiếu chiều dài container bị từ chối. Số lần xác thực RAM và đĩa có đường dẫn trùng nhau, không phải số file duy nhất.
4. Đối chiếu 89 file ngoài log trên máy đang chạy với plaintext xác thực: 88 file khớp SHA256; `/etc/hosts` khác vì alias hostname được bổ sung có chủ đích. Log lịch sử được giải mã, còn log mới trên máy được giữ nguyên.

## An ninh sau khôi phục

Điều tra Purple Team phát hiện cấu hình Edge có đường proxy bị chi phối bởi `Host`/đích yêu cầu. Log cho thấy nguồn ngoài nhận HTTP 200 ở Gitea và trang login Jenkins qua Host IP. Đã gia cố và kiểm thử 36/36 ca cục bộ tại một thời điểm, nhưng phụ lục tái kiểm tra sau gia cố ghi nhận đường Host-IP vẫn chạm được Gitea/Jenkins. Vì vậy **không coi Edge đã đóng hoàn toàn đường vào mạng nội bộ**. Cần chặn dynamic upstream, chuẩn hóa và allowlist Host, giới hạn egress Edge đến backend bắt buộc và kiểm tra lại từ WAN.

## Giới hạn và chứng cứ

`fwupd-refresh` còn failed do không phân giải được `cdn.fwupd.org`; việc CMS trả 200 không chứng minh mọi upstream hoạt động. Sao lưu ban đầu không phải ảnh toàn bộ đĩa. Bằng chứng: [báo cáo phục hồi](recovery-edge/BAO_CAO_KHOI_PHUC.md), [manifest giải mã](recovery-edge/decryption-manifest.json), [đối chiếu bản gốc](recovery-edge/live-original-comparison.json), [kiểm thử gia cố](recovery-edge/hardening-verification.json), [phụ lục tái tấn công](PHU_LUC_IR_TAI_TAN_CONG_SAU_HARDEN_20260911.md).
