# Write-up giải mã Palimpsest trên Edge-proxy

**Sự kiện:** Security Bootcamp 2026  
**Máy bị ảnh hưởng:** `172.16.201.102`  
**Chứng cứ và kết quả xử lý:** ngày 11/09/2026

## 1. Kết quả và phạm vi

Nhóm xác thực giải mã **101/101 container từ bản sao đĩa** `pre-recovery.tar`. Với dữ liệu trích từ RAM, **44/103 container** đủ điều kiện giải mã; 59 bản thiếu chiều dài container bị từ chối. Tổng 145 lần xác thực có đường dẫn trùng giữa hai nguồn, không phải 145 file duy nhất.

Điểm quyết định là tìm frame PRI1 đầy đủ ở dạng văn bản trong RAM Snapshot6. Trước đó, việc tìm plaintext từ đĩa và phục hồi chương trình bằng gói Ubuntu chỉ giúp dịch vụ chạy trở lại; bước giải mã có xác thực hoàn thành sau khi có frame.

## 2. Thu thập chứng cứ và tìm vật liệu khóa

### 2.1. Nhận diện file mã hóa

Hiện trạng ban đầu: root filesystem ext4 chỉ đọc; Nginx không phục vụ HTTP; `/etc/nginx/nginx.conf` có magic `SBC2026\0`, kích thước gốc 4.775 byte, container 4.891 byte. CRC và SHA256 đường dẫn hợp lệ. Các bản `nginx.conf.ctf-orig` và `/etc/hostname` cũng có container cùng định dạng.

Binary Palimpsest và SVG trùng hash với mẫu đã phân tích ở Jenkins. Bản `nginx.conf.bak-limits` còn plaintext nhưng dài 4.747 byte, nên chưa thể coi là bản gốc của container 4.775 byte.

### 2.2. Bảo toàn hai nguồn dữ liệu

Nguồn đĩa được bảo toàn bằng `initial-evidence.tar` và `pre-recovery.tar`. Backup có phạm vi các thư mục cấu hình, chương trình, web, log và mẫu Palimpsest; không phải ảnh toàn bộ đĩa, không bao gồm `/usr/lib` trong phạm vi backup ban đầu.

`pre-recovery.tar` dài 1.532.072.960 byte; báo cáo ghi đã đọc danh mục 3.559 thành viên và kiểm tra hash độc lập:

```text
0399c379c1585ac67100ced51bd6221a7f1e33942ff97742e9e691e552b08f6c
```

Nguồn RAM là `Team24_edge-proxy-Snapshot6.vmem`, cùng archive file đã trích `analysis/edge-snapshot6/recovered_fs.tar.gz`. Phải giữ riêng nguồn RAM/đĩa vì file trích từ RAM có thể thiếu trang hoặc bị cắt.

### 2.3. Hướng tìm plaintext trước khi giải mã

Quét block device còn chỉ đọc thu được ứng viên cấu hình Nginx dài 4.775 byte tại offset `0x68ee04000`. Bản này giúp phục hồi dịch vụ trong lúc chưa có frame. Sau khi giải mã thành công, cấu hình thu hồi bằng carving được đối chiếu khớp bản rõ xác thực. Trình tự này quan trọng: carving tìm bản rõ còn sót; nó không tự tạo ra khóa giải mã.

### 2.4. Tìm frame đầy đủ trong RAM

[extended_key_scan.py](recovery-edge/extended_key_scan.py) mmap RAM ở chế độ đọc, tìm các marker `PRI1`, `PALIKM4`, `UFJJM`, `50524931` và `expand 32-byte k`. Script cũng kiểm tra các ứng viên khóa quanh dấu trạng thái ChaCha bằng tag AEAD; tìm được marker hoặc chuỗi 32 byte chưa đủ để kết luận đó là khóa.

Báo cáo phục hồi ghi frame PRI1 đầy đủ **48 byte** tại offset **`0xeca0a000`**, tìm được nhờ kiểm tra biểu diễn hex/base64. Các dấu PRI1 binary đã thấy trước đó nằm trong chuỗi ELF; tìm riêng magic binary đã bỏ sót frame ở dạng văn bản. Ứng viên được lưu `frame-candidate.bin`, sau đó kiểm chứng bằng bộ đọc với identity Edge và fingerprint SVG.

## 3. Phân tích định dạng file mã hóa

Bộ đọc [palimpsest_recover.py](recovery/palimpsest_recover.py) hiện thực định dạng quan sát được từ Palimpsest. Một container hợp lệ có header 100 byte, ciphertext và tag Poly1305 16 byte:

| Offset | Số byte | Thành phần và cách kiểm tra |
|---|---:|---|
| `0x00` | 8 | Magic `SBC2026\0` |
| `0x08` | 2 | Giá trị phiên bản/thuật toán `02 01` |
| `0x0A` | 2 | Mode theo phân tích định dạng; bước restore dùng mode ghi nhận trong inventory |
| `0x0C` | 8 | Kích thước plaintext, little-endian |
| `0x14` | 8 | Kích thước ciphertext, phải bằng kích thước plaintext |
| `0x1C` | 32 | SHA256 của đường dẫn tuyệt đối ban đầu |
| `0x3C` | 16 | Salt dùng dẫn xuất khóa |
| `0x4C` | 12 | Nonce của ChaCha20-Poly1305 |
| `0x58` | 8 | Trường bổ sung trong header, vẫn nằm trong dữ liệu được xác thực |
| `0x60` | 4 | CRC32 của 96 byte đầu |
| `0x64` | Biến đổi | Ciphertext và tag 16 byte |

Với kích thước gốc `N`, file đầy đủ phải dài `N + 116` byte. CRC32 phát hiện lỗi header; SHA256 đường dẫn kiểm tra đúng tên gốc; tag AEAD mới quyết định vật liệu khóa và dữ liệu có hợp lệ hay không. Không kết luận giải mã thành công chỉ vì đầu ra nhìn giống văn bản.

Đường dẫn truyền vào bộ đọc phải là đường dẫn trên máy nạn nhân, ví dụ `/etc/hostname`, không phải đường dẫn file trích xuất trên Windows hoặc tên đường dẫn có thêm thư mục staging.

## 4. Lấy identity và fingerprint

Script [derive.py](recovery-fleet/derive.py) kiểm tra SHA256 của binary `/opt/palimpsest/palimpsest` trước khi dùng các địa chỉ routine đã phân tích:

```text
832b58a91f1c874167f2956f24c574fb9012328362aec6edd55418d145ae3989
```

Script ánh xạ các segment ELF, xử lý relocation và gọi có kiểm soát routine parse SVG tại `0x402aee`, lấy fingerprint tại `0x400fd8`, thu host profile tại `0x40564c`, dẫn xuất tại `0x4040d6` và lấy identity tại `0x4062bd`. Entry point và một số routine điều phối mã hóa/ghi file bị thay bằng lệnh trả về trong bản ánh xạ; các import ghi/mã hóa như `write`, `rename`, `unlink`, `EVP_Encrypt*` bị chặn. `fopen` chỉ cho chế độ đọc. Đây là cách script phân tích đã thực hiện, không phải hướng dẫn chạy nguyên binary mã hóa.

Các artifact dùng cho bộ đọc gồm `host-identity.bin`, `manuscript-fingerprint.bin` và frame 48 byte. Identity lấy từ host, fingerprint 32 byte được tính từ nội dung SVG qua routine của mẫu; không thay fingerprint bằng SHA256 nguyên file SVG. Với sáu gói fleet đã đối chiếu, identity đều dài 141 byte; cùng chiều dài không có nghĩa cùng nội dung.

## 5. Dẫn xuất khóa và xác thực giải mã

Công thức dưới đây chép theo logic bộ đọc, với `HMAC(key, data)` dùng SHA256:

```text
IKM = "PALIKM4"
      || uint16_le(len(identity))
      || identity
      || frame[4:48]
      || fingerprint

PRK = HMAC(salt, IKM)
K   = HMAC(PRK, "PALINFO-VAULT-v4" || 0x01)

plaintext = ChaCha20Poly1305(K).decrypt(
    nonce = blob[76:88],
    ciphertext_and_tag = blob[100:],
    AAD = blob[0:100]
)
```

Bốn byte magic `PRI1` không được đưa vào IKM; phần còn lại của frame được dùng đầy đủ. Salt và nonce lấy theo từng container. Bộ đọc kiểm tra magic/version, độ dài identity/frame/fingerprint, hash đường dẫn, CRC và chiều dài container trước khi gọi AEAD; sau xác thực còn kiểm tra chiều dài plaintext.

Nếu tag sai, bộ đọc trả `Authentication failed; no plaintext released`. Chỉ plaintext đã xác thực mới được ghi vào staging. CLI của bộ đọc tạo output mới bằng `O_EXCL`, từ chối ghi đè file đã tồn tại. Ví dụ thao tác trên **bản sao phân tích**, thay đường dẫn vật liệu cho đúng host:

```sh
python palimpsest_recover.py \
  --input ./evidence/hostname.enc \
  --original-path /etc/hostname \
  --identity ./material/host-identity.bin \
  --frame ./material/frame.bin \
  --fingerprint ./material/manuscript-fingerprint.bin \
  --output ./recovered/hostname
```

Thư mục output cần tồn tại trước khi chạy. Đây là ví dụ gọi bộ đọc hiện có, không phải nhật ký một lệnh đã chạy nguyên văn trong sự cố.

## 6. Giải mã archive và giữ nguyên nguồn

[decrypt_archives.py](recovery-edge/decrypt_archives.py) xử lý hai archive độc lập:

1. Duyệt regular-file member và chọn các file bắt đầu bằng magic `SBC2026\0`.
2. Khôi phục đường dẫn tuyệt đối gốc từ tên member. Với archive RAM, bỏ đúng một lớp thư mục bao ngoài; từ chối thành phần đường dẫn `..`.
3. Gọi `decrypt` với container, đường dẫn gốc, identity, frame và fingerprint. File đủ điều kiện mới được ghi vào `recovery-edge/decrypted/disk` hoặc `decrypted/ram`.
4. Ghi manifest gồm nguồn, path, trạng thái xác thực, số byte/hash plaintext hoặc lỗi. Các archive đầu vào được đọc, không bị thay thế.

Hàm `decrypt` chỉ trả plaintext sau khi tag hợp lệ. Riêng wrapper archive ghi vào cây output bằng `write_bytes`, khác với chế độ không ghi đè của CLI; nên sử dụng thư mục output mới khi tái dựng kết quả.

## 7. Kiểm chứng kết quả

| Nguồn | Container xem xét | Xác thực thành công | Bị từ chối |
|---|---:|---:|---:|
| Bản sao đĩa | 101 | 101 | 0 |
| File trích từ RAM | 103 | 44 | 59 |

Các container từ RAM thất bại do không đủ chiều dài; không dùng chúng làm plaintext phục hồi. Một số ví dụ plaintext xác thực từ nguồn đĩa: `/etc/hostname` 11 byte, `/etc/crontab` 1.136 byte, `/etc/fstab` 769 byte và `/etc/locale.gen` 9.563 byte.

Log lịch sử được giải mã vào cây output cục bộ; log mới trên máy đang chạy được giữ. Đối chiếu 89 file ngoài log với máy đang chạy: 88 file khớp SHA256; `/etc/hosts` khác vì alias hostname phục hồi được bổ sung có chủ đích. `locale.gen` tái tạo ở giai đoạn trước được thay bằng bản giải mã chính xác.

## 8. Giới hạn và bài học

Kết quả 101/101 chỉ áp dụng cho container trong archive đĩa đã kiểm tra. Không suy rộng thành toàn filesystem. Archive RAM có thiếu dữ liệu nên tag/chiều dài phải được kiểm tra trên từng container. Cùng mẫu Palimpsest hoặc cùng SVG không chứng minh cùng khóa: frame, identity và salt của container đều tham gia dẫn xuất.

## 9. Hồ sơ đối chiếu

- [Đánh giá ban đầu](recovery-edge/BAO_CAO_DANH_GIA.md)
- [Báo cáo các giai đoạn phục hồi](recovery-edge/BAO_CAO_KHOI_PHUC.md)
- [Quét marker và ứng viên khóa](recovery-edge/extended-key-scan.json)
- [Manifest giải mã](recovery-edge/decryption-manifest.json)
- [Kiểm tra frame](recovery-edge/frame-validation.json)
- [Đối chiếu plaintext với file đang chạy](recovery-edge/live-original-comparison.json)
