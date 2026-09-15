# Write-up giải mã Palimpsest trên K3S và ArgoCD

**Sự kiện:** Security Bootcamp 2026  
**Máy bị ảnh hưởng:** `172.16.202.106`  
**Chứng cứ và kết quả xử lý:** ngày 11/09/2026

## 1. Kết quả và phạm vi

113 file được xác thực và ghi phục hồi sau khi tìm frame riêng; kế hoạch không có lỗi. Lượt chính thu được **96.213.706 byte plaintext**. Kết quả được đối chiếu giữa kế hoạch giải mã và log áp dụng; thông tin dịch vụ chỉ dùng để kiểm tra sau phục hồi.

## 2. Thu thập chứng cứ và tìm frame

### Hiện trạng và artifact

`k3s-initial.txt` ghi root filesystem `ro,relatime`; BusyBox và Python còn dùng được. Nhóm ghi nhận boot, mount và service, lấy vật liệu dẫn xuất trên host rồi xác thực container trước khi chuẩn bị thay file.

Gói `k3s-recovery-material.tar` có bốn thành viên: `frame.bin`, `host-identity.bin`, `manuscript-fingerprint.bin`, `palimpsest_recover.py`. Đây là gói vật liệu phục hồi, **không phải RAM dump, backup toàn máy hay archive plan.json**. Kế hoạch/log và bản sao file mã hóa được lưu riêng. Các giá trị vật liệu khóa không chép vào báo cáo.

### Tìm và kiểm tra frame

Lượt thử đầu dùng frame Edge-proxy trả `Authentication failed; no plaintext released`. Nhóm tiếp tục quét RAM K3S bằng [scan_frames.py](recovery-fleet/scan_frames.py). Script tìm chuỗi hex bắt đầu `50524931` và chuỗi base64 bắt đầu `UFJJM`, decode, yêu cầu đúng 48 byte và magic `PRI1`, rồi loại ứng viên trùng.

[Manifest frame](recovery-fleet/frames/manifest.json) ghi nhận ứng viên trong `Team24_k3s-argocd-Snapshot6.vmem`, offset `0x1405484b0`, lưu thành `frames/1.bin`. Frame này kết hợp identity/fingerprint K3S mới cho kết quả xác thực. Đối chiếu gói `k3s-recovery-material.tar` cho thấy frame khớp ứng viên đó và khác frame Edge.

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

## 6. Giải mã hàng loạt và ghi phục hồi

[recover_host.py](recovery-fleet/recover_host.py) tách hai lượt:

1. **Lập kế hoạch:** quét `/etc`, `/usr`, `/var`, `/opt`, `/home`, `/root`; nhận diện regular file bằng 8 byte magic, không đi theo symlink directory. Container được giải mã với đường dẫn gốc, plaintext đặt dưới `/dev/shm/fleet-recovery/plaintext`. `plan.json` ghi path, mode, UID/GID, SHA256 ciphertext/plaintext và số byte; lỗi được lưu riêng.
2. **Áp dụng:** kiểm tra lại hash file mã hóa hiện tại và plaintext trong staging so với kế hoạch. Sau đó remount root sang read-write, tạo archive mới `/root/fleet-recovery-20260911/encrypted-before-repair.tar`, flush/fsync, đọc lại từng member và so SHA256 trước khi thay file.
3. Với mỗi file, ghi bản tạm cùng thư mục có hậu tố `.fleet-restore`, đặt mode/UID/GID cũ rồi dùng `os.replace`. Kế hoạch và lỗi được lưu cùng backup.

Archive này chứa các file thuộc kế hoạch phục hồi, không phải ảnh toàn bộ máy. Script quét cũng có phạm vi đường dẫn xác định; cần lượt bổ sung nếu dữ liệu ứng dụng nằm ngoài các gốc trên.

## 7. Kết quả xác thực và tình huống riêng

- `k3s-recovery-plan-summary.json`: 113 file xác thực, 96.213.706 byte plaintext trong lượt chính.
- `k3s-applied.txt`: 113 file đã ghi phục hồi trong lượt chính, có SHA256 archive backup.
- Không có lỗi trong kế hoạch chính sau khi có vật liệu đúng.

K3S khởi động và node Ready sau phục hồi. Các lỗi kéo image ArgoCD được xử lý ở bước vận hành riêng; 7 pod ArgoCD sau đó Running. Việc xử lý imagePullPolicy không tạo thêm file plaintext và không được tính vào số file giải mã.

## 8. Giới hạn và bài học

Kết quả thử frame Edge thất bại được giữ lại trong `k3s-key-test.txt`; nó thuộc giai đoạn trước khi tìm frame đúng. Chưa reboot host sau giải mã. Dấu magic biến mất hoặc service khởi động không thay thế kiểm tra AEAD. Bản mã và hash phải được giữ để đối chiếu lại các kết luận.

## 9. Hồ sơ đối chiếu

- [Hiện trạng ban đầu](recovery-fleet/k3s-initial.txt)
- [Thử vật liệu khóa](recovery-fleet/k3s-key-test.txt)
- [Kế hoạch giải mã](recovery-fleet/k3s-recovery-plan-summary.json)
- [Kết quả ghi phục hồi và hash backup](recovery-fleet/k3s-applied.txt)
- [Kết quả riêng của máy](recovery-fleet/k3s-argocd-health.txt)
- [Tổng hợp phục hồi](recovery-fleet/BAO_CAO_KHOI_PHUC_TEAM17.md)
