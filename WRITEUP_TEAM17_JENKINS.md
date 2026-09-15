# Team24 — Write-up phân tích và khôi phục Jenkins sau mã hóa Palimpsest

**Sự kiện:** Security Bootcamp 2026  
**Đối tượng:** Máy Jenkins `172.16.202.105`  
**Ngày thực hiện:** 11/09/2026  
**Phạm vi:** Điều tra hai snapshot RAM VMware, xác định dữ liệu bị mã hóa và khôi phục dịch vụ Jenkins trên máy lab được cấp quyền truy cập.

## 1. Tóm tắt kết quả

Team24 xác định được dấu vết mã hóa hàng loạt liên quan đến `/opt/palimpsest/palimpsest`. Các mục tiêu gồm chương trình hệ thống, cấu hình Linux, log và thành phần Jenkins. File bị biến đổi có header chung `SBC2026\0`.

Không có công cụ hoặc khóa phục hồi do ban tổ chức cung cấp. Quá trình xử lý triển khai hai hướng: phân tích cơ chế mã hóa để xây bộ đọc giải mã, đồng thời tìm bản plaintext còn sót trong RAM và trên đĩa. Hướng thứ hai giúp khôi phục được khóa Jenkins gốc, cấu hình, job và dịch vụ mà không cần giải mã toàn bộ container Palimpsest.

Kết quả cuối:

- Jenkins 2.568.2 hoạt động tại `http://172.16.202.105:8080`.
- Trang đăng nhập qua mạng LAN trả HTTP 200. API có xác thực trả HTTP 200 và thấy job `deploy-production`.
- Jenkins giữ `useSecurity=true`; API chưa xác thực trả HTTP 403.
- SSH, cron, rsyslog và dịch vụ phân giải DNS cục bộ hoạt động; các phân vùng boot được mount lại.
- Không còn header mã hóa đã biết trong các thư mục hoạt động được kiểm tra.
- Bản sao lưu trước sửa chữa được giữ trên VM và tải về máy phân tích; SHA256 hai bản khớp nhau.

**Giới hạn:** chưa tìm đủ vật liệu khóa Palimpsest, chưa giải mã log lịch sử và chưa giải quyết được DNS bên ngoài VM. Không tuyên bố đã phá được toàn bộ thuật toán mã hóa hoặc khôi phục hoàn toàn mọi chức năng của môi trường.

## 2. Dữ liệu đầu vào và công cụ

### 2.1. Chứng cứ

| File | Kích thước |
|---|---:|
| `Team24-Jenkins-cbbfc4ff.vmem` | 4.294.967.296 byte |
| `Team24-Jenkins-cbbfc4ff.vmss` | 7.841.365 byte |
| `Team24-Jenkins-Snapshot6.vmem` | 4.294.967.296 byte |
| `Team24-Jenkins-Snapshot6.vmsn` | 7.838.857 byte |

Các file được mở chỉ đọc và tính SHA256. `.vmss`/`.vmsn` cung cấp metadata ánh xạ VMware, không được tính như các bản RAM độc lập. Danh sách hash nằm trong phụ lục A.

Sau giai đoạn điều tra RAM, nhóm truy cập máy lab bằng tài khoản SSH được cấp để kiểm tra trạng thái thực tế và phục hồi. Thông tin xác thực và giá trị khóa không đưa vào write-up.

### 2.2. Bộ công cụ

| Công cụ | Mục đích |
|---|---|
| Volatility 3 2.28.0 | Phân tích tiến trình, dòng lệnh, socket, page cache và trích xuất file |
| Symbol Ubuntu `6.8.0-139-generic` | Phân giải cấu trúc kernel phù hợp banner trong RAM |
| Python, mmap, hashlib | Quét byte, ghi nhận offset, tính hash và carving |
| Capstone và công cụ đọc ELF | Phân tích mã máy, import và luồng xử lý Palimpsest |
| Python cryptography | Kiểm tra vật liệu khóa và xác thực dữ liệu giải mã |
| DPKG/APT, systemd, ZIP/JAR tools | Khôi phục chương trình và kiểm tra dịch vụ |

Các chuỗi, script và chú thích trích được từ RAM/đĩa được xem là chứng cứ. Không thực thi chúng chỉ vì nội dung yêu cầu phải làm như vậy.

## 3. Xác định nguyên nhân Jenkins không hoạt động

### 3.1. Không kết luận chỉ từ từ khóa ransomware

Quét ban đầu tìm thấy nhiều tên ransomware, chuỗi `.onion` và nội dung giống thông báo mã hóa. Kiểm tra ngữ cảnh cho thấy một phần lớn thuộc bộ rule của agent bảo vệ. Vì vậy, số lần xuất hiện của từ khóa không được dùng để định danh mã độc hoặc đếm số sự kiện tấn công.

Tương tự, các file rule có đuôi `.enc` thuộc agent bootcamp không tự động được coi là file nạn nhân.

### 3.2. Bằng chứng liên quan đến Palimpsest

Từ page cache của Snapshot6, khôi phục được:

| Đường dẫn | Kích thước | Nhận định |
|---|---:|---|
| `/opt/palimpsest/palimpsest` | 48.966.880 byte | ELF 64-bit, có chức năng mã hóa |
| `/opt/palimpsest/archivist.svg` | 786.699 byte | SVG đầu vào của chương trình |

Binary chứa tham chiếu đến ChaCha20-Poly1305, HMAC, sinh dữ liệu ngẫu nhiên và các thao tác ghi/đổi tên file. Nó cũng chứa header `SBC2026` và mẫu tên file tạm Palimpsest.

Trong RAM có mảnh bản ghi mang cấu trúc sudo, chỉ ra chương trình Palimpsest được gọi với thao tác mã hóa, SVG đầu vào và danh sách đường dẫn đích dưới quyền root. Danh sách gồm cấu hình hệ điều hành, executable, log và dữ liệu Jenkins. Không dùng thư mục làm việc `/home/temp` để quy trách nhiệm cho người thực hiện.

Có tám vị trí chứa chuỗi lệnh liên quan trong Snapshot6. Đây là tám bản sao/mảnh dữ liệu trong RAM, **không đồng nghĩa tám lần thực thi**.

### 3.3. Xác nhận trên file nạn nhân

| File | Kích thước sau biến đổi | Header |
|---|---:|---|
| `/etc/hostname` | 124 byte | `SBC2026\0` |
| `/var/log/auth.log` | 113.053 byte | `SBC2026\0` |
| `/var/lib/jenkins/secrets/master.key` | 372 byte | `SBC2026\0` |

Sự kết hợp giữa dấu vết dòng lệnh, binary có chức năng mã hóa và nội dung thực tế của file đích là cơ sở kết luận đã xảy ra mã hóa hàng loạt. Chưa có bằng chứng đủ để gán tên một họ ransomware thương mại, xác nhận tống tiền hoặc xác định điểm xâm nhập ban đầu.

### 3.4. Mốc thời gian

Metadata của nhiều file thay đổi sát nhau trong khoảng **07/09/2026 23:40:48–23:40:49 UTC**, tương ứng **08/09/2026 06:40:48–06:40:49 UTC+7**. Đây là mốc mtime của file, không phải timestamp thực thi đã được xác nhận bằng bản ghi audit đầy đủ.

Các phiên SSH thấy vào ngày 10/09 xảy ra sau mốc trên, nên không đủ căn cứ liên hệ chúng với hoạt động mã hóa. Kết quả kiểm tra phục hồi cuối được ghi nhận lúc **11/09/2026 03:27:27 UTC**.

## 4. Phân tích định dạng và xây bộ đọc giải mã

### 4.1. Cấu trúc container quan sát được

Phân tích đường xử lý của binary cho thấy container có header 100 byte, ciphertext và tag xác thực 16 byte. Với các mẫu kiểm tra, tổng kích thước bằng kích thước plaintext cộng 116 byte.

| Offset | Độ dài | Thành phần |
|---|---:|---|
| `0x00` | 8 | Magic `SBC2026\0` |
| `0x08` | 2 | Phiên bản/thuật toán |
| `0x0A` | 2 | Mode của file |
| `0x0C` | 8 | Kích thước plaintext, little-endian |
| `0x14` | 8 | Kích thước ciphertext, little-endian |
| `0x1C` | 32 | SHA256 của đường dẫn đích tuyệt đối |
| `0x3C` | 16 | Salt |
| `0x4C` | 12 | Nonce |
| `0x58` | 8 | Trường dữ liệu bổ sung |
| `0x60` | 4 | CRC32 của 96 byte đầu |
| `0x64` | Biến đổi | Ciphertext, theo sau bởi tag 16 byte |

Ví dụ, `/etc/hostname` có kích thước gốc 8 byte, container 124 byte; `master.key` có kích thước gốc 256 byte, container 372 byte. Quan hệ này giúp kiểm tra tính hợp lý của file được carve, nhưng việc trùng kích thước không thay thế xác thực mật mã.

### 4.2. Vật liệu khóa và giới hạn đạt được

Luồng dẫn xuất khóa sử dụng identity máy, fingerprint thu từ SVG và frame `PRI1` dài 48 byte. Phần frame gồm magic 4 byte, proof 32 byte và 12 byte còn lại. Dẫn xuất khóa dùng HMAC-SHA256; payload được bảo vệ bằng ChaCha20-Poly1305 với header làm dữ liệu xác thực bổ sung.

Nhóm phân tích tĩnh và gọi có kiểm soát các routine đọc/phân tích/dẫn xuất trên một bản ánh xạ phục vụ nghiên cứu. Entry point chính và đường mã hóa không được gọi; các hàm ghi file/mã hóa liên quan được vô hiệu hóa trong bản ánh xạ này. Không chạy thao tác mã hóa trên dữ liệu gốc.

Đã xây `palimpsest_recover.py` với các kiểm tra:

1. Magic, phiên bản và độ dài container.
2. CRC của header và hash đường dẫn gốc.
3. Kích thước identity, fingerprint và frame.
4. Tag ChaCha20-Poly1305 trước khi xuất plaintext.
5. Từ chối ghi đè input hoặc output đã tồn tại.

Bộ đọc vượt qua fixture tổng hợp và sáu trường hợp dữ liệu/vật liệu khóa sai. Tuy nhiên, chưa tìm được đầy đủ 12 byte cuối của frame và **chưa xác thực giải mã thành công container nạn nhân**. Đây là bộ đọc đã xây và thử nghiệm, chưa phải bộ giải mã hoàn chỉnh của bài.

## 5. Hướng phục hồi quyết định: tìm lại plaintext

### 5.1. Khôi phục cấu hình từ RAM

Trong Snapshot6, tìm được XML `config.xml` của Jenkins bắt đầu tại raw file offset **`0x0b904000`**. Đoạn lấy ra dài 2.560 byte, parse XML thành công và có `useSecurity=true`. Độ dài này khớp kích thước gốc ghi trong container tương ứng.

Đây là bản plaintext còn sót trong RAM, không phải kết quả giải mã ciphertext. Sau kiểm tra, bản cấu hình được phục hồi và bản mã hóa được giữ riêng.

### 5.2. Carving trên thiết bị khối

Trước khi thay đổi hệ thống, nhóm tạo archive sao lưu các thư mục hệ thống, Jenkins, công cụ liên quan và log. Máy ban đầu có filesystem root ở chế độ chỉ đọc và nhiều executable không chạy được. Các công cụ còn hoạt động, bao gồm BusyBox, được sử dụng để thiết lập khả năng phục hồi ban đầu.

Nhóm xây `disk_carve_readonly.py` để quét thiết bị khối:

```text
/dev/mapper/ubuntu--vg-ubuntu--lv
```

Công cụ đọc theo chunk, kiểm tra các block 4 KiB và chỉ ghi ứng viên vào thư mục staging. Các mẫu gồm XML Jenkins, cấu hình service, YAML và chuỗi hex có độ dài phù hợp khóa Jenkins. Công cụ bổ sung `disk_carve_targeted.py` tìm tiếp các file theo cấu trúc và kích thước đã biết từ container.

Các offset dưới đây là offset trong thiết bị khối logic LVM, khác hệ tọa độ với offset của file RAM:

| Dữ liệu | Offset đĩa | Kích thước |
|---|---|---:|
| Khóa Jenkins gốc | `0x88e714000` | 256 byte |
| Service Jenkins | `0x68848c000` | 920 byte |
| CasC | `0x68852a000` | 1.837 byte |
| Groovy khởi tạo job | `0x68852c000` | 2.215 byte |
| Danh sách plugin | `0x68852d000` | 223 byte |
| Job `deploy-production` | `0x88e735000` | 1.990 byte |
| Netplan | `0xb59fe000` | 230 byte |

Không mặc định mọi chuỗi hex hoặc XML tìm được đều là dữ liệu đúng. Một số ứng viên là cấu hình cũ, nội dung ví dụ hoặc dữ liệu không liên quan.

### 5.3. Xác minh khóa Jenkins

Ứng viên `master.key` được kiểm tra với secret Jenkins hiện có, cụ thể file `hudson.model.User.DIRNAMES`. Với mỗi ứng viên, công cụ dẫn xuất khóa theo cách Jenkins sử dụng, thử giải mã và kiểm tra padding cùng hậu tố `::::MAGIC::::`.

Ứng viên tại `0x88e714000` vượt qua kiểm tra này. Kết quả cung cấp bằng chứng mật mã cho việc chọn khóa, thay vì chỉ dựa vào tên file hoặc chiều dài chuỗi. Sau đó, khóa được đặt lại đúng vị trí với ownership và quyền truy cập phù hợp.

Không tạo master key mới, vì việc đó sẽ làm mất quan hệ với các secret đã được bảo vệ bằng khóa cũ. Giá trị khóa không công bố trong write-up.

## 6. Khôi phục hệ thống và Jenkins

### 6.1. Executable và cấu hình Linux

Các executable bị mã hóa được thay bằng file sạch từ gói Ubuntu đúng phiên bản đang cài. Nguồn sử dụng là kho Ubuntu chính thức và kho snapshot cho phiên bản cũ. Kiểm tra SHA256 theo metadata APT hoặc đối chiếu file trích xuất với checksum trong cơ sở dữ liệu DPKG cài đặt.

Các thành phần khôi phục gồm Python, systemctl, dpkg, apt, coreutils, mount, tar, OpenSSL, công cụ mạng, procps, cron, rsyslog và systemd-resolved. Không nâng cấp hàng loạt hệ điều hành để thay thế việc sửa chữa.

`fstab`, hosts, netplan và nhiều cấu hình được lấy lại từ plaintext còn trên đĩa. UUID trong `fstab` được đối chiếu với thiết bị thực tế trước khi mount. `locale.gen` được tái tạo, giữ locale `en_US.UTF-8` đang sử dụng. Alias hostname cục bộ được bổ sung để sửa lỗi phân giải tên máy khi dùng sudo.

### 6.2. Dựng lại WAR

`/usr/share/jenkins/jenkins.war` bị mã hóa, nhưng thư mục đã bung sẵn `/var/lib/jenkins/war` còn đọc được. Nhóm xây `rebuild_war.py` để:

1. Kiểm tra manifest và sự tồn tại của entry point Java.
2. Kiểm tra file nguồn không mang header mã hóa đã biết.
3. Kiểm tra CRC của các JAR con.
4. Đóng gói thành WAR mới, giữ manifest.
5. Kiểm tra ZIP và chạy tùy chọn `--version`, nhận kết quả `2.568.2`.

WAR này được tái tạo từ nội dung đã triển khai, không được tuyên bố giống từng byte với archive ban đầu. CRC xác nhận tính toàn vẹn cấu trúc archive, không phải chữ ký chứng minh nguồn gốc mọi file.

Plugin Installation Manager được phục hồi bằng bản phát hành chính thức 2.15.0, có kích thước khớp kích thước gốc và SHA256 khớp digest công bố của release.

### 6.3. Khởi động lại dịch vụ

Sau khi phục hồi cấu hình, khóa, WAR, CasC và job, nhóm reload systemd và khởi động Jenkins. Queue được kiểm tra là rỗng; không kích hoạt job triển khai để thử nghiệm.

Các log còn mã hóa được sao lưu riêng trước khi tạo file log hoạt động mới. Sau đó khởi động cron, rsyslog và các dịch vụ hệ thống liên quan. Cách xử lý này phục hồi khả năng ghi log mới, không giải mã lịch sử log cũ.

## 7. Kiểm chứng kết quả

| Hạng mục | Kết quả ghi nhận |
|---|---|
| HTTP `/login` qua mạng LAN | 200, Jenkins 2.568.2 |
| API có xác thực | 200 |
| API chưa xác thực | 403 |
| Job | `deploy-production`, trạng thái `notbuilt` |
| Executor | 2 |
| Bảo mật Jenkins | `useSecurity=true` |
| Jenkins, SSH, cron, rsyslog, systemd-resolved | active |
| `/boot`, `/boot/efi` | active |
| `dpkg --audit` | Exit 0, không có lỗi được báo |
| `apt-get check` | Exit 0 |
| `findmnt --verify` | 0 lỗi; một cảnh báo liên quan swap file |
| `netplan generate` | Thành công |
| Header mã hóa trong các thư mục hoạt động đã quét | Không còn; không có lỗi đọc |

Phạm vi quét cuối gồm `/etc`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/share/jenkins`, `/var/lib/jenkins` và `/var/log`. Bản mã hóa được giữ trong thư mục chứng cứ riêng. Kết quả âm tính này không phải chứng nhận hệ thống hoàn toàn sạch mã độc.

Các kiểm tra chủ yếu là lệnh đọc trạng thái, ví dụ:

```bash
systemctl is-active jenkins ssh cron rsyslog systemd-resolved
dpkg --audit
apt-get check
findmnt --verify
java -jar /usr/share/jenkins/jenkins.war --version
```

Không reboot VM; khả năng khởi động hoàn chỉnh sau reboot chưa được kiểm chứng. Cấu hình bootcamp gốc được phục hồi, bao gồm các thiết lập cố ý nới lỏng của bài lab; đây không phải một đợt gia cố bảo mật production.

## 8. Hạn chế và hạng mục còn lại

- **DNS:** server lab gốc `172.16.203.109:53` từ chối kết nối; truy vấn tới `8.8.8.8:53` timeout. Jenkins dùng được qua IP, nhưng tên miền nội bộ và truy cập dịch vụ bên ngoài chưa được xác nhận hoạt động.
- **Tác vụ hệ thống:** `apt-daily-upgrade`, `apt-daily`, `fwupd-refresh`, `motd-news`, `update-notifier-download` vẫn mang trạng thái failed tại lần kiểm tra cuối. Chưa chạy lại toàn bộ khi DNS còn lỗi; không khẳng định DNS là nguyên nhân duy nhất của các trạng thái này.
- **Giải mã:** bộ đọc Palimpsest chưa có đầy đủ frame, chưa giải mã được container nạn nhân. Thành công phục hồi Jenkins đến từ dữ liệu plaintext còn sót và chương trình thay thế.
- **Log:** 12 file log mã hóa được bảo toàn, chưa phục hồi đầy đủ nội dung lịch sử.
- **Điều tra:** chưa xác định được người gọi thao tác mã hóa, điểm vào ban đầu hoặc một chuỗi xâm nhập hoàn chỉnh. Các cảnh báo cũ và trạng thái agent không đủ để suy ra quan hệ nhân quả.

## 9. Bài học từ quá trình xử lý

Điểm quyết định của bài là tách hai mục tiêu: giải mã container và phục hồi dịch vụ. Khi hướng giải mã thiếu vật liệu khóa, việc kiểm tra dữ liệu còn sót trong page cache, block đĩa và thư mục ứng dụng đã bung sẵn tạo ra một hướng phục hồi khả thi khác.

Việc chọn đúng khóa Jenkins cần kiểm chứng bằng secret hiện có. Việc chọn đúng cấu hình cần kết hợp cấu trúc, kích thước, nội dung và khả năng hoạt động sau khôi phục. Chỉ nhìn thấy tên file, một chuỗi hex hoặc một trang HTTP phản hồi chưa đủ để kết luận thành công.

Cuối cùng, cần phân biệt rõ dữ liệu được giải mã, dữ liệu được carve và dữ liệu được tái tạo. Cách ghi nhận này giúp ban tổ chức đánh giá đúng phần đã hoàn thành và phần còn giới hạn.

## Phụ lục A — SHA256 chứng cứ

```text
Team24-Jenkins-cbbfc4ff.vmem
394bde7f00232af9f95069ce08835e8258c43b5d1027c669bce51f3cf759c48d

Team24-Jenkins-cbbfc4ff.vmss
a458e07013b67304ae165931f26b9938376714d4d234654bfa6df1c5b06e8ab8

Team24-Jenkins-Snapshot6.vmem
86dab0bacd0c446e3c3661595cc97170ec44642b05c0312664617e93f0ab8dbf

Team24-Jenkins-Snapshot6.vmsn
ffcec6f08563a0ce392c964ec0fd1e0085be26352c1899640ca13aa7e10c7f2f

Palimpsest ELF khôi phục
832b58a91f1c874167f2956f24c574fb9012328362aec6edd55418d145ae3989

archivist.svg khôi phục
92bde5ac9811d9df8bac3020a2739eebbf7719a1f88f88d10ef24e7256eece98

Archive trước sửa chữa, 2.039.137.280 byte
bb3beb4a670d40514f93e75b3a3f4e9032b2b95060cc9086cb2580168d624a63
```

## Phụ lục B — Hồ sơ kiểm chứng và công cụ tự xây

| Tên | Vai trò |
|---|---|
| `evidence/verification-final.json` | Kết quả kiểm tra sau phục hồi |
| `evidence/backup-copy-verified.json` | Đối chiếu hash backup trên VM và máy phân tích |
| `evidence/input-manifest.json` | Hash và kích thước bộ RAM đầu vào |
| `disk_carve_readonly.py` | Quét block chỉ đọc, tìm ứng viên plaintext |
| `disk_carve_targeted.py` | Carving bổ sung theo cấu trúc/kích thước |
| `validate_disk_carved.py` | Xác minh ứng viên khóa Jenkins |
| `carve_exact_config.py` | Trích XML Jenkins từ RAM và kiểm tra |
| `rebuild_war.py` | Tái tạo WAR từ thư mục đã bung |
| `palimpsest_recover.py` | Bộ đọc giải mã có xác thực; chưa đủ vật liệu khóa nạn nhân |
| `test_recovery_reader.py` | Kiểm thử tổng hợp cho bộ đọc |

Gói nộp kèm write-up chỉ gồm báo cáo và JSON kiểm chứng đã rà soát. Các script được liệt kê để mô tả công cụ đã sử dụng, không đính kèm tự động cùng RAM, binary, cấu hình chứa mật khẩu hoặc khóa phục hồi.

## Tài liệu tham chiếu

- [Volatility 3 — Linux tutorial](https://github.com/volatilityfoundation/volatility3/blob/develop/doc/source/getting-started-linux-tutorial.rst).
- [Jenkins — DefaultConfidentialStore](https://github.com/jenkinsci/jenkins/blob/master/core/src/main/java/jenkins/security/DefaultConfidentialStore.java), đối chiếu cơ chế lưu secret; việc xác nhận khóa trong bài dựa trên secret thực tế của VM.
- [Ubuntu Snapshot Service](https://snapshot.ubuntu.com/), nguồn gói cũ dùng khi phục hồi.
- [Jenkins Plugin Installation Manager 2.15.0](https://github.com/jenkinsci/plugin-installation-manager-tool/releases/tag/2.15.0).

Các kết luận sự cố trong write-up dựa vào chứng cứ của bài lab; các tài liệu trên là nguồn công cụ và nguồn đối chiếu kỹ thuật.
