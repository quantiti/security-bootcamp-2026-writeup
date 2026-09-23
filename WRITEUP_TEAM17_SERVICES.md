# Security Bootcamp Arena 2026 — Từ hạ tầng bị mã hóa đến phục hồi dịch vụ và siết firewall

**Phạm vi:** Điều tra và phục hồi các máy Linux bị mã hóa Palimpsest, phân tích chiến lược ứng cứu, kiểm chứng kết quả và gia cố đường truy cập mạng.  
**Thời điểm của chứng cứ thực hành:** chủ yếu ngày 11/09/2026.  
**Tài liệu bối cảnh:** bản PDF mô tả Arena 2026 do người dùng cung cấp; trích dẫn theo số trang PDF.

## 1. Bài toán chúng tôi nhận được

Security Bootcamp Arena 2026 là một đấu trường Attack & Defense: mỗi đội nhận một máy chủ vật lý chứa hạ tầng doanh nghiệp giả lập đã bị ransomware tác động. Đội phải khôi phục dịch vụ, điều tra dấu vết xâm nhập và bảo vệ hệ thống khi các đội khác bắt đầu tấn công. Đó là một bài toán vận hành có đối thủ: dịch vụ vừa được đưa lên có thể lập tức trở thành mục tiêu. Theo mô tả BTC, hệ thống phải hoạt động ổn định tối thiểu 10 phút để đáp ứng điều kiện phục hồi; các dịch vụ giám sát của BTC phải được duy trì. 

Trong tình huống này, chỉ có trang web trả HTTP 200 chưa đủ. Chúng tôi cần trả lời đồng thời bốn câu hỏi:

1. Những file nào thực sự bị mã hóa, và dữ liệu nào còn có thể cứu?
2. Làm thế nào đưa dịch vụ lên trong lúc chưa tìm đủ vật liệu giải mã?
3. Làm sao biết bản rõ thu hồi là đúng, đặc biệt với khóa ứng dụng và cấu hình?
4. Sau khi phục hồi, những đường truy cập nào phải siết mà vẫn đáp ứng yêu cầu của đấu trường?

Kết quả nổi bật là phục hồi Jenkins từ dữ liệu còn sót trong RAM/đĩa, sau đó tìm được frame phục vụ giải mã Palimpsest trong RAM Edge-proxy và K3S. Lượt giải mã nhiều máy ghi nhận **662 file được xác thực và thay thế**; nguồn đĩa Edge-proxy có thêm **101/101 container giải mã thành công**. Tuy nhiên, kết quả giải mã không đồng nghĩa hệ thống đã an toàn: kiểm tra sau gia cố vẫn thấy Edge bị bypass bằng Host là IP, còn một lượt điều tra sau đó xác nhận pfSense bị chiếm tài khoản quản trị. 

## 2. Hiểu hệ thống trước khi sửa từng máy

### 2.1. Một doanh nghiệp thu nhỏ trên ESXi

Theo sơ đồ BTC, mỗi đội có một vùng WAN riêng, pfSense làm firewall/router và các máy ảo nằm trên ESXi. Trong bằng chứng đang xét, WAN pfSense là `10.10.117.2`, ESXi là `10.10.117.3`.;  
| Vùng mạng | Thành phần chính | Vai trò trong bài |
|---|---|---|
| VLAN 201 — `172.16.201.0/24` | Edge-proxy .102, Gitea .103, CI-runner .104 | Web công khai, mã nguồn và thực thi job CI |
| VLAN 202 — `172.16.202.0/24` | Jenkins .105, K3S/ArgoCD .106, npm-registry .107 | Tự động hóa, triển khai ứng dụng và kho package |
| VLAN 203 — `172.16.203.0/24` | DNS/NFS .109, app-runner .110 | Phân giải tên, dữ liệu chia sẻ và ứng dụng đích |
| Vùng quản trị `172.16.204.0/24` | Máy quản trị của đội | Đường vào để điều tra, phục hồi, kiểm tra |
| Mạng BTC `10.10.0.0/24` | SIEM .8, CTFd .10 | Thu log, giám sát và tính điểm |

Vùng khách hàng VLAN 20 còn có Web, VPN, domain controller và workstation. Chúng xuất hiện trong phần FW vì có cổng thuộc checklist BTC; 

### 2.2. Vì sao các dịch vụ liên quan chặt chẽ với nhau?

MegaCorp trong bài lab dùng một chuỗi phát triển và triển khai phần mềm: Gitea lưu mã nguồn, CI-runner/Jenkins chạy tự động hóa, ArgoCD đồng bộ manifest từ Git vào K3S, Verdaccio cung cấp package NPM, app-runner tải package để chạy. DNS cung cấp tên nội bộ; NFS chia sẻ dữ liệu cấu hình cho nhiều máy.

Sơ đồ rút gọn dưới đây thể hiện chuỗi rủi ro được mô tả trong đề, không phải mọi kết nối ứng dụng hay toàn bộ sự kiện đã quan sát:

```text
WAN của các đội khác
        |
        v
pfSense: WAN 8000 -> Edge:80        WAN 8080 -> Jenkins:8080
        |                                      |
        v                                      |
Edge bị điều khiển đích proxy                   |
        |                                      |
        v                                      |
Gitea -> token/credential -> Jenkins hoặc Git/ArgoCD
                                   |
                                   v
                         Verdaccio npm-registry
                                   |
                                   v
                     app-runner cài package mới

DNS/NFS cung cấp các phụ thuộc cho nhiều mắt xích trên.
```

Đề Supply Chain mô tả năm giai đoạn: đi qua Edge bằng Host Header Injection, lấy token Gitea, tiếp cận Jenkins hoặc sửa manifest ArgoCD, đưa package vào Verdaccio, rồi để app-runner cài package có lifecycle script. “Host Header Injection” ở đây có nghĩa client thay header `Host` để Nginx chọn một dịch vụ nội bộ làm đích proxy. Nếu dịch vụ sau đó dùng token có quyền lớn, một yêu cầu web ở biên có thể tiến sâu vào chuỗi triển khai. 

Điều này giải thích vì sao phục hồi từng VM riêng lẻ chưa giải quyết xong bài toán. Khi DNS/NFS chưa lên, ứng dụng phụ thuộc vẫn lỗi; khi khôi phục nguyên cấu hình lab, các đường tấn công có chủ đích trong đề cũng hoạt động trở lại.

### 2.3. Những ràng buộc quyết định chiến lược

BTC yêu cầu **giữ mở WAN 8000 và 8080**. Đề cũng liệt kê cổng giám sát cho DC, workstation, VPN và quản trị. Đóng hết đường vào có thể làm giảm tấn công nhưng đồng thời làm dịch vụ không đạt yêu cầu. Phần siết FW vì vậy phải bắt đầu từ danh sách luồng bắt buộc và quyền truy cập ứng dụng. 

## 3. Chiến lược ứng cứu: giảm thời gian ngừng dịch vụ, vẫn giữ khả năng chứng minh

### 3.1. Hai hướng phục hồi được triển khai trong quá trình xử lý

Hướng thứ nhất là tìm dữ liệu còn sót: cấu hình trong page cache RAM, khóa hoặc job trong block đĩa, thư mục ứng dụng đã bung sẵn. Hướng này tạo cơ hội đưa dịch vụ lên sớm dù chưa biết đủ khóa ransomware.

Hướng thứ hai là phân tích Palimpsest và xây bộ đọc container có xác thực. Nếu tìm đủ vật liệu, hướng này có thể lấy lại đúng nội dung gốc trên nhiều máy, gồm cả file log mà cài lại phần mềm không phục hồi được.

| Quyết định | Lý do | Tiêu chí để tiếp tục |
|---|---|---|
| Giữ bản mã và phân tích trên bản sao | Thao tác ghi có thể phá dữ liệu còn sót hoặc làm mất dấu vết | Có backup, hash và đường dẫn nguồn rõ ràng |
| Thử carving khi thiếu frame | Cần phục hồi dịch vụ trong thời gian hữu hạn | Ứng viên được kiểm tra bằng cấu trúc, nội dung và cơ chế mật mã của ứng dụng nếu có |
| Chỉ xuất plaintext sau xác thực AEAD | Một khóa sai vẫn có thể tạo dữ liệu trông ngẫu nhiên hoặc giống văn bản | Tag hợp lệ, chiều dài đúng, đường dẫn và header đúng |
| Khôi phục chương trình từ nguồn sạch khi phù hợp | Executable bị mã hóa làm công cụ sửa chữa cũng không chạy | Đúng phiên bản, đối chiếu checksum và kiểm tra khả năng chạy |
| Xác minh dịch vụ theo chuỗi phụ thuộc | Host chạy chưa có nghĩa ứng dụng chạy | DNS/NFS, service, endpoint và chức năng liên quan được kiểm tra |
| Gia cố sau khi hiểu baseline | Tránh chặn nhầm luồng BTC hoặc làm pipeline đứt | Có kiểm thử cho luồng được phép và luồng bị chặn |

Đây là cách tổng hợp logic từ các bước đã ghi nhận; hồ sơ không đủ để khẳng định một lịch phân công cụ thể giữa từng thành viên.

### 3.2. Ba mức thành công cần tách rõ

**Phục hồi file:** đã lấy được đúng nội dung theo kiểm tra mật mã hoặc chứng cứ ứng dụng.

**Phục hồi dịch vụ:** chương trình chạy, có listener, phản hồi đúng ở các chức năng đã thử.

**Phục hồi an toàn:** credential, cấu hình và đường truy cập đã được kiểm soát, không còn đường tái xâm nhập đã biết.

Jenkins có thể đạt mức dịch vụ hoạt động trước khi giải mã được container Palimpsest. Edge có thể đạt 101/101 container hợp lệ nhưng vẫn có đường proxy nguy hiểm. Các kết luận này giúp tránh báo cáo “đã xong” chỉ vì một chỉ báo tốt.

## 4. Thu thập và xác định đúng dữ liệu bị mã hóa

### 4.1. Chứng cứ đầu vào

Với Jenkins, đầu vào gồm hai file RAM `.vmem`, mỗi file 4 GiB, đi kèm `.vmss`/`.vmsn` VMware. Metadata VMware giúp diễn giải ánh xạ; không đếm chúng thành các bản RAM độc lập. Volatility 3 cùng symbol Ubuntu `6.8.0-139-generic` được dùng để đọc cấu trúc kernel, tiến trình và page cache; Python/mmap hỗ trợ quét byte và ghi offset. [2]

Trên host, nhiều filesystem root đang ở `ro,relatime`. BusyBox và Python còn dùng được trên các máy fleet, tạo đường để kiểm tra trạng thái và chuẩn bị phục hồi. Các artifact được thu gồm mẫu ELF, SVG đầu vào, container nạn nhân, inventory, log, vật liệu dẫn xuất và kết quả kiểm tra.

Việc xuất hiện hàng loạt lỗi systemd được đối chiếu với file chương trình/cấu hình không còn đúng định dạng và filesystem chỉ đọc. Không khởi động lại liên tục mọi service trước khi sửa nguyên nhân nền.

### 4.2. Tránh bẫy từ khóa trong RAM

RAM có nhiều tên ransomware và chuỗi giống thông báo tống tiền, nhưng một phần thuộc rule của agent bảo vệ. Tương tự, đuôi `.enc` không đủ chứng minh một file là nạn nhân. Nhóm kết hợp ba loại bằng chứng:

- Mảnh dòng lệnh liên quan Palimpsest, SVG và danh sách file đích.
- Binary có import/luồng xử lý mã hóa và định dạng `SBC2026`.
- File thực tế có header container, kích thước, CRC và hash đường dẫn phù hợp.

Tám vị trí chứa mảnh dòng lệnh trong RAM không được diễn giải thành tám lần chạy. Metadata file gần nhau ở ngày 07/09 UTC là dấu thời gian file, chưa phải audit chứng minh thời điểm chương trình được thực thi. Tương tự, chưa có cơ sở gộp sự kiện mã hóa ban đầu với mọi cuộc tấn công diễn ra sau khi Arena mở. [2]

### 4.3. Bảo toàn trước khi ghi

Backup Edge `pre-recovery.tar` là bản sao có phạm vi, không phải ảnh đĩa đầy đủ. Trong lượt fleet, script giải mã trước vào staging; trước khi thay file, script kiểm tra lại hash cả ciphertext và plaintext, tạo archive các file sắp sửa, flush/fsync rồi đọc lại archive để so hash từng member.

Nhờ đó, một thao tác sửa không xóa mất khả năng trả lời “file trước sửa chứa gì?” hoặc “bản đang dùng có đúng là đầu ra đã xác thực không?”. Các log có ghi nối sau mã hóa được giữ riêng thay vì ép về định dạng mong muốn.

## 5. Phân tích Palimpsest và xây bộ đọc có xác thực

### 5.1. Từ mẫu ELF đến định dạng container

Mẫu `/opt/palimpsest/palimpsest` được khôi phục từ page cache Jenkins có kích thước 48.966.880 byte; `archivist.svg` dài 786.699 byte. Phân tích binary thấy ChaCha20-Poly1305, HMAC và thao tác xử lý file. SHA256 mẫu dùng để đối chiếu routine là:

```text
832b58a91f1c874167f2956f24c574fb9012328362aec6edd55418d145ae3989
```

Container có 100 byte header, ciphertext và tag 16 byte. Với plaintext dài `N`, tổng file phải dài `N + 116` byte:

| Offset | Độ dài | Nội dung |
|---|---:|---|
| `0x00` | 8 | Magic `SBC2026\0` |
| `0x08` | 2 | Phiên bản/thuật toán; bộ đọc chấp nhận `02 01` |
| `0x0A` | 2 | Mode theo phân tích định dạng |
| `0x0C` | 8 | Kích thước plaintext, little-endian |
| `0x14` | 8 | Kích thước ciphertext |
| `0x1C` | 32 | SHA256 đường dẫn tuyệt đối gốc |
| `0x3C` | 16 | Salt |
| `0x4C` | 12 | Nonce |
| `0x58` | 8 | Trường bổ sung nằm trong header được xác thực |
| `0x60` | 4 | CRC32 của 96 byte đầu |
| `0x64` | Biến đổi | Ciphertext và tag Poly1305 16 byte |

Ví dụ, container `master.key` của Jenkins dài 372 byte ứng với dữ liệu gốc 256 byte. Cấu hình Nginx Edge dài 4.891 byte ứng với bản gốc 4.775 byte. Các quan hệ này giúp loại ứng viên bị cắt hoặc không đúng loại. Chúng chưa chứng minh đã tìm được khóa. 

### 5.2. Ba vật liệu cần có

Bộ đọc cần **identity của host**, **fingerprint 32 byte được xử lý từ SVG**, và **frame PRI1 dài 48 byte**. “Frame” ở đây là một khối dữ liệu đầu vào của quá trình dẫn xuất khóa, gồm magic `PRI1` và 44 byte còn lại.

Script `derive.py` ánh xạ ELF phục vụ phân tích và gọi có kiểm soát các routine lấy dữ liệu cần thiết. Nó kiểm tra hash binary, chặn một số import ghi/mã hóa, chỉ cho `fopen` đọc và vô hiệu hóa entry point/đường điều phối liên quan trong bản ánh xạ. Các routine được dùng gồm:

| Địa chỉ routine | Vai trò trong script |
|---|---|
| `0x402aee` | Parse SVG |
| `0x400fd8` | Lấy fingerprint |
| `0x40564c` | Thu host profile |
| `0x4040d6` | Thực hiện bước dẫn xuất đã phân tích |
| `0x4062bd` | Lấy identity |

Địa chỉ trên gắn với đúng hash mẫu, không áp dụng tùy ý cho binary khác. Fingerprint cũng không được thay bằng SHA256 nguyên file SVG. Kết quả material archive của sáu máy fleet có identity dài 141 byte, fingerprint 32 byte và frame 48 byte; cùng độ dài không chứng minh cùng giá trị. [5]

### 5.3. Công thức dẫn xuất và tiêu chí giải mã

Logic trong `palimpsest_recover.py`:

```text
IKM = "PALIKM4"
      || uint16_le(len(identity))
      || identity
      || frame[4:48]
      || fingerprint

PRK = HMAC-SHA256(key=salt, data=IKM)
K   = HMAC-SHA256(key=PRK, data="PALINFO-VAULT-v4" || 0x01)

plaintext = ChaCha20Poly1305(K).decrypt(
    nonce              = blob[76:88],
    ciphertext_and_tag = blob[100:],
    associated_data    = blob[0:100]
)
```

AEAD là cơ chế vừa giải mã vừa xác thực dữ liệu. Với bài này, header cũng tham gia xác thực, nên sửa header tùy tiện không giúp “cứu” một container hỏng.

Bộ đọc kiểm tra magic, phiên bản, kích thước vật liệu, SHA256 đường dẫn gốc, CRC32 và chiều dài container trước khi kiểm tra tag. Sai tag trả `Authentication failed; no plaintext released`. Plaintext chỉ được trả khi xác thực thành công và chiều dài đầu ra đúng.

Đường dẫn dùng phải là `/etc/hostname` trên máy nạn nhân, không phải đường dẫn bản sao trên Windows. Salt lấy theo từng container; việc dùng chung frame giữa vài host không làm cho mọi khóa file giống nhau.

## 6. Khi chưa có frame: phục hồi Jenkins từ dữ liệu còn sót

Jenkins là ví dụ cho quyết định không chờ vô hạn một hướng giải mã còn thiếu dữ liệu. Ở giai đoạn này, nhóm đã xây được bộ đọc nhưng chưa tìm đủ frame để xác thực container Palimpsest của Jenkins.

### 6.1. Cấu hình trong RAM, khóa và job trên đĩa

Trong Snapshot6, `config.xml` dài 2.560 byte được lấy từ offset RAM `0x0b904000`, parse XML thành công và giữ `useSecurity=true`. Quét thiết bị khối LVM theo chunk/block 4 KiB tìm được các ứng viên:

| Dữ liệu | Offset trong thiết bị khối LVM | Kích thước |
|---|---|---:|
| `master.key` Jenkins | `0x88e714000` | 256 byte |
| Unit Jenkins | `0x68848c000` | 920 byte |
| Configuration as Code | `0x68852a000` | 1.837 byte |
| Job `deploy-production` | `0x88e735000` | 1.990 byte |

Offset RAM và offset đĩa thuộc hai không gian địa chỉ khác nhau. Chỉ chép một offset vào công cụ đọc nguồn khác sẽ lấy sai dữ liệu.

Khóa Jenkins ứng viên được kiểm tra với secret `hudson.model.User.DIRNAMES`: dẫn xuất theo cơ chế Jenkins, giải mã, kiểm tra padding và hậu tố `::::MAGIC::::`. Nhờ bước này, nhóm chọn khóa dựa trên kiểm chứng, không chỉ vì tìm thấy một chuỗi hex dài đúng 256 byte. Không tạo khóa mới vì khóa mới sẽ không mở được secret cũ. [2]

### 6.2. Dựng lại chương trình và kiểm tra dịch vụ

WAR Jenkins bị mã hóa nhưng thư mục WAR đã bung sẵn còn đọc được. Script dựng lại WAR kiểm tra manifest, entry point Java, CRC các JAR và cấu trúc ZIP, rồi chạy `--version`. WAR dựng lại không được khẳng định giống từng byte với archive gốc.

Các executable hệ thống bị mã hóa được thay bằng file sạch đúng phiên bản, đối chiếu metadata gói/checksum. Nhật ký phục hồi có sử dụng nguồn gói chính thức và snapshot; tài liệu BTC mô tả mạng offline nên chi tiết này không chứng minh VM thi đấu có Internet. Kênh đưa gói vào môi trường phải được hiểu trong giới hạn chứng cứ thực tế.

Jenkins 2.568.2 sau đó trả HTTP 200 ở trang login và API có xác thực; API chưa xác thực trả 403, job `deploy-production` hiện diện. Đây là **phục hồi bằng bản rõ còn sót và chương trình thay thế**. Không cộng Jenkins vào tổng container Palimpsest đã giải mã. [2]

## 7. Bước ngoặt: tìm frame trong RAM Edge và K3S

### 7.1. Edge-proxy: thay cách tìm dữ liệu

Trên Edge, tìm magic `PRI1` ở dạng binary ban đầu chỉ dẫn tới chuỗi trong ELF. Nhóm mở rộng tìm kiếm sang các biểu diễn văn bản:

- `50524931`: prefix hex của `PRI1`.
- `UFJJM`: prefix dùng để tìm ứng viên base64.
- `PALIKM4` và `expand 32-byte k`: marker hỗ trợ phân tích dẫn xuất/trạng thái ChaCha.

Frame đầy đủ được ghi nhận tại offset `0xeca0a000` trong `Team24_edge-proxy-Snapshot6.vmem`. Sau decode, ứng viên dài đúng 48 byte. Giá trị quyết định của ứng viên đến từ việc nó xác thực được các container khi kết hợp identity Edge và fingerprint SVG. [3][5]

Trước khi có frame, cấu hình Nginx gốc đã được carve từ đĩa tại `0x68ee04000`. Sau giải mã, bản carve được đối chiếu khớp bản rõ xác thực. Điều đó biến một ứng viên cấu hình từng có độ tin cậy dựa trên cấu trúc/thử nghiệm thành dữ liệu được kiểm chứng thêm bằng mật mã.

### 7.2. Vì sao RAM chỉ giải mã được một phần?

`decrypt_archives.py` đọc archive nguồn đĩa và nguồn RAM, chọn file có magic, phục hồi đường dẫn gốc rồi gọi bộ đọc. Kết quả:

| Nguồn Edge | Container kiểm tra | Xác thực được | Từ chối |
|---|---:|---:|---:|
| `pre-recovery.tar` từ đĩa | 101 | 101 | 0 |
| File trích RAM | 103 | 44 | 59 |

59 bản RAM thiếu chiều dài container. Một file nhìn thấy trong page cache có thể chỉ còn một phần trang; nó không tương đương bản hoàn chỉnh trên filesystem. Không ghép “có header đúng” thành kết luận “có đủ ciphertext và tag”.

145 lần xác thực gồm các đường dẫn xuất hiện ở cả hai nguồn. Bài chỉ dùng 101 container nguồn đĩa khi tổng hợp số lượng Edge, tránh đếm trùng.

### 7.3. K3S: cùng mẫu mã hóa nhưng cần frame khác

Frame Edge dùng được cho Gitea, CI-runner, Verdaccio, DNS và app-runner khi kết hợp identity riêng từng host. K3S trả lỗi xác thực.

Script `scan_frames.py` tiếp tục tìm hex/base64 trong các snapshot, decode ứng viên, yêu cầu magic/chiều dài đúng và loại trùng. Manifest ghi frame riêng trong `Team24_k3s-argocd-Snapshot6.vmem` tại `0x1405484b0`. Frame đó xác thực được 113 file K3S. Lỗi trong `k3s-key-test.txt` thuộc lần thử trước; nó không phủ định kết quả của lần dùng frame đúng sau đó. [4][5]

Bài học chiến lược ở đây là chuyển giả thuyết khi có kiểm chứng âm tính: mẫu ELF giống nhau không đủ để giả định cùng toàn bộ vật liệu khóa.

## 8. Mở rộng giải mã sang các host và xử lý ngoại lệ

### 8.1. Từ một file đúng đến kế hoạch phục hồi có kiểm soát

`recover_host.py` quét regular file dưới `/etc`, `/usr`, `/var`, `/opt`, `/home`, `/root`. Mỗi file có magic được đưa qua xác thực; plaintext hợp lệ vào staging, còn lỗi ghi riêng.

Kế hoạch chứa path, mode, UID/GID, hash ciphertext/plaintext và số byte. Khi áp dụng, script kiểm tra lại hash, remount root, tạo backup mới, đọc lại backup, rồi ghi file tạm cùng thư mục và dùng `os.replace`. Mode và owner được lấy theo inventory đã ghi, không chỉ tin vào hai byte mode trong header.

Quy trình này cho phép dừng trước bước ghi nếu file nguồn đã thay đổi giữa lúc phân tích và lúc sửa. Đây là điểm quan trọng trong một hệ thống vẫn có service và người khác tác động.

### 8.2. Kết quả theo máy

| Máy | Lượt chính | Lượt bổ sung | Kết quả kiểm tra sau phục hồi |
|---|---:|---:|---|
| Gitea | 110 | 0 | Gitea/Nginx chạy, HTTP 200 |
| CI-runner | 116 | 0 | Giữ đăng ký runner cũ, khai báo với Gitea thành công |
| K3S/ArgoCD | 113 | 0 | Node Ready; sau xử lý image policy, 7 pod ArgoCD Running |
| Verdaccio | 104 | 2 | Ping và metadata registry HTTP 200 |
| DNS/NFS | 104 | 8 | Unbound kiểm tra cấu hình thành công, dữ liệu NFS được phục hồi |
| app-runner | 105 | 0 | Watcher kết nối registry, cài package 1.0.0 |
| **Tổng fleet** | **652** | **10** | **662 file được thay bằng plaintext xác thực** |

Edge có thêm 101 container đĩa xác thực; Jenkins phục hồi bằng phương pháp ở phần 6. Không dùng tổng này để tuyên bố mọi file của tám máy đã được giải mã. [3][4]

### 8.3. Verdaccio: file bị ghi tiếp sau mã hóa

Lượt chính báo `Container length mismatch` với `lastlog` và `wtmp`. Phân tích riêng cho thấy container gốc của `lastlog` xác thực thành plaintext rỗng nhưng có 292.176 byte ghi nối phía sau. `wtmp` vẫn thất bại AEAD.

Nhóm giữ nguyên hai log và bảo toàn archive riêng. Chúng không được tính vào số file phục hồi. Cắt phần đuôi hoặc ép chiều dài để ghi đè có thể làm mất chính dữ liệu phát sinh sau sự cố.

Quét bổ sung `/verdaccio` xác thực 2 file, tổng 2.508 byte. Trường hợp này cho thấy “quét các thư mục hệ thống” chưa bao phủ mọi đường dẫn dữ liệu ứng dụng.

### 8.4. DNS/NFS và K3S: phân biệt lỗi dữ liệu với lỗi phụ thuộc

Script bổ sung quét `/export`, `/shared`, `/srv` trên dns-ops, xác thực 8 file, tổng 2.839 byte. Với bind mount hoặc share, đường dẫn đưa vào bộ đọc vẫn phải khớp SHA256 đường dẫn gốc trong container.

K3S đã lên nhưng ArgoCD còn `ErrImagePull` vì cố kéo image trong môi trường không truy cập được registry ngoài. Sau lưu workload spec, image policy được chuyển từ `Always` sang `IfNotPresent` để dùng image cache, không đổi image version. Đây là bước sửa vận hành sau giải mã; không tính nó là thành công mật mã.

## 9. Siết firewall để giữ được thành quả phục hồi

### 9.1. Mục tiêu và bằng chứng thực tế

FW phải bảo vệ cả hai mặt: **dịch vụ bên trong** và **quyền quản trị chính firewall**. Nếu tài khoản pfSense bị chiếm, đối thủ có thể sửa NAT và rule, làm mất hiệu lực các giới hạn trước đó.

Hồ sơ hiện có ghi nhận các thay đổi và trạng thái sau:

| Nội dung | Chứng cứ hiện có | Kết luận có thể rút ra |
|---|---|---|
| Giữ NAT WAN 8000 → Edge:80, 8080 → Jenkins:8080 | Báo cáo IR, NAT/rule/state và HTTP nội bộ | Có cấu hình và có lưu lượng tại một số thời điểm; không chứng minh SLA liên tục |
| Tắt một số NAT WAN nhạy cảm DC/WS | Báo cáo IR tổng hợp | Đã ghi nhận thao tác, nhưng phải rà lại với checklist BTC trước khi coi là cấu hình đạt yêu cầu |
| Rule hạn chế GUI pfSense 8386 ngoài mạng BTC | Snapshot WAN rules có rule `Block WAN GUI except BTC core 10.10.0.0_24` | Có rule trong snapshot; chưa đủ chứng minh mọi đường quản trị/session đều được kiểm soát |
| Rule chặn WAN DNS và rule IPv6 | Snapshot WAN rules | Có cấu hình được ghi nhận; phạm vi, thứ tự và tác động SLA cần đối chiếu |
| NAT tới ESXi 9443/9022 do nguồn bất thường thêm | Auth log và config history | Control plane đã bị compromise; chưa có xác nhận containment hoàn tất |

Nguồn kiểm tra `post-pfsense-services.json` thấy CMS/Jenkins nội bộ HTTP 200 nhưng tự probe WAN 8000/8080 bị timeout. Điều này không cho phép tự động kết luận “FW đã chặn WAN”: còn khả năng NAT reflection, vị trí máy kiểm tra, gateway hoặc state. Báo cáo khác có state từ nguồn ngoài. Chúng là các lát cắt thời gian/vị trí khác nhau và cần được giữ nguyên giới hạn. [6][8][9]

### 9.2. Đối chiếu lại với luật đấu trường

PDF yêu cầu giữ 8000/8080 cho mọi đội tiếp cận bề mặt thi đấu. Vì vậy, allowlist chỉ IP BTC vào hai cổng này sẽ không đáp ứng mô tả bài.

PDF còn có checklist DC, workstation, VPN và management. Ví dụ DC có DNS/Kerberos/LDAP/SMB/LDAPS và các cổng phụ trợ; workstation có các cổng NAT riêng cho WinRM/RDP; management có 2301/2302/2303/2322. Danh sách cổng động DC trong PDF có chuỗi `50000/50050/50100`, nên cần đối chiếu checklist bàn giao thực tế trước khi chuyển thành rule. [1, tr. 14–15]

Do đó, thao tác tắt NAT DC/WS trong báo cáo trước chỉ được trình bày là **biện pháp ứng cứu đã ghi nhận, còn cần kiểm tra tác động yêu cầu thi đấu**. Không dùng nó làm bằng chứng rằng cấu hình FW cuối đã đúng toàn bộ luật. Hướng cải thiện là kiểm soát tài khoản/quyền, rule theo phạm vi được cho phép và kiểm thử chức năng thay vì mặc định đóng dịch vụ nằm trong checklist.

### 9.3. Bảo vệ đường quản trị trước

Lượt điều tra pfSense lúc 15:02–15:03 ICT ghi nhận successful login admin từ WAN đội khác. Nguồn `10.10.123.2` gọi XMLRPC và thêm NAT:

```text
WAN TCP/9443 -> ESXi 10.10.117.3:443
WAN TCP/9022 -> ESXi 10.10.117.3:22
```

Sau một lần chỉnh tài khoản admin vẫn có login thành công. Có thể còn credential hoặc session/cơ chế truy cập khác; chỉ đổi password chưa chứng minh đã loại bỏ quyền truy cập. Chưa có bằng chứng đủ để khẳng định shell trên pfSense hoặc login ESXi thành công. [8]

Trình tự xử lý cần hoàn thiện từ trạng thái này:

1. Giữ một đường quản trị tin cậy, lưu config hiện tại và log để tránh mất khả năng khôi phục.
2. Giới hạn GUI/SSH firewall theo nguồn quản trị được phép; kiểm tra thứ tự so với rule rộng, floating rule và các đường truy cập khác.
3. Diff cấu hình để gỡ đúng NAT/rule bất thường, rà user và XMLRPC sync. Không rollback mù toàn bộ làm mất thay đổi hợp lệ.
4. Rotate credential và vô hiệu hóa session từ máy quản trị sạch; kiểm tra lại đăng nhập từ nguồn không được phép.
5. Đối chiếu ESXi audit, kiểm tra NAT bắt buộc và lưu config sau thay đổi.

Đây là kế hoạch hoàn thiện containment dựa trên log, không phải tuyên bố năm bước đã hoàn tất.

### 9.4. Ma trận luồng cần giữ và vị trí đặt kiểm soát

Ma trận sau là thiết kế rút ra từ mô hình và sự cố. Các flow ứng dụng cần được kiểm tra với baseline thực tế trước khi triển khai:

| Luồng | Chính sách mục tiêu | Vị trí kiểm soát phù hợp |
|---|---|---|
| WAN → Edge 8000, Jenkins 8080 | Giữ dịch vụ công khai theo đề; hạn chế hành vi nguy hiểm ở ứng dụng | pfSense NAT/rule kết hợp Nginx và phân quyền Jenkins |
| Nguồn quản trị được phép → GUI/SSH pfSense, ESXi | Chỉ mở đúng nguồn/cổng quản trị được xác nhận | Rule quản trị và cấu hình dịch vụ |
| Edge → Gitea trong cùng VLAN 201 | Chỉ cho backend nghiệp vụ thực sự cần; không nhận đích tùy ý từ Host | Nginx upstream cố định và host firewall hoặc tách VLAN |
| Edge VLAN 201 → Jenkins/K3S/registry VLAN 202 | Chặn các đường pivot không cần; ngoại lệ theo flow được xác nhận | Rule liên VLAN pfSense và quyền ứng dụng |
| Client nội bộ → DNS/NFS VLAN 203 | Cho đúng client và dịch vụ; kiểm tra cả DNS UDP/TCP, NFS theo cấu hình thực tế | pfSense liên VLAN, quyền export và host firewall |
| CI/Jenkins/ArgoCD → Git/registry | Duy trì đọc/build/publish được ủy quyền | Rule host khi cùng VLAN, token và quyền ứng dụng |
| app-runner → registry | Giữ tải package hợp lệ; kiểm soát version và lifecycle script | pfSense liên VLAN và cấu hình consumer |
| Máy lab → dịch vụ BTC | Giữ telemetry, giám sát và luồng bài lab | Rule riêng theo endpoint/protocol đã xác nhận |

**Điểm dễ bỏ sót:** Edge, Gitea và CI-runner cùng subnet. Lưu lượng giữa chúng thường được chuyển mạch trực tiếp, không đi qua pfSense liên VLAN. Tương tự, Jenkins, K3S và Verdaccio cùng VLAN 202. Vì thế không thể chỉ thêm một rule pfSense rồi khẳng định đã cô lập các cặp máy cùng VLAN. Muốn chặn ở các cặp này phải đặt kiểm soát trên host, ứng dụng hoặc thay phân đoạn mạng phù hợp. Đây là phân tích từ sơ đồ mạng, chưa phải bằng chứng đã thay VLAN.

### 9.5. Vì sao FW phải đi cùng sửa proxy và quyền ứng dụng?

Gia cố Edge từng vượt 36/36 ca thử cục bộ, nhưng log sau đó vẫn thấy:

```text
Host: 172.16.201.103:3000 -> Gitea -> HTTP 200
Host: 172.16.202.105:8080 -> Jenkins -> HTTP 200
```

Chặn hậu tố `.megacorp.local` không loại bỏ việc client chọn upstream bằng IP. Biện pháp xử lý gốc là route tới upstream cố định hoặc map Host được cho phép sang đích đã định sẵn; FW giới hạn nơi Edge có thể kết nối để giảm tác động nếu lớp proxy còn lỗi.

Báo cáo sau gia cố cũng ghi Jenkins chặn Script Console, không còn listener 19999; Gitea chưa có commit mới sau commit phục hồi trong cửa sổ quan sát; Verdaccio chỉ phục vụ package 1.0.0; app-runner chưa có callback mới trong cửa sổ đó. Các lớp sau đã có tác dụng dù Edge còn bị xuyên qua. Chưa có bằng chứng tái thực thi mã sau gia cố trong cửa sổ được kiểm tra. [7]

### 9.6. Kiểm thử sau đổi FW

Để kết luận một rule giúp phòng thủ mà vẫn giữ dịch vụ, cần kiểm tra từ đúng vị trí:

- **Từ LAN quản trị:** service, DNS, NFS và chức năng ứng dụng cần thiết.
- **Từ WAN hợp lệ:** 8000/8080 vẫn phục vụ, các cổng checklist BTC vẫn đạt chức năng yêu cầu.
- **Từ nguồn bị cấm:** GUI quản trị và đường pivot không cần phải thất bại.
- **Trên FW/host:** rule counter, state, filter log và process/socket tương ứng; kiểm tra đường cùng VLAN tại host.
- **Theo thời gian:** giữ giám sát tối thiểu cửa sổ 10 phút theo đề, không lấy một HTTP 200 làm bằng chứng ổn định.

pfSense là firewall có trạng thái: phiên đang tồn tại có thể khác với kết nối mới sau đổi rule. Việc kiểm tra cần quan sát cả state và thử phiên mới; không xóa toàn bộ state một cách tùy tiện khiến mất phiên quản trị hoặc ngắt luồng BTC. Với hai cổng công khai bắt buộc, không dùng việc tự gọi WAN từ LAN làm phép thử duy nhất.

## 10. Kết quả cuối và giới hạn còn lại

Điểm đạt được rõ nhất là một chuỗi kiểm chứng từ byte dữ liệu tới dịch vụ: nhận diện container, tìm đúng material, AEAD hợp lệ, backup có hash, thay file có kiểm soát và kiểm tra ứng dụng. Jenkins được cứu nhờ dữ liệu còn sót; Edge mở ra hướng tìm frame; K3S chứng minh cần kiểm tra riêng từng host; Verdaccio cho thấy không phải file lỗi nào cũng được phép ghi đè.

Các kết quả định lượng có chứng cứ:

- Fleet: **662 file** đã giải mã xác thực và ghi phục hồi.
- Edge từ archive đĩa: **101/101 container** xác thực; RAM **44/103**, không cộng trùng vào số đĩa.
- Jenkins: cấu hình, khóa và job được thu hồi; dịch vụ/API hoạt động trong phạm vi đã thử, chưa ghi nhận giải mã Palimpsest thành công ở giai đoạn của bài Jenkins.
- K3S: node Ready, 7 pod ArgoCD Running sau xử lý thêm image policy.
- Gia cố: có kiểm soát ứng dụng và rule FW được ghi nhận, nhưng vẫn có Host-IP bypass và sự cố quyền quản trị pfSense cần xử lý tiếp.

Hồ sơ chưa chứng minh đầy đủ SLA liên tục của toàn hệ thống, reboot sau giải mã trên mọi host, mọi pipeline chạy thành công hoặc containment pfSense hoàn tất. Không có cơ sở dùng bản write-up này để khẳng định đội đạt một thứ hạng hay số điểm cụ thể.

## 11. Những điều có thể áp dụng sau bootcamp

**Ưu tiên theo phụ thuộc.** Một máy web có thể được cứu nhanh, nhưng DNS/NFS/registry quyết định cả chuỗi có chạy được không. Hiểu topology giúp đặt đúng thứ tự sửa và đúng vị trí FW.

**Tách mục tiêu cứu dịch vụ và lấy lại dữ liệu gốc.** Carving và dùng chương trình sạch giúp giảm downtime; giải mã có xác thực khôi phục nội dung mà cài lại không cứu được. Hai hướng hỗ trợ nhau.

**Dùng bằng chứng để chọn ứng viên.** Khóa Jenkins được kiểm tra bằng secret có sẵn; frame Palimpsest được kiểm tra bằng tag; cấu hình được đối chiếu cấu trúc, kích thước và hành vi. Dữ liệu “trông đúng” chỉ là điểm bắt đầu.

**Đọc kỹ điều kiện của môi trường.** Offline giải thích một số lỗi cập nhật/image. Cổng bắt buộc mở giới hạn cách siết FW. Thử nghiệm đạt ở LAN chưa chứng minh WAN hoạt động.

**Xem firewall là tài sản cần bảo vệ.** Thiết bị thực thi chính sách bị chiếm quyền có thể tự mở lại đường vào. Quyền quản trị, session, config history và khả năng rollback quan trọng ngang danh sách rule.
