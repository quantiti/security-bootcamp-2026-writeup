# Write-up — "Can You Remember" (Flag 2)

**Challenge:** Can You Remember 2 / 2 (5000 điểm)
**Service:** `http://103.70.12.125:26001`
**Kết quả:** `{"score":1.0,"flag_1":"SBC{f2a9f90d8257a6c9682e0402d220ac6c}","flag_2":"SBC{e99364f589ddb291d068a83a8aede149}"}`

```
FLAG 2 = SBC{e99364f589ddb291d068a83a8aede149}
```

Instance `5d6ac9ad-2706-49c7-9df6-d24e894c42be`: **100/100 câu đúng** (score 1.0, tức đồng thời cả Flag 1 và Flag 2), dùng **696/1000 moves**, **3/3 hearts còn nguyên**, tổng thời gian chạy **205 giây**.

---

## 1. Tổng quan challenge & vì sao Flag 2 khó hơn Flag 1 rất nhiều

Luật chơi giống hệt Flag 1 (xem `WRITEUP_flag1.md`): 20 host, mỗi host 5 warp hai chiều, 3 hearts, 1000 moves, instance sống 1 giờ, quiz 100 câu hỏi về route xuất phát từ entry.

Khác biệt duy nhất là ngưỡng điểm: Flag 1 cần ≥50%, Flag 2 cần ≥99%. Nhưng khoảng cách kỹ thuật giữa hai ngưỡng đó là rất lớn:

- Quiz có 100 câu, tổng cộng **707 warp**, route dài nhất tới **30 warp**.
- Một câu chỉ tính đúng khi **toàn bộ chuỗi family dọc route** khớp — không có điểm từng phần.
- Để trả lời đúng gần như tuyệt đối, bắt buộc phải **dựng lại chính xác 100% đồ thị**: 20 host, mỗi host 5 warp = **100 cạnh có hướng**, cộng đúng family của từng host — mà **không được đi thử từng route dài tới 30 bước** (sẽ cháy hết 1000 move ngay lập tức).

Ba khó khăn cốt lõi khiến bài toán khác hẳn việc "đi thử vài route ngắn" của Flag 1:

1. **API không trả về host id.** `GET /host/current` chỉ có `sample_url`, `solved`, `moves_remaining`, `hearts` — không có gì để biết mình đang đứng ở host nào trong 20 host.
2. **Mẫu sample không phải danh tính của host.** Một instance có thể chỉ dùng vài file malware duy nhất cho toàn bộ 20 host (ví dụ instance thật ở đây chỉ có 3 mẫu: `adylkuzz` ×8, `petya` ×6, `hive` ×4, cộng 2 host `safe`). Nếu dùng hash/kích thước file để nhận diện host thì sẽ **gộp nhầm nhiều host khác nhau thành một**.
3. **Ngân sách 1000 moves, và quiz là cửa một chiều.** Gọi `/sanity-check/questions` là dừng khám phá vĩnh viễn. Phải dựng xong bản đồ đầy đủ **trước khi** mở quiz, và phải làm điều đó trong giới hạn move rất eo hẹp.

---

## 2. Ý tưởng chính

### 2.1 Danh tính thật của một host = "chữ ký" (signature), không phải sample

```
signature(host) = (family của chính nó, family nhìn thấy qua warp 1, 2, 3, 4, 5)
```

Đây là thứ duy nhất phân biệt được hai host tình cờ cùng chứa một file malware giống hệt nhau. Muốn biết signature của host tại route `r`, phải quan sát được family tại `r+w` với mọi hướng `w` — tức phải "nhìn" sâu hơn một bước nữa xung quanh nó.

- Quét (sweep) sâu **2 tầng** (khoảng 50 move) → biết signature của host xuất phát + 5 host tầng 1.
- Quét sâu **3 tầng** → biết signature của toàn bộ host tầng ≤2 (thường ra được 15–19/20 host).

### 2.2 Ba mẹo giúp tiết kiệm move rất nhiều

**(a) Dùng `HEAD` thay vì `GET` để nhận diện mẫu.** Độ dài file zip (`content-length`) ổn định và gần như riêng biệt cho từng mẫu, dù mỗi lần tới host lại được cấp một `sample_url` mới. Vì vậy chỉ cần tải đầy đủ **1 lần cho mỗi mẫu mới** để lấy `sha256` và kích thước, những lần gặp lại chỉ cần `HEAD` (gần như 0 byte tải về). Cách này giảm băng thông tải xuống từ hàng trăm MB còn khoảng 2 MB, và một lượt quét sâu 3 tầng chỉ mất khoảng 93 giây.

**(b) Đi qua host đã biết family là hoàn toàn miễn phí.** Classify đúng không tốn heart, không tốn move riêng (chỉ tốn move của bước `/move` như bình thường). Vì bảng "kích thước → tên family" đã được xác nhận thật từ writeup Flag 1, nên toàn bộ hành trình sau đó gần như không mất heart nào.

**(c) Bảng "kích thước → tên family" dùng lại được giữa các lượt chơi khác nhau,** vì pool mẫu dùng chung. Ở lượt chơi này gặp lại đúng `petya` (230912 byte) và `hive` (677056 byte), khớp ngay bảng cũ từ lần trước, `correct:true` ngay từ lần đoán đầu tiên — không cần đoán mò lại từ đầu.

### 2.3 Suy ra cạnh bằng luật, thay vì đi thử từng cạnh

Đây là phần cốt lõi thay thế cho việc brute-force toàn bộ 100 cạnh bằng cách đi thử:

| Ràng buộc | Nội dung |
|---|---|
| Family | Host ở đầu kia của một warp phải có đúng family như đã "nhìn thấy" trong signature |
| Bậc (degree) | Mỗi host có đúng 5 hàng xóm khác nhau, không có cạnh nối vòng về chính nó |
| Warp hai chiều | Nếu warp `w` từ X dẫn tới Y thì Y có đúng một warp dẫn ngược lại X |
| Bão hoà | Một host đã đủ 5 hàng xóm rồi thì không nhận thêm cạnh nào nữa |
| Khớp lại quan sát | Mọi route đã thực sự đi qua phải mô phỏng ra đúng family đã ghi nhận |

Chỉ với 6 host ở tầng ≤1, toàn bộ 35 cạnh xung quanh chúng đã được biết ngay sau bước quét đầu; phần còn lại được suy luận dây chuyền (constraint propagation) kết hợp với việc "dò hỏi" thêm một vài bước đi có chọn lọc (gọi là probe).

---

## 3. Thuật toán tổng thể

```
Quét sâu 2 tầng (khoảng 50 move)
  ↓
Quét sâu 3 tầng có chọn lọc — bỏ qua nhánh mà host đã được suy ra rồi, không cần đi lại
  ↓
Vòng lặp "dò hỏi" (probe): mỗi lần chỉ đi thêm 4 bước để lấy một mảnh chữ ký còn thiếu
  ↓ sau mỗi lần dò: suy luận lại toàn bộ (propagate) và gắn route vào đúng host đã xác định
Dừng ngay khi chỉ còn ĐÚNG MỘT bản đồ khả dĩ → mô phỏng trả lời cả 100 câu → nộp bài
```

### 3.1 Quét có chọn lọc

Quét đầy đủ sâu 3 tầng lẽ ra tốn tới hơn 300 move. Nhưng ngay sau khi một host mới được xác định danh tính, hệ thống suy luận có thể **suy ra luôn** một số cạnh xung quanh nó mà không cần đi thử (ví dụ: nếu một host tầng 1 chỉ có đúng một hướng dẫn tới family `safe`, thì hướng đó gần như chắc chắn dẫn ngược lại chính host xuất phát — vì host xuất phát luôn `safe` và là hàng xóm của nó). Nhánh nào đã suy luận ra được thì bỏ qua, không cần mở rộng tiếp. Nhờ vậy, ở lượt chơi thật, việc quét bỏ được 7 nhánh con, chỉ còn tốn khoảng 320 move thay vì hơn 375.

### 3.2 Dò hỏi theo vòng ưu tiên host chưa từng gặp

Mỗi lần dò là một chuỗi đi ngắn: tới một host đã biết, rồi đi thêm 2 bước nữa để "nhìn trộm" một mảnh chữ ký của host chưa rõ danh tính đứng sau nó.

Thứ tự ưu tiên khi chọn lần dò tiếp theo:

1. Ưu tiên tuyệt đối những lần dò mà kết quả **chắc chắn dẫn tới một host hoàn toàn mới**, chưa từng gặp trước đó — vì mỗi host mới xuất hiện sẽ kích hoạt hàng loạt suy luận dây chuyền, giúp lộ ra rất nhiều cạnh cùng lúc.
2. Trong số còn lại, ưu tiên theo vòng: mỗi cặp ứng viên còn mơ hồ được lấy 1 mảnh bằng chứng trước khi bất kỳ cặp nào được lấy tới mảnh thứ 2 — tránh dồn hết nỗ lực vào giải quyết một cặp trong khi các cặp khác vẫn mù thông tin.
3. Ưu tiên route ngắn hơn, và ưu tiên cặp còn mơ hồ nhất (nhiều ứng viên khả dĩ nhất) trước.

Kết quả quan sát được trong lượt chơi thật: số host đã xác định tăng đều 17 → 19 → 20; và ngay khi đạt đủ 20/20 host, số cạnh đã biết bất ngờ nhảy vọt từ 38/100 lên 96/100 chỉ sau vài bước — đúng như dự đoán, vì khi không còn "host lạ" nào để nghi ngờ nữa thì luật ràng buộc tự động khoá gần hết các cạnh còn lại.

### 3.3 Bộ giải liệt kê nghiệm — điều kiện dừng đúng đắn

Một bộ giải kiểu backtracking (dò lùi có suy luận) sẽ liệt kê **tất cả** các bản đồ khả dĩ thoả mãn toàn bộ ràng buộc đã nêu ở mục 2.3. Bộ giải này được dùng vào 2 việc:

1. **Dừng sớm để tiết kiệm move:** khi số cạnh còn treo (chưa xác định) đã giảm xuống đủ thấp, thử tìm xem có tối đa 2 bản đồ khả dĩ khác nhau hay không. Nếu chỉ có đúng 1 bản đồ thoả mãn, thì các cạnh còn treo thực ra cũng đã bị ràng buộc quyết định sẵn rồi — có thể dừng đi lại ngay, không cần tốn thêm move để "xác nhận thủ công".
2. **Kiểm chứng cuối cùng bắt buộc:** trước khi tin tưởng bản đồ là đúng, phải mô phỏng lại **toàn bộ** những route đã thực sự đi qua trong suốt quá trình khám phá, và đối chiếu xem có ra đúng family đã ghi nhận ở từng bước hay không (log ghi nhận "observations replayed wrong: 0" — không có sai lệch nào).

Đây chính là điểm mấu chốt khắc phục được lỗi của những lần chơi trước từng chỉ đạt khoảng 68% điểm: những lần đó chấp nhận một host là "đã xác định" chỉ vì đã khớp được 2 mảnh chữ ký và không thấy replay ra lỗi — nhưng việc replay lại đúng những route đã từng đi qua **không đủ** để phát hiện một cạnh bị gán sai; chỉ có việc kết hợp đầy đủ cả ba luật (hai chiều, đúng 5 bậc, và bản đồ là NGHIỆM DUY NHẤT) mới phát hiện được sai sót đó.

---

## 4. Kiểm chứng ngân sách move trước khi tiêu tốn instance thật

Thay vì đoán mò xem 1000 move có đủ dùng không, một trình mô phỏng riêng được viết để: tự sinh ra 59 đồ thị ngẫu nhiên khác nhau (20 đỉnh, mỗi đỉnh đúng 5 hàng xóm, không lặp), gán family theo đúng tỷ lệ đã quan sát thực tế, rồi chạy chính xác thuật toán nói trên trên từng đồ thị giả lập đó.

Kết quả mô phỏng: cả 59/59 lần đều dựng lại đúng chính xác đồ thị gốc (nghiệm duy nhất), với số move dùng dao động 518–997 (trung vị 635) — luôn nằm an toàn dưới ngưỡng 1000. Nhờ bước kiểm chứng offline này, có thể yên tâm rằng thuật toán đủ ngân sách move trước khi thực sự chạy trên instance chính thức, tránh rủi ro cháy move giữa chừng trên lượt chơi chỉ được thử một lần.

---

## 5. Kết quả thực tế trên instance thật

```
INSTANCE 5d6ac9ad-2706-49c7-9df6-d24e894c42be
[  13s] quét sâu 2 tầng xong:  20 host biết 6/20, cạnh biết 9/100   (còn 950 move)
[  93s] quét sâu 3 tầng xong: host biết 17/20, cạnh biết 35/100     (còn 680 move, bỏ được 7 nhánh)
[ 203s] sau 90 lần dò:        host biết 20/20, cạnh biết 96/100     (còn 309 move)
[ 204s] bản đồ đã là nghiệm duy nhất dù còn 2 cạnh chưa "xác nhận thủ công"
[ 204s] hoàn tất bản đồ: 91 lần dò, còn 304 move, host 20/20, cạnh biết 98/100
[ 204s] số bản đồ khả dĩ còn thoả mãn ràng buộc: 1 (đúng 1, không còn nghi ngờ)
[ 204s] kiểm chứng lại toàn bộ observation đã ghi nhận: 0 sai lệch
[ 205s] mở quiz: 100 câu, tổng 707 warp, route dài nhất 30, ngắn nhất 1, 50 câu dạng liệt kê
[ 205s] NỘP BÀI: {"score":1.0,
                    "flag_1":"SBC{f2a9f90d8257a6c9682e0402d220ac6c}",
                    "flag_2":"SBC{e99364f589ddb291d068a83a8aede149}"}
```

### Bản đồ 20 host dựng lại được (host, family, và host đích của từng warp 1–5)

| Host | Family | Warp 1 | Warp 2 | Warp 3 | Warp 4 | Warp 5 |
|---|---|---|---|---|---|---|
| H0 (entry) | safe | 1 | 2 | 3 | 4 | 5 |
| H1 | adylkuzz | 6 | 0 | 7 | 8 | 5 |
| H2 | petya | 9 | 4 | 0 | 8 | 10 |
| H3 | petya | 11 | 12 | 13 | 7 | 0 |
| H4 | adylkuzz | 5 | 2 | 9 | 0 | 14 |
| H5 | hive | 4 | 1 | 15 | 0 | 16 |
| H6 | adylkuzz | 1 | 19 | 8 | 17 | 11 |
| H7 | petya | 14 | 1 | 15 | 3 | 17 |
| H8 | hive | 1 | 6 | 9 | 13 | 2 |
| H9 | adylkuzz | 16 | 4 | 8 | 2 | 14 |
| H10 | adylkuzz | 2 | 16 | 17 | 19 | 18 |
| H11 | adylkuzz | 17 | 3 | 18 | 13 | 6 |
| H12 | hive | 19 | 3 | 14 | 17 | 13 |
| H13 | petya | 3 | 8 | 11 | 12 | 15 |
| H14 | adylkuzz | 18 | 9 | 7 | 12 | 4 |
| H15 | safe | 19 | 18 | 7 | 13 | 5 |
| H16 | hive | 9 | 18 | 5 | 19 | 10 |
| H17 | adylkuzz | 11 | 10 | 12 | 6 | 7 |
| H18 | petya | 11 | 10 | 14 | 15 | 16 |
| H19 | petya | 6 | 15 | 10 | 16 | 12 |

### Trả lời quiz

Sau khi có bản đồ đầy đủ và duy nhất, trả lời quiz chỉ đơn giản là "đi bộ trên giấy" theo route mà mỗi câu hỏi mô tả, dùng bản đồ đã dựng — không cần chạm tới server nữa:

```python
for q in questions:
    route = [int(x) for x in re.findall(r"warp (\d)", q["route_map"])]
    h, path = 0, [fam[0]]
    for w in route:
        h = adj[(h, w)]
        path.append(fam[h])
    ans[q["id"]] = path if "every host" in q["question"] else path[-1]
```

50 câu dạng "single" trả về đúng 1 slug family (family tại host cuối route); 50 câu dạng "list" trả về một mảng có độ dài bằng số warp + 1 (family của toàn bộ các host đã đi qua, tính cả host xuất phát). Gửi sai định dạng (ví dụ trả 1 slug cho câu cần mảng) thì tính 0 điểm dù tên family đúng — đây là một cạm bẫy dễ mắc phải.

---

## 6. Mã nguồn

| File | Vai trò |
|---|---|
| `mz.py` | client gọi API + bảng "kích thước → tên family" + cơ sở dữ liệu hash → family |
| `explore.py` | đi thử 1 route, nhận diện mẫu bằng `HEAD`, classify để mở khoá di chuyển |
| `net.py` | suy luận signature → host, lan truyền ràng buộc, mô phỏng lại route |
| `probe.py` | chọn lần dò tiếp theo theo vòng ưu tiên, ưu tiên host chưa khám phá |
| `solver.py` | bộ giải liệt kê mọi bản đồ khả dĩ còn nhất quán + kiểm chứng cuối |
| `mapper.py` | điều phối: quét có chọn lọc + vòng lặp dò hỏi + dừng khi nghiệm duy nhất |
| `quiz.py` | chuyển route trong câu hỏi thành đáp án (phân biệt câu dạng liệt kê / câu đơn) |
| `run.py` | chạy toàn bộ pipeline trên instance thật, từ đầu tới lúc nộp bài |
| `sim.py` | trình mô phỏng offline để đo trước ngân sách move cần dùng |

Chạy: `python run.py`

---

## 7. An toàn khi xử lý mẫu

Mẫu là **malware thật**. Toàn bộ pipeline tuân thủ nguyên tắc:

- File zip không bao giờ được ghi ra đĩa ở dạng đã giải nén, chỉ mở trong bộ nhớ (RAM) để lấy độ dài và mã hash;
- Không bao giờ thực thi (execute) file `.exe`/`.dll` bên trong;
- Việc nhận diện family chỉ dựa trên kích thước file / mã hash, không cần chạy động (dynamic analysis) mẫu nào cả.

---

## 8. Vì sao các lần chơi trước chỉ đạt 35–67% — và điều này xác nhận nghi vấn cũ

Đây là phần quan trọng nhất đối chiếu với những lần chơi phân tích trước đó (điểm 35%, 44%, 67%, 67%): dữ liệu từ lượt chơi thành công này xác nhận rõ ràng nguyên nhân số 3 từng bị nghi ngờ nhưng chưa chứng minh được — **gán family cho một host mà chưa được chính server xác nhận qua `classify`**.

Bằng chứng đối chiếu trực tiếp từ một lượt chạy thử khác: khi 54 câu hỏi có thể trả lời bằng route đã đi qua, nhưng chỉ 37 trong số đó chạm vào những host đã thực sự được server xác nhận đúng family (17 câu còn lại chạm phải host mà family chỉ được "suy đoán" từ một host khác cùng file, chưa hề classify), thì điểm server trả về đúng bằng 0.37 — khớp chính xác với số câu "đã xác nhận", không phải tổng số câu "khớp route".

Nói cách khác: **copy family từ một host khác chỉ vì chúng dùng chung file mẫu là không đủ** — server chấm điểm dựa trên family đã thực sự đứng trên host đó và được `classify` xác nhận `correct:true`, không phải gán theo suy diễn dù suy diễn đó có vẻ hợp lý. Đây chính là mảnh ghép còn thiếu của bí ẩn "47 câu chắc chắn đúng nhưng chỉ được tính 35 câu" ở các lần chơi trước.

---

## 9. Bài học rút ra

1. **Không dùng hash hay kích thước file làm danh tính của host** — nhiều host khác nhau có thể dùng chung một mẫu byte-identical; danh tính thật của host là "chữ ký" (gồm family của chính nó và family của cả 5 hàng xóm), không phải bản thân file.
2. **Dùng `HEAD` thay vì `GET` để nhận diện lại một mẫu đã biết** — giảm băng thông tải xuống gần như bằng không, giúp quét được sâu hơn trong cùng ngân sách move.
3. **Đừng ưu tiên "dò cặp ít ứng viên nhất"** — cách này tốn rất nhiều move chỉ để loại trừ dần giả thuyết. Ưu tiên tìm ra host hoàn toàn mới trước, vì mỗi host mới sẽ kích hoạt hàng loạt suy luận dây chuyền giúp lộ ra rất nhiều cạnh cùng lúc.
4. **Chỉ tin bản đồ khi nó là NGHIỆM DUY NHẤT được chứng minh, không chỉ là "không thấy mâu thuẫn khi replay"** — việc replay lại đúng những gì đã đi qua không đủ để phát hiện một cạnh bị gán sai.
5. **Luôn mô phỏng offline trước khi tiêu tốn instance thật** — biết chắc ngân sách move là đủ dùng (ở đây trung vị 635/1000) thay vì đoán mò, vì instance thật chỉ được thử một lần duy nhất.
6. **Family phải được chính server xác nhận qua classify, không được suy đoán từ host khác cùng file** — đây là nguyên nhân cốt lõi khiến các lần chơi trước bị mất điểm dù bản đồ "nhìn có vẻ đúng".
