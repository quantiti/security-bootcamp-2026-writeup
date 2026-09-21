# Write-up — "Can You Remember" (Flag 1)

**Challenge:** Can You Remember 1 / 2 (5000 điểm mỗi flag)
**Service:** `http://103.70.12.125:26001`
**Flag 1:** `SBC{f2a9f90d8257a6c9682e0402d220ac6c}` (đạt khi ≥ 50% câu quiz đúng)

---

## 1. Tổng quan challenge

Bối cảnh: năm 2077, bạn "chiến đấu với malware ở góc nhìn thứ nhất". Mỗi *instance* thả bạn vào một **mạng lưới 20 host**:

- Mỗi host **hoặc chứa 1 mẫu malware** (file `sample.bin` trong 1 zip khoá mật khẩu `infected`) **hoặc là host an toàn** (`safe`). Host xuất phát (entry) luôn `safe`.
- Mỗi host có **5 "warp" (đánh số 1..5)** nối sang host hàng xóm. **Warp hai chiều**: nếu warp từ A dẫn tới B thì đúng một warp trên B dẫn ngược lại A (thường khác số).
- Muốn **rời khỏi một host nhiễm** bạn phải **classify đúng malware family** của nó trước ("apply the right cure"). Host `safe` thì đi luôn.
- **3 hearts.** Mỗi lần classify sai mất 1 heart; hết heart → kết thúc instance.
- **1000 moves.** Mỗi `/move` tốn 1 move. `/reset` (về entry) **miễn phí**.
- Instance sống **1 giờ**.

Sau khi khám phá xong, gọi **sanity-check quiz** (100 câu). Điểm ≥ 50% → **Flag 1**; ≥ 99% → **Flag 2**.

### API

| Method | Path | Ý nghĩa |
|---|---|---|
| POST | `/instance/start` | Tạo instance, trả `instance_id`. Gửi header `X-Instance-Id` cho mọi request sau. |
| GET | `/host/current` | Trạng thái host hiện tại: `sample_url`, `solved`, `moves_remaining`, `hearts`. Host safe: `sample_url=null`, `solved=true`. |
| GET | `/samples/{id}.zip` | Tải zip mẫu của host hiện tại (chỉ hợp lệ khi đang đứng trên host; mỗi lần tới mint URL mới). Zip khoá mật khẩu `infected`. |
| POST | `/host/classify` | Body `{"family":"njrat"}` → `{"correct":true/false,"hearts":N}`. Đúng thì mở khoá di chuyển. |
| POST | `/move` | Body `{"warp":3}` → đi 1 warp, tốn 1 move. |
| POST | `/reset` | Về entry, miễn phí. |
| POST | `/sanity-check/questions` | Bắt đầu quiz, trả mảng 100 câu. **Sau khi gọi là dừng khám phá.** |
| POST | `/sanity-check/submit` | Body map `id → answer`. **Một lần duy nhất/instance.** Trả `{"score":..,"flag_1":..,"flag_2":..}`. |

### Format quiz

Cả 100 câu đều là "đi route warp **từ host entry**":

- **50 câu single-stop:** *"...name the malware family on the host where you stop. Answer with one family slug."* → trả về **1 slug** (family tại host cuối route).
- **50 câu list:** *"...name the malware family on every host you stand on, the entry host first and the last host last..."* → trả về **list slug**, độ dài = số warp + 1 (entry `safe` trước, host cuối sau). Host safe dùng `"safe"`.

Ví dụ câu:
```json
{ "id":"q001",
  "question":"Start on the entry host and walk this route ... Answer with one family slug.",
  "route_map":"warp 2 -> warp 4 -> warp 3",
  "answer_example":"njrat" }
```
Route dài từ 1 tới ~27 warp.

---

## 2. Phân tích & chiến lược

Điểm mấu chốt để giải:

1. **Đồ thị random mỗi instance, NHƯNG các file mẫu lấy từ một POOL cố định** dùng chung giữa các instance. Kiểm chứng: hash `4f02a9fc…` (shamoon) xuất hiện y hệt ở nhiều instance khác nhau; và trong một instance nhiều host có thể dùng **cùng một file** (cùng hash). ⇒ `hash sample` (và cả **kích thước sample**) map 1-1 sang **family**, và **kiến thức này tái dùng được cho mọi instance**.

2. **`/host/classify` của server chính là oracle ground-truth.** Không cần biết tên "chuẩn" của malware — chỉ cần tìm đúng **slug** mà server chấp nhận. Vì có thể tạo **vô hạn instance nháp** (mỗi cái 3 hearts = 3 lần thử slug miễn phí), ta brute-force slug trên instance nháp mà **không tốn heart của instance chính**. Mọi host free-reachable đều đi qua host `safe` nên **navigate không tốn heart**, chỉ lần `classify` mới rủi ro.

3. **Phân loại host bằng KÍCH THƯỚC `sample.bin`.** Mỗi family cụm rất chặt theo size (chênh nhau vài KB). Vì thế chỉ cần tải mẫu, tính `len(sample.bin)`, tra bảng `size → slug`. Nếu slug đúng, `classify` trả `correct:true` và **không mất heart** → di chuyển thoải mái để map.

4. **Với route ngắn, không cần dựng lại đồ thị.** Câu quiz hỏi family dọc theo một route **từ entry**. Nếu trong lúc khám phá ta **đã đi đúng path đó**, ta biết ngay family tại **mọi prefix** của path → trả lời trực tiếp, chính xác 100%. BFS theo tầng trong giới hạn 1000 moves phủ được **toàn bộ route ≤ 3–4 warp** (đủ ≈ 50 câu → đạt Flag 1). Route dài hơn (cần adjacency đầy đủ để mô phỏng) để dành cho Flag 2.

> **Ràng buộc quan trọng:** explore bằng `reset + replay` tốn `len(path)` moves mỗi path. Nếu để BFS chạy quá sâu sẽ **vượt 1000 moves**, instance hết lượt và `/sanity-check/questions` trả về lỗi (không phải list 100 câu). Phải **theo dõi `moves_remaining` và dừng trước khi cạn**.

---

## 3. Phân loại 17 cụm malware family (phần khó nhất — 0 solves)

Pool gồm nhiều file, cụm lại thành **14 family / 17 cụm size** (vài family có 2 biến thể size). Bảng `size → slug` (slug đã được **confirm bằng oracle của server** hoặc suy từ VirusTotal + xác nhận qua sibling cùng family):

| Cụm (size xấp xỉ) | Loại | Family slug |
|---|---|---|
| ~3.5 MB | native | `wannacry` |
| ~1.45 MB | native (MinGW/GCC packed) | `adylkuzz` |
| ~989 KB | native | `shamoon` |
| ~677 KB | native | `hive` |
| ~619 KB | native (packed) | `cerber` |
| ~593 KB | .NET (packed, namespace "GameEngine") | `agenttesla` |
| ~589 KB | Delphi | `loki` |
| ~550 KB | native | `trickbot` |
| ~290 KB | .NET | `jigsaw` |
| ~231 KB | native | `petya` |
| ~218 KB | native (UPX) | `hive` |
| ~209 KB | .NET | `njrat` |
| ~118 KB | native (UPX) | `virut` |
| ~73 KB | native (LordPE) | `zeroaccess` |
| ~61 KB | native (DLL) | `turla` |
| ~43 KB | native (UPX, LordPE) | `zeroaccess` |
| ~21 KB | native (UPX, DLL) | `turla` |

### Quy trình định danh (3 lớp, ưu tiên độ tin cậy)

1. **Static triage trong RAM** (không bao giờ execute): giải nén zip bằng mật khẩu `infected` **chỉ trong bộ nhớ**, chạy `strings` / phân tích PE (imports, section, entropy, PDB) bằng `pefile`. Nhiều family lộ ngay chữ ký.
2. **Tra VirusTotal bằng FILE** (upload mẫu, đọc *Popular threat label* + *Family labels*). Lưu ý mẫu đã bị repack nên **tra theo hash thường trượt** — phải upload file.
3. **Confirm slug bằng oracle của server**: đứng trên một host có mẫu tương ứng (trên instance nháp) và gọi `/host/classify` với slug ứng viên. `correct:true` ⇒ đúng slug server cần.

---

## 4. Chữ ký tĩnh của vài mẫu tiêu biểu

- **shamoon (`989K`)** — native C++. Import `NETAPI32` (`NetScheduleJobDel`, `NetRemoteTOD`, `NetApiBufferAllocate`), `WS2_32`. Tạo service **`TrkSvr` → `system32\trksrv.exe`** ("Distributed Link Tracking Server") qua chuỗi:
  `ping -n 30 127.0.0.1 >nul && sc config TrkSvr binpath= system32\trksrv.exe && sc start TrkSvr`
  `.rsrc` lớn (~860 KB, entropy 7.6). Đây là **Shamoon / DistTrack** (wiper, vụ Saudi Aramco). Hash `4f02a9fc…` khớp mẫu thật trên VT/Hybrid-Analysis.
- **jigsaw (`290K`)** — .NET, section packed. Ransom note đặc trưng: *"Every hour files will be deleted. Increasing in amount every time."*, đòi ~150 USD Bitcoin, URL `btc.blockr.io`. ⇒ **Jigsaw**.
- **zeroaccess (`73K` & `43K`)** — DLL, sửa bằng **LordPE**, import `MSWSOCK`/`WS2_32`, chuỗi protocol `cnct` / `disc` / `recv` / `send`. VT: `trojan.sirefef/zaccess`. ⇒ **ZeroAccess (Sirefef)**.
- **turla (`61K` & `21K`)** — DLL nhỏ, VT: `trojan.turla/mikey` và `trojan.turla/ursu`. ⇒ **Turla**.
- **petya (`231K`)** — VT: `trojan.petya/diskcoder`. **hive (`677K`/`218K`)** — VT: `ransomware.hive/smyxcda`. **virut (`118K`)** — VT: `virus.virut/virtob` (file infector). **adylkuzz (`1.45M`)** — VT: `trojan.adylkuzz/tspy` (crypto-miner worm). **agenttesla (`593K` .NET)** — VT family label `agenttesla`. **cerber (`619K`)** — `trojan.cerber/zerber`. **trickbot (`550K`)** — `trojan.trickbot/inject3`.

---

## 5. Engine giải (`map_and_quiz.py`)

Pipeline: **classify theo size → BFS phủ route ngắn (giới hạn moves) → trả lời trực tiếp từ `path → family` → auto-submit.**

Phân loại theo size:
```python
# SIZES = [(size, slug), ...] lấy từ bảng 17 cụm đã confirm
def slug_by_size(sz):
    best = min(SIZES, key=lambda t: abs(t[0] - sz))
    return best[1] if abs(best[0] - sz) <= max(4000, best[0]*0.06) else "?"
```

Giải mã mẫu **chỉ trong RAM** (không ghi PE ra đĩa, không execute):
```python
def famhere(self):
    c = self.S.get(BASE + "/host/current").json()
    u = c.get("sample_url")
    if not u:
        return "safe"
    zb = self.S.get(BASE + u).content
    mb = zipfile.ZipFile(io.BytesIO(zb)).read("sample.bin", pwd=b"infected")
    return slug_by_size(len(mb))
```

`nav(path)` — reset về entry rồi đi theo path, **classify từng host nhiễm bằng slug (size) để mở khoá di chuyển**; cache family theo path; dừng nếu gần cạn moves:
```python
def nav(self, path):
    self.reset(); cur = (); f = self.pathfam.get(cur) or self.famhere()
    self.pathfam[cur] = f
    for w in path:
        if f != "safe":
            if f == "?":              # size không khớp cụm nào -> chặn
                return False, f
            if not self.classify(f).get("correct"):   # slug sai -> chặn (mất 1 heart)
                return False, f
        if self.moves_left <= 3:
            return False, f
        self.move(w); cur += (w,)
        f = self.pathfam.get(cur) or self.famhere()
        self.pathfam[cur] = f
    return True, f
```

`explore` — BFS theo tầng (level order), chỉ giữ path đi tới được, dừng khi `moves_remaining` xuống thấp. Vì BFS theo tầng nên **hoàn tất depth ≤ 3 (toàn bộ 156 path, ~430 moves) trước** rồi mới sang depth 4.

Trả lời quiz **trực tiếp** (không cần đồ thị):
```python
qs = post("/sanity-check/questions")
for q in qs:
    route = tuple(int(x.split()[1]) for x in q["route_map"].split("->"))
    prefixes = [route[:i] for i in range(len(route)+1)]
    known = all(p in reached for p in prefixes)   # đã đi qua toàn bộ route?
    if "every host" in q["question"]:             # câu list
        ans[q["id"]] = [reached.get(p, guess) for p in prefixes]
    else:                                         # câu single-stop
        ans[q["id"]] = reached.get(route, guess)
# guess = family phổ biến nhất trong reached (cho route quá dài chưa đi tới)
```
Nếu số câu "fully-known" đủ lớn (≥ ~50) thì `submit`.

---

## 6. Kết quả

Một lần chạy trên instance có nhiều route ngắn cho:
```
depth_hist = {0:1, 1:5, 2:25, 3:125, 4:128}   # phủ đủ depth ≤3 + 128 path depth-4
hearts = 3                                     # size-classification đúng -> 0 heart mất
fully-known routes: 50/100
SUBMIT 200 {"score":0.5,"flag_1":"SBC{f2a9f90d8257a6c9682e0402d220ac6c}","flag_2":null}
```

➡️ **score 0.5 → FLAG 1:**
```
SBC{f2a9f90d8257a6c9682e0402d220ac6c}
```
50 câu route-ngắn đã đi qua đều đúng tuyệt đối; đó chính là 50% cần thiết.

---

## 7. Cạm bẫy đã gặp (nên tránh)

- **Live malware:** mẫu là malware thật. Chỉ **phân tích tĩnh trong RAM** (strings / `pefile`), **tuyệt đối không execute** file `.exe`/`.dll`. Giữ zip ở dạng khoá mật khẩu (inert); nếu cần chạy động thì làm trong **VM cách ly**.
- **Không đọc được VT bằng tool tự động:** trang `virustotal.com/gui/...` là SPA cần đăng nhập → công cụ fetch chỉ nhận khung trắng. Phải xem bằng mắt / copy dòng *Popular threat label*.
- **Tra VT theo hash thường trượt** với mẫu đã repack → **upload chính file** mới ra kết quả.
- **Đừng brute-force slug ồ ạt** làm quá tải server; hãy **narrow ứng viên bằng static + VT trước**, rồi mới confirm bằng oracle.
- **Nhầm family:** cụm 550K ban đầu bị đoán là `gandcrab` (từ marker nhiễu), thực tế VT xác định là **`trickbot`**. Luôn xác nhận lại bằng oracle của server.
- **Cháy moves:** explore quá sâu → hết 1000 moves → `/questions` lỗi. Phải bám `moves_remaining` và chừa buffer.
- **Định danh host bằng cấu trúc, không bằng hash:** trong một instance nhiều host có thể **cùng một sample (cùng hash)**, nên hash KHÔNG phải id duy nhất của host — điều này quan trọng khi tiến tới Flag 2 (dựng lại đồ thị).
