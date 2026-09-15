# Team17 — Danh mục write-up dịch vụ Security Bootcamp 2026

Các write-up dưới đây bổ sung cho [write-up Jenkins hiện có](WRITEUP_TEAM17_JENKINS.md). Nội dung được đối chiếu với báo cáo và log lưu trong workspace; không công bố password, token, khóa giải mã hay secret lab. Các số liệu là kết quả của lượt kiểm tra/phục hồi ngày 11/09/2026, không phải xác nhận trạng thái live ngày hôm nay.

| Nhóm | Write-up | Kết quả được chứng minh |
|---|---|---|
| Edge-proxy | [Edge-proxy](WRITEUP_TEAM17_EDGE_PROXY.md) | 101 container xác thực, CMS/Nginx HTTP 200; Host-IP bypass cần xử lý tiếp |
| Git | [Gitea](WRITEUP_TEAM17_GITEA.md) | 110 file phục hồi, Gitea/Nginx hoạt động |
| CI | [CI-runner](WRITEUP_TEAM17_CI_RUNNER.md) | 116 file phục hồi, act_runner khai báo thành công |
| GitOps | [K3S và ArgoCD](WRITEUP_TEAM17_K3S_ARGOCD.md) | 113 file phục hồi, node Ready, 7 pod ArgoCD Running |
| Registry | [Verdaccio](WRITEUP_TEAM17_VERDACCIO.md) | 104 + 2 file phục hồi, registry HTTP 200; hai log không xác thực được giữ nguyên |
| Nền tảng | [DNS và NFS](WRITEUP_TEAM17_DNS_NFS.md) | 104 + 8 file phục hồi, Unbound/NFS hoạt động |
| Consumer | [app-runner](WRITEUP_TEAM17_APP_RUNNER.md) | 105 file phục hồi, watcher cài package 1.0.0 |
| Firewall | [pfSense](WRITEUP_TEAM17_PFSENSE.md) | Compromise control plane/NAT được xác nhận; chưa ghi nhận containment hoàn tất |
| Dịch vụ chỉ kiểm tra | [Web-AOI, VPN, Windows, CTFd](WRITEUP_TEAM17_WEB_VPN_WINDOWS.md) | Health checks; không có sửa/giải mã trong lượt này |

Đọc cùng [báo cáo phục hồi toàn đội](recovery-fleet/BAO_CAO_KHOI_PHUC_TEAM17.md), [báo cáo Purple Team](BAO_CAO_IR_PURPLE_TEAM_20260911.md) và [phụ lục tái tấn công sau gia cố](PHU_LUC_IR_TAI_TAN_CONG_SAU_HARDEN_20260911.md) để phân biệt trạng thái dịch vụ với mức độ an toàn sau sự cố.
