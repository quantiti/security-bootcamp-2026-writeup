# Danh mục write-up giải mã Palimpsest

Bộ bài tập trung vào các máy có file mã hóa trong Security Bootcamp 2026: thu thập chứng cứ, phân tích container, tìm frame/identity/fingerprint, dẫn xuất khóa, xác thực AEAD và ghi phục hồi. Số liệu là kết quả xử lý ngày 11/09/2026.

| Máy | Write-up | Kết quả giải mã được xác thực |
|---|---|---|
| Edge-proxy | [Thu thập RAM và giải mã Edge](WRITEUP_TEAM17_EDGE_PROXY.md) | Đĩa 101/101; RAM 44/103, có trùng đường dẫn giữa hai nguồn |
| Gitea | [Giải mã Gitea](WRITEUP_TEAM17_GITEA.md) | 110 file |
| CI-runner | [Giải mã CI-runner](WRITEUP_TEAM17_CI_RUNNER.md) | 116 file |
| K3S/ArgoCD | [Tìm frame riêng và giải mã K3S](WRITEUP_TEAM17_K3S_ARGOCD.md) | 113 file |
| Verdaccio | [Giải mã registry và xử lý log ghi nối](WRITEUP_TEAM17_VERDACCIO.md) | 104 + 2 file; giữ nguyên hai log có vấn đề |
| DNS/NFS | [Giải mã host và vùng dữ liệu chia sẻ](WRITEUP_TEAM17_DNS_NFS.md) | 104 + 8 file |
| app-runner | [Giải mã app-runner](WRITEUP_TEAM17_APP_RUNNER.md) | 105 file |

Lượt fleet có tổng **662 file** ghi phục hồi, chưa cộng 101 container Edge từ đĩa. Không cộng số file RAM trùng đường dẫn vào số file đĩa.

[Write-up Jenkins hiện có](WRITEUP_TEAM17_JENKINS.md) trình bày điều tra RAM/đĩa và phục hồi bằng plaintext còn sót. Trong phạm vi kết quả ghi ở bài Jenkins, bộ đọc đã được xây nhưng chưa xác thực giải mã container nạn nhân do thiếu frame đầy đủ. Các bài bổ sung trình bày giai đoạn tìm được frame và giải mã thành công; không gán ngược kết quả này cho Jenkins.

Mỗi bài dẫn tới script và log đối chiếu. Các gói recovery-material chứa vật liệu khóa nên bài chỉ mô tả cấu trúc và phương pháp, không chép giá trị khóa.
