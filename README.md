# Cursor Account Checker

Bulk check tài khoản Cursor (cursor.com) — login + đọc plan (Free / Pro / Pro Trial / Team / Enterprise).

## Cách hoạt động

Tool reverse-engineer flow đăng nhập Cursor (WorkOS AuthKit + Next.js server actions):

1. `GET /` → lấy `authorization_session_id` + `state`
2. `POST` fingerprint signals (device fingerprint blob)
3. `POST` email step → redirect `/password`
4. Solve **Cloudflare Turnstile** (qua captcha solver)
5. `POST` password step (+ turnstile token) → redirect `/success`
6. Follow `/success` → callback → `WorkosCursorSessionToken`
7. `GET /api/auth/me` → đọc `membershipType` (plan)

Dùng `curl_cffi` (impersonate Chrome) để tránh block TLS fingerprint.

## Yêu cầu

```bash
pip install -r requirements.txt     # curl_cffi, requests, colorama
```

**Captcha solver (bat buoc cho login mode):** Cursor yeu cau Cloudflare Turnstile o buoc password. Chain mac dinh doc `keys.txt`. Section trong = bo qua.

| Solver | Section `keys.txt` | Chi phi | Ghi chu |
|--------|---------------------|---------|---------|
| **rendercf** (slot 1) | `[rendercf]` + `[rendercf2]` url= | FREE | cfsolve pool round-robin Oregon+Singapore, queue Cursor ~0ms, ~2 token/s |
| **rendercf2** (dung rieng) | `[rendercf2]` url= | FREE | Chi service Oregon (`--captcha rendercf2`) |
| **turntitle** (slot 2) | `[turntitle]` url= / token= | FREE | turntitle.onrender (Chrome that + Xvfb), ~12s |
| nocaptchaai | `[nocaptchaai]` 1 key / dong | Tra phi | AntiTurnstileTask, clientKey, rotate tu dong |
| captchasonic | `[captchasonic]` 1 key / dong | Tra phi | AntiTurnstileTaskProxyLess, apiKey |
| 2captcha | `[2captcha]` | Tra phi | method=turnstile |
| capsolver | `[capsolver]` | Tra phi | AntiTurnstileTaskProxyLess |

Chain mac dinh (config.py): `rendercf (pool 2 service) -> turntitle -> nocaptchaai -> captchasonic -> 2captcha -> capsolver`.


## Cách chạy

```bash
# Mặc định: login mode, captcha yeat, proxy từ proxies.txt, 4 vòng retry tự động
python checker.py --bots 6

# Không proxy (chạy thẳng IP máy)
python checker.py --bots 4 --no-proxy

# Retry loop: mặc định 4 round. Mỗi round recheck toàn bộ RETRY+ERROR còn lại.
python checker.py --bots 6 --retries 4
python checker.py --bots 6 --retries 0    # tắt retry (chỉ pass 1)

# Capsolver thay YeatLegit
python checker.py --captcha capsolver --captcha-key YOUR_KEY --bots 20

# Chạy lại những cái cần retry
python checker.py --accounts results\retry.txt --bots 6
```

### Gom acc từ folder khác

```bash
# Gom tat ca email:pass tu 1 folder (recursive), loc bad format, dedupe, merge vao accounts.txt
python gather.py "C:\path\to\combo\folder"
```

### Token mode (nhanh, không login)

Nếu đã có `WorkosCursorSessionToken` (format `email:password:token` hoặc `:token`):

```bash
python checker.py --tokens tokens.txt --bots 50
```

Token mode bypass login + Turnstile hoàn toàn → rất nhanh (50+ bots).

## Input

- `accounts.txt` — `email:password` mỗi dòng (bỏ qua dòng `#`)
- `proxies.txt` — `ip:port` / `ip:port:user:pass` / `user:pass@ip:port` mỗi dòng
- `tokens.txt` — `email:password:token` hoặc `:token` (token mode)

## Output (`results/`)

| File | Ý nghĩa |
|------|---------|
| `hits.txt` | **HIT** — login OK + có plan. Dòng có `Renew=YYYY-MM-DD | Left=Nd` (plan tháng đang active). Trial/đã hủy: `Ends=`. Yearly: `UsageReset=` (reset usage tháng, không phải ngày charge năm) |
| `free.txt` | **FREE** — login OK nhưng free tier |
| `fail.txt` | **FAIL** — sai password / email không tồn tại |
| `retry.txt` | **RETRY** — rate limit / radar (bot detection) — chạy lại là reset |
| `error.txt` | **ERROR** — lỗi network / proxy chết |
| `custom.txt` | **CUSTOM** — cần 2FA / OTP |
| `badformat.txt` | **BADFORMAT** — email sai format |

## Quan trọng

- **Radar (bot detection):** WorkOS có thể redirect `/radar-challenge` nếu IP/request đáng ngờ → tool xếp RETRY. Dùng proxy residential sạch + retry nhiều pass sẽ giảm radar.
- **Proxy:** proxy datacenter rẻ thường chết hoặc bị radar. Cần proxy tốt để check hàng loạt.
- **Bots:** với login mode + YeatLegit solver, `--bots 5-6` là tối ưu (match solver pool 5). Token mode chạy được `--bots 50+`. `start.bat` đã hạ về 6.
- **Pool theo host:** `proxy_pool.py` chỉ cấp MỘT login mỗi gateway host cùng lúc, host nghỉ `HOST_COOLDOWN_OK=30s` sau login OK và `HOST_COOLDOWN_FAIL=90s` sau CF/403/radar. 16 bot trên 36 host từng đốt exit thành CF 403 hàng loạt (run 2026-10-07: 25/26 ERROR là `no authorization_session_id`). CF 403 giờ ghi rõ `cloudflare 403 challenge (exit IP blocked)` trong `error.txt`.
- **Action IDs:** nếu Cursor update server, các hash trong `config.py` (`ACTION_*`) sẽ đổi → tool báo lỗi. Chạy `crawl_fresh.py` để crawl lại, hoặc capture traffic browser mới.
- **Ngày renew:** không nằm ở `full_stripe_profile`. Lấy `billingCycleEnd` từ `GET https://api2.cursor.sh/auth/usage-summary` (Bearer JWT, checker đã gọi). Cookie `GET https://cursor.com/api/usage-summary` cùng body. Chi tiết: `notes/2026-10-07_renew_endpoint.md`.

## Cấu trúc code

- `config.py` — constants: action IDs, endpoints, sitekey, paths
- `cursor_auth.py` — login flow (WorkOS AuthKit) + đọc account info
- `captcha_solvers.py` — Turnstile solvers (capsolver/yescaptcha/2captcha/local/yeat/none)
- `proxy_pool.py` — proxy rotation + per-line lock + per-host lock/cooldown (tránh đốt exit CF)
- `checker.py` — main: multithread, multi-pass, colored output
- `YeatTheLegit_Solver/` — local Turnstile solver (Node.js, port 6767)
