"""
Cursor Account Checker - Config
================================
Constants cho flow dang nhap Cursor (WorkOS + Next.js server actions).
Moi constant da duoc reverse-engineer tu Cursor IDE traffic.
"""

from pathlib import Path

# ====================== PATHS ======================
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_ACCOUNTS = str(BASE_DIR / "accounts.txt")
DEFAULT_PROXIES = str(BASE_DIR / "proxies.txt")
DEFAULT_TOKENS = str(BASE_DIR / "tokens.txt")   # che do check bang token (skip login)
OUT_DIR = str(BASE_DIR / "results")

# ====================== ENDPOINTS ======================
AUTH = "https://authenticator.cursor.sh"
CURSOR = "https://cursor.com"
API2 = "https://api2.cursor.sh"

# Endpoint doc thong tin user / subscription
AUTH_ME_URL = f"{CURSOR}/api/auth/me"
USAGE_URL = f"{CURSOR}/api/usage"
STRIPE_PROFILE_URL = f"{API2}/auth/full_stripe_profile"
USAGE_SUMMARY_URL = f"{CURSOR}/api/usage-summary"
# Usage THAT (Bearer, khong can cookie) - individualUsage.plan.used/limit + onDemand.used (cents)
USAGE_SUMMARY_API2_URL = f"{API2}/auth/usage-summary"

# ====================== CURSOR AUTH FLOW (WorkOS AuthKit) ======================
# Next.js server action IDs (full 42-char hex, trong header "next-action").
# Reverse-engineered tu browser capture 2026-08. Flow:
#   1. GET /                          -> lay authorization_session_id + state
#   2. POST [SIGNALS]   text/plain    -> gui device fingerprint hash
#   3. POST [EMAIL]     multipart     -> submit email  -> 303 /password
#   4. GET /password                  -> (set cookie)
#   5. solve Turnstile (YeatLegit / capsolver / ...)
#   6. POST [PASSWORD]  multipart     -> submit password + bot_detection_token -> 303 /success
#   7. follow /success -> callback    -> WorkosCursorSessionToken
#
# Neu Cursor update server code, hash se doi -> tool bao loi.
# Cap nhat: capture_fresh.py / crawl_fresh.py
ACTION_SIGNALS = "408b9aebd871f4bb455f1e0f1a9bf3b72bdf9624ed"   # fingerprint text/plain tren /password [2026-09-01b]
ACTION_EMAIL = "409dfdd69397fa9f326db3612977e0aa51bada7cdb"      # email step (multipart) [2026-09-01b]
ACTION_PASSWORD = "40d83d93180836f1c3673f123e9fce710c3610829a"   # password step (multipart + turnstile) [2026-09-01b]
# LUU Y: Cursor doi hash nay ~tuan/lan. Neu checker thay FAIL [404] hang loat
# -> chay: python capture_patch.py roi paste hash moi vao day.

# Next-router-state-tree (encoded) - KHAC nhau giua email page vs password page.
# Live capture 2026-09-01 (indices 4096/4112, password node tren /password).
ROUTER_STATE_TREE = (
    "%5B%22%22%2C%7B%22children%22%3A%5B%22(main)%22%2C%7B%22children%22%3A"
    "%5B%22(root)%22%2C%7B%22children%22%3A%5B%22(sign-in)%22%2C%7B%22children"
    "%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%2C4096%5D%7D%2Cnull%2Cnull"
    "%2C4096%5D%7D%2Cnull%2Cnull%2C4096%5D%7D%2Cnull%2Cnull%2C4096%5D%7D%2Cnull%2Cnull%2C4112%5D"
)
ROUTER_STATE_TREE_PASSWORD = (
    "%5B%22%22%2C%7B%22children%22%3A%5B%22(main)%22%2C%7B%22children%22%3A"
    "%5B%22(root)%22%2C%7B%22children%22%3A%5B%22(sign-in)%22%2C%7B%22children"
    "%22%3A%5B%22password%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D"
    "%2Cnull%2Cnull%2C4096%5D%7D%2Cnull%2Cnull%2C4096%5D%7D%2Cnull%2Cnull%2C4096"
    "%5D%7D%2Cnull%2Cnull%2C4096%5D%7D%2Cnull%2Cnull%2C4096%5D%7D%2Cnull%2Cnull%2C4112%5D"
)
X_DEPLOYMENT_ID = "hosted-authkit-671e27984b8e9bfb6e050b834fd3d3ad5cd527e4-40351430283"   # fresh 2026-10-30 (capture_patch)
# Static fingerprint signals hash (gui o step 2, text/plain TREN /password)
SIGNALS_HASH = "13fe697814e1451d697837d0eb2d761c8bfeafe8105a7986d7018b670a6ddf6d"

# Cloudflare Turnstile sitekey cua Cursor (public)
TURNSTILE_SITEKEY = "0x4AAAAAAAMNIvC45A4Wjjln"
TURNSTILE_PAGE_URL = AUTH  # url de solve turnstile

# Cookie chua session
SESSION_COOKIE_NAME = "WorkosCursorSessionToken"

# ====================== USER-AGENT ======================
# Cursor dung Chrome standard (Windows)
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)

# Browser profile de impersonate qua curl_cffi ( tranh block bot )
# GOC = chrome124 + UA145: WorkOS radar chap nhan (da test: password step khong radar).
# DON DOI sang chrome142/146/150 -> radar o password step (test 2026-09-21).
IMPERSONATE_PROFILE = "chrome124"

# ====================== NETWORK ======================
TIMEOUT = 15           # proxy song thuong <8s/request — 25s chi keo dai cho proxy chet
MAX_PROXY_SWITCH = 3   # doi proxy toi da 3 lan (radar WorkOS flag theo IP)
PROXY_COOLDOWN = 5     # proxy nghi sau moi lan dung (s)
HOST_COOLDOWN_OK = 20   # host nghi sau login OK (s)
HOST_COOLDOWN_FAIL = 45  # host nghi sau fail — 90s lam pool can kit tren Render (87 host)

# ---- CF 403 latch: JA3 Android qua khi Chrome desktop bi block ----
# Live 2026-10-07: 4 exit bi 403 voi chrome124/131/136 deu tra 200 + asid voi
# chrome99_android. CF block theo JA3 Chrome desktop, khong phai theo exit.
# Password step + radar voi android UA CHUA test acc that (moi chuoi den turnstile).
IMPERSONATE_FALLBACK = "chrome99_android"
UA_FALLBACK = ("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")
MAX_RETRIES = 5        # retry request khi loi transient

# ====================== CAPTCHA ======================
# Chain: yeatcloud (turntitle cloud) -> nocaptchaai -> captchasonic -> 2captcha -> capsolver.
# Section trong keys.txt = bo qua. Key dien vao keys.txt, khong hardcode o day.
DEFAULT_CAPTCHA_SOLVER = "rendercf,turntitle,nocaptchaai,captchasonic,2captcha,capsolver"
CAPSOLVER_API_URL = "https://api.capsolver.com/createTask"
CAPSOLVER_RESULT_URL = "https://api.capsolver.com/getTaskResult"
TWOCAPTCHA_API_URL = "https://2captcha.com/in.php"
TWOCAPTCHA_RESULT_URL = "https://2captcha.com/res.php"
CAPTCHA_POLL_INTERVAL = 3
CAPTCHA_MAX_WAIT = 120

# yeatcloud. [turntitle] url= / token= trong keys.txt override neu co.
YEAT_CLOUD_URL = "https://turntitle-cloud-solver-production.up.railway.app"
YEAT_CLOUD_TOKEN = ""   # doc tu keys.txt [turntitle] token= (khong hardcode)
YEAT_CLOUD_CONCURRENCY = 8
YEAT_CLOUD_MIN_GAP = 0.2
YEAT_CLOUD_TIMEOUT = 45

# nocaptchaai: anti-captcha createTask, auth clientKey, task AntiTurnstileTask.
NOCAPTCHAAI_CREATE_URL = "https://api.nocaptchaai.com/createTask"
NOCAPTCHAAI_RESULT_URL = "https://api.nocaptchaai.com/getTaskResult"
NOCAPTCHAAI_TASK_TYPE = "AntiTurnstileTask"
NOCAPTCHAAI_AUTH_FIELD = "clientKey"
NOCAPTCHAAI_TIMEOUT = 180

# captchasonic: cung createTask, auth apiKey (khong phai clientKey).
CAPTCHASONIC_CREATE_URL = "https://api.captchasonic.com/createTask"
CAPTCHASONIC_RESULT_URL = "https://api.captchasonic.com/getTaskResult"
CAPTCHASONIC_TASK_TYPE = "AntiTurnstileTaskProxyLess"
CAPTCHASONIC_AUTH_FIELD = "apiKey"
CAPTCHASONIC_TIMEOUT = 120


def _load_keys_file():
    """keys.txt -> {section: [dong]}. # = comment. 1 key / dong."""
    p = BASE_DIR / "keys.txt"
    data = {}
    if not p.exists():
        return data
    alias = {
        "capsolver": "capsolver",
        "2captcha": "twocaptcha",
        "twocaptcha": "twocaptcha",
        "turntitle": "turntitle",
        "turntitle-cloud": "turntitle",
        "nocaptchaai": "nocaptchaai",
        "captchasonic": "captchasonic",
        "rendercf": "rendercf",
        "rendercf2": "rendercf2",
    }
    section = None
    try:
        raw = p.read_text(encoding="utf-8-sig", errors="ignore")
    except Exception:
        return data
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower().strip("[]")
        if low in alias:
            section = alias[low]
            data.setdefault(section, [])
            continue
        if section:
            data.setdefault(section, []).append(line)
    return data


_KEYS = _load_keys_file()


def _load_turntitle():
    url, token = "", ""
    for line in _KEYS.get("turntitle", []):
        low = line.lower()
        if low.startswith("url="):
            url = line.split("=", 1)[1].strip().strip('"').strip("'")
        elif low.startswith("token="):
            token = line.split("=", 1)[1].strip().strip('"').strip("'")
    return url, token


_tt_url, _tt_token = _load_turntitle()
if _tt_url:
    YEAT_CLOUD_URL = _tt_url.rstrip("/")
if _tt_token:
    YEAT_CLOUD_TOKEN = _tt_token

def _load_rendercf():
    """env CFSOLVE_URLS > keys.txt. Format 'oregon_url,singapore_url' (Oregon = primary pool)."""
    import os as _os
    env = _os.environ.get("CFSOLVE_URLS", "")
    if env:
        parts = [u.strip().rstrip("/") for u in env.split(",") if u.strip()]
        if parts:
            # RENDER_CF2 = primary (pool dung truoc), RENDER_CF = backup
            return (parts[1] if len(parts) > 1 else ""), parts[0]
    urls = ["", ""]
    for i, sec in enumerate(("rendercf", "rendercf2")):
        for line in _KEYS.get(sec, []):
            if line.lower().startswith("url="):
                urls[i] = line.split("=", 1)[1].strip().strip('"').strip("'")
    return urls[0], urls[1]


RENDER_CF_URL, RENDER_CF2_URL = _load_rendercf()

CAPSOLVER_API_KEYS = _KEYS.get("capsolver", [])
TWOCAPTCHA_API_KEYS = _KEYS.get("twocaptcha", [])
NOCAPTCHAAI_API_KEYS = _KEYS.get("nocaptchaai", [])
CAPTCHASONIC_API_KEYS = _KEYS.get("captchasonic", [])

# ====================== OUTPUT CATEGORIES ======================
# HIT  = login OK + co plan (Pro/Pro Trial/Team/Enterprise)
# FREE = login OK nhung free tier (khong co subscription)
# FAIL = login sai (sai pass / email khong ton tai)
# RETRY = rate limit / quota (cho retry o pass sau)
# ERROR = loi network/proxy
# BADFORMAT = email sai format
# CUSTOM = 2FA / can verify email (khong check duoc)
# Cac category se duoc RETRY o pass sau (cho den khi het hoac dat gioi han retry).
# Ca RETRY (radar/rate) va ERROR (network/proxy chet) deu retry duoc.
RETRY_CATEGORIES = {"RETRY", "ERROR"}
# So lan retry toi da sau pass 1 (mỗi lan = 1 round retry lai toan bo RETRY+ERROR con lai)
MAX_RETRY_ROUNDS = 4

# ====================== DISPLAY ======================
MARKERS = {
    "HIT": "[+]",
    "FREE": "[F]",
    "TERMINAL": "[T]",
    "FAIL": "[-]",
    "ERROR": "[!]",
    "BADFORMAT": "[X]",
    "CUSTOM": "[?]",
    "DUPLICATE": "[D]",
}

# Colorama colors (hex -> colorama)
COLORS = {
    "HIT": "\033[92m",      # green
    "FREE": "\033[93m",     # yellow
    "RETRY": "\033[96m",    # cyan
    "FAIL": "\033[91m",     # red
    "ERROR": "\033[97m",    # white
    "BADFORMAT": "\033[90m", # dark gray
    "CUSTOM": "\033[95m",   # magenta
    "DUPLICATE": "\033[90m", # dark gray
}
RESET = "\033[0m"
