"""
Captcha Solvers - Turnstile token providers
============================================
Chain mac dinh: yeatcloud -> nocaptchaai -> captchasonic -> 2captcha -> capsolver.
Section trong keys.txt = bo qua. Het credit -> xoa dong key, khong goi lai.

  yeatcloud      : turntitle cloud (Railway). FREE. MAIN.
  nocaptchaai    : AntiTurnstileTask, clientKey, nhieu key round-robin.
  captchasonic   : AntiTurnstileTaskProxyLess, apiKey.
  capsolver      : AntiTurnstileTaskProxyLess, clientKey.
  2captcha       : method=turnstile, last resort.
Mo rong: ke thua BaseSolver, them vao SOLVERS registry.
"""

import time
import logging
import threading
import requests

from config import (
    BASE_DIR,
    TURNSTILE_SITEKEY, TURNSTILE_PAGE_URL,
    CAPSOLVER_API_URL, CAPSOLVER_RESULT_URL,
    TWOCAPTCHA_API_URL, TWOCAPTCHA_RESULT_URL,
    CAPSOLVER_API_KEYS, TWOCAPTCHA_API_KEYS,
    NOCAPTCHAAI_API_KEYS, NOCAPTCHAAI_CREATE_URL, NOCAPTCHAAI_RESULT_URL,
    NOCAPTCHAAI_TASK_TYPE, NOCAPTCHAAI_AUTH_FIELD, NOCAPTCHAAI_TIMEOUT,
    CAPTCHASONIC_API_KEYS, CAPTCHASONIC_CREATE_URL, CAPTCHASONIC_RESULT_URL,
    CAPTCHASONIC_TASK_TYPE, CAPTCHASONIC_AUTH_FIELD, CAPTCHASONIC_TIMEOUT,
    RENDER_CF_URL, RENDER_CF2_URL,
    YEAT_CLOUD_URL, YEAT_CLOUD_TOKEN, YEAT_CLOUD_CONCURRENCY,
    YEAT_CLOUD_MIN_GAP, YEAT_CLOUD_TIMEOUT,
    CAPTCHA_POLL_INTERVAL, CAPTCHA_MAX_WAIT, UA,
)

DEFAULT_KEYS = {
    "capsolver": ",".join(CAPSOLVER_API_KEYS),
    "2captcha": ",".join(TWOCAPTCHA_API_KEYS),
    "twocaptcha": ",".join(TWOCAPTCHA_API_KEYS),
    "nocaptchaai": ",".join(NOCAPTCHAAI_API_KEYS),
    "captchasonic": ",".join(CAPTCHASONIC_API_KEYS),
}

log = logging.getLogger(__name__)

_CLOUD_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36")


class CaptchaError(Exception):
    """Loi khi solve captcha."""


# ====================== BASE ======================
class BaseSolver:
    """Base class - implement solve_turnstile()."""
    name = "base"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    def solve_turnstile(self, page_url: str = None, sitekey: str = None) -> str:
        """Tra ve Turnstile token. Raise CaptchaError neu fail."""
        raise NotImplementedError

    def last_solver_name(self):
        """Solver thuc te da solve lan cuoi (hien thi). None = chua solve."""
        return self.name


# ====================== NO SOLVER ======================
class NoSolver(BaseSolver):
    """Khong solve - tra ve empty."""
    name = "none"

    def solve_turnstile(self, page_url: str = None, sitekey: str = None) -> str:
        return ""


# ====================== YEATCLOUD (Railway, FREE - MAIN) ======================
class YeatCloudSolver(BaseSolver):
    """
    Solver cloud tu deploy Railway (turntitle-solver). FREE, khong ton credit.
    API: GET {url}/solve?url=&sitekey=&timeout=  (header X-Token)
    Server max 8 concurrent -> client semaphore de khong spam.
    """
    name = "yeatcloud"

    def __init__(self, api_key: str = ""):
        self.base_url = YEAT_CLOUD_URL.rstrip("/")
        self.token = api_key or YEAT_CLOUD_TOKEN
        self.timeout = YEAT_CLOUD_TIMEOUT
        self._sem = threading.Semaphore(YEAT_CLOUD_CONCURRENCY)
        self._gap_lock = threading.Lock()
        self._last_call = 0.0

    def _acquire(self):
        self._sem.acquire()
        # min-gap giua 2 lan goi (nhe, tranh don request)
        while True:
            with self._gap_lock:
                now = time.time()
                wait = self._last_call + YEAT_CLOUD_MIN_GAP - now
                if wait <= 0:
                    self._last_call = now
                    return
            time.sleep(min(wait, 0.5))

    def solve_turnstile(self, page_url: str = None, sitekey: str = None) -> str:
        page_url = page_url or TURNSTILE_PAGE_URL
        sitekey = sitekey or TURNSTILE_SITEKEY
        self._acquire()
        try:
            h = {"Accept": "application/json", "User-Agent": _CLOUD_UA}
            if self.token:
                h["X-Token"] = self.token
            t0 = time.time()
            try:
                r = requests.get(
                    f"{self.base_url}/solve",
                    params={"url": page_url, "sitekey": sitekey, "timeout": int(self.timeout)},
                    headers=h, timeout=self.timeout + 20,
                )
                j = r.json()
            except (requests.RequestException, ValueError) as e:
                raise CaptchaError(f"yeatcloud net: {e}")
            if r.status_code == 401:
                raise CaptchaError("yeatcloud 401: sai X-Token (kiem tra YEAT_CLOUD_TOKEN)")
            if not j.get("success"):
                raise CaptchaError(f"yeatcloud fail: {str(j.get('err') or j)[:80]}")
            token = j.get("token", "")
            if not token or len(token) < 50:
                raise CaptchaError(f"yeatcloud: token rong/ngan: {str(j)[:80]}")
            log.info(f"yeatcloud solved in {time.time()-t0:.1f}s | token={token[:24]}...")
            return token
        finally:
            self._sem.release()

# ====================== RENDERCF (cfsolve tren Render, browser-free) ======================
class RenderCfSolver(BaseSolver):
    """
    cfsolve websolve (Render): POST /solve {sitekey,url} -> pop queue ~0ms,
    queue can -> on-demand mint ~7-15s. Breaker 3 fail -> nghi 120s.
    2026-10-30 (port tu Grok-Checker): session keep-alive + semaphore 6
    (20 bot don conn 7-15s lam Render bao hoa -> reset TLS/SSLError).
    """
    name = "rendercf"
    _fail_n = 0
    _disabled_until = 0.0
    _SESSION = None
    _SEM = None
    _sem_lock = threading.Lock()

    def __init__(self, api_key: str = ""):
        self.base_url = (RENDER_CF_URL or "").rstrip("/")

    @classmethod
    def _session(cls):
        from requests.adapters import HTTPAdapter
        with cls._sem_lock:
            if cls._SESSION is None:
                sess = requests.Session()
                sess.mount("https://", HTTPAdapter(pool_connections=4, pool_maxsize=8,
                                                   max_retries=1))
                cls._SESSION = sess
                cls._SEM = threading.BoundedSemaphore(6)
        return cls._SESSION

    def solve_turnstile(self, page_url: str = None, sitekey: str = None) -> str:
        if not self.base_url:
            raise CaptchaError("rendercf: khong co url (keys.txt [rendercf])")
        if time.time() < type(self)._disabled_until:
            raise CaptchaError("rendercf circuit open")
        url = page_url or TURNSTILE_PAGE_URL
        key = sitekey or TURNSTILE_SITEKEY
        sess = self._session()
        t0 = time.time()
        with type(self)._SEM:
            r = None
            for attempt in (1, 2):  # retry 1 lan khi mang/SSL gat
                try:
                    r = sess.post(f"{self.base_url}/solve",
                                  json={"sitekey": key, "url": url}, timeout=25)
                    break
                except Exception as e:
                    if attempt == 2:
                        self._breaker_fail()
                        raise CaptchaError(f"rendercf net ({type(e).__name__})")
                    time.sleep(0.5)
        try:
            j = r.json()
        except Exception:
            j = {}
        tok = j.get("token") or ""
        if len(tok) >= 100:
            type(self)._fail_n = 0
            log.info(f"rendercf solved in {time.time()-t0:.1f}s | token={tok[:24]}...")
            return tok
        msg = str(j.get("message") or (r.status_code if r is not None else "?"))[:60]
        self._breaker_fail()
        raise CaptchaError(f"rendercf fail ({msg})")

    @classmethod
    def _breaker_fail(cls):
        cls._fail_n += 1
        if cls._fail_n >= 3:
            cls._disabled_until = time.time() + 120
            cls._fail_n = 0


class RenderCf2Solver(RenderCfSolver):
    """cfsolve-2 Oregon — breaker + semaphore RIENG (class attr rieng)."""
    name = "rendercf2"
    _fail_n = 0
    _disabled_until = 0.0
    _SESSION = None
    _SEM = None

    def __init__(self, api_key: str = ""):
        RenderCfSolver.__init__(self, api_key)
        self.base_url = (RENDER_CF2_URL or "").rstrip("/")

class RenderCfPoolSolver(BaseSolver):
    """
    cfsolve MULTI-TARGET pool (2026-10-30): round-robin 2 service Render
    (Oregon + Singapore, identical, egress khac region) -> ~1.6-2 token/s.
    Breaker RIENG tung service (3 fail -> nghi 120s). Token single-use TTL ~300s.
    Queue chi an (sitekey, host) khop va khong action/cdata.
    """
    name = "rendercf"
    _SESSION = None
    _SEM = None
    _lock = threading.Lock()
    _idx = 0
    _fails = {}           # url -> so fail lien tiep
    _disabled_until = {}  # url -> timestamp ngh den

    def __init__(self, api_key: str = ""):
        self.urls = [u.rstrip("/") for u in (RENDER_CF2_URL, RENDER_CF_URL) if u.strip()]

    @classmethod
    def _session(cls):
        from requests.adapters import HTTPAdapter
        with cls._lock:
            if cls._SESSION is None:
                sess = requests.Session()
                sess.mount("https://", HTTPAdapter(pool_connections=4, pool_maxsize=8,
                                                   max_retries=1))
                cls._SESSION = sess
                cls._SEM = threading.BoundedSemaphore(6)
        return cls._SESSION

    def _pick(self):
        """Url ke tiep con song (round-robin, bo url dang mo breaker)."""
        now = time.time()
        cls = type(self)
        with cls._lock:
            n = len(self.urls)
            for k in range(n):
                u = self.urls[(cls._idx + k) % n]
                if now >= cls._disabled_until.get(u, 0):
                    cls._idx = (cls._idx + k + 1) % n
                    return u
        return None  # moi url dang mo breaker

    def _mark_fail(self, url):
        cls = type(self)
        with cls._lock:
            f = cls._fails.get(url, 0) + 1
            if f >= 3:
                cls._disabled_until[url] = time.time() + 120
                f = 0
            cls._fails[url] = f

    def solve_turnstile(self, page_url: str = None, sitekey: str = None) -> str:
        if not self.urls:
            raise CaptchaError("rendercf: khong co url (keys.txt [rendercf]/[rendercf2])")
        base = self._pick()
        if not base:
            raise CaptchaError("rendercf pool: ca 2 service dang mo breaker")
        url = page_url or TURNSTILE_PAGE_URL
        key = sitekey or TURNSTILE_SITEKEY
        sess = self._session()
        t0 = time.time()
        with type(self)._SEM:
            r = None
            for attempt in (1, 2):  # retry 1 lan khi mang/SSL gat
                try:
                    r = sess.post(f"{base}/solve",
                                  json={"sitekey": key, "url": url}, timeout=25)
                    break
                except Exception as e:
                    if attempt == 2:
                        self._mark_fail(base)
                        raise CaptchaError(f"rendercf net ({type(e).__name__})")
                    time.sleep(0.5)
        try:
            j = r.json()
        except Exception:
            j = {}
        tok = j.get("token") or ""
        if len(tok) >= 100:
            with type(self)._lock:
                type(self)._fails[base] = 0
            log.info(f"rendercf[{base.split('//')[1]}] {time.time()-t0:.1f}s | token={tok[:24]}...")
            return tok
        msg = str(j.get("message") or (r.status_code if r is not None else "?"))[:60]
        self._mark_fail(base)
        raise CaptchaError(f"rendercf fail ({msg})")

class Capsolver(BaseSolver):
    """Capsolver.com - AntiTurnstileTaskProxyLess."""
    name = "capsolver"

    def solve_turnstile(self, page_url: str = None, sitekey: str = None) -> str:
        page_url = page_url or TURNSTILE_PAGE_URL
        sitekey = sitekey or TURNSTILE_SITEKEY
        if not self.api_key:
            raise CaptchaError("Capsolver: thieu API key")

        payload = {
            "clientKey": self.api_key,
            "task": {
                "type": "AntiTurnstileTaskProxyLess",
                "websiteURL": page_url,
                "websiteKey": sitekey,
            },
        }
        try:
            r = requests.post(CAPSOLVER_API_URL, json=payload, timeout=30)
            j = r.json()
        except Exception as e:
            raise CaptchaError(f"Capsolver createTask network: {e}")
        if j.get("errorId", 1) != 0:
            raise CaptchaError(f"Capsolver createTask: {j.get('errorDescription', j)}")
        task_id = j.get("taskId")
        if not task_id:
            raise CaptchaError(f"Capsolver: khong co taskId: {j}")

        start = time.time()
        while time.time() - start < CAPTCHA_MAX_WAIT:
            time.sleep(CAPTCHA_POLL_INTERVAL)
            try:
                r = requests.post(
                    CAPSOLVER_RESULT_URL,
                    json={"clientKey": self.api_key, "taskId": task_id},
                    timeout=30,
                )
                j = r.json()
            except Exception as e:
                log.debug(f"Capsolver poll error: {e}")
                continue
            if j.get("errorId", 0) != 0:
                raise CaptchaError(f"Capsolver getTaskResult: {j.get('errorDescription', j)}")
            if j.get("status") == "ready":
                token = j.get("solution", {}).get("token", "")
                if token:
                    return token
                raise CaptchaError(f"Capsolver: solution khong co token: {j}")
        raise CaptchaError(f"Capsolver: timeout {CAPTCHA_MAX_WAIT}s")


# ====================== 2CAPTCHA ======================
class TwoCaptcha(BaseSolver):
    """2captcha.com - method=turnstile."""
    name = "2captcha"

    def solve_turnstile(self, page_url: str = None, sitekey: str = None) -> str:
        page_url = page_url or TURNSTILE_PAGE_URL
        sitekey = sitekey or TURNSTILE_SITEKEY
        if not self.api_key:
            raise CaptchaError("2Captcha: thieu API key")

        params = {
            "key": self.api_key,
            "method": "turnstile",
            "sitekey": sitekey,
            "pageurl": page_url,
            "json": 1,
        }
        try:
            r = requests.get(TWOCAPTCHA_API_URL, params=params, timeout=30)
            j = r.json()
        except Exception as e:
            raise CaptchaError(f"2Captcha submit network: {e}")
        if j.get("status") != 1:
            raise CaptchaError(f"2Captcha submit: {j.get('request', j)}")
        task_id = j.get("request")

        start = time.time()
        while time.time() - start < CAPTCHA_MAX_WAIT:
            time.sleep(CAPTCHA_POLL_INTERVAL)
            try:
                r = requests.get(
                    TWOCAPTCHA_RESULT_URL,
                    params={"key": self.api_key, "action": "get", "id": task_id, "json": 1},
                    timeout=30,
                )
                j = r.json()
            except Exception as e:
                log.debug(f"2Captcha poll error: {e}")
                continue
            if j.get("status") == 1:
                return j.get("request", "")
            if j.get("request") != "CAPCHA_NOT_READY":
                raise CaptchaError(f"2Captcha: {j.get('request', j)}")
        raise CaptchaError(f"2Captcha: timeout {CAPTCHA_MAX_WAIT}s")



_dead_keys = set()
_dead_lock = threading.Lock()
_BALANCE_ERR = (
    "insufficient balance", "low balance", "no balance", "balance is zero", "zero balance",
    "zero_balance", "error_zero_balance", "out of funds", "no funds",
    "insufficient credit", "not enough credit", "no credit",
    "please recharge", "add funds", "top up",
    "use balance is disabled", "wallet is empty", "wallet disabled",
    "does not exist", "key does not", "invalid key", "key is invalid",
    "error_key_does_not_exist", "plan expired", "plan_expired",
)


def _is_balance_err(msg):
    m = (msg or "").lower()
    return any(w in m for w in _BALANCE_ERR)


def _drop_key(key):
    """Xoa dung 1 dong key khoi keys.txt. Khong goi lai trong process."""
    key = (key or "").strip()
    if not key:
        return
    with _dead_lock:
        if key in _dead_keys:
            return
        _dead_keys.add(key)
        p = BASE_DIR / "keys.txt"
        if not p.exists():
            return
        raw = p.read_text(encoding="utf-8-sig", errors="ignore")
        lines = raw.splitlines(keepends=True)
        kept = [ln for ln in lines if ln.strip() != key]
        if len(kept) == len(lines):
            return
        p.write_text("".join(kept), encoding="utf-8")
        print(f"\033[93m[solver] xoa key het tien ({key[:8]}...)\033[0m", flush=True)


class AntiCaptchaSolver(BaseSolver):
    """createTask + getTaskResult. Dung cho nocaptchaai (clientKey) va captchasonic (apiKey)."""
    create_url = ""
    result_url = ""
    task_type = "AntiTurnstileTaskProxyLess"
    auth_field = "clientKey"
    solve_timeout = CAPTCHA_MAX_WAIT
    _gate = None

    def solve_turnstile(self, page_url: str = None, sitekey: str = None) -> str:
        page_url = page_url or TURNSTILE_PAGE_URL
        sitekey = sitekey or TURNSTILE_SITEKEY
        if not self.api_key:
            raise CaptchaError(f"{self.name}: thieu API key")
        gate = type(self)._gate
        if gate is not None:
            gate.acquire()
        try:
            return self._poll(page_url, sitekey)
        finally:
            if gate is not None:
                gate.release()

    def _poll(self, page_url, sitekey):
        body = {
            self.auth_field: self.api_key,
            "task": {
                "type": self.task_type,
                "websiteURL": page_url,
                "websiteKey": sitekey,
            },
        }
        try:
            r = requests.post(self.create_url, json=body, timeout=30)
            j = r.json()
        except (requests.RequestException, ValueError) as e:
            raise CaptchaError(f"{self.name} createTask: {e}")
        if j.get("errorId"):
            raise CaptchaError(
                f"{self.name} createTask err {j.get('errorId')}: "
                f"{str(j.get('errorDescription') or j.get('msg') or j)[:140]}"
            )
        task_id = j.get("taskId")
        if not task_id:
            raise CaptchaError(f"{self.name}: khong co taskId: {str(j)[:140]}")
        deadline = time.time() + self.solve_timeout
        while time.time() < deadline:
            time.sleep(CAPTCHA_POLL_INTERVAL)
            try:
                r = requests.post(
                    self.result_url,
                    json={self.auth_field: self.api_key, "taskId": task_id},
                    timeout=30,
                )
                j = r.json()
            except (requests.RequestException, ValueError):
                continue
            if j.get("errorId"):
                raise CaptchaError(
                    f"{self.name} result err {j.get('errorId')}: "
                    f"{str(j.get('errorDescription') or j.get('msg') or j)[:140]}"
                )
            if j.get("status") in ("ready", "completed"):
                token = (j.get("solution") or {}).get("token", "")
                if token:
                    return token
                raise CaptchaError(f"{self.name}: ready nhung khong co token")
        raise CaptchaError(f"{self.name}: timeout {self.solve_timeout}s")


class NocaptchaAI(AntiCaptchaSolver):
    name = "nocaptchaai"
    create_url = NOCAPTCHAAI_CREATE_URL
    result_url = NOCAPTCHAAI_RESULT_URL
    task_type = NOCAPTCHAAI_TASK_TYPE
    auth_field = NOCAPTCHAAI_AUTH_FIELD
    solve_timeout = NOCAPTCHAAI_TIMEOUT
    _gate = threading.Semaphore(6)


class CaptchaSonic(AntiCaptchaSolver):
    name = "captchasonic"
    create_url = CAPTCHASONIC_CREATE_URL
    result_url = CAPTCHASONIC_RESULT_URL
    task_type = CAPTCHASONIC_TASK_TYPE
    auth_field = CAPTCHASONIC_AUTH_FIELD
    solve_timeout = CAPTCHASONIC_TIMEOUT
    _gate = threading.Semaphore(4)


# ====================== MULTI-KEY (primary + fallback) ======================
class MultiKeySolver(BaseSolver):
    """Nhieu key cung loai. rotate=False: key dau, fail moi chuyen key ke.
    rotate=True: round-robin, tranh 1 key an het load.
    Het credit -> xoa dong trong keys.txt, khong goi lai.
    """
    def __init__(self, solver_cls, api_key: str, label: str, rotate=False):
        if isinstance(api_key, str):
            keys = [k.strip() for k in api_key.split(",") if k.strip()]
        else:
            keys = [k for k in api_key if k]
        self.keys = keys
        self.solvers = [solver_cls(k) for k in keys]
        self.name = f"{label}(x{len(keys)})" if keys else label
        self._label = label
        self.rotate = rotate
        self._rr = 0
        self._rr_lock = threading.Lock()
        self._tl = threading.local()

    def solve_turnstile(self, page_url: str = None, sitekey: str = None) -> str:
        alive = [s for s in self.solvers if s.api_key not in _dead_keys]
        if not alive:
            raise CaptchaError(f"{self._label}: khong co API key")
        with self._rr_lock:
            start = (self._rr % len(alive)) if self.rotate else 0
            if self.rotate:
                self._rr += 1
        order = alive[start:] + alive[:start]
        errs = []
        for s in order:
            tag = f"{self._label}:{s.api_key[-6:]}"
            try:
                tok = s.solve_turnstile(page_url, sitekey)
                if tok and len(tok) > 50:
                    self._tl.name = tag
                    return tok
                errs.append(f"{tag}: empty/short token")
            except CaptchaError as e:
                if _is_balance_err(str(e)):
                    _drop_key(s.api_key)
                errs.append(f"{tag}: {e}")
        raise CaptchaError(f"{self._label} all-keys fail | " + " || ".join(errs))

    def last_solver_name(self):
        return getattr(self._tl, "name", None)


# ====================== FALLBACK (multi-solver chain) ======================
class FallbackSolver(BaseSolver):
    """Thu tung solver theo thu tu, tra ve token cua solver dau tien thanh cong.

    --captcha "yeatcloud,capsolver,2captcha" -> yeatcloud chinh (free),
    capsolver/2captcha chi dung khi yeatcloud fail (tiet kiem credit).
    """
    name = "fallback"

    def __init__(self, solvers_list):
        self.solvers = solvers_list
        self.name = "fallback(" + ",".join(s.name for s in solvers_list) + ")"
        self._tl = threading.local()

    def solve_turnstile(self, page_url: str = None, sitekey: str = None) -> str:
        errs = []
        for s in self.solvers:
            try:
                tok = s.solve_turnstile(page_url, sitekey)
                if tok and len(tok) > 50:
                    log.info(f"Fallback: solved by [{s.name}]")
                    self._tl.name = s.last_solver_name() if s.last_solver_name() else s.name
                    return tok
                errs.append(f"{s.name}: empty/short token")
            except CaptchaError as e:
                errs.append(f"{s.name}: {e}")
            except Exception as e:
                errs.append(f"{s.name}: {e}")
        raise CaptchaError("Tat ca solver fail | " + " || ".join(errs))

    def last_solver_name(self):
        # Tra ve solver/key thuc te solve (per-thread); None neu chua solve
        return getattr(self._tl, "name", None)


# ====================== FACTORY ======================
_ALWAYS = {"yeatcloud", "turntitle", "none"}
_URL_ARMED = {"rendercf": (RENDER_CF_URL or RENDER_CF2_URL), "rendercf2": RENDER_CF2_URL}


class _CapsolverMulti(MultiKeySolver):
    def __init__(self, api_key: str = ""):
        super().__init__(Capsolver, api_key or DEFAULT_KEYS["capsolver"], "capsolver")


class _TwoCaptchaMulti(MultiKeySolver):
    def __init__(self, api_key: str = ""):
        super().__init__(TwoCaptcha, api_key or DEFAULT_KEYS["2captcha"], "2captcha")


class _NocaptchaMulti(MultiKeySolver):
    def __init__(self, api_key: str = ""):
        super().__init__(NocaptchaAI, api_key or DEFAULT_KEYS["nocaptchaai"], "nocaptchaai", rotate=True)


class _SonicMulti(MultiKeySolver):
    def __init__(self, api_key: str = ""):
        super().__init__(CaptchaSonic, api_key or DEFAULT_KEYS["captchasonic"], "captchasonic", rotate=True)


class _TurntitleSolver(YeatCloudSolver):
    """Cung API yeatcloud (GET /solve + X-Token) nhung ten hien thi = turntitle."""
    name = "turntitle"


SOLVERS = {
    "rendercf": RenderCfPoolSolver,
    "rendercf2": RenderCf2Solver,
    "turntitle": _TurntitleSolver,
    "nocaptchaai": _NocaptchaMulti,
    "captchasonic": _SonicMulti,
    "capsolver": _CapsolverMulti,
    "2captcha": _TwoCaptchaMulti,
    "twocaptcha": _TwoCaptchaMulti,
    "none": NoSolver,
}


def _armed(name, api_key):
    if name in _URL_ARMED:
        return bool(_URL_ARMED[name].strip())
    if name in _ALWAYS:
        return True
    return bool((api_key or DEFAULT_KEYS.get(name, "")).strip())


def get_solver(name: str, api_key: str = "") -> BaseSolver:
    """Lay solver theo ten.

      - 1 solver:  get_solver("nocaptchaai")
      - chain:     get_solver("yeatcloud,nocaptchaai,captchasonic,2captcha")
      - section trong keys.txt = bo qua, khong loi
    """
    name = (name or "none").lower().strip()

    if "," in name:
        parts = [p.strip() for p in name.split(",") if p.strip()]
        chain = []
        for p in parts:
            cls = SOLVERS.get(p)
            if not cls:
                raise ValueError(f"Solver khong ho tro: {p}. Co: {list(SOLVERS.keys())}")
            if not _armed(p, "" if p in _ALWAYS else api_key):
                continue
            key = "" if p in _ALWAYS else (api_key or DEFAULT_KEYS.get(p, ""))
            chain.append(cls(api_key=key))
        if not chain:
            raise ValueError("Khong co solver nao co key. Dien keys.txt hoac --captcha yeatcloud")
        if len(chain) == 1:
            return chain[0]
        return FallbackSolver(chain)

    cls = SOLVERS.get(name)
    if not cls:
        raise ValueError(f"Solver khong ho tro: {name}. Co: {list(SOLVERS.keys())}")
    if not _armed(name, api_key):
        raise ValueError(f"{name}: khong co key trong keys.txt")
    key = api_key or DEFAULT_KEYS.get(name, "")
    return cls(api_key=key)
