"""
Cursor Auth - WorkOS AuthKit login flow & account info
======================================================
Flow dang nhap Cursor (authenticator.cursor.sh / WorkOS AuthKit + Next.js server actions):

  1. GET  /                          -> lay authorization_session_id + state
  2. POST [SIGNALS]   text/plain     -> gui device fingerprint hash
  3. POST [EMAIL]     multipart      -> submit email  -> 303 x-action-redirect: /password
  4. GET  /password                  -> (set __Host-state cookie)
  5. solve Turnstile token (captcha solver)
  6. POST [PASSWORD]  multipart      -> submit password + _1_bot_detection_token
                                       -> 303 x-action-redirect: /success  (OK)
                                       -> 303 /radar-challenge            (bot detected)
                                       -> form re-render                  (bad pass / error)
  7. follow /success -> callback     -> WorkosCursorSessionToken cookie

QUAN TRONG: phai gui DU browser-like headers (sec-ch-ua, sec-fetch-*, x-deployment-id)
            neu khong WorkOS radar se redirect /radar-challenge (bot detection).

Dung curl_cffi (impersonate chrome) de tranh block TLS fingerprint.
"""

import re
import json
import time
from datetime import datetime, timezone
import base64
import random
import string
import urllib.parse
import logging

from curl_cffi import requests as curl_req

from config import (
    AUTH, CURSOR, AUTH_ME_URL, USAGE_URL, STRIPE_PROFILE_URL, USAGE_SUMMARY_URL,
    USAGE_SUMMARY_API2_URL, ACTION_SIGNALS, ACTION_EMAIL, ACTION_PASSWORD,
    ROUTER_STATE_TREE, ROUTER_STATE_TREE_PASSWORD, X_DEPLOYMENT_ID, SIGNALS_HASH,
    SESSION_COOKIE_NAME,
    TURNSTILE_SITEKEY, UA, IMPERSONATE_PROFILE, TIMEOUT,
    IMPERSONATE_FALLBACK, UA_FALLBACK,
)

# ====================== TIER RANKING ======================
# membershipType co the la: free, free_trial, pro_trial, pro, pro_plus, ultra, team, enterprise.
# Cross-check 2 endpoint (stripe_profile + usage_summary), lay tier CAO HON.
# (Mot so acc Ultra/Pro+ tra "pro" o stripe_profile nhung dung tier o usage_summary.)
_TIER_RANK = {
    "free": 0, "": 0,
    "free_trial": 1,
    "pro_trial": 2,
    "pro": 3,
    "pro_plus": 4,
    "ultra": 5,
    "team": 6,
    "enterprise": 7,
}


def _tier_rank(mt):
    return _TIER_RANK.get((mt or "").lower(), 0)
from captcha_solvers import CaptchaError

log = logging.getLogger(__name__)

# ====================== DEVICE FINGERPRINT (_1_signals blob) ======================
# Static, realistic Windows/Chrome fingerprint. Base64-encoded JSON, gui trong moi POST.
# WorkOS scoring chap nhan fingerprint co gan nhu static (khong validate ngheim).
_BASE_SIGNALS = {
    "timezone": "Asia/Bangkok", "language": "en-US", "hardwareConcurrency": 8,
    "webdriver": False, "appVersion": UA.replace("Mozilla/", ""), "platform": "Win32",
    "screen": {"width": 1920, "height": 1080, "availWidth": 1920, "availHeight": 1040,
               "windowOuterWidth": 1920, "windowOuterHeight": 1040, "colorDepth": 24, "pixelDepth": 24},
    "rangeErrorLength": 0, "evalStringLength": 33,
    "playwrightDetected": False, "phantomDetected": False, "nightmareDetected": False,
    "seleniumDetected": False, "puppeteerDetected": False,
    "maxTouchPoints": 0, "deviceMemory": 16,
    "permissionsState": "prompt", "notificationPermission": "default",
    "devicePixelRatio": 1.0000000149011612, "pluginsLength": 5, "mimeTypesCount": 2,
    "documentHidden": False, "documentVisibilityState": "visible",
    "mediaPreferences": {"colorScheme": "light", "reducedMotion": False, "reducedTransparency": False,
                         "contrast": "no-preference", "colorGamut": "srgb", "hdr": False,
                         "forcedColors": False, "invertedColors": False},
    "webGLVendor": "Google Inc. (Intel)",
    "webGLRenderer": "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x00009A49) Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "minimalSurface": {"windowFeaturesHash": "AOPOKapeY_rO88sdd_6OcvQytOk67q3_dy9Hvr3h_fA",
                       "windowFeaturesCount": 1231, "cssKeysHash": "b2ni-Sqlvx0m7IuPN_BOCd7LHaHQIw5v3VpCQbnagCI",
                       "cssKeysCount": 1415, "voicesHash": "47DEQpj8HBSa-_TImW5yMHj0KK8WvQ",
                       "voicesLocalCount": 0, "voicesRemoteCount": 0, "voicesLanguagesCount": 0,
                       "mediaMimeHash": "kZhx7yaWeGtKjuD7WOEr3WTtuDBSuluHtsXg3uGZGSw",
                       "mediaMimeCount": 9, "fontsHash": "8Q_OWX6z9rR0EAtKKlbXiyuA9ClMKEeRnA84uOyJXQ",
                       "fontsCount": 19},
    "worker": {"ok": True, "hardwareConcurrency": 8, "platform": "Win32", "userAgent": UA,
               "language": "en-US",
               "webGLRenderer": "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x00009A49) Direct3D11 vs_5_0 ps_5_0, D3D11)",
               "webGLVendor": "Google Inc. (Intel)"},
    "canvasHash": "bdnRkj84IA9dhhgf_CTworQJ3HEq1BLSmkx5efVeE",
    "audioHash": "7FEQpj8HBSa-_TImW5yMHj0KK8WvQ",
}


# ---- LOAD SIGNALS THAT tu browser capture ----
# Cursor (deploy 2026-08+) cham diem signals o PASSWORD step: blob tinh cu bi radar.
# File nay do capture_patch.py xuat ra (browser that login → signals cua deploy hien tai).
# Refresh khi bi radar hang loat: python capture_patch.py (khong can sua code).
try:
    from pathlib import Path as _P
    _sig_file = _P(__file__).resolve().parent / "_captured_signals.txt"
    _BASE_SIGNALS = json.loads(base64.b64decode(_sig_file.read_text(encoding="utf-8").strip()))
except Exception as _e:
    log.warning(f"Khong load duoc _captured_signals.txt ({_e}) -> dung signals TINH CU (nguy co radar!)")


def _rand_b64_hash():
    """Hash 43 chars base64url (32 bytes) — format giong canvas/audio hash that."""
    return base64.urlsafe_b64encode(random.getrandbits(256).to_bytes(32, "big")).decode().rstrip("=")


_SCREEN_POOL = [(1920, 1080), (1536, 864), (1366, 768), (2560, 1440), (1440, 900), (1280, 800), (1680, 1050)]


def _signals_b64(ua=None):
    """Generate base64-encoded signals blob — DEVICE PERSONA MOI MOI LOGIN.

    2026-10-31 (dem): WorkOS flag theo DEVICE-HASH (canvas/audio/webGL identical
    9,000 lan -> radar 43% overnight). Timestamps refresh chi lam cham (23%).
    Fix: random hash-set + screen/hw/memory moi login = "thiet bi moi", khong tich luy.
    """
    sig = dict(_BASE_SIGNALS)
    now = int(time.time() * 1000)
    sig["createdAtMs"] = now - random.randint(3000, 9000)
    sig["collectedAtMs"] = sig["createdAtMs"] - random.randint(500, 2000)
    sig["submittedAtMs"] = now
    for k in ("canvasHash", "audioHash", "webGLParamsHash", "mathHash", "intlHash"):
        if k in sig:
            sig[k] = _rand_b64_hash()
    w, h = random.choice(_SCREEN_POOL)
    avail_h = h - random.choice((40, 48, 56, 72))
    if isinstance(sig.get("screen"), dict):
        sc = dict(sig["screen"])
        sc.update({"width": w, "height": h, "availWidth": w, "availHeight": avail_h})
        sig["screen"] = sc
    sig["hardwareConcurrency"] = random.choice((4, 6, 8, 8, 12, 16))
    sig["deviceMemory"] = random.choice((4, 8, 8, 16))
    sig["evalStringLength"] = 33 + random.randint(0, 4)
    sig["userAgent"] = ua or UA
    return base64.b64encode(json.dumps(sig, separators=(",", ":")).encode()).decode()

def _boundary():
    return "----WebKitFormBoundary" + "".join(
        random.choices(string.ascii_letters + string.digits, k=16)
    )


def _multipart(fields: dict, boundary: str) -> bytes:
    parts = []
    for name, value in fields.items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n"
        )
    parts.append(f"--{boundary}--\r\n")
    return "".join(parts).encode()


def _make_session(proxy_obj=None, impersonate=None):
    """curl_cffi session impersonate Chrome + proxy."""
    s = curl_req.Session(impersonate=impersonate or IMPERSONATE_PROFILE)
    if proxy_obj:
        s.proxies = {"http": proxy_obj["http"], "https": proxy_obj["https"]}
    return s


def _browser_headers(referer, next_action, content_type, accept="text/x-component",
                     router_state=None, ua=None):
    """Full browser-like headers (CRITICAL cho WorkOS radar)."""
    return {
        "user-agent": ua or UA,
        "accept": accept,
        "accept-language": "en-US,en;q=0.9",
        "content-type": content_type,
        "origin": AUTH,
        "referer": referer,
        # Live capture 2026-09-01: Chromium 149 + Not)A;Brand 24 (patchright)
        "sec-ch-ua": '"Chromium";v="145", "Not)A;Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "next-action": next_action,
        "next-router-state-tree": router_state or ROUTER_STATE_TREE,
        "x-deployment-id": X_DEPLOYMENT_ID,
    }


def _extract_token(session):
    """Doc WorkosCursorSessionToken tu cookie jar."""
    for cookie in session.cookies.jar:
        if cookie.name == SESSION_COOKIE_NAME:
            return urllib.parse.unquote(cookie.value)
    return None


# ====================== MAIN LOGIN ======================
class CursorAuth:
    """Xu ly flow dang nhap Cursor (WorkOS AuthKit)."""

    def __init__(self, proxy_obj=None, captcha_solver=None):
        self.s = _make_session(proxy_obj)
        self.proxy_obj = proxy_obj
        self.proxy_url = (proxy_obj or {}).get("http")
        self._ua = UA
        self.captcha_solver = captcha_solver

    def login(self, email, password, auto_solve_captcha=True):
        """
        Full login flow. Tra ve dict:
          {ok, status, token, msg}

        status:
          'ok'        -> login thanh cong, co token
          'bad_pass'  -> sai pass / email khong ton tai
          'captcha'   -> turnstile solve fail / rejected
          'radar'     -> WorkOS bot detection (radar-challenge)
          'need_2fa'  -> can OTP / 2FA
          'rate'      -> rate limit
          'error'     -> loi khac (network / parse)
        """
        try:
            return self._do_login(email, password, auto_solve_captcha)
        except Exception as e:
            return {"ok": False, "status": "error", "msg": f"exception: {e}"}

    def _do_login(self, email, password, auto_solve):
        # ---------- STEP 1: GET / -> auth session (tu dong solve CF 403) ----------
        def _get_entry():
            return self.s.get(
                AUTH,
                headers={"user-agent": self._ua, "accept": "text/html",
                         "accept-language": "en-US,en;q=0.9"},
                allow_redirects=True, timeout=TIMEOUT,
            )

        try:
            r0 = _get_entry()
        except Exception as e:
            return {"ok": False, "status": "error", "msg": f"GET / network: {e}"}

        page_url = str(r0.url)
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(page_url).query)
        asid = qs.get("authorization_session_id", [None])[0]
        if not asid:
            body0 = (r0.text or "")[:600].lower()
            cf_blocked = (r0.status_code == 403 or "just a moment" in body0
                          or "challenge-platform" in body0)
            if cf_blocked:
                # Lach CF (hybrid): CF chi chan JA3 Chrome desktop o GET entry.
                # Lay entry bang session Android roi copy cookie (__cf_bm, state)
                # sang session chrome124 chinh. POST steps di tiep bang chrome124
                # + UA desktop — combo WorkOS radar da tune (config 2026-09-21).
                # Session Android xuyen suot password step gay radar/FAIL (run
                # 2026-10-07-014449: 0 FREE, acc tung FREE bi ghi FAIL/ERROR).
                try:
                    s_cf = _make_session(self.proxy_obj, impersonate=IMPERSONATE_FALLBACK)
                    r0 = s_cf.get(
                        AUTH,
                        headers={"user-agent": UA_FALLBACK, "accept": "text/html",
                                 "accept-language": "en-US,en;q=0.9"},
                        allow_redirects=True, timeout=TIMEOUT,
                    )
                    page_url = str(r0.url)
                    qs = urllib.parse.parse_qs(urllib.parse.urlparse(page_url).query)
                    asid = qs.get("authorization_session_id", [None])[0]
                    if asid:
                        for ck in s_cf.cookies.jar:
                            try:
                                self.s.cookies.set(ck.name, ck.value,
                                                   domain=ck.domain, path=ck.path)
                            except Exception:
                                pass
                except Exception as e:
                    return {"ok": False, "status": "error", "msg": f"GET / retry network: {e}"}
            if not asid:
                if cf_blocked:
                    return {"ok": False, "status": "error",
                            "msg": "cloudflare 403 challenge (exit IP blocked)"}
                return {"ok": False, "status": "error", "msg": "no authorization_session_id"}

        redirect_uri = qs.get("redirect_uri", [f"{CURSOR}/api/auth/callback"])[0]
        state = qs.get("state", [""])[0]

        # ---------- STEP 2: email step (multipart) ----------
        # Browser KHONG gui fingerprint text/plain o trang email nua;
        # signals hash POST o /password (sau GET /password).
        bd = _boundary()
        try:
            r2 = self.s.post(
                page_url,
                headers=_browser_headers(page_url, ACTION_EMAIL, f"multipart/form-data; boundary={bd}", ua=self._ua),
                data=_multipart({
                    "_1_signals": _signals_b64(self._ua), "_1_email": email,
                    "_1_redirect_uri": redirect_uri, "_1_authorization_session_id": asid,
                    "_1_state": state, "0": '["$K1"]',
                }, bd),
                allow_redirects=False, timeout=TIMEOUT,
            )
        except Exception as e:
            return {"ok": False, "status": "error", "msg": f"email step network: {e}"}

        redir = r2.headers.get("x-action-redirect", "").split(";")[0]
        if "/password" not in redir:
            if "/radar-challenge" in redir:
                return {"ok": False, "status": "radar", "msg": "radar-challenge (email step)"}
            if "/mfa" in redir or "/two-factor" in redir:
                return {"ok": False, "status": "need_2fa", "msg": "2FA required (email step)"}
            if r2.status_code == 429:
                return {"ok": False, "status": "rate", "msg": "rate limit (email step)"}
            # No /password redirect = email khong ton tai hoac loi
            return {"ok": False, "status": "bad_pass", "msg": f"email not found / rejected (no /password redirect) [{r2.status_code}]"}

        pw_url = f"{AUTH}{redir}" if redir.startswith("/") else redir

        # ---------- STEP 3: GET /password (set cookie) ----------
        try:
            self.s.get(pw_url, headers={"user-agent": self._ua, "accept": "text/html"}, allow_redirects=True, timeout=TIMEOUT)
        except Exception:
            pass

        # ---------- STEP 4: fingerprint signals tren /password (text/plain) ----------
        # Live capture: POST text/plain next-action=ACTION_SIGNALS, body=["<SIGNALS_HASH>"]
        try:
            self.s.post(
                pw_url,
                headers=_browser_headers(
                    pw_url, ACTION_SIGNALS, "text/plain;charset=UTF-8",
                    router_state=ROUTER_STATE_TREE_PASSWORD,
                    ua=self._ua,
                ),
                data=json.dumps([SIGNALS_HASH]),
                allow_redirects=False, timeout=TIMEOUT,
            )
        except Exception:
            pass  # non-fatal

        # ---------- STEP 5: solve Turnstile ----------
        captcha_token = ""
        if auto_solve and self.captcha_solver and self.captcha_solver.name != "none":
            try:
                captcha_token = self.captcha_solver.solve_turnstile(AUTH, TURNSTILE_SITEKEY)
            except CaptchaError as e:
                return {"ok": False, "status": "captcha", "msg": f"turnstile solve: {e}"}
            except Exception as e:
                return {"ok": False, "status": "captcha", "msg": f"turnstile solve error: {e}"}
        if not captcha_token:
            return {"ok": False, "status": "captcha", "msg": "no turnstile token (need captcha solver)"}

        # ---------- STEP 6: password step (multipart + turnstile) ----------
        bd2 = _boundary()
        try:
            r5 = self.s.post(
                pw_url,
                headers=_browser_headers(
                    pw_url, ACTION_PASSWORD, f"multipart/form-data; boundary={bd2}",
                    router_state=ROUTER_STATE_TREE_PASSWORD,
                    ua=self._ua,
                ),
                data=_multipart({
                    "_1_bot_detection_token": captcha_token,
                    "_1_signals": _signals_b64(self._ua),
                    "_1_email": email,
                    "_1_password": password,
                    "_1_intent": "password",
                    "_1_redirect_uri": redirect_uri,
                    "_1_authorization_session_id": asid,
                    "_1_state": state,
                    "0": '["$K1"]',
                }, bd2),
                allow_redirects=False, timeout=TIMEOUT,
            )
        except Exception as e:
            return {"ok": False, "status": "error", "msg": f"password step network: {e}"}

        pw_redir = r5.headers.get("x-action-redirect", "").split(";")[0]

        # Phan tich dua TREN REDIRECT HEADER (tin cay hon body, vi body RSC chua
        # nhieu i18n string "verify"/"code" -> false positive).
        #
        # /success        -> login OK
        # /radar-challenge-> bot detection (RETRY)
        # /mfa, /two-factor, /verify-email, /enroll-mfa -> 2FA that su
        # redirect empty  -> form re-render = sai password (pass dung -> /success)
        if "/success" in pw_redir:
            return self._finish_login(pw_redir, state)
        if "/radar-challenge" in pw_redir:
            return {"ok": False, "status": "radar", "msg": "WorkOS bot detection (radar-challenge)"}
        if "/mfa" in pw_redir or "/two-factor" in pw_redir or "/enroll-mfa" in pw_redir:
            return {"ok": False, "status": "need_2fa", "msg": f"2FA/MFA required: {pw_redir}"}
        if "/verify-email" in pw_redir or "/email-verification" in pw_redir:
            return {"ok": False, "status": "need_2fa", "msg": f"email verification required: {pw_redir}"}

        # Khong co redirect = form re-render = sai password (pass dung thi redirect /success)
        if not pw_redir or "/password" in pw_redir:
            # Confirm voi status code: 200 + form re-render = bad pass
            if r5.status_code == 429:
                return {"ok": False, "status": "rate", "msg": "rate limit (429)"}
            return {"ok": False, "status": "bad_pass", "msg": f"wrong password (no /success redirect) [{r5.status_code}]"}

        # Redirect khac la (khong nhan dien) -> bao error de investigate
        return {"ok": False, "status": "error",
                "msg": f"password step [{r5.status_code}] redir={pw_redir[:80]!r}"}

    def _finish_login(self, success_redir, state):
        """Follow /success -> callback -> extract WorkosCursorSessionToken.

        /success page does a (JS/meta) redirect to cursor.com/api/auth/callback?code=XXX.
        curl_cffi khong follow JS redirect nen phai parse code roi hit callback explicit.
        """
        succ_url = f"{AUTH}{success_redir}" if success_redir.startswith("/") else success_redir
        try:
            rs = self.s.get(succ_url, headers={"user-agent": self._ua, "accept": "text/html"},
                            allow_redirects=True, timeout=TIMEOUT)
            body = rs.text
            final_url = str(rs.url)
        except Exception:
            body = ""
            final_url = ""

        # 1. Co the cookie da duoc set sau redirect chain
        token = _extract_token(self.s)
        if token:
            return {"ok": True, "status": "ok", "token": token}

        # 2. Parse code tu body / url roi hit cursor.com callback explicit
        code = None
        for source in (final_url, body, success_redir):
            m = re.search(r'[?&]code=([A-Za-z0-9_\-]{8,})', source)
            if m:
                code = m.group(1)
                break
        if code:
            try:
                cb = f"{CURSOR}/api/auth/callback?code={code}&state={state}"
                self.s.get(cb, headers={"user-agent": self._ua, "accept": "text/html"},
                           allow_redirects=True, timeout=TIMEOUT)
            except Exception:
                pass
            token = _extract_token(self.s)
            if token:
                return {"ok": True, "status": "ok", "token": token}

        # 3. Fallback: dung access-token JWT (co the lay tu cookie) -> construct sub::jwt
        for ck in self.s.cookies.jar:
            if ck.name == "access-token" and ck.value and ck.value.startswith("eyJ"):
                sub = _decode_jwt_sub(ck.value)
                if sub:
                    return {"ok": True, "status": "ok", "token": f"{sub}::{ck.value}"}

        return {"ok": True, "status": "ok", "token": "", "msg": "logged in but token not captured"}


def _parse_when(value):
    """ISO-8601, epoch seconds, or epoch ms. None if absent or unparseable."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        sec = value / 1000.0 if value > 10_000_000_000 else float(value)
        return datetime.fromtimestamp(sec, timezone.utc)
    text = str(value).strip()
    if not text or text.lower() == "null":
        return None
    if text.isdigit():
        return _parse_when(int(text))
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _fmt_day(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _left_days(dt):
    delta = (dt - datetime.now(timezone.utc)).total_seconds() / 86400
    if delta <= 0:
        return "0d"
    if delta >= 10:
        return f"{delta:.0f}d"
    return f"{delta:.1f}d"


def _renew_label(cycle_end, cancel_at, yearly, status, membership, individual):
    """Renew = next charge for active monthly. Ends = trial or scheduled cancel.
    Yearly billingCycleEnd is the monthly usage reset, not the annual charge.
    """
    paid = (membership or "") not in ("", "free", "unknown")
    trial = (
        membership in ("free_trial", "pro_trial")
        or individual == "pro_trial"
        or status == "trialing"
        or (membership == "pro" and status not in ("active", "past_due"))
    )
    if cancel_at:
        bits = [f"Ends={_fmt_day(cancel_at)}", f"Left={_left_days(cancel_at)}"]
        if cycle_end and abs((cancel_at - cycle_end).total_seconds()) > 3600:
            bits.append(f"CycleEnd={_fmt_day(cycle_end)}")
        return " | ".join(bits)
    if not cycle_end:
        return ""
    stamp = _fmt_day(cycle_end)
    left = _left_days(cycle_end)
    if trial:
        return f"Ends={stamp} | Left={left}"
    if paid and status == "active" and yearly:
        return f"UsageReset={stamp} | Left={left} | Yearly"
    if paid and status == "active":
        return f"Renew={stamp} | Left={left}"
    return f"CycleEnd={stamp} | Left={left}"


# ====================== ACCOUNT INFO ======================
def get_account_info(token, proxy_obj=None):
    """
    Doc thong tin account + plan.

    QUAN TRONG: plan info KHONG nam o /api/auth/me (chi co profile).
    Plan nam o  api2.cursor.sh/auth/full_stripe_profile  (auth = Bearer JWT).

    Tra ve dict:
      {ok, email, membershipType, subscriptionStatus, plan, usage, renew, msg}
    """
    info = {"ok": False, "email": "", "membershipType": "unknown",
            "subscriptionStatus": "unknown", "plan": "Free", "usage": "",
            "renew": "", "msg": ""}
    if not token:
        info["msg"] = "no token"
        return info

    # Tach JWT (phan sau "::") va cookie value
    jwt = token.split("::", 1)[1] if "::" in token else token
    cookie_val = urllib.parse.quote(token, safe="")
    proxies = {"http": proxy_obj["http"], "https": proxy_obj["https"]} if proxy_obj else None
    cookie_headers = {"user-agent": UA, "accept": "application/json",
                      "cookie": f"{SESSION_COOKIE_NAME}={cookie_val}"}
    bearer_headers = {"user-agent": UA, "accept": "application/json",
                      "authorization": f"Bearer {jwt}"}

    # 1. /api/auth/me (cookie) -> email/name (khong co plan)
    try:
        r = curl_req.get(AUTH_ME_URL, headers=cookie_headers, proxies=proxies,
                         impersonate=IMPERSONATE_PROFILE, timeout=TIMEOUT)
        if r.status_code == 200:
            me = r.json()
            info["email"] = me.get("email", "")
        elif r.status_code == 204:
            info["msg"] = "token invalid (me 204)"
            return info
    except Exception:
        pass

    # 2. full_stripe_profile (Bearer JWT) -> PLAN INFO (membershipType, subscriptionStatus, ...)
    try:
        r2 = curl_req.get(STRIPE_PROFILE_URL, headers=bearer_headers, proxies=proxies,
                          impersonate=IMPERSONATE_PROFILE, timeout=TIMEOUT)
    except Exception as e:
        info["msg"] = f"stripe profile network: {e}"
        return info

    if r2.status_code == 401:
        info["msg"] = "token invalid (stripe 401)"
        return info
    if r2.status_code != 200:
        info["msg"] = f"stripe profile {r2.status_code}: {r2.text[:120]}"
        return info
    try:
        sp = r2.json()
    except Exception:
        info["msg"] = f"stripe profile not JSON: {r2.text[:120]}"
        return info

    info["ok"] = True
    mt = (sp.get("membershipType") or "").lower()
    ss = (sp.get("subscriptionStatus") or "").lower()
    imt = (sp.get("individualMembershipType") or "").lower()
    tmt = (sp.get("teamMembershipType") or "").lower()
    is_team = sp.get("isTeamMember", False)
    is_yearly = sp.get("isYearlyPlan", False)
    cancel_raw = sp.get("pendingCancellationDate")
    cycle_end_raw = None

    # Cross-check voi usage-summary (dashboard) -> tier chinh xac hon cho Ultra/Pro+.
    # Uu tien api2 Bearer (luon chay voi JWT tu login), fallback cookie cursor.com.
    mt_summary = ""
    try:
        r3a = curl_req.get(USAGE_SUMMARY_API2_URL, headers=bearer_headers, proxies=proxies,
                           impersonate=IMPERSONATE_PROFILE, timeout=TIMEOUT)
        if r3a.status_code != 200:
            r3a = curl_req.get(USAGE_SUMMARY_URL, headers=cookie_headers, proxies=proxies,
                               impersonate=IMPERSONATE_PROFILE, timeout=TIMEOUT)
        if r3a.status_code == 200:
            summ = r3a.json()
            mt_summary = (summ.get("membershipType") or "").lower()
            cycle_end_raw = summ.get("billingCycleEnd")
            if not ss:
                ss = (summ.get("subscriptionStatus") or "").lower()
            # USAGE THAT (dashboard moi): individualUsage.plan.used/limit
            # (endpoint cu gpt-4.numRequestsTotal deprecated -> luon 0/null)
            iu = summ.get("individualUsage") or {}
            plan_u = iu.get("plan") or {}
            used, lim = plan_u.get("used"), plan_u.get("limit")
            parts = []
            if used is not None:
                pct = f" ({used*100//lim}%)" if lim else ""
                parts.append(f"Usage={used}/{lim}{pct}")
            # SPENDING that (on-demand, cents -> $)
            od_cents = (iu.get("onDemand") or {}).get("used") or 0
            if od_cents > 0:
                parts.append(f"Spend=${od_cents/100:.2f}")
            if parts:
                info["usage"] = " | ".join(parts)
    except Exception:
        pass

    # Chon tier cao hon
    if _tier_rank(mt_summary) > _tier_rank(mt):
        mt = mt_summary
    info["membershipType"] = mt
    info["subscriptionStatus"] = ss
    info["renew"] = _renew_label(
        _parse_when(cycle_end_raw), _parse_when(cancel_raw), bool(is_yearly), ss, mt, imt,
    )

    # Map -> plan label (HIT = co plan tra phi / premium features)
    if is_team or mt == "team":
        info["plan"] = f"Team ({tmt})" if tmt else "Team"
    elif mt == "enterprise":
        info["plan"] = "Enterprise"
    elif mt == "ultra":
        info["plan"] = "Ultra"
    elif mt == "pro_plus":
        info["plan"] = "Pro+"
    elif mt == "pro":
        info["plan"] = "Pro Trial" if (ss != "active" or imt == "pro_trial") else "Pro"
        if is_yearly:
            info["plan"] += " (Yearly)"
    elif mt == "pro_trial":
        info["plan"] = "Pro Trial"
    elif mt == "free_trial":
        info["plan"] = "Free Trial"
    elif mt == "free" or not mt:
        info["plan"] = "Free"
    else:
        info["plan"] = mt.capitalize()

    # 3. /api/usage (extra info - non-fatal; CHI fallback neu usage-summary khong co du lieu)
    try:
        if not info.get("usage"):
            r3 = curl_req.get(USAGE_URL, headers=cookie_headers, proxies=proxies,
                              impersonate=IMPERSONATE_PROFILE, timeout=TIMEOUT)
            if r3.status_code == 200:
                u = r3.json()
                gpt4 = u.get("gpt-4", {})
                num = gpt4.get("numRequestsTotal", 0)
                mx = gpt4.get("maxRequestUsage", "?")
                info["usage"] = f"Usage={num}/{mx}"
    except Exception:
        pass

    return info


def _decode_jwt_sub(jwt_token):
    """Lay 'sub' claim tu JWT."""
    try:
        parts = jwt_token.split(".")
        if len(parts) < 2:
            return None
        p = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(p)).get("sub")
    except Exception:
        return None
