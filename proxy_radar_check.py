"""
Radar-aware proxy filter (BO SUNG cho proxy_check.py).
Chay SAU khi da loc dead (proxy_check.py). Test moi proxy con song:
  GET / + POST email step (KHONG can captcha, vi radar xuat hien truoc captcha).
    /password redirect    -> proxy SACH (pass WorkOS radar) -> KEEP
    /radar-challenge      -> proxy bi WorkOS flag           -> DROP
    dead/timeout/other    -> DROP

Cach dung:
    python proxy_radar_check.py                  # test proxies.txt
    python proxy_radar_check.py --threads 30 --timeout 12
"""
import os
import sys
import time
import random
import string
import argparse
import threading
import urllib.parse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from curl_cffi import requests as curl_req
from cursor_auth import _browser_headers, _multipart, _signals_b64
from config import (
    AUTH, ACTION_EMAIL, ROUTER_STATE_TREE, X_DEPLOYMENT_ID,
    UA, IMPERSONATE_PROFILE, TIMEOUT,
)
from proxy_pool import ProxyPool

BASE_DIR = Path(__file__).resolve().parent
PROXIES_FILE = str(BASE_DIR / "proxies.txt")
BAD_FILE = str(BASE_DIR / "proxies_radar_bad.txt")

# Email test phai la acc Cursor THAT (de nhan /password khi proxy sach).
# Xoay vong de tranh rate-limit per-email.
TEST_EMAILS = [
    "ahamed@bigboxit.net",
    "essikdevsarlau@gmail.com",
    "kriri@vk.com",
]

print_lock = threading.Lock()


def _boundary():
    return "----WebKitFormBoundary" + "".join(random.choices(string.ascii_letters + string.digits, k=16))


def test_one(line, email, timeout):
    """Test 1 proxy qua email step. Tra ve (line, status, err)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return (line, "skip", "")
    try:
        p = ProxyPool._parse_proxy(line)
    except Exception as e:
        return (line, "bad_format", str(e)[:50])
    proxies = {"http": p["http"], "https": p["https"]}

    try:
        s = curl_req.Session(impersonate=IMPERSONATE_PROFILE, proxies=proxies)
        # Step 1: GET / -> auth session
        try:
            r0 = s.get(AUTH, headers={"user-agent": UA, "accept": "text/html"},
                       allow_redirects=True, timeout=timeout)
        except Exception as e:
            msg = str(e)[:50].lower()
            if "timeout" in msg or "timed out" in msg:
                return (line, "slow", "timeout")
            return (line, "dead", str(e)[:50])

        if r0.status_code == 403:
            return (line, "banned", "403 cloudflare")

        qs = urllib.parse.parse_qs(urllib.parse.urlparse(str(r0.url)).query)
        asid = qs.get("authorization_session_id", [None])[0]
        redirect_uri = qs.get("redirect_uri", ["https://cursor.com/api/auth/callback"])[0]
        state = qs.get("state", [""])[0]
        if not asid:
            return (line, "no_session", f"{r0.status_code}")
        page_url = str(r0.url)

        # Step 2: POST email step (KHONG can captcha)
        bd = _boundary()
        try:
            r2 = s.post(
                page_url,
                headers=_browser_headers(page_url, ACTION_EMAIL, f"multipart/form-data; boundary={bd}"),
                data=_multipart({
                    "_1_signals": _signals_b64(),
                    "_1_email": email,
                    "_1_redirect_uri": redirect_uri,
                    "_1_authorization_session_id": asid,
                    "_1_state": state,
                    "0": '["$K1"]',
                }, bd),
                allow_redirects=False, timeout=timeout,
            )
        except Exception as e:
            msg = str(e)[:50].lower()
            if "timeout" in msg or "timed out" in msg:
                return (line, "slow", "email timeout")
            return (line, "dead", f"email post: {str(e)[:40]}")

        redir = r2.headers.get("x-action-redirect", "").split(";")[0]
        if "/password" in redir:
            return (line, "good", "")
        if "/radar-challenge" in redir:
            return (line, "radar", "")
        if r2.status_code == 429:
            return (line, "rate", "429")
        return (line, "other", f"{r2.status_code} {redir[:30]}")
    except Exception as e:
        return (line, "error", str(e)[:50])


def main():
    ap = argparse.ArgumentParser(description="Radar-aware proxy filter")
    ap.add_argument("--file", default=PROXIES_FILE)
    ap.add_argument("--timeout", type=int, default=12)
    ap.add_argument("--threads", type=int, default=30)
    ap.add_argument("--emails", default="", help="csv email test (override mac dinh)")
    args = ap.parse_args()

    emails = [e.strip() for e in args.emails.split(",") if e.strip()] or TEST_EMAILS

    with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    print(f"[+] Test radar {len(lines)} proxy (timeout {args.timeout}s, {args.threads} threads)")
    print(f"    Target: {AUTH}  (email step, KHONG captcha)")
    print(f"    Test emails: {emails}\n")

    results = []
    done = 0
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {
            ex.submit(test_one, line, emails[i % len(emails)], args.timeout): line
            for i, line in enumerate(lines)
        }
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            done += 1
            line, status, err = res
            with print_lock:
                if done % 50 == 0 or status == "good":
                    mark = {
                        "good": "\033[92mOK\033[0m", "radar": "\033[91mRADAR\033[0m",
                        "dead": "\033[90mDEAD\033[0m", "slow": "\033[93mSLOW\033[0m",
                        "banned": "\033[91mBAN\033[0m", "rate": "\033[93mRATE\033[0m",
                        "no_session": "\033[91mNOSESS\033[0m", "other": "\033[91m?\033[0m",
                        "bad_format": "\033[90mFMT\033[0m",
                    }.get(status, "?")
                    print(f"  [{done}/{len(lines)}] {mark:18} {line.split(':')[0]:18} {err}")

    good = [r for r in results if r[1] == "good"]
    radar = [r for r in results if r[1] == "radar"]
    bad = [r for r in results if r[1] in ("dead", "slow", "banned", "rate", "no_session", "other", "bad_format", "error")]

    print(f"\n{'=' * 52}")
    print(f"  GOOD  (pass radar -> /password):  {len(good)}")
    print(f"  RADAR (WorkOS flagged):           {len(radar)}")
    print(f"  DEAD/banned/other:                {len(bad)}")
    print(f"  -> KEEP: {len(good)} proxy")
    print(f"{'=' * 52}")

    if good:
        speeds_note = ""

    # Backup + ghi lai chi good
    if os.path.exists(args.file):
        os.replace(args.file, args.file + ".radarbak")
        print(f"\n[+] Backup -> {args.file}.radarbak")
    with open(args.file, "w", encoding="utf-8") as f:
        f.write("\n".join(r[0] for r in good) + ("\n" if good else ""))
    print(f"[+] Ghi {len(good)} good proxy -> {args.file}")
    with open(BAD_FILE, "w", encoding="utf-8") as f:
        for line, st, err in radar + bad:
            f.write(f"{line}  # {st} {err}\n")
    print(f"[+] {len(radar) + len(bad)} bad/radar -> {BAD_FILE}")


if __name__ == "__main__":
    main()
