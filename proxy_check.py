"""
Test proxies: xem cai nao reach duoc authenticator.cursor.sh.
Bo proxy chet/timeout, giu proxy good. Backup goc -> proxies_bad.txt.

Usage:
    python proxy_check.py                 # test tat ca, timeout 15s/proxy
    python proxy_check.py --timeout 12    # timeout ngan hon
"""
import os
import sys
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from curl_cffi import requests as curl_req
from proxy_pool import ProxyPool
from config import IMPERSONATE_PROFILE, UA

BASE_DIR = Path(__file__).resolve().parent
PROXIES_FILE = str(BASE_DIR / "proxies.txt")
BAD_FILE = str(BASE_DIR / "proxies_bad.txt")
TEST_URL = "https://authenticator.cursor.sh/"

print_lock = threading.Lock()


def test_one(line, timeout):
    """Test 1 proxy. Tra ve (line, ok, ms, status_or_err)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return (line, "skip", 0, "")
    try:
        p = ProxyPool._parse_proxy(line)
    except Exception as e:
        return (line, "bad_format", 0, str(e)[:60])
    proxies = {"http": p["http"], "https": p["https"]}
    t0 = time.time()
    try:
        r = curl_req.get(
            TEST_URL,
            headers={"user-agent": UA, "accept": "text/html"},
            proxies=proxies, impersonate=IMPERSONATE_PROFILE,
            timeout=timeout, allow_redirects=True,
        )
        ms = int((time.time() - t0) * 1000)
        if r.status_code == 403:
            return (line, "cf403", ms, "HTTP 403")
        if r.status_code != 200:
            return (line, "bad_status", ms, f"HTTP {r.status_code}")
        url = str(r.url)
        body = (r.text or "")[:600].lower()
        if "just a moment" in body or "cf-browser-verification" in body or "challenge-platform" in body:
            return (line, "cf_challenge", ms, "cloudflare challenge")
        if "authorization_session_id" not in url:
            return (line, "no_session", ms, "no authorization_session_id")
        return (line, "good", ms, "session")
    except curl_req.exceptions.ProxyError as e:
        ms = int((time.time() - t0) * 1000)
        return (line, "dead", ms, "proxy error")
    except curl_req.exceptions.Timeout:
        ms = int((time.time() - t0) * 1000)
        return (line, "slow", ms, f"timeout >{timeout}s")
    except Exception as e:
        ms = int((time.time() - t0) * 1000)
        msg = str(e)[:60]
        if "connect" in msg.lower() or "refused" in msg.lower() or "reset" in msg.lower():
            return (line, "dead", ms, msg)
        return (line, "error", ms, msg)


def main():
    ap = argparse.ArgumentParser(description="Cursor proxy tester")
    ap.add_argument("--file", default=PROXIES_FILE)
    ap.add_argument("--timeout", type=int, default=15, help="timeout/proxy (s)")
    ap.add_argument("--threads", type=int, default=20)
    ap.add_argument("--keep-slow", action="store_true", help="giu proxy slow (timeout)")
    args = ap.parse_args()

    with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    print(f"[+] Test {len(lines)} proxy (timeout {args.timeout}s, {args.threads} threads)...")
    print(f"    Target: {TEST_URL}\n")

    results = []
    done = 0
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(test_one, line, args.timeout): line for line in lines}
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            done += 1
            line, status, ms, err = res
            with print_lock:
                mark = {"good": "\033[92mOK\033[0m", "dead": "\033[91mDEAD\033[0m",
                        "slow": "\033[93mSLOW\033[0m", "bad_status": "\033[91mBAD\033[0m",
                        "cf403": "\033[91m403\033[0m", "cf_challenge": "\033[91mCF\033[0m",
                        "no_session": "\033[91mNOSESS\033[0m",
                        "error": "\033[91mERR\033[0m", "bad_format": "\033[90mFMT\033[0m"}.get(status, "?")
                print(f"  [{done}/{len(lines)}] {mark:27} {ms:>6}ms  {line.split(':')[0]:18} {err}")

    # Phan loai
    good = [r for r in results if r[1] == "good"]
    slow = [r for r in results if r[1] == "slow"]
    dead = [r for r in results if r[1] in (
        "dead", "bad_status", "error", "bad_format", "cf403", "cf_challenge", "no_session",
    )]

    # Sort good theo toc do (nhan nhat truoc)
    good.sort(key=lambda r: r[2])

    keep = [r[0] for r in good]
    if args.keep_slow:
        slow.sort(key=lambda r: r[2])
        keep += [r[0] for r in slow]

    print(f"\n{'='*50}")
    print(f"  GOOD  (session id OK):     {len(good)}")
    print(f"  SLOW  (timeout):           {len(slow)}")
    print(f"  DEAD  (fail):              {len(dead)}")
    print(f"  -> KEEP: {len(keep)} proxy")
    print(f"{'='*50}")

    if good:
        speeds = [r[2] for r in good]
        print(f"  Good proxy speed: min={min(speeds)}ms avg={sum(speeds)//len(speeds)}ms max={max(speeds)}ms")

    # Backup goc + ghi lai
    if os.path.exists(args.file):
        os.replace(args.file, args.file + ".bak")
        print(f"\n[+] Backup goc -> {args.file}.bak")

    with open(args.file, "w", encoding="utf-8") as f:
        f.write("\n".join(keep) + ("\n" if keep else ""))
    print(f"[+] Ghi {len(keep)} good proxy -> {args.file}")

    # Ghi bad ra file rieng (de review)
    with open(BAD_FILE, "w", encoding="utf-8") as f:
        for line, status, ms, err in (dead + ([r for r in results if r[1]=="slow"] if not args.keep_slow else [])):
            f.write(f"{line}  # {status} {ms}ms {err}\n")
    print(f"[+] {len(dead)} bad proxy -> {BAD_FILE}")


if __name__ == "__main__":
    main()
