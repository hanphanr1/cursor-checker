"""
Monkeypatch window.turnstile so WorkOS's Turnstile widget 'solves' with
our YeatLegit token. This makes the password submit POST fire, revealing
the password action ID + fields.
"""
import time, re, requests as plain_req
from patchright.sync_api import sync_playwright

AUTH = "https://authenticator.cursor.sh"
SITEKEY = "0x4AAAAAAAMNIvC45A4Wjjln"
# 2026-10-30: solver chuyen sang cfsolve rendercf pool (queue cursor ~0ms, free).
import requests as _rq0
def _solve_rendercf():
    for base in ("https://cfsolve-2.onrender.com", "https://cfsolve.onrender.com"):
        try:
            r = _rq0.post(f"{base}/solve", json={"sitekey": SITEKEY, "url": AUTH}, timeout=25)
            j = r.json()
            tok = j.get("token") or ""
            if j.get("success") and len(tok) >= 100:
                return tok, f"rendercf[{base.split('//')[1]}]"
        except Exception:
            continue
    return None, "rendercf pool fail"
SOLVER_HEADERS = {"Accept": "application/json"}

# Acc capture PHAI co email hop le (co @) — email sai format -> form khong submit
# -> khong bao gio toi trang password -> timeout (bug da gay).
import re as _re
_EMAIL_RE = _re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
with open("accounts.txt","r",encoding="utf-8") as f:
    accounts=[l.strip() for l in f if l.strip() and ":" in l and not l.startswith("#")]
email,password = None,None
for line in accounts:
    parts=line.split(":",1)
    if len(parts)==2 and _EMAIL_RE.match(parts[0].strip()) and parts[1].strip():
        email,password = parts[0].strip(),parts[1].strip()
        break
if not email:
    # fallback: acc test da biet login OK
    email,password = "essikdevsarlau@gmail.com","Coderweb19952010@@"
print(f"[+] {email}\n")

# Solve Turnstile FIRST (before navigating)
# Chain: yeatcloud (free) -> capsolver (paid backup). yeatcloud hay crash (Railway).
from config import CAPSOLVER_API_KEYS, CAPSOLVER_API_URL, CAPSOLVER_RESULT_URL

def _solve_yeatcloud():
    # 2026-10-30: alias sang rendercf pool (yeatcloud Railway cu da doi url)
    return _solve_rendercf()


def _solve_capsolver():
    import json as _json
    import time as _t
    for key in CAPSOLVER_API_KEYS:
        try:
            r=plain_req.post(CAPSOLVER_API_URL,json={"clientKey":key,"task":{
                "type":"AntiTurnstileTaskProxyLess","websiteURL":AUTH,"websiteKey":SITEKEY}},timeout=30)
            j=r.json()
            tid=j.get("taskId")
            if not tid: continue
            t0=_t.time()
            while _t.time()-t0<90:
                _t.sleep(3)
                r2=plain_req.post(CAPSOLVER_RESULT_URL,json={"clientKey":key,"taskId":tid},timeout=30)
                j2=r2.json()
                if j2.get("status")=="ready":
                    tok=(j2.get("solution") or {}).get("token")
                    if tok: return tok, f"capsolver {_t.time()-t0:.0f}s"
                    break
                if j2.get("errorId",0)!=0: break
        except Exception:
            continue
    return None, "all capsolver keys fail"

def _solve_2captcha():
    # key dau tien ($16.50 con tien, check 2026-09)
    from config import TWOCAPTCHA_API_KEYS
    import time as _t
    for key in TWOCAPTCHA_API_KEYS:
        try:
            r=plain_req.get("https://2captcha.com/in.php",params={
                "key":key,"method":"turnstile","sitekey":SITEKEY,"pageurl":AUTH,"json":1},timeout=30)
            j=r.json()
            if j.get("status")!=1: continue
            tid=j.get("request")
            t0=_t.time()
            while _t.time()-t0<110:
                _t.sleep(5)
                r2=plain_req.get("https://2captcha.com/res.php",params={
                    "key":key,"action":"get","id":tid,"json":1},timeout=30)
                j2=r2.json()
                if j2.get("status")==1:
                    return j2.get("request"), f"2captcha {_t.time()-t0:.0f}s"
                if j2.get("request")!="CAPCHA_NOT_READY":
                    break
        except Exception:
            continue
    return None, "all 2captcha keys fail"

print("[0] Solving Turnstile (rendercf -> capsolver -> 2captcha)...")
TOKEN=None; src=""
for fn,label in ((_solve_rendercf,"rendercf"),(_solve_capsolver,"capsolver"),(_solve_2captcha,"2captcha")):
    try:
        TOKEN,src=fn()
    except Exception as e:
        src=f"{label} exc: {e}"
    if TOKEN: break
    print(f"  {label} fail ({src})")
if not TOKEN:
    print("FATAL: ca ba solver fail:",src); exit()
print(f"  token: {TOKEN[:40]}... ({src})\n")

captured=[]
def on_request(req):
    if req.method=="POST" and "cursor.sh" in req.url:
        h=dict(req.headers); body=(req.post_data or "").replace(email,"<EMAIL>").replace(password,"<PASSWORD>")
        ct=h.get("content-type","")
        # dump ALL POSTs that carry next-action (multipart + text/plain signals)
        if h.get("next-action") or "multipart" in ct or "x-action" in str(h).lower():
            print(f"\n=== POST {req.url[:90]} ===")
            print(f"  content-type: {ct[:60]}")
            print(f"  next-action: {h.get('next-action','(none)')}")
            print(f"  x-deployment-id: {h.get('x-deployment-id','(none)')}")
            print(f"  sec-ch-ua: {h.get('sec-ch-ua','(none)')}")
            rst = h.get('next-router-state-tree','')
            if rst:
                print(f"  next-router-state-tree: {rst[:120]}")
            if "text/plain" in ct:
                print(f"  body: {body[:200]!r}")
            if h.get('next-action'):
                with open('_captured_headers.txt','a',encoding='utf-8') as hf:
                    hf.write(f"url={req.url}\n")
                    hf.write(f"content-type={ct}\n")
                    hf.write(f"next-action={h.get('next-action')}\n")
                    hf.write(f"x-deployment-id={h.get('x-deployment-id')}\n")
                    hf.write(f"sec-ch-ua={h.get('sec-ch-ua')}\n")
                    hf.write(f"user-agent={h.get('user-agent')}\n")
                    hf.write(f"next-router-state-tree={h.get('next-router-state-tree')}\n")
                    if "text/plain" in ct:
                        hf.write(f"plain-body={body[:300]}\n")
                    hf.write('---\n')
            if "multipart" in ct:
                fields=re.findall(r'name="([^"]+)"',body)
                print(f"  FIELDS: {fields}")
                for fn in fields:
                    m=re.search(r'name="'+re.escape(fn)+r'"\r\n\r\n(.*?)\r\n------',body,re.DOTALL)
                    if m:
                        print(f"    {fn}: len={len(m.group(1))} = {m.group(1)[:60]!r}")
                        # LUU signals blob THAT (fingerprint cua deploy hien tai) de cap nhat tool
                        if fn == "_1_signals":
                            with open("_captured_signals.txt","w") as sf:
                                sf.write(m.group(1))
                            print(f"    >>> _1_signals saved -> _captured_signals.txt ({len(m.group(1))} chars)")
            captured.append(h.get('next-action'))
def on_response(resp):
    if resp.request.method=="POST" and "cursor.sh" in resp.url:
        loc=""; xar=""
        try: loc=resp.headers.get("location","")
        except: pass
        try: xar=resp.headers.get("x-action-redirect","")
        except: pass
        if loc or xar or resp.status in (303,302):
            print(f"  -> {resp.status} loc={loc[:70]} xar={xar[:70]}")

# The turnstile monkeypatch script - runs before CF script loads
PATCH_JS = """
window.__SOLVED_TOKEN = %r;
// Prevent CF from overwriting: define turnstile as non-writable
let _cb_fired = false;
const fakeTurnstile = {
  render: function(container, opts) {
    this._opts = opts || {};
    // fire the success callback with our token after a short delay
    setTimeout(() => {
      try {
        if (this._opts.callback && !_cb_fired) {
          _cb_fired = true;
          this._opts.callback(window.__SOLVED_TOKEN);
        }
      } catch(e) { console.log('cb err', e); }
    }, 800);
    // also set the hidden input
    setTimeout(() => {
      try {
        let el = document.querySelector('[name=cf-turnstile-response]');
        if (el) el.value = window.__SOLVED_TOKEN;
      } catch(e) {}
    }, 900);
    return 'fake-widget-1';
  },
  execute: function(){},
  reset: function(){ _cb_fired=false; },
  getResponse: function(){ return window.__SOLVED_TOKEN; },
  remove: function(){},
  isExpired: function(){ return false; },
};
try {
  Object.defineProperty(window, 'turnstile', { value: fakeTurnstile, writable: false, configurable: true });
} catch(e) { window.turnstile = fakeTurnstile; }
""" % TOKEN

with sync_playwright() as p:
    browser=p.chromium.launch(headless=False)
    ctx=browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",viewport={"width":1280,"height":900},locale="en-US")
    # Inject patch BEFORE any page script runs
    ctx.add_init_script(PATCH_JS)
    page=ctx.new_page()
    page.on("request",on_request); page.on("response",on_response)

    print("[1] goto + email step...")
    page.goto(AUTH,timeout=30000,wait_until="domcontentloaded"); time.sleep(2)
    page.locator('input[type="email"]').first.wait_for(timeout=15000)
    page.locator('input[type="email"]').first.fill(email); time.sleep(0.5)
    page.locator('button[type="submit"]').first.click()

    print("[2] password page...")
    page.locator('input[type="password"]').first.wait_for(timeout=20000); time.sleep(1)
    page.locator('input[type="password"]').first.fill(password); time.sleep(1.5)

    # check if turnstile callback fired (React should have token now)
    has_tok = page.evaluate("() => { let e=document.querySelector('[name=cf-turnstile-response]'); return e&&e.value?e.value.length:0; }")
    print(f"[3] cf-turnstile-response value len: {has_tok}")

    print("[4] Click submit...")
    page.locator('button[type="submit"]').first.click()

    print("[5] wait for password POST / login (20s)...")
    for i in range(20):
        time.sleep(1)
        u=page.url
        if "/api/auth/callback" in u or "cursor.com" in u and "authenticator" not in u:
            print(f"  -> redirect at +{i+1}s: {u[:80]}"); break

    time.sleep(2)
    cookies=ctx.cookies()
    print(f"\n[6] cookies: {[c['name'] for c in cookies]}")
    for c in cookies:
        if "session" in c["name"].lower() or "token" in c["name"].lower():
            print(f"  {c['name']}={c['value'][:70]}")
    print(f"\ncaptured action IDs: {captured}")
    page.screenshot(path="debug_patch.png")
    time.sleep(2); browser.close()
