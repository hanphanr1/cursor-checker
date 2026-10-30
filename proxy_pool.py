"""
Proxy Pool - Quan ly proxy rotation + cooldown + per-proxy lock
===============================================================
- Parse nhieu format proxy: ip:port, ip:port:user:pass, user:pass@ip:port
- Lock tung proxy (tranh 2 thread dung cung 1 IP cung luc)
- Cooldown sau moi lan dung (Firebase / Cloudflare can IP nghi)
- Fail counter: proxy fail >= 5 lan -> skip
"""

import time
import threading
from urllib.parse import urlparse

from config import PROXY_COOLDOWN, HOST_COOLDOWN_OK, HOST_COOLDOWN_FAIL


class ProxyPool:
    def __init__(self, proxy_lines):
        self.proxies = []
        for line in proxy_lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                p = self._parse_proxy(line)
                if p:
                    p["_lock"] = threading.Lock()
                    p["_fails"] = 0
                    p["_free_at"] = 0
                    p["_str"] = line          # truoc _host: _host_of dung _str cho rotating
                    p["_host"] = self._host_of(p)
                    self.proxies.append(p)
            except Exception:
                pass
        self.pool_lock = threading.Lock()
        self.idx = 0
        self.host_busy = set()
        self.host_free_at = {}

    @staticmethod
    def _parse_proxy(line):
        """Parse 1 dong proxy -> dict {'http','https'} . Tra ve None neu loi."""
        try:
            import re as _re
            m = _re.match(r"^(https?|socks4a?|socks5h?)://", line)
            scheme = (m.group(1) + "://") if m else "http://"
            if m:
                line = line[m.end():]
            if "@" in line:
                creds, host = line.rsplit("@", 1)
                user, pwd = creds.split(":", 1)
                ip, port = host.split(":", 1)
            else:
                parts = line.split(":")
                if len(parts) == 4:
                    ip, port, user, pwd = parts
                elif len(parts) == 2:
                    ip, port = parts
                    user, pwd = None, None
                else:
                    return None
            url = scheme
            if user:
                url += f"{user}:{pwd}@"
            url += f"{ip}:{port}"
            return {"http": url, "https": url}
        except Exception:
            return None
    @staticmethod
    def _host_of(proxy):
        """Hostname cua gateway proxy (nhieu dong tren 1 gateway = 1 host).
        ROTATING gateway (oxylabs): moi dong = 1 session/IP rieng -> key = full line
        (2026-10-31: 87 IP tinh bi WorkOS flag dan sau ~2000 acc -> rotating la nen)."""
        try:
            host = urlparse(proxy["http"]).hostname or proxy["http"]
            if "oxylabs" in (host or ""):
                return proxy.get("_str", host)
            return host
        except Exception:
            return proxy.get("http", "")

    def checkout(self, timeout=15):
        """Lay 1 proxy free. Tra ve proxy obj hoac None neu het."""
        start = time.time()
        n = len(self.proxies)
        if n == 0:
            return None
        while time.time() - start < timeout:
            now = time.time()
            with self.pool_lock:
                for _ in range(n):
                    p = self.proxies[self.idx % n]
                    self.idx += 1
                    if p["_fails"] >= 5:
                        continue
                    if p["_free_at"] > now:
                        continue
                    host = p["_host"]
                    if host in self.host_busy or self.host_free_at.get(host, 0) > now:
                        continue
                    if p["_lock"].acquire(blocking=False):
                        self.host_busy.add(host)
                        return p
            time.sleep(0.1)
        return None

    def checkin(self, proxy, failed=False):
        """Tra proxy ve pool. failed=True de tang fail counter."""
        if proxy is None:
            return
        if failed:
            proxy["_fails"] += 1
        proxy["_free_at"] = time.time() + PROXY_COOLDOWN
        host = proxy.get("_host")
        if host:
            rest = HOST_COOLDOWN_FAIL if failed else HOST_COOLDOWN_OK
            with self.pool_lock:
                self.host_busy.discard(host)
                self.host_free_at[host] = max(
                    self.host_free_at.get(host, 0), time.time() + rest
                )

    def reset_bad(self):
        """Reset fail counter (dung giua cac pass)."""
        with self.pool_lock:
            for p in self.proxies:
                p["_fails"] = 0
                p["_free_at"] = 0

    def count(self):
        return len(self.proxies)
