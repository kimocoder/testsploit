"""Free public HTTP-proxy rotation pool.

Pulls proxy candidates from a few well-known free-proxy GitHub repos,
validates a sample in parallel, keeps a small rolling pool of fast working
proxies, and refreshes hourly. Used by `fetch_text()` as a retry fallback
when a direct request hits 403/429/418/400/connection-error — servers that
fingerprint our datacentre IP get a different one on retry.

Free proxies are inherently unreliable. The pool is best-effort: empty pool
means the retry simply doesn't happen and the original error is returned.
Never blocks startup — the refresh runs in a background task and a stale
on-disk cache is loaded synchronously so retries can start working
immediately after restart.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from pathlib import Path

import aiohttp

LOG = logging.getLogger(__name__)

_PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&proxy_format=protocolipport&format=text",
    "https://www.proxy-list.download/api/v1/get?type=http",
]

_VALIDATE_URL = "https://httpbin.org/ip"
_VALIDATE_TIMEOUT = 6.0
# Free proxy lists have ~0.4% liveness so we have to validate a *lot* of
# candidates to get a usable pool. 1500 candidates × 60-concurrency × 6s
# timeout ≈ 150s upper bound, runs in background so doesn't block scans.
_MAX_VALIDATE = 1500
_VALIDATE_CONCURRENCY = 60
_TARGET_POOL_SIZE = 40     # Stop early once we have this many working.
_REFRESH_INTERVAL = 3600   # Seconds between refresh attempts.
_CACHE_FILE = Path("monitor/data/proxy_pool_cache.json")


class ProxyPool:
    def __init__(self) -> None:
        self._pool: list[str] = []
        self._lock = asyncio.Lock()
        self._last_refresh = 0.0
        self._refreshing = False
        self.stats = {
            "refreshes": 0,
            "last_size": 0,
            "last_refresh_at": 0.0,
            "validated_count": 0,
        }
        self._load_cache()

    # ── Cache I/O ────────────────────────────────────────────────────────
    def _load_cache(self) -> None:
        try:
            if _CACHE_FILE.exists():
                d = json.loads(_CACHE_FILE.read_text())
                age = time.time() - d.get("ts", 0)
                # Accept stale cache up to 2× refresh interval — better to
                # try probably-dead proxies than have an empty pool right
                # after restart.
                if age < _REFRESH_INTERVAL * 2:
                    self._pool = list(d.get("proxies", []))
                    self.stats["last_size"] = len(self._pool)
                    LOG.info("proxy_pool: loaded %d cached proxies (age %.0fs)", len(self._pool), age)
        except Exception as e:
            LOG.warning("proxy_pool: cache load failed: %s", e)

    def _save_cache(self) -> None:
        try:
            _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            _CACHE_FILE.write_text(json.dumps({"ts": time.time(), "proxies": self._pool}))
        except Exception as e:
            LOG.warning("proxy_pool: cache save failed: %s", e)

    # ── Public API ───────────────────────────────────────────────────────
    def get(self) -> str | None:
        if not self._pool:
            return None
        return random.choice(self._pool)

    def remove(self, proxy: str) -> None:
        try:
            self._pool.remove(proxy)
        except ValueError:
            pass

    def size(self) -> int:
        return len(self._pool)

    # ── Refresh ──────────────────────────────────────────────────────────
    async def maybe_refresh(self, force: bool = False) -> None:
        if self._refreshing:
            return
        if not force and self._pool and (time.time() - self._last_refresh) < _REFRESH_INTERVAL:
            return
        async with self._lock:
            if self._refreshing:
                return
            self._refreshing = True
        try:
            await self._refresh()
        finally:
            self._refreshing = False
            self._last_refresh = time.time()

    async def _refresh(self) -> None:
        candidates: set[str] = set()
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for src in _PROXY_SOURCES:
                    try:
                        async with session.get(src) as resp:
                            if resp.status != 200:
                                continue
                            text = await resp.text()
                            for line in text.splitlines():
                                line = line.strip()
                                if not line or line.startswith("#"):
                                    continue
                                if "://" not in line:
                                    line = "http://" + line
                                if line.startswith(("http://", "https://")):
                                    candidates.add(line)
                    except Exception as e:
                        LOG.warning("proxy_pool: source %s failed: %s", src, e)
        except Exception as e:
            LOG.warning("proxy_pool: fetch session failed: %s", e)
            return

        cand_list = list(candidates)
        random.shuffle(cand_list)
        cand_list = cand_list[:_MAX_VALIDATE]
        LOG.info("proxy_pool: validating %d candidates from %d total", len(cand_list), len(candidates))

        working: list[str] = []
        sem = asyncio.Semaphore(_VALIDATE_CONCURRENCY)
        stop_event = asyncio.Event()

        async def validate(proxy: str) -> None:
            if stop_event.is_set():
                return
            async with sem:
                if stop_event.is_set():
                    return
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=_VALIDATE_TIMEOUT)
                    ) as s:
                        async with s.get(_VALIDATE_URL, proxy=proxy) as resp:
                            if resp.status == 200:
                                working.append(proxy)
                                if len(working) >= _TARGET_POOL_SIZE:
                                    stop_event.set()
                except Exception:
                    pass

        await asyncio.gather(*(validate(p) for p in cand_list), return_exceptions=True)
        # Keep previous pool if refresh produced nothing — better stale than empty.
        if working:
            self._pool = working
        self.stats["refreshes"] += 1
        self.stats["last_size"] = len(self._pool)
        self.stats["last_refresh_at"] = time.time()
        self.stats["validated_count"] = len(cand_list)
        LOG.info("proxy_pool: refresh done — %d working / %d validated", len(self._pool), len(cand_list))
        self._save_cache()


PROXY_POOL = ProxyPool()


async def proxy_refresh_loop() -> None:
    """Run forever, refreshing the pool every _REFRESH_INTERVAL seconds.

    Schedule with `asyncio.create_task(proxy_refresh_loop())` from main.
    Errors are swallowed so a failed refresh never crashes the monitor.
    """
    # First refresh runs after a short delay so the cycle can start
    # immediately on launch using the cached pool.
    await asyncio.sleep(10)
    while True:
        try:
            await PROXY_POOL.maybe_refresh()
        except Exception as e:
            LOG.warning("proxy_pool: refresh loop error: %s", e)
        await asyncio.sleep(_REFRESH_INTERVAL)
