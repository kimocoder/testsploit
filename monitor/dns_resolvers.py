"""
dns_resolvers.py — High-scale distributed DNS resolver pool.

Features:
  1. Auto-fetch: Downloads thousands of public DNS IPs from public-dns.info
     and GitHub raw lists. Falls back to built-in ~300-IP list offline.
  2. Mass probe: Concurrently tests all candidates (up to 1 000 workers).
     Validates A-record response and measures RTT.
  3. Weighted distribution: Resolvers are bucketed by latency; faster ones
     get proportionally more queries (inverse-latency weights).
  4. Error tracking: Per-resolver failure counters.  Resolvers that fail or
     return SERVFAIL/REFUSED repeatedly are temporarily blacklisted.
  5. Auto-refresh: Pool re-probes + re-fetches online list every hour.
  6. DoH fallback: Google / Cloudflare DNS-over-HTTPS when UDP/53 blocked.

Public interface (unchanged from previous version):
    pool = ResolverPool()
    await pool.start()
    hostname = await pool.rdns("1.2.3.4")
    await pool.close()
    print(pool.size)      # working UDP resolvers
    print(pool.ready)     # True after start()
    print(pool.stats)     # dict with detailed metrics
"""
from __future__ import annotations

import asyncio
import ipaddress
import itertools
import json
import logging
import os
import random
import socket
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

try:
    import aiohttp as _aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False

try:
    import aiodns as _aiodns
    _HAS_AIODNS = True
except ImportError:
    _HAS_AIODNS = False

logger = logging.getLogger(__name__)

# ── Persistent cache config ────────────────────────────────────────────────
# Resolver probes are expensive (~100-180s for 40k candidates). Persist the
# probed list to disk so subsequent scanner runs start instantly.
_DEFAULT_CACHE_FILE = str(
    Path(__file__).resolve().parent / "data" / "dns_resolvers_cache.json"
)
_DEFAULT_CACHE_TTL = 86_400  # 24 hours


def _load_cache(path: str) -> tuple[list[tuple[str, float]], float] | None:
    """Load cached probe results. Returns (ranked, age_seconds) or None."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
        ts = float(data.get("timestamp", 0))
        ranked_raw = data.get("ranked", [])
        ranked: list[tuple[str, float]] = []
        for item in ranked_raw:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                ip, lat = item
                if isinstance(ip, str) and isinstance(lat, (int, float)):
                    ranked.append((ip, float(lat)))
        if not ranked:
            return None
        age = max(0.0, time.time() - ts)
        return ranked, age
    except Exception:
        return None


def _save_cache(path: str, ranked: list[tuple[str, float]]) -> None:
    """Persist probe results atomically (tmp + rename)."""
    if not ranked:
        return
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(path + ".tmp")
        tmp.write_text(json.dumps({
            "timestamp": time.time(),
            "ranked": [[ip, round(lat, 1)] for ip, lat in ranked],
        }))
        tmp.replace(path)
    except Exception as e:
        logger.warning("DNS cache save failed: %s", e)


# ── DoH providers ──────────────────────────────────────────────────────────
_DOH_PROVIDERS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
    "https://doh.opendns.com/dns-query",
    "https://doh.dns.apple.com/dns-query",
    "https://dns.quad9.net/dns-query",
]

# ── Online DNS list sources (fetched at pool start) ────────────────────────
_ONLINE_SOURCES = [
    # plain text, one IPv4 per line (IPv6 lines filtered out)
    "https://public-dns.info/nameservers.txt",
    # backup mirrors
    "https://raw.githubusercontent.com/fanqie/dns-list/main/dns.list",
    "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
]

# ── Built-in resolver list (fallback when offline) ─────────────────────────
_BUILTIN: list[str] = [
    # Tier-1 — well-known public resolvers
    "8.8.8.8", "8.8.4.4",                           # Google
    "1.1.1.1", "1.0.0.1",                           # Cloudflare
    "9.9.9.9", "149.112.112.112",                   # Quad9
    "208.67.222.222", "208.67.220.220",             # OpenDNS
    "208.67.222.220", "208.67.220.222",
    "94.140.14.14", "94.140.15.15",                 # AdGuard
    "185.228.168.9", "185.228.169.9",               # CleanBrowsing
    "76.76.2.0", "76.76.10.0",                      # Control D
    "64.6.64.6", "64.6.65.6",                       # Verisign
    "74.82.42.42",                                   # Hurricane Electric
    "156.154.70.1", "156.154.71.1",                 # UltraDNS
    "4.2.2.1", "4.2.2.2", "4.2.2.3",               # Level3
    "4.2.2.4", "4.2.2.5", "4.2.2.6",
    # Tier-2 — regional / ISP public resolvers
    "80.80.80.80", "80.80.81.81",
    "77.88.8.8",  "77.88.8.1",                      # Yandex
    "84.200.69.80", "84.200.70.40",                 # DNS.Watch
    "89.233.43.71", "91.239.100.100",
    "185.95.218.42", "185.95.218.43",
    "176.103.130.130", "176.103.130.131",
    "193.110.81.0", "185.253.5.0",
    "156.154.70.22", "156.154.71.22",
    "114.114.114.114", "114.114.115.115",           # 114DNS
    "119.29.29.29", "182.254.116.116",              # DNSPod
    "223.5.5.5",   "223.6.6.6",                     # AliDNS
    "168.126.63.1", "168.126.63.2",                 # KT Korea
    "203.80.96.10", "203.80.96.9",
    "198.101.242.72", "23.253.163.53",              # Alternate DNS
    "45.33.97.5",  "37.235.1.174", "37.235.1.177", # FreeDNS
    "8.26.56.26",  "8.20.247.20",                   # Comodo
    "209.222.18.222", "209.222.18.218",
    "50.116.23.211",
    "208.76.50.50", "208.76.51.51",
    "66.42.0.62",  "66.42.0.63",
    "64.68.200.200", "64.68.200.201",
    "87.98.175.85",
    "91.108.4.4",
    "196.202.192.1", "196.202.192.2",
    "41.190.3.190",
    "80.67.169.12",
    "193.183.98.66",
    "45.55.55.55",
    "45.77.165.194",
    "185.222.222.222", "45.11.45.11",
    "88.198.7.1",  "88.198.7.2",
    "46.246.46.246",
    "5.9.49.12",   "5.9.134.186",
    "89.101.160.6",
    "82.141.44.50", "82.141.44.51",
    "195.159.0.1",
    "195.175.39.39",
    "195.123.240.76",
    "93.188.84.2",
    "213.187.11.62",
    "88.191.254.20",
    "109.69.8.51",
    "121.121.121.121",
    "101.226.4.6", "218.30.118.6",
    "210.2.4.8",   "61.8.0.113",
    "62.109.122.222",
    "46.101.151.249",
    "178.62.199.161",
    "185.83.83.83",
    "83.146.24.29",
    "79.143.185.180",
    "63.251.222.9", "65.22.196.1",
    "207.67.222.222",
]


# ── Helpers ────────────────────────────────────────────────────────────────

def _is_valid_ipv4(s: str) -> bool:
    try:
        addr = ipaddress.ip_address(s.strip())
        return addr.version == 4 and not addr.is_private and not addr.is_loopback
    except ValueError:
        return False


async def _fetch_text(url: str, timeout: float = 10.0) -> str | None:
    """Fetch plain text from `url`. Returns None on error."""
    if not _HAS_AIOHTTP:
        return None
    try:
        connector = _aiohttp.TCPConnector(ssl=False)
        async with _aiohttp.ClientSession(connector=connector) as s:
            async with s.get(url, timeout=_aiohttp.ClientTimeout(total=timeout)) as r:
                if r.status == 200:
                    return await r.text(errors="ignore")
    except Exception:
        pass
    return None


async def fetch_online_list(sources: list[str] | None = None,
                            max_per_source: int = 30_000) -> list[str]:
    """
    Download public DNS server IPs from online sources.
    Returns deduplicated list of valid public IPv4 addresses.
    """
    sources = sources or _ONLINE_SOURCES
    tasks   = [_fetch_text(url) for url in sources]
    texts   = await asyncio.gather(*tasks, return_exceptions=True)

    seen: set[str] = set()
    result: list[str] = []

    for text in texts:
        if not isinstance(text, str):
            continue
        count = 0
        for line in text.splitlines():
            ip = line.strip().split()[0] if line.strip() else ""
            if ip and _is_valid_ipv4(ip) and ip not in seen:
                seen.add(ip)
                result.append(ip)
                count += 1
                if count >= max_per_source:
                    break

    logger.info("fetch_online_list: %d unique public IPv4 DNS servers fetched", len(result))
    return result


# ── Probing ────────────────────────────────────────────────────────────────

_PROBE_QUERY = "google.com"  # well-known domain to validate response

async def _probe_one(ip: str, timeout: float = 1.5) -> tuple[str, float] | None:
    """
    Send an A query to `ip`. Returns (ip, latency_ms) on success, None on fail.
    Validates that the resolver returns at least one A record (anti-poisoning).
    """
    if not _HAS_AIODNS:
        return None
    try:
        loop = asyncio.get_event_loop()
        resolver = _aiodns.DNSResolver(
            loop=loop,
            nameservers=[ip],
            timeout=timeout,
        )
        t0 = time.monotonic()
        result = await asyncio.wait_for(
            resolver.query_dns(_PROBE_QUERY, "A"),
            timeout=timeout + 0.5,
        )
        if result and result.answer:
            lat = (time.monotonic() - t0) * 1000
            return (ip, lat)
    except Exception:
        pass
    return None


async def probe_all(candidates: list[str],
                    concurrency: int = 1000,
                    timeout: float = 1.5,
                    keep: int | None = None) -> list[tuple[str, float]]:
    """
    Test all `candidates` concurrently (limited by `concurrency`).
    Returns list of (ip, latency_ms) sorted by latency (fastest first).
    If `keep` is set, returns only the top-N fastest.
    """
    if not _HAS_AIODNS:
        return []
    sem = asyncio.Semaphore(concurrency)

    async def _safe(ip: str) -> tuple[str, float] | None:
        async with sem:
            return await _probe_one(ip, timeout=timeout)

    t0 = time.monotonic()
    raw = await asyncio.gather(*[_safe(ip) for ip in candidates],
                               return_exceptions=True)
    elapsed = time.monotonic() - t0

    working = sorted(
        [r for r in raw if isinstance(r, tuple)],
        key=lambda x: x[1],
    )

    logger.info(
        "probe_all: %d/%d resolvers OK in %.1fs (best %.0fms, p50 %.0fms)",
        len(working), len(candidates), elapsed,
        working[0][1] if working else 0,
        working[len(working) // 2][1] if working else 0,
    )

    if keep is not None:
        working = working[:keep]
    return working


# ── Weighted pool ──────────────────────────────────────────────────────────

class _WeightedPool:
    """
    Weighted round-robin over DNS resolvers.
    Resolvers are bucketed by latency; weight = max_latency / resolver_latency.
    Resolvers that fail repeatedly are temporarily blacklisted.
    """

    # Latency → relative weight
    _LATENCY_BUCKETS = [
        (50,  8),   # < 50ms  → weight 8
        (100, 5),   # 50-100ms → weight 5
        (200, 3),   # 100-200ms → weight 3
        (400, 2),   # 200-400ms → weight 2
        (9999, 1),  # > 400ms  → weight 1
    ]

    def __init__(self) -> None:
        # list of (ip, weight), shuffled to spread load
        self._pool:   list[str] = []
        self._weights: list[int] = []
        self._idx:    int = 0
        # error tracking
        self._errors: dict[str, int]  = defaultdict(int)
        self._bl:     dict[str, float] = {}   # ip → blacklisted_until
        self._BL_THRESHOLD = 5    # errors before blacklist
        self._BL_SECONDS   = 120  # blacklist duration (seconds)
        self._total_queries = 0
        self._total_errors  = 0

    def load(self, ranked: list[tuple[str, float]]) -> None:
        """Load resolvers from probe results [(ip, latency_ms), ...]."""
        expanded: list[str] = []
        for ip, lat in ranked:
            weight = 1
            for threshold, w in self._LATENCY_BUCKETS:
                if lat < threshold:
                    weight = w
                    break
            expanded.extend([ip] * weight)
        random.shuffle(expanded)
        self._pool    = expanded
        self._weights = []   # not used separately
        self._idx     = 0
        self._errors  = defaultdict(int)
        self._bl      = {}
        logger.info(
            "_WeightedPool.load: %d resolvers → %d weighted slots",
            len(ranked), len(expanded),
        )

    def next(self) -> str | None:
        """Return the next resolver IP, skipping blacklisted ones."""
        if not self._pool:
            return None
        now = time.monotonic()
        tried = 0
        while tried < len(self._pool):
            ip = self._pool[self._idx % len(self._pool)]
            self._idx += 1
            # Lift blacklist if expired
            if ip in self._bl and now >= self._bl[ip]:
                del self._bl[ip]
                self._errors[ip] = 0
            if ip not in self._bl:
                self._total_queries += 1
                return ip
            tried += 1
        return None   # all blacklisted

    def report_error(self, ip: str) -> None:
        """Record a failure for `ip`. Blacklist it after threshold."""
        self._errors[ip] += 1
        self._total_errors += 1
        if self._errors[ip] >= self._BL_THRESHOLD:
            self._bl[ip] = time.monotonic() + self._BL_SECONDS
            logger.debug("DNS blacklisted %s (>=%d errors)", ip, self._BL_THRESHOLD)

    def report_success(self, ip: str) -> None:
        """Reset error counter on success."""
        if ip in self._errors:
            self._errors[ip] = max(0, self._errors[ip] - 1)

    @property
    def size(self) -> int:
        return len(set(ip for ip in self._pool if ip not in self._bl))

    @property
    def pool_ips(self) -> list[str]:
        return list(dict.fromkeys(self._pool))   # deduplicated

    @property
    def blacklisted(self) -> int:
        return len(self._bl)

    @property
    def query_stats(self) -> dict:
        return {
            "total_queries": self._total_queries,
            "total_errors": self._total_errors,
            "error_rate": round(
                self._total_errors / max(1, self._total_queries), 4
            ),
        }


# ── DoH PTR lookup ─────────────────────────────────────────────────────────

async def _doh_rdns(ip: str,
                    session: "_aiohttp.ClientSession | None" = None,
                    providers: list[str] | None = None,
                    timeout: float = 3.0) -> str | None:
    """Reverse DNS via DNS-over-HTTPS. Cycles through providers."""
    if not _HAS_AIOHTTP:
        return None
    reversed_ip = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    plist = list(providers or _DOH_PROVIDERS)
    random.shuffle(plist)
    for provider in plist:
        url = f"{provider}?name={reversed_ip}&type=PTR"
        try:
            headers = {"Accept": "application/dns-json"}
            if session and not session.closed:
                ctx = session.get(url, headers=headers,
                                  timeout=_aiohttp.ClientTimeout(total=timeout))
            else:
                ctx = _aiohttp.ClientSession().get(
                    url, headers=headers,
                    timeout=_aiohttp.ClientTimeout(total=timeout))
            async with ctx as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    for ans in data.get("Answer", []):
                        if ans.get("type") == 12:
                            name = str(ans.get("data", "")).rstrip(".")
                            if name and name != ip:
                                return name
        except Exception:
            continue
    return None


# ── UDP PTR lookup ─────────────────────────────────────────────────────────

async def _udp_rdns(ip: str, resolver_ip: str, timeout: float = 2.0) -> str | None:
    """PTR lookup via aiodns with a specific nameserver."""
    if not _HAS_AIODNS:
        return None
    try:
        loop = asyncio.get_event_loop()
        resolver = _aiodns.DNSResolver(
            loop=loop, nameservers=[resolver_ip], timeout=timeout
        )
        reversed_ip = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        result = await asyncio.wait_for(
            resolver.query_dns(reversed_ip, "PTR"),
            timeout=timeout + 0.5,
        )
        if result and result.answer:
            dname = str(result.answer[0].data.dname).rstrip(".")
            if dname and dname != ip:
                return dname
    except Exception:
        pass
    return None


# ── ResolverPool ───────────────────────────────────────────────────────────

class ResolverPool:
    """
    Distributed DNS pool with:
      - Auto-fetch of thousands of public DNS servers at start
      - Mass parallel probing to find fastest resolvers
      - Weighted round-robin by inverse latency
      - Per-resolver error tracking + automatic blacklisting
      - Hourly re-fetch + re-probe for freshness
      - DoH fallback when UDP/53 is blocked

    Constructor args:
        probe_concurrency  Max concurrent probe workers  (default: 1000)
        probe_timeout      Probe timeout per resolver    (default: 1.5s)
        keep               Max resolvers to keep active  (default: 500)
        rdns_timeout       Timeout for PTR queries       (default: 2.0s)
        refresh_interval   Pool refresh interval (s)     (default: 3600)
        prefer_doh         Try DoH before UDP            (default: False)
        fetch_online       Fetch IPs from internet       (default: True)
    """

    def __init__(self,
                 probe_concurrency: int   = 1000,
                 probe_timeout:     float = 1.5,
                 keep:              int   = 500,
                 rdns_timeout:      float = 2.0,
                 refresh_interval:  int   = 3600,
                 prefer_doh:        bool  = False,
                 fetch_online:      bool  = True,
                 cache_file:        str | None = None,
                 cache_ttl_seconds: int   = _DEFAULT_CACHE_TTL):

        self._probe_concurrency = probe_concurrency
        self._probe_timeout     = probe_timeout
        self._keep              = keep
        self._rdns_timeout      = rdns_timeout
        self._refresh_interval  = refresh_interval
        self._prefer_doh        = prefer_doh
        self._fetch_online      = fetch_online
        # Cache config — env vars override constructor args.
        self._cache_file        = (
            os.environ.get("DNS_CACHE_FILE")
            or cache_file
            or _DEFAULT_CACHE_FILE
        )
        try:
            self._cache_ttl = int(
                os.environ.get("DNS_CACHE_TTL", cache_ttl_seconds)
            )
        except ValueError:
            self._cache_ttl = cache_ttl_seconds

        self._wp       = _WeightedPool()
        self._ready    = False
        self._last_refresh: float = 0.0
        self._doh_session: "_aiohttp.ClientSession | None" = None

        # Stats
        self._total_fetched   = 0   # IPs fetched from online sources
        self._total_probed    = 0   # IPs probed
        self._total_working   = 0   # IPs that passed probe
        self._start_time:  float = 0.0
        self._init_time_s: float = 0.0
        # Cache provenance for status reporting
        self._cache_source: str = "fresh"      # "fresh" | "cached" | "stale"
        self._cache_age_s:  float = 0.0
        self._bg_refresh_task: asyncio.Task | None = None
        self._last_ranked: list[tuple[str, float]] = []

    async def start(self) -> None:
        self._start_time = time.monotonic()
        print("[dns_pool] Starting distributed DNS pool…", flush=True)

        if _HAS_AIOHTTP:
            self._doh_session = _aiohttp.ClientSession(
                connector=_aiohttp.TCPConnector(limit=50, ssl=False),
                headers={"Accept": "application/dns-json"},
            )

        # ── Try persistent cache first — avoids 100-180s probe storm ─────
        cached = _load_cache(self._cache_file)
        if cached is not None:
            ranked, age = cached
            if age <= self._cache_ttl:
                self._wp.load(ranked)
                self._total_working = len(ranked)
                self._total_probed  = len(ranked)
                self._last_refresh  = time.monotonic()
                self._cache_source  = "cached"
                self._cache_age_s   = age
                self._ready = True
                self._init_time_s = time.monotonic() - self._start_time
                print(
                    f"[dns_pool] Loaded {len(ranked)} resolvers from cache "
                    f"(age {int(age)}s, ttl {self._cache_ttl}s) in "
                    f"{self._init_time_s:.2f}s — refreshing in background",
                    flush=True,
                )
                # Kick a background refresh so the next run gets fresh data,
                # but the current scan starts NOW.
                self._bg_refresh_task = asyncio.create_task(
                    self._refresh_and_save(quiet=True)
                )
                return
            else:
                print(
                    f"[dns_pool] Cache stale (age {int(age)}s > ttl "
                    f"{self._cache_ttl}s) — full refresh", flush=True,
                )
                # Note: this is only the *transient* state during the refresh
                # itself. Once the refresh below completes we flip back to
                # "fresh" so stats/UX reflect that we're now on fresh data.
                self._cache_source = "stale"

        await self._refresh_and_save()
        # After a synchronous full refresh (no usable cache, or stale),
        # we ARE running on freshly probed data — make stats say so.
        self._cache_source = "fresh"
        self._cache_age_s  = 0.0
        self._ready = True
        self._init_time_s = time.monotonic() - self._start_time
        print(
            f"[dns_pool] Ready: {self._wp.size} resolvers "
            f"({self._total_fetched} fetched, {self._total_probed} probed, "
            f"{self._total_working} working) in {self._init_time_s:.1f}s",
            flush=True,
        )

    async def _refresh_and_save(self, quiet: bool = False) -> None:
        """Run a full refresh and persist results to cache on success."""
        try:
            await self._refresh()
            if self._wp.size > 0:
                # Reconstruct (ip, lat) pairs from internal pool — easier path
                # is to track the last `ranked` list. We save the latest probe
                # results captured in `_refresh`.
                _save_cache(self._cache_file, self._last_ranked)
                if not quiet:
                    print(
                        f"[dns_pool] Cache saved → {self._cache_file} "
                        f"({len(self._last_ranked)} resolvers)",
                        flush=True,
                    )
        except Exception as e:
            logger.warning("DNS background refresh failed: %s", e)

    async def close(self) -> None:
        if self._doh_session and not self._doh_session.closed:
            await self._doh_session.close()

    async def _build_candidates(self) -> list[str]:
        """Merge online list + built-in, deduplicate."""
        online: list[str] = []
        if self._fetch_online and _HAS_AIOHTTP:
            print("[dns_pool] Fetching online DNS lists…", flush=True)
            online = await fetch_online_list()
            self._total_fetched = len(online)
            print(f"[dns_pool] Fetched {len(online)} IPs from online sources", flush=True)

        # Merge: online first (more diverse), built-in as fallback
        seen: set[str] = set()
        merged: list[str] = []
        for ip in online + _BUILTIN:
            if ip not in seen and _is_valid_ipv4(ip):
                seen.add(ip)
                merged.append(ip)

        if not merged:
            merged = [ip for ip in _BUILTIN if _is_valid_ipv4(ip)]

        return merged

    async def _refresh(self) -> None:
        candidates = await self._build_candidates()
        self._total_probed = len(candidates)

        if not candidates:
            logger.warning("DNS pool: no candidates to probe")
            return

        print(f"[dns_pool] Probing {len(candidates)} candidates "
              f"(concurrency={self._probe_concurrency})…", flush=True)

        ranked = await probe_all(
            candidates,
            concurrency=self._probe_concurrency,
            timeout=self._probe_timeout,
            keep=self._keep,
        )

        self._total_working = len(ranked)
        self._wp.load(ranked)
        self._last_ranked  = ranked          # capture for cache persistence
        self._last_refresh = time.monotonic()

        if ranked:
            print(
                f"[dns_pool] {len(ranked)} working resolvers "
                f"(best {ranked[0][1]:.0f}ms, "
                f"p50 {ranked[len(ranked)//2][1]:.0f}ms, "
                f"p90 {ranked[int(len(ranked)*0.9)][1]:.0f}ms)",
                flush=True,
            )
        else:
            print("[dns_pool] No working UDP resolvers; DoH/system only", flush=True)

    async def _maybe_refresh(self) -> None:
        """Trigger background refresh if pool is stale."""
        if (time.monotonic() - self._last_refresh) > self._refresh_interval:
            asyncio.create_task(self._refresh())

    async def rdns(self, ip: str) -> str | None:
        """Reverse DNS lookup: DoH → UDP → system."""
        await self._maybe_refresh()

        if self._prefer_doh and _HAS_AIOHTTP:
            result = await _doh_rdns(ip, session=self._doh_session,
                                     timeout=self._rdns_timeout)
            if result:
                return result

        # UDP via weighted pool
        resolver_ip = self._wp.next()
        if resolver_ip:
            result = await _udp_rdns(ip, resolver_ip, self._rdns_timeout)
            if result:
                self._wp.report_success(resolver_ip)
                return result
            else:
                self._wp.report_error(resolver_ip)

        # DoH second (if not prefer_doh)
        if not self._prefer_doh and _HAS_AIOHTTP:
            result = await _doh_rdns(ip, session=self._doh_session,
                                     timeout=self._rdns_timeout)
            if result:
                return result

        # System resolver last resort
        return await self._system_rdns(ip)

    async def _system_rdns(self, ip: str) -> str | None:
        loop = asyncio.get_event_loop()
        try:
            res = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)),
                timeout=self._rdns_timeout,
            )
            h = res[0]
            return h if h and h != ip else None
        except Exception:
            return None

    @property
    def size(self) -> int:
        return self._wp.size

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def stats(self) -> dict:
        qs = self._wp.query_stats
        return {
            "udp_resolvers":     self._wp.size,
            "blacklisted":       self._wp.blacklisted,
            "doh_enabled":       _HAS_AIOHTTP,
            "doh_providers":     len(_DOH_PROVIDERS),
            "aiodns_available":  _HAS_AIODNS,
            "total_fetched":     self._total_fetched,
            "total_probed":      self._total_probed,
            "total_working":     self._total_working,
            "init_time_s":       round(self._init_time_s, 1),
            "cache_source":      self._cache_source,
            "cache_age_seconds": int(self._cache_age_s),
            "cache_file":        self._cache_file,
            "cache_ttl_seconds": self._cache_ttl,
            "strategy": (
                "DoH+UDP+system" if _HAS_AIOHTTP and self._wp.size
                else "DoH+system" if _HAS_AIOHTTP
                else "UDP+system" if self._wp.size
                else "system"
            ),
            **qs,
        }


# ── Module-level singleton ─────────────────────────────────────────────────

_pool: ResolverPool | None = None


async def get_pool(**kwargs) -> ResolverPool:
    global _pool
    if _pool is None:
        _pool = ResolverPool(**kwargs)
        await _pool.start()
    return _pool


# ── CLI ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, json
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description="Distributed DNS resolver pool")
    ap.add_argument("--fetch",  action="store_true", help="Fetch online list only")
    ap.add_argument("--probe",  action="store_true", help="Probe UDP resolvers")
    ap.add_argument("--rdns",   metavar="IP",        help="Reverse-DNS lookup")
    ap.add_argument("--keep",   type=int,   default=500)
    ap.add_argument("--concurrency", type=int, default=1000)
    ap.add_argument("--timeout", type=float, default=1.5)
    ap.add_argument("--no-fetch", dest="no_fetch", action="store_true",
                    help="Skip online fetch, use built-in list only")
    args = ap.parse_args()

    async def _main() -> None:
        if args.fetch:
            ips = await fetch_online_list()
            print(json.dumps({"count": len(ips), "sample": ips[:10]}))
        elif args.probe:
            if args.no_fetch:
                cands = [ip for ip in _BUILTIN if _is_valid_ipv4(ip)]
            else:
                cands = await fetch_online_list()
                if not cands:
                    cands = [ip for ip in _BUILTIN if _is_valid_ipv4(ip)]
            ranked = await probe_all(cands, concurrency=args.concurrency,
                                     timeout=args.timeout, keep=args.keep)
            print(json.dumps({
                "working": len(ranked),
                "total_probed": len(cands),
                "fastest": ranked[:5],
                "slowest": ranked[-5:],
            }, indent=2))
        elif args.rdns:
            pool = ResolverPool(
                keep=args.keep,
                probe_concurrency=args.concurrency,
                probe_timeout=args.timeout,
                fetch_online=not args.no_fetch,
            )
            await pool.start()
            result = await pool.rdns(args.rdns)
            print(f"PTR {args.rdns} → {result or '(no result)'}")
            print(json.dumps(pool.stats, indent=2))
            await pool.close()
        else:
            ap.print_help()

    asyncio.run(_main())
