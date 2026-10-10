from __future__ import annotations

import asyncio
import hashlib
import html
import json
import os
import random
import re
import signal
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, urljoin

import aiohttp
from bs4 import BeautifulSoup
from dateutil import parser as date_parser

from proxy_pool import PROXY_POOL, proxy_refresh_loop

ROOT = Path(__file__).resolve().parent
CONFIG_DIR = ROOT / "config"
SETTINGS_FILE = CONFIG_DIR / "settings.json"
DATA_DIR = ROOT / "data"
LOG_DIR = ROOT / "logs"
STATE_FILE = DATA_DIR / "state.json"
RESULTS_FILE = DATA_DIR / "results.jsonl"
NEW_RESULTS_FILE = DATA_DIR / "new_results.jsonl"
KEYS_FILE = DATA_DIR / "found_keys.jsonl"
STATUS_FILE = DATA_DIR / "status.json"
TRIGGER_FILE = DATA_DIR / "trigger_cycle"

# ── API key patterns ────────────────────────────────────────────────────────
# (service, category, pattern)
HIGH_CONFIDENCE_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # ── AI ──────────────────────────────────────────────────────────────────
    ("openai",      "ai", re.compile(r'(?<![A-Za-z0-9_])(sk-proj-[A-Za-z0-9_-]{20,200})(?![A-Za-z0-9_-])')),
    ("openai",      "ai", re.compile(r'(?<![A-Za-z0-9_])(sk-[A-Za-z0-9]{48})(?![A-Za-z0-9])')),
    ("anthropic",   "ai", re.compile(r'(?<![A-Za-z0-9_])(sk-ant-api03-[A-Za-z0-9_-]{85,200})(?![A-Za-z0-9_-])')),
    ("anthropic",   "ai", re.compile(r'(?<![A-Za-z0-9_])(sk-ant-[A-Za-z0-9_-]{90,200})(?![A-Za-z0-9_-])')),
    ("openrouter",  "ai", re.compile(r'(?<![A-Za-z0-9_])(sk-or-v1-[A-Za-z0-9_-]{60,200})(?![A-Za-z0-9_-])')),
    ("google-gemini","ai",re.compile(r'(?<![A-Za-z0-9_])(AIza[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])')),
    ("huggingface", "ai", re.compile(r'(?<![A-Za-z0-9_])(hf_[A-Za-z0-9]{34,100})(?![A-Za-z0-9])')),
    ("replicate",   "ai", re.compile(r'(?<![A-Za-z0-9_])(r8_[A-Za-z0-9]{37})(?![A-Za-z0-9])')),
    ("groq",        "ai", re.compile(r'(?<![A-Za-z0-9_])(gsk_[A-Za-z0-9]{52})(?![A-Za-z0-9])')),
    ("perplexity",  "ai", re.compile(r'(?<![A-Za-z0-9_])(pplx-[A-Za-z0-9]{48})(?![A-Za-z0-9])')),
    ("deepseek",    "ai", re.compile(r'(?<![A-Za-z0-9_])(sk-[a-zA-Z0-9]{32,50})(?![A-Za-z0-9_-])')),
    ("cohere",      "ai", re.compile(r'(?<![A-Za-z0-9])(CO\.[A-Za-z0-9_-]{38,60})(?![A-Za-z0-9_-])')),
    ("mistral",     "ai", re.compile(r'(?<![A-Za-z0-9])(mist[A-Za-z0-9_-]{30,50})(?![A-Za-z0-9_-])')),
    ("xai",         "ai", re.compile(r'(?<![A-Za-z0-9_])(xai-[A-Za-z0-9_-]{40,120})(?![A-Za-z0-9_-])')),
    # ── Chinese AI providers ──────────────────────────────────────────────────
    ("moonshot",    "ai", re.compile(r'(?:MOONSHOT_API_KEY|KIMI_API_KEY|kimi[_\s-]?api[_\s-]?key|moonshot[_\s-]?api[_\s-]?key)["\']?\s*[:=]\s*["\']?(sk-[A-Za-z0-9]{32,96})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("dashscope",   "ai", re.compile(r'(?:DASHSCOPE_API_KEY|QWEN_API_KEY|qwen[_\s-]?api[_\s-]?key|dashscope[_\s-]?api[_\s-]?key|ALIBABA_API_KEY)["\']?\s*[:=]\s*["\']?(sk-[A-Za-z0-9]{32,96})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("minimax",     "ai", re.compile(r'(?:MINIMAX_API_KEY|minimax[_\s-]?api[_\s-]?key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9._-]{32,200})(?![A-Za-z0-9._-])', re.IGNORECASE)),
    ("zhipuai",     "ai", re.compile(r'(?:ZHIPUAI_API_KEY|ZHIPU_API_KEY|GLM_API_KEY|zhipuai[_\s-]?api[_\s-]?key|zhipu[_\s-]?api[_\s-]?key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9._-]{20,200})(?![A-Za-z0-9._-])', re.IGNORECASE)),
    ("zhipuai",     "ai", re.compile(r'(?<![A-Za-z0-9_])([a-f0-9]{16}\.[A-Za-z0-9]{32,48})(?![A-Za-z0-9.])')),
    # ── Payments ─────────────────────────────────────────────────────────────
    ("stripe",      "payments", re.compile(r'(?<![A-Za-z0-9_])(sk_live_[A-Za-z0-9]{24,})(?![A-Za-z0-9_])')),
    ("stripe",      "payments", re.compile(r'(?<![A-Za-z0-9_])(sk_test_[A-Za-z0-9]{24,})(?![A-Za-z0-9_])')),
    ("stripe",      "payments", re.compile(r'(?<![A-Za-z0-9_])(rk_live_[A-Za-z0-9]{24,})(?![A-Za-z0-9_])')),
    ("paypal",      "payments", re.compile(r'(?<![A-Za-z0-9_])(access_token\$(?:production|sandbox)\$[A-Za-z0-9._-]{60,300})(?![A-Za-z0-9_])')),
    ("braintree",   "payments", re.compile(r'(?<![A-Za-z0-9_])(access_token\$sandbox\$[A-Za-z0-9_]{60,300})(?![A-Za-z0-9_])')),
    ("square",      "payments", re.compile(r'(?<![A-Za-z0-9_])(EAAAE[A-Za-z0-9_-]{50,200})(?![A-Za-z0-9_-])')),
    ("square",      "payments", re.compile(r'(?<![A-Za-z0-9_])(sq0[a-z]{3}-[A-Za-z0-9_-]{22,50})(?![A-Za-z0-9_-])')),
    ("shopify",     "payments", re.compile(r'(?<![A-Za-z0-9_])(shpat_[A-Za-z0-9]{32,})(?![A-Za-z0-9_])')),
    ("shopify",     "payments", re.compile(r'(?<![A-Za-z0-9_])(shpss_[A-Za-z0-9]{32,})(?![A-Za-z0-9_])')),
    ("shopify",     "payments", re.compile(r'(?<![A-Za-z0-9_])(shpca_[A-Za-z0-9]{32,})(?![A-Za-z0-9_])')),
    ("paddle",      "payments", re.compile(r'(?<![A-Za-z0-9_])(pdl_[a-z]{2}_[A-Za-z0-9_-]{60,200})(?![A-Za-z0-9_-])')),
    # ── Email ─────────────────────────────────────────────────────────────────
    ("sendgrid",    "email", re.compile(r'(?<![A-Za-z0-9])(SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{40,})(?![A-Za-z0-9_-])')),
    ("resend",      "email", re.compile(r'(?<![A-Za-z0-9_])(re_[A-Za-z0-9]{32,50})(?![A-Za-z0-9_])')),
    ("mailgun",     "email", re.compile(r'(?<![A-Za-z0-9_-])(key-[a-f0-9]{32})(?![A-Za-z0-9_-])')),
    # ── Cloud ─────────────────────────────────────────────────────────────────
    ("aws",         "cloud", re.compile(r'(?<![A-Za-z0-9])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9])')),
    ("digitalocean","cloud", re.compile(r'(?<![A-Za-z0-9_])(dop_v1_[A-Za-z0-9]{64,})(?![A-Za-z0-9_])')),
    ("cloudflare",  "cloud", re.compile(r'(?<![A-Za-z0-9_])(cf_[A-Za-z0-9_-]{37,})(?![A-Za-z0-9_])')),
    # ── Auth / VCS ───────────────────────────────────────────────────────────
    ("github",      "auth", re.compile(r'(?<![A-Za-z0-9_])(ghp_[A-Za-z0-9]{36,})(?![A-Za-z0-9_])')),
    ("github",      "auth", re.compile(r'(?<![A-Za-z0-9_])(gho_[A-Za-z0-9]{36,})(?![A-Za-z0-9_])')),
    ("github",      "auth", re.compile(r'(?<![A-Za-z0-9_])(ghs_[A-Za-z0-9]{36,})(?![A-Za-z0-9_])')),
    ("github",      "auth", re.compile(r'(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{80,})(?![A-Za-z0-9_])')),
    ("gitlab",      "auth", re.compile(r'(?<![A-Za-z0-9_])(glpat-[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])')),
    # ── Messaging ────────────────────────────────────────────────────────────
    ("telegram",    "messaging", re.compile(r'(?<![A-Za-z0-9_])(\d{8,12}:[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])')),
    ("slack",       "messaging", re.compile(r'(?<![A-Za-z0-9_])(xoxb-[0-9]{8,13}-[0-9]{8,13}-[A-Za-z0-9]{24,})(?![A-Za-z0-9_-])')),
    ("slack",       "messaging", re.compile(r'(?<![A-Za-z0-9_])(xoxp-[0-9]{8,13}-[0-9]{8,13}-[0-9]{8,13}-[A-Za-z0-9]{64,})(?![A-Za-z0-9_-])')),
    ("twilio",      "messaging", re.compile(r'(?<![A-Za-z0-9])(SK[a-f0-9]{32})(?![A-Za-z0-9])')),
    # ── Database ─────────────────────────────────────────────────────────────
    ("postgresql",  "database", re.compile(r'(?<!["\'])(postgres(?:ql)?://[A-Za-z0-9_-]+:[^@\s"\']{6,}@[A-Za-z0-9._-]+(?::\d+)?/[A-Za-z0-9_-]+)(?![A-Za-z0-9_])')),
    ("mysql",       "database", re.compile(r'(?<!["\'])(mysql2?://[A-Za-z0-9_-]+:[^@\s"\']{6,}@[A-Za-z0-9._-]+(?::\d+)?/[A-Za-z0-9_-]+)(?![A-Za-z0-9_])')),
    ("mongodb",     "database", re.compile(r'(?<!["\'])(mongodb(?:\+srv)?://[A-Za-z0-9_-]+:[^@\s"\']{6,}@[A-Za-z0-9._-]+(?::\d+)?(?:/[A-Za-z0-9_-]*)?)(?![A-Za-z0-9_])')),
    ("redis",       "database", re.compile(r'(?<!["\'])(redis(?:s)?://(?:[A-Za-z0-9_-]+:[^@\s"\']{4,}@)[A-Za-z0-9._-]+(?::\d+)?)(?![A-Za-z0-9_])')),
    # ── Crypto / Wallets (context-required to keep false-positives low) ──────
    ("ethereum",    "crypto", re.compile(r'(?:private[_\s-]?key|priv[_\s-]?key|eth[_\s-]?key|wallet[_\s-]?key|secret[_\s-]?key)["\']?\s*[:=]\s*["\']?(0x[a-fA-F0-9]{64})(?![a-fA-F0-9])', re.IGNORECASE)),
    ("bitcoin",     "crypto", re.compile(r'(?:btc|bitcoin|wif|wallet)[_\s-]?(?:private[_\s-]?key|priv|secret|wif)["\']?\s*[:=]\s*["\']?([5KL][1-9A-HJ-NP-Za-km-z]{50,51})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("solana",      "crypto", re.compile(r'(?:solana|sol|phantom)[_\s-]?(?:private[_\s-]?key|secret[_\s-]?key|secret)["\']?\s*[:=]\s*["\']?([1-9A-HJ-NP-Za-km-z]{87,88})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("bip39_seed",  "crypto", re.compile(r'(?:mnemonic|seed[_\s-]?phrase|seedphrase|recovery[_\s-]?phrase|wallet[_\s-]?seed|backup[_\s-]?phrase)["\']?\s*[:=]\s*["\']?((?:\b[a-z]{3,8}\b[\s\u00A0]+){11,23}\b[a-z]{3,8}\b)', re.IGNORECASE)),
    ("binance",     "crypto", re.compile(r'(?:binance[_\s-]?api[_\s-]?(?:key|secret)|BINANCE_API_KEY|BINANCE_SECRET_KEY)["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{64})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("coinbase",    "crypto", re.compile(r'(?:coinbase[_\s-]?api[_\s-]?(?:key|secret)|COINBASE_API_KEY)["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{32,128})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("kraken",      "crypto", re.compile(r'(?:kraken[_\s-]?api[_\s-]?(?:key|secret)|KRAKEN_API_KEY)["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=]{56,128})', re.IGNORECASE)),
    ("metamask_vault","crypto", re.compile(r'("vault"\s*:\s*"[^"]{60,800}"|"keyringTypes"\s*:\s*\[[^\]]{1,200}\]|"data"\s*:\s*"[A-Za-z0-9+/=]{120,}")')),
]

PLACEHOLDER_PATTERNS = re.compile(
    r'(xxxx|your[_-]?key|api[_-]?key|insert|replace|example|placeholder|dummy|test[_-]?key'
    r'|changeme|todo|fixme|secret_here|my[_-]?key|<[^>]+>|\.\.\.)',
    re.IGNORECASE
)

stop_event = asyncio.Event()


# ── Helpers ─────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(path)
    except Exception:
        pass


def append_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("a", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception:
        pass


def parse_date(value: Any) -> str | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        ts = value / 1000 if value > 10_000_000_000 else value
        return datetime.fromtimestamp(ts, timezone.utc).replace(microsecond=0).isoformat()
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = date_parser.parse(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()
    except Exception:
        return None


def clean_text(text: str, limit: int = 240) -> str:
    text = html.unescape(re.sub(r"\s+", " ", text or "")).strip()
    return text[: limit - 1] + "…" if len(text) > limit else text


def mask_key(key: str) -> str:
    if len(key) <= 12:
        return key[:4] + "..." + key[-2:]
    return key[:8] + "..." + key[-4:]


def make_fingerprint(basis: str) -> str:
    return hashlib.sha256(basis.encode("utf-8", "ignore")).hexdigest()[:24]


def build_url(template: str, query: str, limit: int) -> str:
    return template.format(query=quote_plus(query), raw_query=query, limit=limit)


def date_sort_key(d: dict[str, Any]) -> float:
    for field_name in ("published_at", "first_seen_at"):
        v = d.get(field_name)
        if v:
            try:
                return date_parser.parse(v).timestamp()
            except Exception:
                pass
    return 0.0


# ── Query categorisation (for cycle rotation) ────────────────────────────────
# Maps category name → list of substrings; if any substring is present in a
# query string (case-insensitive), the query goes in that category. First
# match wins, so order entries from most specific → least.
QUERY_CATEGORY_KEYWORDS: list[tuple[str, list[str]]] = [
    ("payments", [
        "sk_live_", "sk_test_", "rk_live_", "STRIPE_", "shpat_", "shpss_",
        "shpca_", "EAAAE", "sq0", "pdl_", "Authorization: Bearer sk_live_",
    ]),
    # AI is split into 3 tiers by service popularity / leak frequency.
    # ORDER MATTERS — first-match-wins, so ai_top before ai_mid before ai_low.
    # Helicone keys must match ai_low BEFORE the generic "Authorization: Bearer sk-"
    # in ai_top would catch them — that's fine because "sk-helicone-" is a more
    # specific substring and we explicitly route it to ai_low first via order.
    ("ai_low", [
        # Niche / env-var-only — match these FIRST so they don't fall into ai_top
        # via generic prefixes like "OPENAI_" (none of these collide, but keeping
        # ai_low first preserves explicit routing for future additions).
        "sk-helicone-", "msk-", "tgp_v1_", "nvapi-", "csk-", "tvly-",
        "lsv2_", "esecret_", "modal-", "fw_", "v0_", "NRII-",
        "TOGETHER_", "FIREWORKS_", "NVIDIA_", "CEREBRAS_",
        "MOONSHOT_", "ZHIPU_", "PINECONE_", "TAVILY_",
        "LANGSMITH_", "LANGCHAIN_", "STABILITY_",
        "ASSEMBLYAI_", "HELICONE_", "MODAL_TOKEN",
    ]),
    ("ai_top", [
        # Tier-1 giants: OpenAI, Anthropic, Google Gemini, HuggingFace.
        # Most commonly leaked, highest impact.
        "sk-proj-", "sk-ant-", "AIza", "hf_",
        "OPENAI_", "ANTHROPIC_",
        "openai.api_key", "anthropic_api_key",
        "Authorization: Bearer sk-",
    ]),
    ("ai_mid", [
        # Tier-2 popular alternatives: OpenRouter, Groq, Perplexity,
        # Replicate, xAI, Cohere, DeepSeek, Mistral, ElevenLabs.
        "sk-or-", "gsk_", "pplx-", "r8_", "xai-", "CO.",
        "DEEPSEEK_", "GROQ_", "MISTRAL_", "PERPLEXITY_",
        "REPLICATE_", "COHERE_", "XAI_", "ELEVENLABS_",
    ]),
    ("email", ["SG.", "key-", "re_", "SENDGRID_", "MAILGUN_", "RESEND_"]),
    ("cloud", [
        "AKIA", "dop_v1_", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "DIGITALOCEAN_", "CLOUDFLARE_",
    ]),
    ("auth", [
        "ghp_", "gho_", "ghs_", "github_pat_", "glpat-", "eyJhbGci",
        "GITHUB_TOKEN", "GITLAB_TOKEN", "sbp_", "SUPABASE_",
    ]),
    ("messaging", [
        "hooks.slack.com", "discord.com/api/webhooks", "TELEGRAM_BOT_TOKEN",
        "xoxb-", "xoxp-",
    ]),
    ("db", [
        "postgres://", "mongodb+srv://", "redis://", "DATABASE_URL",
        "MONGODB_URI", "REDIS_URL",
    ]),
    ("media", ["pk.eyJ", "cloudinary://"]),
    ("monitoring", ["NRAK-", "HRKU-", "DATADOG_", "SENTRY_DSN"]),
    ("crypto", [
        "MNEMONIC=", "SEED_PHRASE=", "PRIVATE_KEY=0x", "ETH_PRIVATE_KEY",
        "BINANCE_API_KEY", "COINBASE_API_KEY", "TRON_PRIVATE_KEY",
    ]),
]


def _classify_query(q: str) -> str:
    ql = q.lower()
    for cat, needles in QUERY_CATEGORY_KEYWORDS:
        for n in needles:
            if n.lower() in ql:
                return cat
    return "other"


def _group_queries_by_category(queries: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for q in queries:
        out.setdefault(_classify_query(q), []).append(q)
    # Drop empty buckets just in case (shouldn't happen).
    return {k: v for k, v in out.items() if v}


# ── Key extraction ───────────────────────────────────────────────────────────

def extract_keys_from_text(text: str, source: str, query: str, url: str, title: str) -> list[dict[str, Any]]:
    """Extract actual API keys from raw text using high-confidence patterns."""
    found: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    for service, category, pattern in HIGH_CONFIDENCE_PATTERNS:
        for match in pattern.finditer(text):
            key = match.group(1)
            if key in seen_keys:
                continue
            # Skip placeholders
            if PLACEHOLDER_PATTERNS.search(key):
                continue
            # Minimum entropy check — reject keys that are all same char
            if len(set(key)) < 6:
                continue
            # Skip keys that are too common/generic
            if key in ("sk-", "hf_", "r8_", "gsk_"):
                continue
            # For DB connection strings: skip ones with obvious placeholder creds
            if category == "database" and re.search(r':(password|passwd|secret|changeme|example|your[_-]?pass|<[^>]+>)@', key, re.IGNORECASE):
                continue
            seen_keys.add(key)
            fp = make_fingerprint(f"key|{key}")
            # Get context around the key
            start = max(0, match.start() - 80)
            end = min(len(text), match.end() + 80)
            context = clean_text(text[start:end], 300)
            found.append({
                "id": fp,
                "type": "key",
                "key": key,
                "key_masked": mask_key(key),
                "service": service,
                "category": category,
                "source": source,
                "query": query,
                "url": url,
                "title": title,
                "snippet": context,
                "status": "unchecked",
                "validated_at": None,
                "published_at": None,
                "first_seen_at": now_iso(),
                "fingerprint": fp,
            })
    return found


def detect_service(key: str) -> str | None:
    """Auto-detect service from key prefix."""
    for service, _category, pattern in HIGH_CONFIDENCE_PATTERNS:
        m = pattern.search(key)
        if m and m.group(1) == key:
            return service
    # Fallback prefix checks
    if key.startswith("sk-proj-"):      return "openai"
    if key.startswith("sk-ant-api03-") or key.startswith("sk-ant-"): return "anthropic"
    if key.startswith("sk-or-v1-"):     return "openrouter"
    if key.startswith("AIza"):          return "google-gemini"
    if key.startswith("hf_"):           return "huggingface"
    if key.startswith("r8_"):           return "replicate"
    if key.startswith("gsk_"):          return "groq"
    if key.startswith("pplx-"):         return "perplexity"
    if key.startswith("CO."):           return "cohere"
    if key.startswith("sk_live_") or key.startswith("sk_test_"): return "stripe"
    if key.startswith("SG."):           return "sendgrid"
    if key.startswith("re_"):           return "resend"
    if key.startswith("AKIA"):          return "aws"
    if key.startswith("ghp_") or key.startswith("gho_") or key.startswith("ghs_"): return "github"
    if key.startswith("glpat-"):        return "gitlab"
    if key.startswith("dop_v1_"):       return "digitalocean"
    if key.startswith("xoxb-") or key.startswith("xoxp-"): return "slack"
    if re.match(r'\d{8,12}:', key):     return "telegram"
    if key.startswith("postgres://") or key.startswith("postgresql://"): return "postgresql"
    if key.startswith("mysql"):         return "mysql"
    if key.startswith("mongodb"):       return "mongodb"
    if key.startswith("redis"):         return "redis"
    return None


# ── Key validation ───────────────────────────────────────────────────────────

VALIDATION_ENDPOINTS: dict[str, dict[str, Any]] = {
    "openai": {
        "url": "https://api.openai.com/v1/models",
        "method": "GET",
        "headers_fn": lambda key: {"Authorization": f"Bearer {key}"},
        "valid_status": [200],
        "invalid_status": [401, 403],
    },
    "anthropic": {
        "url": "https://api.anthropic.com/v1/models",
        "method": "GET",
        "headers_fn": lambda key: {"x-api-key": key, "anthropic-version": "2023-06-01"},
        "valid_status": [200],
        "invalid_status": [401, 403],
    },
    "openrouter": {
        "url": "https://openrouter.ai/api/v1/models",
        "method": "GET",
        "headers_fn": lambda key: {"Authorization": f"Bearer {key}"},
        "valid_status": [200],
        "invalid_status": [401, 403],
    },
    "google": {
        "url": "https://generativelanguage.googleapis.com/v1beta/models?key={key}",
        "method": "GET",
        "headers_fn": lambda key: {},
        "url_fn": lambda key: f"https://generativelanguage.googleapis.com/v1beta/models?key={key}",
        "valid_status": [200],
        "invalid_status": [400, 403],
    },
    "huggingface": {
        "url": "https://huggingface.co/api/whoami",
        "method": "GET",
        "headers_fn": lambda key: {"Authorization": f"Bearer {key}"},
        "valid_status": [200],
        "invalid_status": [401, 403],
    },
    "groq": {
        "url": "https://api.groq.com/openai/v1/models",
        "method": "GET",
        "headers_fn": lambda key: {"Authorization": f"Bearer {key}"},
        "valid_status": [200],
        "invalid_status": [401, 403],
    },
    "perplexity": {
        "url": "https://api.perplexity.ai/models",
        "method": "GET",
        "headers_fn": lambda key: {"Authorization": f"Bearer {key}"},
        "valid_status": [200],
        "invalid_status": [401, 403],
    },
    "replicate": {
        "url": "https://api.replicate.com/v1/account",
        "method": "GET",
        "headers_fn": lambda key: {"Authorization": f"Token {key}"},
        "valid_status": [200],
        "invalid_status": [401, 403],
    },
    "cohere": {
        "url": "https://api.cohere.com/v2/models",
        "method": "GET",
        "headers_fn": lambda key: {"Authorization": f"Bearer {key}"},
        "valid_status": [200],
        "invalid_status": [401, 403],
    },
    "deepseek": {
        "url": "https://api.deepseek.com/models",
        "method": "GET",
        "headers_fn": lambda key: {"Authorization": f"Bearer {key}"},
        "valid_status": [200],
        "invalid_status": [401, 403],
    },
}


async def validate_key(session: aiohttp.ClientSession, key: str, service: str) -> tuple[str, str]:
    """Returns (status, message) where status is 'valid'|'invalid'|'error'."""
    endpoint = VALIDATION_ENDPOINTS.get(service)
    if not endpoint:
        return "unchecked", f"No validator for service '{service}'"
    try:
        url = endpoint.get("url_fn", lambda k: endpoint["url"])(key)
        headers = endpoint["headers_fn"](key)
        timeout = aiohttp.ClientTimeout(total=12)
        async with session.request(
            endpoint.get("method", "GET"),
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        ) as resp:
            if resp.status in endpoint.get("valid_status", [200]):
                return "valid", f"HTTP {resp.status} - key accepted"
            elif resp.status in endpoint.get("invalid_status", [401, 403]):
                return "invalid", f"HTTP {resp.status} - key rejected"
            else:
                return "error", f"HTTP {resp.status} - unexpected response"
    except Exception as exc:
        return "error", f"Request failed: {type(exc).__name__}: {exc}"


# ── Search result dataclass ──────────────────────────────────────────────────

@dataclass
class SearchResult:
    source: str
    category: str
    query: str
    title: str
    url: str
    snippet: str = ""
    published_at: str | None = None
    first_seen_at: str | None = None
    fingerprint: str = ""

    def build_fingerprint(self) -> str:
        basis = f"{self.source}|{self.url}|{self.title}".lower().strip()
        self.fingerprint = make_fingerprint(basis)
        return self.fingerprint


# ── HTTP fetch ───────────────────────────────────────────────────────────────

USER_AGENTS = [
    # Real browser UA strings rotated randomly per request to dodge naive
    # anti-bot 403s on npm/Mojeek/Reddit/SourceForge/Maven Central. Mixing OS
    # + browser + language hints helps because many WAFs fingerprint a single
    # constant UA as "scraper". Updated 2026-Q1.
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.2849.46",
]


def _build_browser_headers(ua_index: int = 0) -> dict[str, str]:
    # Minimal header set — exact match to the pre-proxy-experiment baseline,
    # plus random UA rotation. We deliberately do NOT send Sec-Fetch-*,
    # Accept-Encoding, DNT, or Upgrade-Insecure-Requests because adding
    # them caused 23+ sources to start dropping connections (http_0):
    # several anti-bot stacks treat sec-fetch-site=none on a non-document
    # request as suspicious and silently RST. Stick with what works.
    if ua_index == 0:
        ua = random.choice(USER_AGENTS)
    else:
        ua = USER_AGENTS[ua_index % len(USER_AGENTS)]
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }


# IP-ban statuses retried through a rotating proxy when proxy retry is on.
# Excludes status 0 (network timeout) — real network errors, not WAF blocks.
_RETRY_VIA_PROXY_STATUSES = {403, 418, 429, 451}
_PROXY_RETRY_COUNT = 2

# Proxy retry config is loaded from monitor/data/proxy_config.json so the
# user can toggle it from the UI without restarting. We re-read the file
# at the start of every cycle (cheap; small JSON). Default OFF.
_PROXY_CONFIG_FILE = Path(__file__).parent / "data" / "proxy_config.json"


def is_proxy_retry_enabled() -> bool:
    try:
        if _PROXY_CONFIG_FILE.exists():
            cfg = json.loads(_PROXY_CONFIG_FILE.read_text())
            return bool(cfg.get("enabled", False))
    except Exception:
        pass
    return False


# Mutable flag set by the main loop at cycle start; fetch_text reads it on
# the hot path so we avoid a file-stat per request.
ENABLE_PROXY_RETRY = False


async def fetch_text(session: aiohttp.ClientSession, url: str, timeout: int, ua_index: int = 0) -> tuple[int, str, str]:
    # ua_index=0 (the default for nearly every caller) means "pick random",
    # so each request rotates UA. Explicit ua_index>0 callers still get a
    # deterministic UA. Browser-realistic Accept-* and sec-fetch-* headers
    # turn most 403 walls into 200s on sites that just gate on header shape.
    # When ENABLE_PROXY_RETRY is on AND the response is a likely IP ban,
    # we retry up to _PROXY_RETRY_COUNT times via random free proxies.
    headers = _build_browser_headers(ua_index)
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=True, headers=headers) as resp:
            text = await resp.text(errors="ignore")
            status = resp.status
            final_url = str(resp.url)
            if not ENABLE_PROXY_RETRY or status not in _RETRY_VIA_PROXY_STATUSES:
                return status, final_url, text
            last = (status, final_url, text)
    except asyncio.TimeoutError:
        return 0, url, "FETCH_ERROR: TimeoutError"
    except Exception as exc:
        return 0, url, f"FETCH_ERROR: {type(exc).__name__}: {exc}"

    if PROXY_POOL.size() == 0:
        return last
    proxy_timeout = min(timeout, 12)
    for _ in range(_PROXY_RETRY_COUNT):
        proxy = PROXY_POOL.get()
        if not proxy:
            break
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=proxy_timeout),
                allow_redirects=True,
                headers=_build_browser_headers(0),
                proxy=proxy,
            ) as resp:
                text = await resp.text(errors="ignore")
                if resp.status not in _RETRY_VIA_PROXY_STATUSES:
                    return resp.status, str(resp.url), text
                last = (resp.status, str(resp.url), text)
        except Exception:
            PROXY_POOL.remove(proxy)
            continue
    return last


# ── Source-specific page fetchers ────────────────────────────────────────────

async def fetch_raw_file(
    session: aiohttp.ClientSession,
    repo: str,
    filepath: str,
    timeout: int,
) -> str:
    """Fetch raw file content — tries GitHub raw first, then Sourcegraph raw."""
    # Try GitHub raw URL
    github_raw = f"https://raw.githubusercontent.com/{repo}/HEAD/{filepath}"
    try:
        async with session.get(
            github_raw,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": USER_AGENTS[0]},
        ) as resp:
            if resp.status == 200:
                text = await resp.text(errors="ignore")
                if len(text) < 2_000_000:
                    return text
    except Exception:
        pass

    # Try Sourcegraph raw
    sg_raw = f"https://sourcegraph.com/{repo}/-/raw/{filepath}"
    try:
        async with session.get(
            sg_raw,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": USER_AGENTS[0]},
        ) as resp:
            if resp.status == 200:
                text = await resp.text(errors="ignore")
                if len(text) < 2_000_000:
                    return text
    except Exception:
        pass

    return ""


async def fetch_sourcegraph_results(
    session: aiohttp.ClientSession,
    query: str,
    timeout: int,
    fetch_files: bool = True,
) -> list[dict[str, Any]]:
    """
    Sourcegraph public search — streams up to 5000 file matches, then fetches raw files
    to extract complete API keys (not just truncated snippet previews).

    Live-tested 2026-05: bare query gives ~6 matches, query+`count:5000`
    +display=5000 gives ~150-400 matches per query (50-70x boost).
    Sourcegraph's stream API has no cursor pagination — `count:` is the
    only way to get past the default 500 cap.
    """
    # Inject `count:5000` if the user didn't already specify a count: clause.
    q = query if "count:" in query else f"{query} count:5000"
    api_url = (
        f"https://sourcegraph.com/.api/search/stream"
        f"?q={quote_plus(q)}&display=5000&v=V3"
    )
    file_matches: list[dict[str, Any]] = []

    try:
        async with session.get(
            api_url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"Accept": "text/event-stream"},
        ) as resp:
            if resp.status != 200:
                return []
            buffer = ""
            async for chunk in resp.content.iter_chunked(16384):
                buffer += chunk.decode("utf-8", errors="ignore")
                while "\n\n" in buffer:
                    event, buffer = buffer.split("\n\n", 1)
                    lines = event.strip().splitlines()
                    event_type = ""
                    event_data = ""
                    for line in lines:
                        if line.startswith("event:"):
                            event_type = line[6:].strip()
                        elif line.startswith("data:"):
                            event_data = line[5:].strip()
                    if event_type == "matches" and event_data:
                        try:
                            matches = json.loads(event_data)
                            for m in matches:
                                if m.get("type") != "content":
                                    continue
                                repo = m.get("repository", "")
                                path_val = m.get("path", "")
                                if not repo or not path_val:
                                    continue
                                line_matches = m.get("lineMatches", [])
                                # Collect all line previews for inline key extraction
                                all_previews = " ".join(
                                    lm.get("preview", "") for lm in line_matches
                                )
                                file_matches.append({
                                    "repo": repo,
                                    "path": path_val,
                                    "url": f"https://sourcegraph.com/{repo}/-/blob/{path_val}",
                                    "title": f"{repo}: {path_val}",
                                    "preview": all_previews,
                                })
                        except Exception:
                            pass
                    if event_type in ("done", "error"):
                        break
    except Exception:
        return []

    # Build results list — each file is a result
    results = []
    seen_urls: set[str] = set()
    for fm in file_matches:
        if fm["url"] in seen_urls:
            continue
        seen_urls.add(fm["url"])
        results.append({
            "url": fm["url"],
            "title": fm["title"],
            "snippet": clean_text(fm["preview"], 400),
            "source": "Sourcegraph",
            "raw_content": fm["preview"],  # inline extraction from preview
            "repo": fm["repo"],
            "path": fm["path"],
            "fetch_raw": fetch_files,  # flag to fetch full file
        })

    # Fetch raw files in parallel for full key extraction.
    # Was: 80 files × 15 concurrency. With pagination giving 1500-2000 matches,
    # 80 was <5% coverage. Now 400 × 25 = ~95% of typical responses, ~16s wall.
    if fetch_files and results:
        fetch_sem = asyncio.Semaphore(25)

        async def fetch_and_attach(item: dict[str, Any]) -> None:
            async with fetch_sem:
                raw = await fetch_raw_file(session, item["repo"], item["path"], min(timeout, 20))
                if raw:
                    item["raw_content"] = raw

        await asyncio.gather(*[fetch_and_attach(r) for r in results[:400]])

    return results


async def fetch_kaggle_results(
    session: aiohttp.ClientSession,
    query: str,
    timeout: int,
) -> list[dict[str, Any]]:
    """
    Kaggle search — uses both HTML scraping and the kernels/datasets API.
    Then fetches kernel source code to extract keys.
    """
    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    async def try_kernel_api(page: int) -> list[dict[str, Any]]:
        api_url = (
            f"https://www.kaggle.com/api/v1/kernels/list"
            f"?search={quote_plus(query)}&page={page}&pageSize=20&sortBy=dateCreated"
        )
        try:
            async with session.get(
                api_url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"User-Agent": USER_AGENTS[0], "Accept": "application/json"},
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    items = []
                    for k in data if isinstance(data, list) else []:
                        owner = k.get("author") or k.get("currentRunningVersion", {}).get("authorUserName", "")
                        slug = k.get("title", "").replace(" ", "-").lower() if k.get("currentUrlSlug") is None else k.get("currentUrlSlug", "")
                        slug = k.get("currentUrlSlug") or slug
                        if owner and slug:
                            url = f"https://www.kaggle.com/{owner}/{slug}"
                            items.append({"url": url, "title": k.get("title", slug), "owner": owner, "slug": slug})
                    return items
        except Exception:
            pass
        return []

    async def try_dataset_api(page: int) -> list[dict[str, Any]]:
        api_url = (
            f"https://www.kaggle.com/api/v1/datasets/list"
            f"?search={quote_plus(query)}&page={page}&sortBy=dateCreated"
        )
        try:
            async with session.get(
                api_url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"User-Agent": USER_AGENTS[0], "Accept": "application/json"},
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    items = []
                    for d in data if isinstance(data, list) else []:
                        ref = d.get("ref", "")
                        title = d.get("title", ref)
                        if ref:
                            url = f"https://www.kaggle.com/datasets/{ref}"
                            items.append({"url": url, "title": title})
                    return items
        except Exception:
            pass
        return []

    async def scrape_html_search() -> list[dict[str, Any]]:
        search_url = f"https://www.kaggle.com/search?q={quote_plus(query)}+sortBy%3Adate"
        status, final_url, body = await fetch_text(session, search_url, timeout)
        items = []
        if status == 200 and not body.startswith("FETCH_ERROR"):
            # Try __NEXT_DATA__ JSON
            m = re.search(r'<script[^>]*id="__NEXT_DATA__"[^>]*>(.*?)</script>', body, re.DOTALL)
            if m:
                try:
                    nd = json.loads(m.group(1))
                    # Walk through props for results
                    def extract_kaggle_links(obj: Any, depth: int = 0) -> None:
                        if depth > 10:
                            return
                        if isinstance(obj, dict):
                            url = obj.get("url") or obj.get("href") or ""
                            title = obj.get("title") or obj.get("name") or ""
                            if url and title and (
                                url.startswith("/") or url.startswith("https://www.kaggle.com")
                            ) and any(p in url for p in ["/code/", "/datasets/", "/models/"]):
                                full = f"https://www.kaggle.com{url}" if url.startswith("/") else url
                                items.append({"url": full, "title": str(title)})
                            for v in obj.values():
                                extract_kaggle_links(v, depth + 1)
                        elif isinstance(obj, list):
                            for v in obj:
                                extract_kaggle_links(v, depth + 1)
                    extract_kaggle_links(nd)
                except Exception:
                    pass
            # Fallback: HTML links
            if not items:
                soup = BeautifulSoup(body, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if href.startswith("/") and any(p in href for p in ["/code/", "/datasets/", "/models/"]):
                        title = clean_text(a.get_text(" ", strip=True), 160)
                        if title and len(title) > 5:
                            items.append({"url": f"https://www.kaggle.com{href}", "title": title})
        return items

    # Run all discovery in parallel
    gathered = await asyncio.gather(
        try_kernel_api(1),
        try_kernel_api(2),
        try_dataset_api(1),
        scrape_html_search(),
        return_exceptions=True,
    )
    for group in gathered:
        if isinstance(group, list):
            for item in group:
                url = item.get("url", "")
                if url and url not in seen:
                    seen.add(url)
                    results.append(item)

    # Fetch notebook source for each found URL to extract keys
    fetch_sem = asyncio.Semaphore(6)

    async def fetch_kernel_source(item: dict[str, Any]) -> None:
        async with fetch_sem:
            url = item.get("url", "")
            if not url:
                return
            # Try direct notebook fetch — Kaggle sometimes embeds notebook JSON
            status, _, body = await fetch_text(session, url, timeout)
            if status != 200 or body.startswith("FETCH_ERROR"):
                return
            # Look for __NEXT_DATA__
            m = re.search(r'<script[^>]*id="__NEXT_DATA__"[^>]*>(.*?)</script>', body, re.DOTALL)
            if m:
                item["raw_content"] = m.group(1)
            else:
                # Extract any visible code blocks
                soup = BeautifulSoup(body, "html.parser")
                code_blocks = soup.find_all(["pre", "code"])
                if code_blocks:
                    item["raw_content"] = " ".join(b.get_text(" ") for b in code_blocks)

    await asyncio.gather(*[fetch_kernel_source(r) for r in results[:30]])

    return results[:50]


async def fetch_grepapp_results(
    session: aiohttp.ClientSession,
    query: str,
    timeout: int,
    pages: int = 5,
) -> list[dict[str, Any]]:
    """grep.app — best public code search, no auth needed, returns actual code snippets.
    Paginates through multiple pages."""
    results = []
    seen_urls: set[str] = set()

    for page in range(1, pages + 1):
        url = f"https://grep.app/api/search?q={quote_plus(query)}&regexp=false&page={page}"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"Accept": "application/json"},
            ) as resp:
                if resp.status != 200:
                    break
                data = await resp.json(content_type=None)
        except Exception:
            break

        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            break

        for hit in hits:
            repo = hit.get("repo", {}).get("raw", "")
            filepath = hit.get("path", {}).get("raw", "")
            content = hit.get("content", {}).get("snippet", "")
            url_hit = f"https://github.com/{repo}/blob/HEAD/{filepath}" if repo and filepath else ""
            if not url_hit or url_hit in seen_urls:
                continue
            seen_urls.add(url_hit)
            results.append({
                "url": url_hit,
                "title": f"{repo}: {filepath}",
                "snippet": clean_text(content, 400),
                "source": "grep.app",
                "raw_content": content,
                "repo": repo,
                "path": filepath,
            })

        # Check if there are more pages
        total = data.get("hits", {}).get("total", {}).get("value", 0)
        if len(results) >= total:
            break

    # Fetch raw files for complete key extraction
    fetch_sem = asyncio.Semaphore(10)

    async def fetch_raw(item: dict[str, Any]) -> None:
        async with fetch_sem:
            raw = await fetch_raw_file(session, item.get("repo", ""), item.get("path", ""), min(timeout, 20))
            if raw:
                item["raw_content"] = raw

    await asyncio.gather(*[fetch_raw(r) for r in results[:60]])
    return results


def _github_auth_headers(settings: dict[str, Any] | None) -> dict[str, str]:
    """Build Authorization header from settings.github_token (if set).

    Token is a personal access token (classic or fine-grained). Boosts the
    GitHub API rate limit from 60/h (anon) to 5000/h (auth) and unlocks
    code search results. Empty / missing → no header.
    """
    if not settings:
        return {}
    tok = settings.get("github_token")
    if not isinstance(tok, str) or not tok.strip():
        return {}
    return {"Authorization": f"Bearer {tok.strip()}"}


async def fetch_github_code_results(
    session: aiohttp.ClientSession,
    query: str,
    timeout: int,
    settings: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """GitHub code search — uses settings.github_token when present."""
    # When a token is configured, prefer the API (returns clean JSON + raw
    # snippets), otherwise fall back to scraping the public search HTML page.
    auth = _github_auth_headers(settings)
    if auth:
        # per_page=100 + 3 pages = up to 300 hits (GitHub code API caps at 1000).
        out: list[dict[str, Any]] = []
        seen_html: set[str] = set()
        for page in range(1, 4):
            api_url = f"https://api.github.com/search/code?q={quote_plus(query)}&per_page=100&page={page}"
            try:
                async with session.get(
                    api_url,
                    headers={**auth, "Accept": "application/vnd.github+json",
                             "User-Agent": "Mozilla/5.0 (compatible; researchbot/1.0)"},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as r:
                    if r.status != 200:
                        break
                    data = await r.json(content_type=None)
            except Exception:
                break
            items = data.get("items", []) or []
            if not items:
                break
            for item in items:
                u = item.get("html_url", "")
                if not u or u in seen_html:
                    continue
                seen_html.add(u)
                repo = (item.get("repository") or {}).get("full_name", "")
                path_ = item.get("path", "")
                out.append({
                    "url": u,
                    "title": clean_text(f"{repo} / {path_}", 180),
                    "snippet": "",
                    "source": "GitHub Code",
                    "repo": repo,
                    "path": path_,
                })
            if len(items) < 100:
                break
        if out:
            # GitHub Code API doesn't return file content — fetch raw blobs in
            # parallel so the key extractor sees actual code, not just URLs.
            fetch_sem = asyncio.Semaphore(20)

            async def fetch_gh_raw(item: dict[str, Any]) -> None:
                async with fetch_sem:
                    raw = await fetch_raw_file(
                        session, item.get("repo", ""), item.get("path", ""),
                        min(timeout, 20),
                    )
                    if raw:
                        item["raw_content"] = raw
                        item["snippet"] = clean_text(raw[:400], 400)

            await asyncio.gather(*[fetch_gh_raw(r) for r in out[:300]])
            return out
        # else: fall through to HTML scrape

    url = f"https://github.com/search?q={quote_plus(query)}&type=code&s=indexed&o=desc"
    status, final_url, body = await fetch_text(session, url, timeout)
    if status != 200 or body.startswith("FETCH_ERROR"):
        return []

    results = []
    soup = BeautifulSoup(body, "html.parser")
    for item in soup.select(".code-list-item, [data-testid='search-result']"):
        link = item.find("a", href=True)
        if not link:
            continue
        href = link["href"]
        if "/blob/" not in href:
            continue
        full_url = f"https://github.com{href}" if href.startswith("/") else href
        title = clean_text(link.get_text(" ", strip=True), 160) or href
        snippet_el = item.find("td", class_="blob-code") or item.find(".search-match")
        snippet = clean_text(snippet_el.get_text(" ", strip=True), 300) if snippet_el else ""
        results.append({
            "url": full_url,
            "title": title,
            "snippet": snippet,
            "source": "GitHub Code",
        })
    return results[:20]


async def fetch_searchcode_results(
    session: aiohttp.ClientSession,
    query: str,
    timeout: int,
) -> list[dict[str, Any]]:
    """searchcode.com JSON API — returns code snippets."""
    results = []
    seen: set[str] = set()

    for page in range(0, 5):
        # per_page=100 (was 20) gives 5x results per page; 5 pages = 500 max.
        api_url = f"https://searchcode.com/api/codesearch_I/?q={quote_plus(query)}&p={page}&per_page=100"
        try:
            async with session.get(
                api_url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"Accept": "application/json"},
            ) as resp:
                if resp.status != 200:
                    break
                data = await resp.json(content_type=None)
        except Exception:
            break

        items = data.get("results", [])
        if not items:
            break

        for item in items:
            url = item.get("url", "")
            if not url or url in seen:
                continue
            seen.add(url)
            lines = item.get("lines", {})
            # lines is a dict like {"10": "code line", ...}
            raw_content = "\n".join(str(v) for v in lines.values()) if isinstance(lines, dict) else ""
            title = f"{item.get('repo', '')} / {item.get('filename', url)}"
            results.append({
                "url": url,
                "title": clean_text(title, 180),
                "snippet": clean_text(raw_content[:300], 400),
                "source": "searchcode.com",
                "raw_content": raw_content,
            })

    return results


async def fetch_gist_results(
    session: aiohttp.ClientSession,
    query: str,
    timeout: int,
) -> list[dict[str, Any]]:
    """GitHub Gists API for finding keys in gists."""
    # Use GitHub gist search via public API
    api_url = f"https://api.github.com/gists/public?per_page=30"
    results = []
    seen: set[str] = set()

    # Search by fetching recent gists and checking content
    html_url = f"https://gist.github.com/search?q={quote_plus(query)}"
    status, _, body = await fetch_text(session, html_url, timeout)
    if status == 200 and not body.startswith("FETCH_ERROR"):
        soup = BeautifulSoup(body, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if re.match(r"^/[^/]+/[a-f0-9]{20,}$", href):
                url = f"https://gist.github.com{href}"
                if url not in seen:
                    seen.add(url)
                    title = clean_text(a.get_text(" ", strip=True), 160) or href
                    results.append({"url": url, "title": title, "source": "GitHub Gists"})

    # Fetch gist raw content
    fetch_sem = asyncio.Semaphore(6)

    async def fetch_gist(item: dict[str, Any]) -> None:
        async with fetch_sem:
            raw_url = item["url"] + "/raw"
            s, _, body = await fetch_text(session, raw_url, min(timeout, 15))
            if s == 200 and not body.startswith("FETCH_ERROR"):
                item["raw_content"] = body[:500_000]

    await asyncio.gather(*[fetch_gist(r) for r in results[:60]])
    return results


async def fetch_publicwww_results(
    session: aiohttp.ClientSession,
    query: str,
    timeout: int,
) -> list[dict[str, Any]]:
    """PublicWWW — searches website source code."""
    url = f"https://publicwww.com/websites/{quote_plus(query)}/"
    status, _, body = await fetch_text(session, url, timeout)
    if status != 200 or body.startswith("FETCH_ERROR"):
        return []

    results = []
    soup = BeautifulSoup(body, "html.parser")
    for item in soup.select(".results-item, .site-url, .urlresult"):
        link = item.find("a", href=True) or item
        if hasattr(link, "get"):
            href = link.get("href", "")
            if href and href.startswith("http"):
                title = clean_text(link.get_text(" ", strip=True), 160)
                snippet = clean_text(item.get_text(" ", strip=True), 300)
                results.append({"url": href, "title": title or href, "snippet": snippet, "source": "PublicWWW"})
    return results[:20]


# ── HTML generic parser ───────────────────────────────────────────────────────

def html_results(source: dict[str, Any], query: str, final_url: str, body: str, limit: int) -> list[SearchResult]:
    if body.startswith("FETCH_ERROR:"):
        return []
    soup = BeautifulSoup(body, "html.parser")
    for bad in soup(["script", "style", "noscript", "svg"]):
        bad.decompose()

    dated_by_url: dict[str, str] = {}
    for time_tag in soup.find_all("time"):
        dt = parse_date(time_tag.get("datetime") or time_tag.get_text(" ", strip=True))
        if not dt:
            continue
        parent = time_tag.find_parent(["article", "li", "div"])
        if parent:
            link = parent.find("a", href=True)
            if link:
                dated_by_url[urljoin(final_url, link["href"])] = dt

    out: list[SearchResult] = []
    seen: set[str] = set()
    query_terms = [t for t in re.split(r"\W+", query.lower()) if len(t) >= 3]

    for a in soup.find_all("a", href=True):
        href = a.get("href", "").strip()
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            continue
        url = urljoin(final_url, href)
        if url in seen:
            continue
        title = clean_text(a.get_text(" ", strip=True), 160)
        if not title or len(title) < 3:
            continue
        haystack = f"{title} {url}".lower()
        if query_terms and not any(term in haystack for term in query_terms):
            parent_text = clean_text(a.find_parent().get_text(" ", strip=True) if a.find_parent() else "", 260).lower()
            if not any(term in parent_text for term in query_terms):
                continue
        parent = a.find_parent(["article", "li", "div", "tr"])
        snippet = clean_text(parent.get_text(" ", strip=True), 260) if parent else title
        pub = dated_by_url.get(url)
        if not pub and parent:
            time_tag = parent.find("time")
            pub = parse_date(time_tag.get("datetime") or time_tag.get_text(" ", strip=True)) if time_tag else None
        result = SearchResult(
            source=source["name"],
            category=source.get("category", "other"),
            query=query,
            title=title,
            url=url,
            snippet=snippet,
            published_at=pub,
            first_seen_at=now_iso(),
        )
        result.build_fingerprint()
        out.append(result)
        seen.add(url)
        if len(out) >= limit:
            break
    return out


def zenodo_results(source: dict[str, Any], query: str, data: dict[str, Any]) -> list[SearchResult]:
    hits = data.get("hits", {}).get("hits", [])
    out = []
    for item in hits:
        md = item.get("metadata", {})
        title = clean_text(md.get("title") or "Zenodo record", 180)
        url = item.get("links", {}).get("html") or str(item.get("id", ""))
        desc = clean_text(BeautifulSoup(md.get("description", ""), "html.parser").get_text(" "), 260)
        pub = parse_date(md.get("publication_date") or item.get("created"))
        r = SearchResult(source["name"], source.get("category", "datasets"), query, title, url, desc, pub, now_iso())
        r.build_fingerprint()
        out.append(r)
    return out


def stackexchange_results(source: dict[str, Any], query: str, data: dict[str, Any]) -> list[SearchResult]:
    out = []
    for item in data.get("items", []):
        title = clean_text(item.get("title") or "Stack Overflow result", 180)
        url = item.get("link") or ""
        pub = parse_date(item.get("creation_date") or item.get("last_activity_date"))
        tags = ", ".join(item.get("tags", [])[:8])
        snippet = f"score={item.get('score', 0)} answers={item.get('answer_count', 0)} tags={tags}"
        r = SearchResult(source["name"], source.get("category", "qa"), query, title, url, snippet, pub, now_iso())
        r.build_fingerprint()
        out.append(r)
    return out


def hn_results(source: dict[str, Any], query: str, data: dict[str, Any]) -> list[SearchResult]:
    out = []
    for item in data.get("hits", []):
        title = clean_text(item.get("title") or item.get("comment_text") or "HN result", 180)
        url = item.get("url") or f"https://news.ycombinator.com/item?id={item.get('objectID')}"
        pub = parse_date(item.get("created_at") or item.get("created_at_i"))
        snippet = clean_text(BeautifulSoup(item.get("comment_text", ""), "html.parser").get_text(" "), 260)
        r = SearchResult(source["name"], source.get("category", "qa"), query, title, url, snippet, pub, now_iso())
        r.build_fingerprint()
        out.append(r)
    return out


# ── Single source search ─────────────────────────────────────────────────────

async def search_one(
    session: aiohttp.ClientSession,
    source: dict[str, Any],
    query: str,
    settings: dict[str, Any],
) -> tuple[str, list[SearchResult], list[dict[str, Any]], str | None]:
    """Returns (name, url_results, key_results, error)"""
    limit = int(settings.get("max_results_per_source", 30))
    timeout_sec = int(settings.get("http_timeout_seconds", 40))
    name = source["name"]
    url_results: list[SearchResult] = []
    key_results: list[dict[str, Any]] = []

    try:
        if name == "grep.app":
            raw = await fetch_grepapp_results(session, query, timeout_sec, pages=5)
            for item in raw:
                fp = make_fingerprint(f"url|{item['url']}")
                sr = SearchResult(name, "code", query, item["title"], item["url"],
                                  item.get("snippet", ""), None, now_iso())
                sr.fingerprint = fp
                url_results.append(sr)
                if item.get("raw_content"):
                    keys = extract_keys_from_text(item["raw_content"], name, query, item["url"], item["title"])
                    key_results.extend(keys)
            return name, url_results, key_results, None

        if name == "Sourcegraph":
            raw = await fetch_sourcegraph_results(session, query, timeout_sec + 30, fetch_files=True)
            for item in raw:
                fp = make_fingerprint(f"url|{item['url']}")
                sr = SearchResult(name, "code", query, item["title"], item["url"],
                                  item.get("snippet", ""), None, now_iso())
                sr.fingerprint = fp
                url_results.append(sr)
                if item.get("raw_content"):
                    keys = extract_keys_from_text(item["raw_content"], name, query, item["url"], item["title"])
                    key_results.extend(keys)
            return name, url_results, key_results, None

        if name == "Kaggle":
            raw = await fetch_kaggle_results(session, query, timeout_sec)
            for item in raw:
                fp = make_fingerprint(f"url|{item['url']}")
                sr = SearchResult(name, "datasets", query, item["title"], item["url"],
                                  item.get("snippet", ""), None, now_iso())
                sr.fingerprint = fp
                url_results.append(sr)
                if item.get("raw_content"):
                    keys = extract_keys_from_text(item["raw_content"], name, query, item["url"], item["title"])
                    key_results.extend(keys)
            return name, url_results, key_results, None

        if name == "GitHub Code Search":
            raw = await fetch_github_code_results(session, query, timeout_sec, settings)
            for item in raw:
                fp = make_fingerprint(f"url|{item['url']}")
                sr = SearchResult(name, "code", query, item["title"], item["url"],
                                  item.get("snippet", ""), None, now_iso())
                sr.fingerprint = fp
                url_results.append(sr)
                # Prefer raw_content (full file fetched via raw.githubusercontent),
                # fall back to snippet for HTML-scrape path.
                text_for_keys = item.get("raw_content") or item.get("snippet") or ""
                if text_for_keys:
                    keys = extract_keys_from_text(text_for_keys, name, query, item["url"], item["title"])
                    key_results.extend(keys)
            return name, url_results, key_results, None

        if name == "searchcode.com":
            raw = await fetch_searchcode_results(session, query, timeout_sec)
            for item in raw:
                fp = make_fingerprint(f"url|{item['url']}")
                sr = SearchResult(name, "code", query, item["title"], item["url"],
                                  item.get("snippet", ""), None, now_iso())
                sr.fingerprint = fp
                url_results.append(sr)
                if item.get("raw_content"):
                    keys = extract_keys_from_text(item["raw_content"], name, query, item["url"], item["title"])
                    key_results.extend(keys)
            return name, url_results, key_results, None

        if name == "GitHub Repositories":
            # Live-tested: per_page=100 + 3 pages = up to 300 repos per query
            # (was 30 single-page). Live API confirmed total_count=341 for AKIA.
            seen_repo_urls: set[str] = set()
            for page in range(1, 4):
                api_url = (
                    f"https://api.github.com/search/repositories?q={quote_plus(query)}"
                    f"&sort=updated&per_page=100&page={page}"
                )
                try:
                    async with session.get(
                        api_url,
                        headers={**_github_auth_headers(settings),
                                 "Accept": "application/vnd.github+json",
                                 "User-Agent": "Mozilla/5.0 (compatible; researchbot/1.0)"},
                        timeout=aiohttp.ClientTimeout(total=timeout_sec),
                    ) as r:
                        if r.status == 429:
                            return name, url_results, key_results, "rate_limited"
                        if r.status >= 400:
                            if page == 1:
                                return name, [], [], f"http_{r.status}"
                            break
                        data = await r.json(content_type=None)
                except Exception as exc:
                    if page == 1:
                        return name, [], [], f"error_{type(exc).__name__}"
                    break
                items = data.get("items", []) or []
                if not items:
                    break
                for item in items:
                    repo_url = item.get("html_url", "")
                    if not repo_url or repo_url in seen_repo_urls:
                        continue
                    seen_repo_urls.add(repo_url)
                    title = item.get("full_name", repo_url)
                    desc = item.get("description") or ""
                    sr = SearchResult(name, "code", query, title, repo_url,
                                      clean_text(desc, 260), parse_date(item.get("updated_at")), now_iso())
                    sr.fingerprint = make_fingerprint(f"url|{repo_url}")
                    url_results.append(sr)
                    keys = extract_keys_from_text(desc, name, query, repo_url, title)
                    key_results.extend(keys)
                if len(items) < 100:
                    break
            return name, url_results, key_results, None

        if name == "GitLab Explore":
            # per_page=100 + 3 pages = up to 300 projects (was 20 single-page).
            seen_proj_urls: set[str] = set()
            for page in range(1, 4):
                api_url = (
                    f"https://gitlab.com/api/v4/projects?search={quote_plus(query)}"
                    f"&order_by=last_activity_at&per_page=100&page={page}"
                )
                try:
                    async with session.get(
                        api_url,
                        headers={"User-Agent": "Mozilla/5.0 (compatible; researchbot/1.0)"},
                        timeout=aiohttp.ClientTimeout(total=timeout_sec),
                    ) as r:
                        if r.status == 429:
                            return name, url_results, key_results, "rate_limited"
                        if r.status >= 400:
                            if page == 1:
                                return name, [], [], f"http_{r.status}"
                            break
                        items = await r.json(content_type=None)
                except Exception as exc:
                    if page == 1:
                        return name, [], [], f"error_{type(exc).__name__}"
                    break
                if not isinstance(items, list) or not items:
                    break
                added = 0
                for item in items:
                    proj_url = item.get("web_url", "")
                    if not proj_url or proj_url in seen_proj_urls:
                        continue
                    seen_proj_urls.add(proj_url)
                    added += 1
                    title = item.get("path_with_namespace", proj_url)
                    desc = item.get("description") or ""
                    sr = SearchResult(name, "code", query, title, proj_url,
                                      clean_text(desc, 260), parse_date(item.get("last_activity_at")), now_iso())
                    sr.fingerprint = make_fingerprint(f"url|{proj_url}")
                    url_results.append(sr)
                    keys = extract_keys_from_text(desc, name, query, proj_url, title)
                    key_results.extend(keys)
                if added == 0 or len(items) < 100:
                    break
            return name, url_results, key_results, None

        if name == "GitHub Gists":
            raw = await fetch_gist_results(session, query, timeout_sec)
            for item in raw:
                fp = make_fingerprint(f"url|{item['url']}")
                sr = SearchResult(name, "snippets", query, item["title"], item["url"],
                                  item.get("snippet", ""), None, now_iso())
                sr.fingerprint = fp
                url_results.append(sr)
                if item.get("raw_content"):
                    keys = extract_keys_from_text(item["raw_content"], name, query, item["url"], item["title"])
                    key_results.extend(keys)
            return name, url_results, key_results, None

        if name == "PublicWWW":
            raw = await fetch_publicwww_results(session, query, timeout_sec)
            for item in raw:
                fp = make_fingerprint(f"url|{item['url']}")
                sr = SearchResult(name, "web", query, item["title"], item["url"],
                                  item.get("snippet", ""), None, now_iso())
                sr.fingerprint = fp
                url_results.append(sr)
            return name, url_results, key_results, None

        # ── Paginated JSON API sources ─────────────────────────────────────
        # Live-tested: each of these has a clear page parameter and returns
        # different items per page. Burning ~3-10 pages per query gets us
        # 10-50x more results for one extra HTTP RTT.
        stype_paginated = source.get("type", "html")
        if stype_paginated == "hn_algolia_api":
            # Live: 50 pages × 50/page = 2500 hits. Fetch first 5 pages = 250.
            seen_urls: set[str] = set()
            for page in range(0, 5):
                api_url = (
                    f"https://hn.algolia.com/api/v1/search_by_date?query={quote_plus(query)}"
                    f"&tags=story,comment&hitsPerPage=50&page={page}"
                )
                status, _, body = await fetch_text(session, api_url, timeout_sec)
                if status == 429:
                    return name, url_results, key_results, "rate_limited"
                if status >= 400 or status == 0:
                    if page == 0:
                        return name, [], [], f"http_{status}"
                    break
                try:
                    data = json.loads(body)
                except Exception:
                    break
                page_results = hn_results(source, query, data)
                if not page_results:
                    break
                added = 0
                for r in page_results:
                    if r.url and r.url not in seen_urls:
                        seen_urls.add(r.url)
                        url_results.append(r)
                        added += 1
                        keys = extract_keys_from_text(
                            r.snippet or "", name, query, r.url, r.title
                        )
                        key_results.extend(keys)
                if added == 0:
                    break
            return name, url_results, key_results, None

        if stype_paginated == "zenodo_api":
            # Live-tested 2026-05: Zenodo caps anonymous size at 25; size>=50
            # returns "A validation error occurred." So fetch 5 pages × 25 = 125.
            seen_urls = set()
            for page in range(1, 6):
                api_url = (
                    f"https://zenodo.org/api/records?q={quote_plus(query)}"
                    f"&sort=mostrecent&page={page}&size=25"
                )
                status, _, body = await fetch_text(session, api_url, timeout_sec)
                if status == 429:
                    return name, url_results, key_results, "rate_limited"
                if status >= 400 or status == 0:
                    if page == 1:
                        return name, [], [], f"http_{status}"
                    break
                try:
                    data = json.loads(body)
                except Exception:
                    break
                page_results = zenodo_results(source, query, data)
                if not page_results:
                    break
                added = 0
                for r in page_results:
                    if r.url and r.url not in seen_urls:
                        seen_urls.add(r.url)
                        url_results.append(r)
                        added += 1
                        keys = extract_keys_from_text(
                            r.snippet or "", name, query, r.url, r.title
                        )
                        key_results.extend(keys)
                if added == 0:
                    break
            return name, url_results, key_results, None

        # Generic HTML / API sources (single fetch)
        url = build_url(source["url_template"], query, limit)
        status, final_url, body = await fetch_text(session, url, timeout_sec)

        if status == 429:
            return name, [], [], "rate_limited"
        if status >= 400 or status == 0:
            return name, [], [], f"http_{status}"

        stype = source.get("type", "html")
        if stype == "html":
            url_results = html_results(source, query, final_url, body, limit)
            if not body.startswith("FETCH_ERROR"):
                soup = BeautifulSoup(body, "html.parser")
                raw_text = soup.get_text(" ")
                inline_keys = extract_keys_from_text(raw_text, name, query, final_url, f"Inline in {name}")
                key_results.extend(inline_keys)
        else:
            try:
                data = json.loads(body)
                if stype == "stackexchange_api":
                    url_results = stackexchange_results(source, query, data)
            except Exception as exc:
                return name, [], [], f"parse_{type(exc).__name__}"

        return name, url_results, key_results, None

    except Exception as exc:
        return name, [], [], f"error_{type(exc).__name__}"


# ── Monitor ──────────────────────────────────────────────────────────────────

class Monitor:
    def __init__(self) -> None:
        self.settings: dict[str, Any] = {}
        self.sources: list[dict[str, Any]] = []
        self.state: dict[str, Any] = {"seen": {}, "seen_keys": {}, "last_cycle_at": None}
        self.status: dict[str, str] = {}
        self.stats = {
            "cycles": 0, "new": 0, "seen_total": 0, "errors": 0,
            "keys_found": 0, "keys_valid": 0, "keys_invalid": 0, "keys_unchecked": 0,
            "service_breakdown": {},
        }
        self.current_action = "initializing"
        self.next_run_at = time.time()
        self.cycle_in_progress = False
        self.reload_config()

    def reload_config(self) -> None:
        new_settings = load_json(CONFIG_DIR / "settings.json", {})
        if new_settings:
            self.settings = new_settings
        new_sources = load_json(CONFIG_DIR / "sources.json", [])
        if new_sources:
            enabled = set(self.settings.get("enabled_sources", []))
            if enabled:
                self.sources = [s for s in new_sources if s.get("name") in enabled]
            else:
                self.sources = [s for s in new_sources if s.get("enabled", True)]
        state = load_json(STATE_FILE, None)
        if state:
            self.state = state
            self.stats["seen_total"] = len(state.get("seen", {}))
            self.stats["keys_found"] = len(state.get("seen_keys", {}))

    def write_status(self) -> None:
        remaining = max(0, int(self.next_run_at - time.time()))
        # Sliding-window rate: keep (ts, done) samples for the last 60s and
        # report (delta_done / delta_t) over that window. Cumulative rate
        # lies hard once parallelism becomes uneven (fast sources finish
        # early, slow tail at max_parallel=1 trickles): cumulative says
        # "16 tasks/s" while reality is "2 tasks/s" — so ETA crashes to
        # near-zero with 5+ minutes still to go.
        now_ts = time.time()
        done_now = getattr(self, "tasks_done", 0)
        if not hasattr(self, "_progress_samples"):
            self._progress_samples = []  # type: ignore[attr-defined]
        samples: list[tuple[float, int]] = self._progress_samples  # type: ignore[attr-defined]
        samples.append((now_ts, done_now))
        # Prune anything older than 60s; keep at least the oldest sample
        # so we have a baseline even on a fresh cycle.
        cutoff = now_ts - 60
        while len(samples) > 2 and samples[0][0] < cutoff:
            samples.pop(0)
        rate_recent: float | None = None
        if len(samples) >= 2:
            t0, d0 = samples[0]
            dt = now_ts - t0
            if dt > 0.5:
                rate_recent = max(0.0, (done_now - d0) / dt)
        save_json(STATUS_FILE, {
            "running": True,
            "current_action": self.current_action,
            "last_cycle_at": self.state.get("last_cycle_at"),
            "next_run_at": datetime.fromtimestamp(self.next_run_at, timezone.utc).isoformat(),
            "seconds_until_next": remaining,
            "cycle_in_progress": self.cycle_in_progress,
            "cycle_progress": {
                "done": done_now,
                "total": getattr(self, "tasks_total", 0),
                "started_at": getattr(self, "cycle_started_at", None),
                "rate_recent_per_sec": rate_recent,
                "current_category": getattr(self, "current_category", None),
            },
            "stats": self.stats,
            "source_statuses": [
                {
                    "name": src["name"],
                    "category": src.get("category", "other"),
                    "status": self.status.get(src["name"], "pending"),
                    "enabled": True,
                }
                for src in self.sources
            ],
        })

    async def run_cycle(self) -> None:
        self.reload_config()
        # Re-read proxy toggle so user UI changes take effect on the next
        # cycle without needing a process restart.
        global ENABLE_PROXY_RETRY
        new_flag = is_proxy_retry_enabled()
        if new_flag != ENABLE_PROXY_RETRY:
            ENABLE_PROXY_RETRY = new_flag
            if new_flag:
                # User just turned proxies ON — kick off the refresh task.
                asyncio.create_task(proxy_refresh_loop())
        self.cycle_in_progress = True
        self.cycle_started_at = now_iso()
        all_queries = [q.strip() for q in self.settings.get("queries", []) if q.strip()]
        if not all_queries:
            self.current_action = "no queries configured"
            self.cycle_in_progress = False
            return

        # ── Category rotation ────────────────────────────────────────────────
        # Instead of scanning ALL 100+ key prefixes every cycle (8888 tasks,
        # ~8 min), classify queries by service category and rotate one
        # category per cycle. Default ON. Each cycle scans ~1/10 of the
        # query list → ~50s cycles. A full sweep across all categories
        # completes in ~10-15 cycles (under an hour at default interval),
        # while leaving CPU/network headroom for ENV scanner + auto-chain.
        rotation_enabled = bool(self.settings.get("category_rotation", True))
        self.current_category = None
        if rotation_enabled:
            grouped = _group_queries_by_category(all_queries)
            # Stable order: alphabetic by category name. "other" rotates too.
            cat_names = sorted(grouped.keys())
            if cat_names:
                idx = int(self.state.get("category_index", 0)) % len(cat_names)
                category = cat_names[idx]
                queries = grouped[category]
                self.current_category = category
                # Advance the rotation pointer for the NEXT cycle. Persist
                # immediately so a crash mid-cycle doesn't repeat the same
                # category forever.
                self.state["category_index"] = (idx + 1) % len(cat_names)
                save_json(STATE_FILE, self.state)
            else:
                queries = all_queries
        else:
            queries = all_queries

        auto_validate = self.settings.get("auto_validate", True)
        # Global cap on in-flight search requests across all sources.
        # Default raised from 4→25: with per-source semaphores below, no single
        # search engine ever sees more than its `max_parallel` slots, so the
        # global cap is just a CPU/FD ceiling. ~25 keeps us under 1000 FDs.
        concurrency = int(self.settings.get("concurrency", 25))
        sem = asyncio.Semaphore(concurrency)
        timeout_val = aiohttp.ClientTimeout(total=int(self.settings.get("http_timeout_seconds", 40)) + 30)

        # Per-source semaphores, sized from sources.json `max_parallel`
        # (default 2). This is the real ban-prevention layer: search engines
        # rate-limit per source, not globally. With this in place we can run
        # global concurrency=25 instead of 4 without triggering CAPTCHAs.
        per_source_sems: dict[str, asyncio.Semaphore] = {}
        for src in self.sources:
            mp = int(src.get("max_parallel", 2)) if isinstance(src.get("max_parallel", 2), (int, float, str)) else 2
            mp = max(1, min(10, mp))
            per_source_sems[src["name"]] = asyncio.Semaphore(mp)

        all_url_results: list[SearchResult] = []
        all_key_results: list[dict[str, Any]] = []
        errors = 0
        self.tasks_total = len(queries) * len(self.sources)
        self.tasks_done = 0

        connector = aiohttp.TCPConnector(ssl=False, limit=concurrency * 5)
        async with aiohttp.ClientSession(timeout=timeout_val, connector=connector) as session:
            async def guarded(source: dict[str, Any], query: str):
                nonlocal errors
                src_sem = per_source_sems.get(source["name"])
                # Take per-source slot first, then a global slot. This way the
                # global cap throttles total CPU/FD load while per-source
                # caps prevent any single engine from being hammered.
                async with (src_sem if src_sem is not None else sem):
                    async with sem:
                        self.current_action = f"searching: {source['name']} / {query}"
                        self.write_status()
                        sname, urls, keys, error = await search_one(session, source, query, self.settings)
                        self.status[sname] = error or f"ok:{len(urls)}+{len(keys)}keys"
                        if error:
                            errors += 1
                        return urls, keys

            # Per-task hard ceiling. Without this, a single stuck task (e.g. a
            # github code-search that chains many raw-file fetches, or a search
            # engine that hangs the response mid-stream) will park the cycle
            # forever — manifests as "stuck at 99%" with the last few tasks
            # never completing. The session-level ClientTimeout doesn't save
            # us because each sub-request resets its own timer. So we wrap
            # every guarded() call in a wait_for at 2× the http timeout.
            per_task_ceiling = int(self.settings.get("http_timeout_seconds", 40)) * 2 + 30

            async def with_ceiling(coro):
                try:
                    return await asyncio.wait_for(coro, timeout=per_task_ceiling)
                except asyncio.TimeoutError:
                    raise  # propagate so the as_completed loop counts as error

            tasks = [with_ceiling(guarded(src, q)) for q in queries for src in self.sources]
            for fut in asyncio.as_completed(tasks):
                if stop_event.is_set():
                    break
                try:
                    urls, keys = await fut
                    all_url_results.extend(urls)
                    all_key_results.extend(keys)
                except asyncio.TimeoutError:
                    errors += 1
                except Exception:
                    errors += 1
                self.tasks_done += 1

            # Deduplicate and filter new URL results
            seen: dict[str, Any] = self.state.setdefault("seen", {})
            new_url_results: list[SearchResult] = []
            for r in all_url_results:
                r.build_fingerprint()
                if r.fingerprint not in seen:
                    seen[r.fingerprint] = {"first_seen_at": r.first_seen_at, "source": r.source, "url": r.url}
                    new_url_results.append(r)

            # Deduplicate key results
            seen_keys: dict[str, Any] = self.state.setdefault("seen_keys", {})
            new_key_results: list[dict[str, Any]] = []
            for k in all_key_results:
                fp = k.get("fingerprint", make_fingerprint(k.get("key", "")))
                if fp not in seen_keys:
                    seen_keys[fp] = True
                    new_key_results.append(k)

            # Auto-validate new keys
            if auto_validate and new_key_results:
                self.current_action = f"validating {len(new_key_results)} new keys..."
                self.write_status()
                val_sem = asyncio.Semaphore(5)
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as val_session:
                    async def validate_one(k: dict[str, Any]):
                        async with val_sem:
                            service = k.get("service", "")
                            if not service or service not in VALIDATION_ENDPOINTS:
                                return
                            status_val, msg = await validate_key(val_session, k["key"], service)
                            k["status"] = status_val
                            k["validated_at"] = now_iso()
                            k["validation_message"] = msg
                            if status_val == "valid":
                                self.stats["keys_valid"] += 1
                            elif status_val == "invalid":
                                self.stats["keys_invalid"] += 1

                    await asyncio.gather(*[validate_one(k) for k in new_key_results])

        # Update stats
        self.stats["cycles"] += 1
        self.stats["new"] += len(new_url_results)
        self.stats["seen_total"] = len(seen)
        self.stats["errors"] += errors
        self.stats["keys_found"] += len(new_key_results)
        self.stats["keys_unchecked"] = sum(1 for k in new_key_results if k.get("status") == "unchecked")

        for k in new_key_results:
            svc = k.get("service", "unknown")
            self.stats["service_breakdown"][svc] = self.stats["service_breakdown"].get(svc, 0) + 1

        self.state["last_cycle_at"] = now_iso()
        # ── LRU eviction for `seen` ───────────────────────────────────────
        # `seen` is a per-fingerprint dict that grows ~unboundedly across
        # cycles (one entry per unique URL ever seen). At 25 MB / 100k+
        # entries the file load on each restart starts costing real RAM
        # and IO. Cap to SEEN_MAX entries, evicting the oldest by
        # `first_seen_at`. We keep the rest because dedup wants O(1)
        # lookup; an LRU by access time would be more correct but
        # `first_seen_at` is good enough — old fingerprints rarely come
        # back from new sources.
        SEEN_MAX = 50_000
        seen = self.state.get("seen", {})
        if len(seen) > SEEN_MAX:
            # Sort fingerprints by first_seen_at ascending, drop the
            # oldest until we're at SEEN_MAX. Missing/None timestamps
            # sort first, so they get evicted first too.
            ordered = sorted(
                seen.items(),
                key=lambda kv: (kv[1] or {}).get("first_seen_at") or "",
            )
            evict = len(seen) - SEEN_MAX
            for fp, _ in ordered[:evict]:
                seen.pop(fp, None)
            print(f"[state] evicted {evict} oldest seen entries (kept {SEEN_MAX})", flush=True)
            self.stats["seen_total"] = len(seen)
        save_json(STATE_FILE, self.state)

        new_url_results.sort(key=lambda r: date_sort_key(asdict(r)), reverse=True)
        if new_url_results:
            append_jsonl(RESULTS_FILE, [asdict(r) for r in new_url_results])
            append_jsonl(NEW_RESULTS_FILE, [asdict(r) for r in new_url_results])
        if new_key_results:
            append_jsonl(KEYS_FILE, new_key_results)

        self.current_action = (
            f"cycle done: {len(new_url_results)} new urls, "
            f"{len(new_key_results)} keys ({self.stats['keys_valid']} valid), "
            f"{errors} errors"
        )
        self.cycle_in_progress = False
        self.write_status()

    async def loop(self) -> None:
        interval = int(self.settings.get("interval_seconds", 3600))
        self.next_run_at = time.time()
        try:
            (DATA_DIR / "pid").write_text(str(os.getpid()))
        except Exception:
            pass
        # Always bootstrap a cycle on process start regardless of disk state:
        # if auto-chain is enabled it would otherwise sit waiting for a
        # trigger_cycle file that auto-chain might not write for many minutes
        # (auto_chain_interval throttle). One free bootstrap cycle is the
        # cheapest way to make the dashboard come alive immediately.
        first_cycle_done = False
        while not stop_event.is_set():
            now = time.time()
            triggered = TRIGGER_FILE.exists()
            if triggered:
                try:
                    TRIGGER_FILE.unlink(missing_ok=True)
                except Exception:
                    pass

            # Re-read settings each tick so the user can flip auto-chain
            # on/off without restarting. When auto-chain is enabled the
            # public scanner stops running on its own interval timer —
            # auto-chain becomes the sole orchestrator (it triggers a new
            # public cycle via trigger_cycle file after each Discovery×N +
            # Env×N round). The very first cycle still runs on schedule
            # to bootstrap the chain, otherwise auto-chain would wait
            # forever for a public-cycle edge that never comes.
            try:
                self.settings = load_json(SETTINGS_FILE, self.settings)
            except Exception:
                pass
            auto_chain_on = bool(self.settings.get("auto_chain_enabled", False))
            # Manual mode: operator pressed the "stop / manual" button. Pause
            # the public scanner entirely (no bootstrap, no interval cycles,
            # no trigger reactions) until the button is pressed again.
            manual_mode_on = bool(self.settings.get("manual_mode", False))

            should_run = False
            if manual_mode_on:
                should_run = False  # paused by operator (manual mode)
            elif triggered:
                should_run = True
            elif not first_cycle_done:
                should_run = True  # bootstrap
            elif auto_chain_on:
                should_run = False  # wait for trigger_cycle from auto-chain
            elif now >= self.next_run_at:
                should_run = True

            if should_run:
                await self.run_cycle()
                first_cycle_done = True
                interval = int(self.settings.get("interval_seconds", 3600))
                self.next_run_at = time.time() + interval
            self.write_status()
            await asyncio.sleep(1)


def handle_stop(*_: Any) -> None:
    stop_event.set()


async def main() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    LOG_DIR.mkdir(exist_ok=True, parents=True)
    try:
        signal.signal(signal.SIGINT, handle_stop)
        signal.signal(signal.SIGTERM, handle_stop)
    except Exception:
        pass
    # Background task: rotating free-proxy pool. Only started when the user
    # has enabled it via the UI (proxy_config.json). Free proxies are
    # unreliable and validation has measurable cost, so default is OFF.
    global ENABLE_PROXY_RETRY
    ENABLE_PROXY_RETRY = is_proxy_retry_enabled()
    if ENABLE_PROXY_RETRY:
        asyncio.create_task(proxy_refresh_loop())
    monitor = Monitor()
    await monitor.loop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
