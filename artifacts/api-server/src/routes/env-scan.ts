import { Router } from "express";
import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { execSync } from "child_process";
import { getWatchdogStatus } from "../scan-watchdog";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MONITOR_DIR = path.resolve(__dirname, "../../../monitor");
const DATA_DIR    = path.join(MONITOR_DIR, "data");

const INPUT_FILE   = path.join(DATA_DIR, "env_scan_input.txt");
const STATUS_FILE  = path.join(DATA_DIR, "env_scan_status.json");
const FOUND_FILE   = path.join(DATA_DIR, "env_found.jsonl");
const STOP_FILE    = path.join(DATA_DIR, "env_scan_stop");
const OFFSET_FILE  = path.join(DATA_DIR, "env_scan_input.txt.offset");
const PID_FILE     = path.join(DATA_DIR, "env_scan.pid");
const HISTORY_FILE = path.join(DATA_DIR, "env_scan_history.jsonl");
const DEEP_FOUND_FILE  = path.join(DATA_DIR, "env_found_deep.jsonl");
const DEEP_STATUS_FILE = path.join(DATA_DIR, "deep_scan_status.json");

interface DeepKey {
  service?: string; category?: string; key?: string;
  fingerprint?: string; masked?: string;
}
interface DeepRow {
  url?: string; deep_keys?: DeepKey[];
}

/** Build a Map<url, deepKeys[]> by reading env_found_deep.jsonl. */
function loadDeepIndex(): Map<string, DeepKey[]> {
  const idx = new Map<string, DeepKey[]>();
  if (!fs.existsSync(DEEP_FOUND_FILE)) return idx;
  try {
    const raw = fs.readFileSync(DEEP_FOUND_FILE, "utf-8");
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      let row: DeepRow;
      try { row = JSON.parse(line) as DeepRow; } catch { continue; }
      if (!row.url || !Array.isArray(row.deep_keys)) continue;
      const list = idx.get(row.url) ?? [];
      // dedupe by fingerprint within URL (deep_scan re-runs may append same key)
      const seen = new Set(list.map(k => k.fingerprint).filter(Boolean));
      for (const k of row.deep_keys) {
        if (k.fingerprint && seen.has(k.fingerprint)) continue;
        list.push(k);
        if (k.fingerprint) seen.add(k.fingerprint);
      }
      idx.set(row.url, list);
    }
  } catch { /* ignore */ }
  return idx;
}

// ── Engine selection (Python ⟷ Go) ──────────────────────────────────────────
const ENGINE_CONFIG_FILE = path.join(DATA_DIR, "engine_config.json");
const GO_BINARY          = path.join(MONITOR_DIR, "go-scanner", "bin", "env-scanner");
const PATHS_FULL_JSON    = path.join(DATA_DIR, "env_paths_full.json");
const PATHS_FAST_JSON    = path.join(DATA_DIR, "env_paths_fast.json");

// ── Go scanner tuning (per-host-class performance knobs) ────────────────────
// Mirrors monitor/go-scanner/main.go: defaultTuning() and Tuning struct.
// Resolution order (Go side): per-run env var > this file > defaultTuning().
const TUNING_FILE = path.join(DATA_DIR, "scanner_tuning.json");
const TUNING_DEFAULTS = {
  host_concurrency_cap_deep: 100,
  path_sem_cap: 4000,
  path_sem_per_host: 60,
  tcp_precheck_max_ms: 1000,
  tcp_precheck_min_ms: 100,
  host_overall_timeout_sec: 120,
} as const;
type TuningKey = keyof typeof TUNING_DEFAULTS;
type Tuning = Record<TuningKey, number>;
const TUNING_KEYS = Object.keys(TUNING_DEFAULTS) as TuningKey[];

function readTuning(): { tuning: Tuning; source: "defaults" | "file" | "invalid" } {
  if (!fs.existsSync(TUNING_FILE)) {
    return { tuning: { ...TUNING_DEFAULTS }, source: "defaults" };
  }
  try {
    const raw = JSON.parse(fs.readFileSync(TUNING_FILE, "utf-8")) as Record<string, unknown>;
    const merged: Tuning = { ...TUNING_DEFAULTS };
    for (const k of TUNING_KEYS) {
      const v = raw[k];
      if (typeof v === "number" && Number.isFinite(v) && v > 0) merged[k] = Math.floor(v);
    }
    return { tuning: merged, source: "file" };
  } catch {
    return { tuning: { ...TUNING_DEFAULTS }, source: "invalid" };
  }
}

export type Engine = "py" | "go";

function normalizeEngine(v: unknown): Engine {
  return v === "go" ? "go" : "py";
}

export function readEngineConfig(): Engine {
  try {
    const j = JSON.parse(fs.readFileSync(ENGINE_CONFIG_FILE, "utf-8")) as { engine?: unknown };
    return normalizeEngine(j.engine);
  } catch { return "py"; }
}

export function writeEngineConfig(engine: Engine): void {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(ENGINE_CONFIG_FILE, JSON.stringify({ engine }));
}

/**
 * The Go scanner reads its path lists from `data/env_paths_*.json`. These
 * are produced by `monitor/dump_paths.py` from the canonical Python lists
 * in `env_paths.py`. We materialize them on demand so the Go engine works
 * out of the box on a fresh checkout.
 */
function ensurePathsExported(): void {
  if (fs.existsSync(PATHS_FULL_JSON) && fs.existsSync(PATHS_FAST_JSON)) return;
  try {
    const py = getPythonBin();
    execSync(`${py} dump_paths.py`, { cwd: MONITOR_DIR, stdio: "inherit", timeout: 15000 });
  } catch (err) {
    console.error("[env-scan] failed to export path JSON for Go engine:", err);
  }
}

/**
 * Wipe the status file so the UI doesn't show stale progress from the
 * previous run while the new Python process is still booting (DNS init can
 * take a long time). The Python scanner writes a fresh status with run_id
 * almost immediately on startup, so this is just for the in-between window.
 */
function writePendingStatus(): void {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(STATUS_FILE, JSON.stringify({
      running: true,
      scanner: "env",
      current_action: "spawning scanner…",
      processed: 0,
      total: 0,
      found: 0,
      keys: 0,
      elapsed_seconds: 0,
      rate_per_sec: 0,
      eta_seconds: 0,
      updated_at: new Date().toISOString(),
      dns: {},
    }));
  } catch {}
}

function readJson(filePath: string, fallback: unknown): unknown {
  try { return JSON.parse(fs.readFileSync(filePath, "utf-8")); }
  catch { return fallback; }
}

function readJsonl(filePath: string): Record<string, unknown>[] {
  try {
    return fs.readFileSync(filePath, "utf-8").trim().split("\n")
      .filter(Boolean)
      .map(l => { try { return JSON.parse(l) as Record<string, unknown>; } catch { return null; } })
      .filter(Boolean) as Record<string, unknown>[];
  } catch { return []; }
}

// ── Results cache ────────────────────────────────────────────────────────────
// With up to 200k lines in env_found.jsonl (~170 MB), reading + parsing +
// deduplicating the file on every page request would be noticeably slow.
// We cache the full processed result for 30 s, keyed on file mtime so any
// new finding immediately invalidates the cache on the next request.
type RawFindingRow = Record<string, unknown>;
type OrderedRow = RawFindingRow & { aliases: string[]; aliasCount: number; runIds: string[] };

interface ResultsCache {
  mtimeMs:  number;
  raw:      RawFindingRow[];
  ordered:  OrderedRow[];
  honeypot: Set<string>;
}
let _resultsCache: ResultsCache | null = null;
const RESULTS_CACHE_TTL_MS = 30_000;
let _cacheExpiresAt = 0;

function getResultsCache(dedupe: boolean): {
  raw: RawFindingRow[];
  ordered: OrderedRow[];
  honeypot: Set<string>;
} {
  const now = Date.now();
  let mtime = 0;
  try { mtime = fs.statSync(FOUND_FILE).mtimeMs; } catch { /* file missing */ }

  if (_resultsCache && now < _cacheExpiresAt && _resultsCache.mtimeMs === mtime) {
    return { raw: _resultsCache.raw, ordered: _resultsCache.ordered, honeypot: _resultsCache.honeypot };
  }

  const deepIdx = loadDeepIndex();
  const raw = readJsonl(FOUND_FILE).map(r => {
    const url = r.url as string;
    const deepKeys = deepIdx.get(url) ?? [];
    const baseSvcs = (r.key_services as string[]) ?? [];
    const baseCats = (r.key_categories as string[]) ?? [];
    const deepSvcs = deepKeys.map(k => k.service ?? "").filter(Boolean);
    const deepCats = deepKeys.map(k => k.category ?? "").filter(Boolean);
    return {
      host:           r.host,
      mode:           r.mode,
      path:           r.path,
      url,
      status:         r.status,
      keys_found:     ((r.keys_found as number) ?? 0) + deepKeys.length,
      key_categories: Array.from(new Set([...baseCats, ...deepCats])),
      key_services:   Array.from(new Set([...baseSvcs, ...deepSvcs])),
      deep_keys_count: deepKeys.length,
      content_preview:(r.content_preview as string)?.slice(0, 500) ?? "",
      content_length: r.content_length ?? 0,
      keys_preview:   [
        ...(Array.isArray(r.keys_preview) ? r.keys_preview as Array<Record<string, unknown>> : []),
        ...deepKeys.map(k => ({
          service:  k.service ?? null,
          category: k.category ?? null,
          masked:   (k as Record<string, unknown>).key_masked ?? k.masked ?? null,
          snippet:  (k as Record<string, unknown>).snippet     ?? null,
          source:   "deep",
        })),
      ].slice(0, 20),
      found_at:       r.found_at ?? "",
      run_id:         r.run_id ?? null,
      trigger:        r.trigger ?? null,
    };
  });

  const ordered: OrderedRow[] = dedupe
    ? (dedupeFindings(raw) as unknown as OrderedRow[])
    : raw.slice().reverse().map(r => ({
        ...r,
        aliases: [] as string[],
        aliasCount: 0,
        runIds: r.run_id ? [String(r.run_id)] : [],
      }));

  const honeypot = detectHoneypotHosts(ordered);

  _resultsCache = { mtimeMs: mtime, raw, ordered, honeypot };
  _cacheExpiresAt = now + RESULTS_CACHE_TTL_MS;
  return { raw, ordered, honeypot };
}

function getPythonBin(): string {
  const workspace = path.resolve(__dirname, "../../../");
  const candidates = [
    path.join(workspace, ".pythonlibs", "bin", "python3"),
    path.join(MONITOR_DIR, ".venv", "bin", "python"),
    "python3",
  ];
  return candidates.find(p => { try { return fs.existsSync(p); } catch { return false; } }) ?? "python3";
}

/**
 * Verify a PID belongs to one of the scanner engines. Linux only — reads
 * /proc/<pid>/cmdline (NUL-separated argv). On non-Linux platforms or any
 * read failure we conservatively return true so we don't break the running
 * environment, but on Linux this guards against pid-recycle false positives
 * where another process happens to inherit our stale PID and would otherwise
 * make `/start` refuse to launch.
 */
function pidLooksLikeScanner(pid: number): boolean {
  try {
    const cmd = fs.readFileSync(`/proc/${pid}/cmdline`, "utf-8");
    if (!cmd) return true; // empty cmdline is exotic — don't false-block.
    return cmd.includes("env_scanner.py") || cmd.includes("env-scanner");
  } catch {
    // /proc/<pid>/cmdline missing → process is gone (handled by signal-0
    // check) or not Linux. Either way, fall back to permissive.
    return true;
  }
}

/** Read saved PID and check if the process is still alive AND ours. */
function getScannerPid(): number | null {
  try {
    const pid = parseInt(fs.readFileSync(PID_FILE, "utf-8").trim(), 10);
    if (isNaN(pid)) return null;
    // Send signal 0 to check if process exists
    process.kill(pid, 0);
    if (!pidLooksLikeScanner(pid)) {
      // PID was recycled by an unrelated process. Drop the stale file so
      // the next /start isn't blocked on a phantom "already running".
      try { fs.unlinkSync(PID_FILE); } catch {}
      return null;
    }
    return pid;
  } catch {
    return null;
  }
}

function isProcessRunning(): boolean {
  return getScannerPid() !== null;
}

function killScanner(): void {
  // 1. Write stop file so the scanner exits gracefully (both engines watch it).
  try { fs.writeFileSync(STOP_FILE, "1"); } catch {}
  // 2. Kill by PID if available
  const pid = getScannerPid();
  if (pid) {
    try { process.kill(pid, "SIGTERM"); } catch {}
    // Give it 2s then SIGKILL
    setTimeout(() => {
      try { process.kill(pid, "SIGKILL"); } catch {}
    }, 2000);
  }
  // 3. Also try pkill as fallback for both Python and Go engines.
  try { execSync("pkill -f env_scanner.py", { stdio: "ignore" }); } catch {}
  try { execSync("pkill -f go-scanner/bin/env-scanner", { stdio: "ignore" }); } catch {}
  // 4. Clean pid file
  try { fs.unlinkSync(PID_FILE); } catch {}
}

/**
 * Spawn the selected scanner engine. Both engines accept the same env-var
 * configuration and write to the same files; the only difference is the
 * binary that's executed. Returns the spawned child process.
 */
function spawnScanner(opts: {
  engine:           Engine;
  trigger:          string;
  timeout:          number;
  concurrency:      number;
  maxFail:          number;
  deepScan:         boolean;
  hostConcurrency?: number;
}): { proc: ReturnType<typeof spawn>; engineUsed: Engine } {
  // High-throughput defaults: in fast mode (34 paths) we measured 600-750 h/s
  // In deep mode (1700+ paths) the path-fanout dominates, so we keep host
  // workers lower to avoid saturating PathSemCap (8000 in scanner_tuning.json).
  const hostConc = opts.hostConcurrency ?? (opts.deepScan ? 250 : 1500);
  const baseEnv = {
    ...process.env,
    PYTHONUNBUFFERED:          "1",
    ENV_SCAN_TRIGGER:          opts.trigger,
    ENV_SCAN_TIMEOUT:          String(opts.timeout),
    ENV_SCAN_CONCURRENCY:      String(opts.concurrency),
    ENV_SCAN_HOST_CONCURRENCY: String(hostConc),
    ENV_SCAN_MAX_FAIL:         String(opts.maxFail),
    ENV_SCAN_FULL:             opts.deepScan ? "1" : "0",
    // Pure-Go DNS resolver — avoids cgo getaddrinfo serialization that
    // becomes a hard bottleneck above ~200 inflight DNS lookups.
    GODEBUG:                   process.env.GODEBUG && process.env.GODEBUG.includes("netdns=")
      ? process.env.GODEBUG
      : (process.env.GODEBUG ? `${process.env.GODEBUG},netdns=go+1` : "netdns=go+1"),
  };

  // Best-effort sysctl bumps for high-fanout scans. Skipped silently when
  // so the user knows performance may be capped by net.* defaults.
  try {
    const probe = execSync("sysctl -n net.ipv4.ip_local_port_range 2>/dev/null", { encoding: "utf-8" }).trim();
    if (probe) {
      const tries = [
        "net.ipv4.ip_local_port_range=1024 65535",
        "net.ipv4.tcp_tw_reuse=1",
        "net.core.somaxconn=65535",
      ];
      for (const kv of tries) {
        try { execSync(`sysctl -w ${kv} 2>/dev/null`, { stdio: "ignore" }); } catch {}
      }
    }
  } catch {
    console.warn("[env-scan] sysctl not available (no root) — skipping kernel tuning");
  }

  // Graceful fallback: if the user picked Go but the binary isn't built (e.g.
  // fresh checkout, ran `git clean`, build script not run), don't 500 — drop
  // back to Python and let the caller surface a warning. This mirrors what
  // auto-chain already does for the same edge case.
  let engineUsed: Engine = opts.engine;
  if (engineUsed === "go" && !fs.existsSync(GO_BINARY)) {
    console.warn(`[env-scan] Go binary missing at ${GO_BINARY}, falling back to Python`);
    engineUsed = "py";
    // Persist the corrected choice so /engine GET, the UI, and auto-chain
    // all converge on a single source of truth.
    try { writeEngineConfig("py"); } catch {}
  }

  if (engineUsed === "go") {
    ensurePathsExported();
    // Wrap in bash so we can `ulimit -n 1048576` per process before exec.
    // `2>/dev/null || true` keeps us alive on hosts where the requested
    // limit exceeds the hard cap; bash will silently keep the inherited
    // soft limit instead of failing the spawn.
    return {
      proc: spawn("bash", ["-c", `ulimit -n 1048576 2>/dev/null || true; exec "$0" "$@"`, GO_BINARY], {
        cwd: MONITOR_DIR,
        detached: true,
        stdio: ["ignore", "pipe", "pipe"],
        env: baseEnv,
      }),
      engineUsed,
    };
  }

  // Default: Python engine (unchanged behavior).
  return {
    proc: spawn(getPythonBin(), ["env_scanner.py"], {
      cwd: MONITOR_DIR,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: baseEnv,
    }),
    engineUsed,
  };
}

// ── Dedup & filter helpers (module-level so they can be unit-tested) ─────────

type EnvFinding = {
  host?:            unknown;
  mode?:            unknown;
  path?:            unknown;
  url?:             unknown;
  status?:          unknown;
  keys_found?:      unknown;
  key_categories?:  unknown;
  key_services?:    unknown;
  content_preview?: unknown;
  content_length?:  unknown;
  found_at?:        unknown;
  run_id?:          unknown;
  trigger?:         unknown;
};

type DedupedFinding<T> = T & { aliases: string[]; aliasCount: number; runIds: string[] };

/**
 * Dedupe findings that point at the same logical leak.
 *
 * A single misconfigured server commonly serves the same `.env` (or other
 * sensitive file) under many URL variants — different ports, alias paths,
 * http vs https. From a leak-monitoring perspective these are one finding:
 * the same secret on the same host. Showing 4–8 rows for it just buries
 * other unique leaks below the fold.
 *
 * Grouping key combines the host, byte length, the *full* truncated
 * preview (already capped to 500 chars by the read mapping) and the
 * extracted `key_services` list. Including the full preview rather than
 * a 256-byte prefix avoids collapsing two leaks that happen to share an
 * identical header but diverge later (e.g. same comment block, different
 * AWS keys further down). Including `key_services` is a cheap belt-and-
 * braces check: if the scanner extracted distinct service categories
 * from the two files, they are by definition different leaks.
 *
 * The representative we keep is the shortest URL (canonical-looking),
 * but we promote the *latest* `found_at` and that entry's `run_id` onto
 * the representative so newest-first ordering and `?runId=` filtering
 * work even when the canonical URL was first seen on an older run. The
 * full set of contributing run ids is preserved on `runIds` so the
 * filter can match any of them.
 */
export function dedupeFindings<T extends EnvFinding>(raw: T[]): DedupedFinding<T>[] {
  const groups = new Map<string, T[]>();
  for (const r of raw) {
    const host     = String(r.host ?? "");
    const length   = Number(r.content_length ?? 0);
    const preview  = String(r.content_preview ?? "");
    const services = JSON.stringify((r.key_services as string[] | undefined) ?? []);
    const key      = `${host}\u0001${length}\u0001${preview}\u0001${services}`;
    const list     = groups.get(key);
    if (list) list.push(r);
    else groups.set(key, [r]);
  }
  const out: DedupedFinding<T>[] = [];
  for (const list of groups.values()) {
    // Pick the entry with the most recent `found_at` to source timestamp,
    // run_id, and trigger from — that's what the UI should display so the
    // row sorts correctly and `?runId=` filtering finds the latest hit.
    const newest = list.reduce((acc, e) =>
      String(e.found_at ?? "").localeCompare(String(acc.found_at ?? "")) > 0 ? e : acc
    , list[0]);

    // Pick the shortest URL as the canonical representative shape (path,
    // mode, url shown to the user). This tends to be `/.env` on port 80
    // rather than `/some/long/alias/.env` on a custom port.
    const canonical = list.reduce((acc, e) =>
      String(e.url ?? "").length < String(acc.url ?? "").length ? e : acc
    , list[0]);

    const aliases = list
      .filter(e => e !== canonical)
      .map(e => String(e.url ?? ""))
      .filter(Boolean);
    const runIds = Array.from(new Set(
      list.map(e => String(e.run_id ?? "")).filter(Boolean)
    ));

    out.push({
      ...canonical,
      // override timestamp & run association with the newest contributor
      found_at: newest.found_at,
      run_id:   newest.run_id,
      trigger:  newest.trigger,
      aliases,
      aliasCount: aliases.length,
      runIds,
    } as DedupedFinding<T>);
  }
  // Newest first by representative's (now-promoted-to-latest) found_at.
  out.sort((a, b) => String(b.found_at ?? "").localeCompare(String(a.found_at ?? "")));
  return out;
}

export type FilterOpts = {
  mode?:          string;
  hasKeys?:       string;
  q?:             string;
  runId?:         string;
  category?:      string;
  honeypotHosts?: Set<string>;
};

export function applyFindingsFilters<T extends EnvFinding & { aliases?: string[]; runIds?: string[]; key_categories?: string[] }>(
  items: T[],
  opts: FilterOpts,
): T[] {
  const mode     = (opts.mode     ?? "").toLowerCase();
  const hasKeys  = opts.hasKeys  ?? "";
  const q        = (opts.q        ?? "").toLowerCase();
  const runId    = opts.runId    ?? "";
  const category = (opts.category ?? "").toLowerCase();
  return items.filter(r => {
    if (mode    && mode !== "all"  && r.mode !== mode) return false;
    if (hasKeys === "yes" && !((r.keys_found as number) > 0)) return false;
    if (hasKeys === "no"  &&  ((r.keys_found as number) > 0)) return false;
    if (q) {
      const aliases = r.aliases ?? [];
      const haystack = [
        String(r.url  ?? ""),
        String(r.path ?? ""),
        ...aliases,
      ].join("\n").toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    if (runId) {
      // After dedup a single row can carry findings from multiple runs
      // (the same leak surfacing on every scan). Match if ANY contributing
      // run matches the filter, not just the representative's run_id.
      const allRuns = r.runIds ?? [String(r.run_id ?? "")];
      if (!allRuns.includes(runId)) return false;
    }
    if (category && category !== "all") {
      const cats: string[] = (r.key_categories as string[] | undefined) ?? [];
      if (!cats.map(c => c.toLowerCase()).includes(category)) return false;
    }
    if (opts.honeypotHosts?.has(String(r.host ?? ""))) return false;
    return true;
  });
}

/**
 * Detect honeypot hosts: a host that serves ≥4 paths where all
 * content-lengths fall within a 200-byte window is almost certainly
 * returning a catch-all response (server-side honeypot / SPA router /
 * CDN default page). The byte-range check is intentionally generous —
 * some honeypots vary their filler by a few dozen bytes to defeat hash-
 * based dedup while still being structurally identical.
 */
/** Normalize a URL path: percent-decode, lowercase, strip leading slash.
 *  This ensures that /.git/config, /%2egit/config and /%2f.git/config
 *  all collapse to the same canonical path so they aren't counted as
 *  multiple distinct paths when detecting catch-all honeypots.
 */
function normalizeUrlPath(rawPath: string): string {
  try {
    // decodeURIComponent handles %2e → ., %2f → /, etc.
    return decodeURIComponent(rawPath).toLowerCase().replace(/^\/+/, "");
  } catch {
    return rawPath.toLowerCase().replace(/^\/+/, "");
  }
}

export function detectHoneypotHosts(
  items: Record<string, unknown>[],
): Set<string> {
  // Deduplicate by (host, normalizedPath) so URL-encoding variants
  // (/.git/config vs /%2egit/config) don't inflate the path count.
  const seen = new Set<string>();
  const byHost = new Map<string, number[]>();

  for (const item of items) {
    const host = String(item["host"] ?? "");
    if (!host) continue;

    const rawPath = String(item["path"] ?? "");
    const normPath = normalizeUrlPath(rawPath);
    const dedupeKey = `${host}|${normPath}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    const len = Number(item["content_length"] ?? 0);
    const arr = byHost.get(host);
    if (arr) arr.push(len);
    else byHost.set(host, [len]);
  }

  const honeypots = new Set<string>();
  for (const [host, lengths] of byHost) {
    // Require 6+ unique paths with near-identical content.
    // (threshold=4 caused false positives on legit servers
    //  with a small number of similar-sized config files)
    if (lengths.length < 6) continue;
    const min = Math.min(...lengths);
    const max = Math.max(...lengths);
    if (max - min <= 200) honeypots.add(host);
  }
  return honeypots;
}

export function buildEnvScanRouter(): Router {
  const router = Router();

  router.post("/start", (req, res) => {
    const body = req.body as Record<string, unknown>;
    const hosts       = (body.hosts as string) ?? "";
    const timeout         = Number(body.timeout         ?? 2);
    const concurrency     = Number(body.concurrency     ?? 1000);
    const hostConcurrency = body.hostConcurrency !== undefined ? Number(body.hostConcurrency) : undefined;
    const maxFail         = Number(body.maxFail         ?? 2);
    const deepScan        = Boolean(body.deepScan       ?? false);
    // Engine: explicit body.engine wins; otherwise fall back to the persisted
    // engine_config.json (so auto-chain and the UI agree). Persist the chosen
    // engine so subsequent /resume and auto-chain runs match.
    const engine: Engine = body.engine !== undefined
      ? normalizeEngine(body.engine)
      : readEngineConfig();
    writeEngineConfig(engine);

    if (!hosts.trim()) {
      res.status(400).json({ success: false, message: "No hosts provided" });
      return;
    }

    // Kill any existing scanner process
    if (isProcessRunning()) {
      killScanner();
    }

    fs.mkdirSync(DATA_DIR, { recursive: true });
    try { fs.unlinkSync(STOP_FILE);   } catch {}
    try { fs.unlinkSync(OFFSET_FILE); } catch {}
    try { fs.unlinkSync(PID_FILE);    } catch {}

    const lines = hosts.split(/[\n,\r]+/).map(h => h.trim()).filter(Boolean);
    fs.writeFileSync(INPUT_FILE, lines.join("\n") + "\n");

    // Reset status BEFORE spawning so the UI immediately drops stale
    // progress from the previous run.
    writePendingStatus();

    let proc, engineUsed: Engine;
    try {
      ({ proc, engineUsed } = spawnScanner({
        engine, trigger: "manual",
        timeout, concurrency, maxFail, deepScan, hostConcurrency,
      }));
    } catch (err) {
      res.status(500).json({ success: false, message: String(err) });
      return;
    }

    // Save PID immediately
    if (proc.pid) {
      fs.writeFileSync(PID_FILE, String(proc.pid));
    }

    const tag = `[env-scan/${engineUsed}]`;
    proc.stdout?.on("data", (d: Buffer) => process.stdout.write(`${tag} ${d}`));
    proc.stderr?.on("data", (d: Buffer) => process.stderr.write(`${tag} ${d}`));
    proc.on("exit", () => {
      try { fs.unlinkSync(PID_FILE); } catch {}
    });
    proc.unref();

    res.json({
      success: true,
      message: `Scan started: ${lines.length} hosts (${engineUsed})`
        + (engineUsed !== engine ? " — Go binary missing, fell back to Python" : ""),
      hosts: lines.length,
      engine: engineUsed,
      engineRequested: engine,
    });
  });

  router.post("/resume", (req, res) => {
    if (isProcessRunning()) {
      res.json({ success: false, message: "Scanner already running" });
      return;
    }
    if (!fs.existsSync(INPUT_FILE)) {
      res.status(400).json({ success: false, message: "No previous scan to resume" });
      return;
    }
    const body = (req.body ?? {}) as Record<string, unknown>;
    const timeout         = Number(body.timeout         ?? 2);
    const concurrency     = Number(body.concurrency     ?? 1000);
    const hostConcurrency = body.hostConcurrency !== undefined ? Number(body.hostConcurrency) : undefined;
    const maxFail         = Number(body.maxFail         ?? 2);
    const deepScan        = Boolean(body.deepScan       ?? false);
    const engine: Engine = body.engine !== undefined
      ? normalizeEngine(body.engine)
      : readEngineConfig();
    writeEngineConfig(engine);

    try { fs.unlinkSync(STOP_FILE); } catch {}

    let proc, engineUsed: Engine;
    try {
      ({ proc, engineUsed } = spawnScanner({
        engine, trigger: "manual",
        timeout, concurrency, maxFail, deepScan, hostConcurrency,
      }));
    } catch (err) {
      res.status(500).json({ success: false, message: String(err) });
      return;
    }
    if (proc.pid) fs.writeFileSync(PID_FILE, String(proc.pid));
    const tag = `[env-scan/${engineUsed}]`;
    proc.stdout?.on("data", (d: Buffer) => process.stdout.write(`${tag} ${d}`));
    proc.stderr?.on("data", (d: Buffer) => process.stderr.write(`${tag} ${d}`));
    proc.on("exit", () => { try { fs.unlinkSync(PID_FILE); } catch {} });
    proc.unref();
    res.json({
      success: true,
      message: `Scan resumed from previous offset (${engineUsed})`
        + (engineUsed !== engine ? " — Go binary missing, fell back to Python" : ""),
      engine: engineUsed,
      engineRequested: engine,
    });
  });

  // Persist + read the engine selection used by the auto-chain orchestrator
  // and surfaced in the UI's engine toggle.
  router.get("/engine", (_req, res) => {
    res.json({ engine: readEngineConfig(), goBinaryAvailable: fs.existsSync(GO_BINARY) });
  });

  router.post("/engine", (req, res) => {
    const engine = normalizeEngine((req.body as Record<string, unknown>)?.engine);
    if (engine === "go" && !fs.existsSync(GO_BINARY)) {
      res.status(400).json({
        success: false,
        message: "Go binary not built — run monitor/go-scanner/build.sh",
      });
      return;
    }
    writeEngineConfig(engine);
    res.json({ success: true, engine });
  });

  // ── Go scanner tuning JSON: read / write / reset ──────────────────────────
  router.get("/tuning", (_req, res) => {
    const { tuning, source } = readTuning();
    res.json({ tuning, defaults: TUNING_DEFAULTS, source });
  });

  router.post("/tuning", (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const merged: Tuning = { ...TUNING_DEFAULTS };
    const errors: string[] = [];
    for (const k of TUNING_KEYS) {
      const v = body[k];
      if (v === undefined || v === null || v === "") continue;
      const n = typeof v === "number" ? v : Number(v);
      if (!Number.isFinite(n) || n <= 0) {
        errors.push(`${k} must be a positive number`);
        continue;
      }
      merged[k] = Math.floor(n);
    }
    if (merged.tcp_precheck_min_ms >= merged.tcp_precheck_max_ms) {
      errors.push("tcp_precheck_min_ms must be < tcp_precheck_max_ms");
    }
    if (errors.length) {
      res.status(400).json({ success: false, errors });
      return;
    }
    fs.mkdirSync(DATA_DIR, { recursive: true });
    // Preserve any leading "_comment" key if the user has one in the file.
    let comment: unknown;
    try {
      const cur = JSON.parse(fs.readFileSync(TUNING_FILE, "utf-8")) as Record<string, unknown>;
      if (cur._comment !== undefined) comment = cur._comment;
    } catch {}
    const out: Record<string, unknown> = comment !== undefined
      ? { _comment: comment, ...merged }
      : { ...merged };
    fs.writeFileSync(TUNING_FILE, JSON.stringify(out, null, 2) + "\n");
    res.json({ success: true, tuning: merged });
  });

  router.delete("/tuning", (_req, res) => {
    try { fs.unlinkSync(TUNING_FILE); } catch {}
    res.json({ success: true, tuning: { ...TUNING_DEFAULTS } });
  });

  router.post("/stop", (_req, res) => {
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      killScanner();
      // Mark status as not running
      try {
        const st = readJson(STATUS_FILE, {}) as Record<string, unknown>;
        st.running = false;
        st.current_action = "stopped by user";
        fs.writeFileSync(STATUS_FILE, JSON.stringify(st));
      } catch {}
      res.json({ success: true, message: "Stop signal sent" });
    } catch (err) {
      res.json({ success: false, message: String(err) });
    }
  });

  router.get("/status", (_req, res) => {
    const status = readJson(STATUS_FILE, {
      running: false, scanner: "env", current_action: "idle",
      processed: 0, total: 0, found: 0, keys: 0,
    }) as Record<string, unknown>;

    // Authoritative: check actual process, not just status file flag
    const alive = isProcessRunning();

    // Self-heal stale status: if file says running but no real process,
    // overwrite the action so the UI doesn't get stuck on "spawning…"
    // from a previous crashed run.
    if (!alive && (status.running === true || String(status.current_action ?? "").includes("spawning"))) {
      const healed = { ...status, running: false, current_action: "idle" };
      try { fs.writeFileSync(STATUS_FILE, JSON.stringify(healed)); } catch {}
      status.running = false;
      status.current_action = "idle";
    }

    const dns = (status.dns ?? {}) as Record<string, unknown>;
    res.json({
      running:        alive,
      // The engine that produced the most recent status. Falls back to the
      // persisted user choice so the UI can show a sensible value before any
      // scan has run yet.
      engine:         (status.engine as string | undefined) ?? readEngineConfig(),
      runId:          (status.run_id     as string | undefined) ?? null,
      trigger:        (status.trigger    as string | undefined) ?? null,
      startedAt:      (status.started_at as string | undefined) ?? null,
      finishedAt:     (status.finished_at as string | undefined) ?? null,
      deepScan:       Boolean(status.deep_scan ?? false),
      concurrency:    (status.concurrency as number | undefined) ?? null,
      stopped:        Boolean(status.stopped ?? false),
      currentAction:  status.current_action ?? "idle",
      processed:      status.processed      ?? 0,
      total:          status.total          ?? 0,
      found:          status.found          ?? 0,
      keys:           status.keys           ?? 0,
      elapsedSeconds: status.elapsed_seconds ?? 0,
      ratePerSec:     status.rate_per_sec   ?? 0,
      etaSeconds:     status.eta_seconds    ?? 0,
      updatedAt:      status.updated_at     ?? null,
      pid:            getScannerPid(),
      dns: {
        udpResolvers:    dns.udp_resolvers     ?? 0,
        blacklisted:     dns.blacklisted       ?? 0,
        dohEnabled:      dns.doh_enabled       ?? false,
        dohProviders:    dns.doh_providers     ?? 0,
        strategy:        dns.strategy          ?? "system",
        totalFetched:    dns.total_fetched     ?? 0,
        totalProbed:     dns.total_probed      ?? 0,
        totalWorking:    dns.total_working     ?? 0,
        initTimeS:       dns.init_time_s       ?? 0,
        errorRate:       dns.error_rate        ?? 0,
        cacheSource:     dns.cache_source      ?? null,
        cacheAgeSeconds: dns.cache_age_seconds ?? 0,
        cacheTtlSeconds: dns.cache_ttl_seconds ?? 0,
      },
    });
  });

  router.get("/history", (req, res) => {
    const limit = Math.min(500, Math.max(1, parseInt(String(req.query.limit ?? "50"))));
    const items = readJsonl(HISTORY_FILE).map(r => ({
      runId:          r.run_id,
      trigger:        r.trigger,
      startedAt:      r.started_at,
      finishedAt:     r.finished_at,
      total:          r.total          ?? 0,
      processed:      r.processed      ?? 0,
      found:          r.found          ?? 0,
      keys:           r.keys           ?? 0,
      elapsedSeconds:   r.elapsed_seconds  ?? 0,
      ratePerSec:       r.rate_per_sec     ?? 0,
      deepScan:         Boolean(r.deep_scan ?? false),
      engine:           (r.engine as string | undefined) ?? "py",
      concurrency:      r.concurrency      ?? null,
      stopped:          Boolean(r.stopped ?? false),
      dnsInitSeconds:   r.dns_init_seconds ?? 0,
      dnsCacheSource:   r.dns_cache_source ?? null,
    }));
    items.reverse();
    res.json({ items: items.slice(0, limit), total: items.length });
  });

  router.get("/results", (req, res) => {
    const page  = Math.max(1, parseInt(String(req.query.page  ?? "1")));
    const limit = Math.min(200, Math.max(1, parseInt(String(req.query.limit ?? "50"))));
    // Allow disabling dedup via `?dedupe=0` for debugging / power users.
    const dedupe = String(req.query.dedupe ?? "1") !== "0";
    // Use the shared cache (keyed on file mtime) so repeated page flips
    // don't re-read & re-parse the entire env_found.jsonl (up to 200k lines).
    const { raw, ordered, honeypot: honeypotHosts } = getResultsCache(dedupe);
    const hideHoneypots = String(req.query.hideHoneypots ?? "") === "yes";
    const filtered = applyFindingsFilters(ordered, {
      mode:          String(req.query.mode     ?? ""),
      hasKeys:       String(req.query.hasKeys  ?? ""),
      q:             String(req.query.q        ?? ""),
      runId:         String(req.query.runId    ?? ""),
      category:      String(req.query.category ?? ""),
      honeypotHosts: hideHoneypots ? honeypotHosts : undefined,
    });
    const totalRaw    = raw.length;
    const totalUnique = ordered.length;
    const total       = filtered.length;
    const items = filtered.slice((page - 1) * limit, page * limit).map(r => ({
      host:           r.host,
      mode:           r.mode,
      path:           r.path,
      url:            r.url,
      status:         r.status,
      contentPreview: r.content_preview as string,
      contentLength:  r.content_length as number,
      keysFound:      r.keys_found as number,
      deepKeysCount:  (r.deep_keys_count as number) ?? 0,
      keyCategories:  r.key_categories as string[],
      keyServices:    r.key_services as string[],
      keysPreview:    (r.keys_preview as Array<Record<string, unknown>>) ?? [],
      foundAt:        r.found_at as string,
      runId:          (r.run_id as string | null) ?? null,
      trigger:        (r.trigger as string | null) ?? null,
      aliases:        (r.aliases as string[]) ?? [],
      aliasCount:     (r.aliasCount as number) ?? 0,
      runIds:         (r.runIds as string[]) ?? [],
      isHoneypot:     honeypotHosts.has(String(r.host ?? "")),
    }));
    // Deep scanner summary (last run state)
    let deepSummary: Record<string, unknown> | null = null;
    try {
      if (fs.existsSync(DEEP_STATUS_FILE)) {
        deepSummary = JSON.parse(fs.readFileSync(DEEP_STATUS_FILE, "utf-8"));
      }
    } catch { /* ignore */ }
    let deepKeysTotal = 0;
    for (const r of raw) deepKeysTotal += Number(r.deep_keys_count ?? 0);
    res.json({
      items, total, page, limit,
      pages: Math.ceil(total / limit) || 1,
      totalRaw,
      totalUnique,
      deduped: dedupe,
      deepKeysTotal,
      deepStatus: deepSummary,
    });
  });

  router.get("/export", (req, res) => {
    const raw = readJsonl(FOUND_FILE).map(r => ({ ...r }));
    raw.reverse();
    // Export deliberately keeps every URL (no dedup) — operators want the
    // full list of exposed paths, including alias URLs.
    const filtered = applyFindingsFilters(raw, {
      mode:    String(req.query.mode    ?? ""),
      hasKeys: String(req.query.hasKeys ?? ""),
      q:       String(req.query.q       ?? ""),
      runId:   String(req.query.runId   ?? ""),
    });
    const lines = filtered.map(r => String(r.url ?? "")).filter(Boolean);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="env_scan_results.txt"`);
    res.send(lines.join("\n") + (lines.length ? "\n" : ""));
  });

  const PATHS_OVERRIDE = path.join(DATA_DIR, "custom_paths_override.json");

  router.get("/paths", (_req, res) => {
    if (fs.existsSync(PATHS_OVERRIDE)) {
      try {
        const paths = JSON.parse(fs.readFileSync(PATHS_OVERRIDE, "utf-8")) as string[];
        res.json({ paths, source: "custom", count: paths.length });
        return;
      } catch {}
    }
    try {
      const pythonBin = getPythonBin();
      const out = execSync(
        `${pythonBin} -c "from env_paths import ENV_PATHS; import json; print(json.dumps(ENV_PATHS))"`,
        { cwd: MONITOR_DIR, encoding: "utf-8", timeout: 8000 }
      );
      const paths = JSON.parse(out.trim()) as string[];
      res.json({ paths, source: "base", count: paths.length });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  router.put("/paths", (req, res) => {
    const body = req.body as { paths?: unknown };
    if (!Array.isArray(body.paths)) {
      res.status(400).json({ error: "paths must be an array" });
      return;
    }
    const paths = (body.paths as unknown[]).map(String).filter(Boolean);
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(PATHS_OVERRIDE, JSON.stringify(paths, null, 2));
    res.json({ success: true, count: paths.length });
  });

  router.delete("/paths", (_req, res) => {
    try { fs.unlinkSync(PATHS_OVERRIDE); } catch {}
    res.json({ success: true });
  });

  router.get("/watchdog", (_req, res) => {
    res.json(getWatchdogStatus());
  });

  router.delete("/results", (_req, res) => {
    try {
      for (const f of [FOUND_FILE, INPUT_FILE, OFFSET_FILE]) {
        try { fs.unlinkSync(f); } catch {}
      }
      res.json({ success: true });
    } catch (err) {
      res.json({ success: false, message: String(err) });
    }
  });


  // ?? Delete by host (added) ?????????????????????????????????????????????????
  router.get("/results/count-by-host", (req, res) => {
    const host = String(req.query.host ?? "").trim();
    if (!host) { res.status(400).json({ error: "host required" }); return; }
    try {
      const lines = fs.existsSync(FOUND_FILE)
        ? fs.readFileSync(FOUND_FILE, "utf-8").trim().split("\n").filter(Boolean)
        : [];
      const count = lines.filter(l => {
        try { return String((JSON.parse(l) as {host?:string}).host ?? "").includes(host); }
        catch { return false; }
      }).length;
      res.json({ host, count });
    } catch (err) { res.status(500).json({ error: String(err) }); }
  });

  router.delete("/results/by-host", (req, res) => {
    const host = String(req.query.host ?? "").trim();
    if (!host) { res.status(400).json({ error: "host required" }); return; }
    try {
      const lines = fs.existsSync(FOUND_FILE)
        ? fs.readFileSync(FOUND_FILE, "utf-8").trim().split("\n").filter(Boolean)
        : [];
      const kept: string[] = [];
      let removed = 0;
      for (const line of lines) {
        try {
          const obj = JSON.parse(line) as { host?: string; url?: string };
          if (String(obj.host ?? obj.url ?? "").includes(host)) { removed++; }
          else { kept.push(line); }
        } catch { kept.push(line); }
      }
      const tmp = FOUND_FILE + ".tmp." + process.pid;
      fs.writeFileSync(tmp, kept.join("\n") + (kept.length ? "\n" : ""));
      fs.renameSync(tmp, FOUND_FILE);
      _resultsCache = null;
      res.json({ success: true, removed, kept: kept.length });
    } catch (err) { res.status(500).json({ error: String(err) }); }
  });

  // ── Cleanup analytics ──────────────────────────────────────────────────────
  // Shared path to found_keys.jsonl (written by monitor/env scanner)
  const KEYS_FILE = path.join(DATA_DIR, "found_keys.jsonl");

  // Known junk/placeholder key patterns
  const JUNK_PATTERNS = [
    /wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/i,
    /FUCK_YOU_BLACKHAT/i,
    /EXAMPLE(?:KEY|SECRET|API)/i,
    /YOUR[_-]?(?:API[_-]?)?KEY/i,
    /INSERT[_-]?HERE/i,
    /CHANGEME/i,
    /PLACEHOLDER/i,
    /TESTKEY/i,
    /SAMPLEKEY/i,
  ];

  function readKeyLines(): string[] {
    try {
      return fs.existsSync(KEYS_FILE)
        ? fs.readFileSync(KEYS_FILE, "utf-8").trim().split("\n").filter(Boolean)
        : [];
    } catch { return []; }
  }

  function deduplicateKeyLines(lines: string[]): Record<string, unknown>[] {
    const map = new Map<string, Record<string, unknown>>();
    for (const line of lines) {
      try {
        const r = JSON.parse(line) as Record<string, unknown>;
        const id = String(r.fingerprint ?? r.id ?? "");
        if (!id) continue;
        const ex = map.get(id);
        if (!ex || (ex.validated_at == null && r.validated_at != null)) map.set(id, r);
      } catch { /* skip */ }
    }
    return [...map.values()];
  }

  // GET /env-scan/results/stats
  router.get("/results/stats", (_req, res) => {
    try {
      const { ordered, honeypot: honeypotHosts } = getResultsCache(true);

      // Collect per-host counts for high-volume detection (500+ keys from env_found)
      const hostCount = new Map<string, number>();
      for (const r of ordered) {
        const h = String(r.host ?? "");
        if (h) hostCount.set(h, (hostCount.get(h) ?? 0) + Number(r.keys_found ?? 1));
      }
      const highVolumeHosts = [...hostCount.entries()]
        .filter(([, c]) => c >= 500)
        .map(([host, count]) => ({ host, count }))
        .sort((a, b) => b.count - a.count);
      const highVolumeSet = new Set(highVolumeHosts.map(h => h.host));

      // Merge honeypot sets (catch-all detected + high volume)
      const allHoneypotHosts = new Set([...honeypotHosts, ...highVolumeSet]);

      // Read deduped keys to count affected categories
      const allKeys = deduplicateKeyLines(readKeyLines());
      const total = allKeys.length;

      // Keys from honeypot hosts (by URL host match)
      let honeypotHostKeys = 0;
      let confirmedInvalid = 0;
      let testJunk = 0;

      for (const r of allKeys) {
        const url = String(r.url ?? r.query ?? "");
        let host = "";
        try { host = new URL(url).hostname; } catch { host = url; }

        if (allHoneypotHosts.has(host)) honeypotHostKeys++;
        if (r.status === "invalid" && !allHoneypotHosts.has(host)) confirmedInvalid++;
        const keyVal = String(r.key ?? "");
        if (JUNK_PATTERNS.some(p => p.test(keyVal))) testJunk++;
      }

      res.json({
        total,
        envDetected: honeypotHosts.size,
        highVolume: highVolumeHosts.length,
        honeypotHosts: [...allHoneypotHosts].slice(0, 200),
        honeypotHostKeys,
        confirmedInvalid,
        testJunk,
        highVolumeHosts: highVolumeHosts.slice(0, 50),
      });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  // POST /env-scan/results/purge-honeypots
  router.post("/results/purge-honeypots", (_req, res) => {
    try {
      const { honeypot: honeypotHosts } = getResultsCache(true);

      // Also collect high-volume hosts (500+ keys)
      const { ordered } = getResultsCache(true);
      const hostCount = new Map<string, number>();
      for (const r of ordered) {
        const h = String(r.host ?? "");
        if (h) hostCount.set(h, (hostCount.get(h) ?? 0) + Number(r.keys_found ?? 1));
      }
      const allHoneypotHosts = new Set([
        ...honeypotHosts,
        ...[...hostCount.entries()].filter(([, c]) => c >= 500).map(([h]) => h),
      ]);

      const lines = readKeyLines();
      const kept: string[] = [];
      let removed = 0;
      for (const line of lines) {
        try {
          const r = JSON.parse(line) as Record<string, unknown>;
          const url = String(r.url ?? r.query ?? "");
          let host = "";
          try { host = new URL(url).hostname; } catch { host = url; }
          if (allHoneypotHosts.has(host)) { removed++; }
          else { kept.push(line); }
        } catch { kept.push(line); }
      }
      const tmp = KEYS_FILE + ".tmp.purge." + process.pid;
      fs.writeFileSync(tmp, kept.join("\n") + (kept.length ? "\n" : ""));
      fs.renameSync(tmp, KEYS_FILE);
      _resultsCache = null;
      res.json({ success: true, removed, kept: kept.length });
    } catch (err) { res.status(500).json({ error: String(err) }); }
  });

  // POST /env-scan/results/purge-invalid
  router.post("/results/purge-invalid", (_req, res) => {
    try {
      const lines = readKeyLines();
      const kept: string[] = [];
      let removed = 0;
      // Only delete if validated (has validated_at) to avoid deleting genuinely unchecked
      for (const line of lines) {
        try {
          const r = JSON.parse(line) as Record<string, unknown>;
          if (r.status === "invalid" && r.validated_at) { removed++; }
          else { kept.push(line); }
        } catch { kept.push(line); }
      }
      const tmp = KEYS_FILE + ".tmp.inv." + process.pid;
      fs.writeFileSync(tmp, kept.join("\n") + (kept.length ? "\n" : ""));
      fs.renameSync(tmp, KEYS_FILE);
      res.json({ success: true, removed, kept: kept.length });
    } catch (err) { res.status(500).json({ error: String(err) }); }
  });

  // POST /env-scan/results/purge-junk
  router.post("/results/purge-junk", (_req, res) => {
    try {
      const lines = readKeyLines();
      const kept: string[] = [];
      let removed = 0;
      for (const line of lines) {
        try {
          const r = JSON.parse(line) as Record<string, unknown>;
          const keyVal = String(r.key ?? "");
          if (JUNK_PATTERNS.some(p => p.test(keyVal))) { removed++; }
          else { kept.push(line); }
        } catch { kept.push(line); }
      }
      const tmp = KEYS_FILE + ".tmp.junk." + process.pid;
      fs.writeFileSync(tmp, kept.join("\n") + (kept.length ? "\n" : ""));
      fs.renameSync(tmp, KEYS_FILE);
      res.json({ success: true, removed, kept: kept.length });
    } catch (err) { res.status(500).json({ error: String(err) }); }
  });

  return router;
}
