/**
 * Scan Watchdog — monitors env-scan health and kills stalled runs.
 *
 * Kill conditions (either is enough):
 *   A) running > MAX_HANG_MIN  AND  rate_per_sec < MIN_RATE_HS  (zombie/stalled)
 *   B) running > HARD_MAX_MIN  regardless of rate               (runaway)
 *
 * After killing it writes a record to watchdog_events.jsonl and lets
 * auto-chain restart the next scan on its regular schedule.
 */

import fs   from "fs";
import path from "path";
import { execSync } from "child_process";
import { fileURLToPath } from "url";

const __dirname    = path.dirname(fileURLToPath(import.meta.url));
// When bundled by esbuild into dist/index.mjs, __dirname = artifacts/api-server/dist/
// so we need to go 3 levels up to reach the project root's monitor/ directory.
const MONITOR_DIR  = path.resolve(__dirname, "../../../monitor");
const DATA_DIR     = path.join(MONITOR_DIR, "data");

const STATUS_FILE  = path.join(DATA_DIR, "env_scan_status.json");
const PID_FILE     = path.join(DATA_DIR, "env_scan.pid");
const STOP_FILE    = path.join(DATA_DIR, "env_scan_stop");
const EVENTS_FILE  = path.join(DATA_DIR, "watchdog_events.jsonl");

// ── tunables ─────────────────────────────────────────────────────────────────
const CHECK_INTERVAL_MS = 5 * 60 * 1000;   // check every 5 min
const MAX_HANG_MIN      = 60;              // stalled threshold (rate-gated)
const MIN_RATE_HS       = 1.0;            // hosts/s — below = stalled
const HARD_MAX_MIN      = 120;            // absolute ceiling regardless of rate

// ── state (exported for the /watchdog endpoint) ──────────────────────────────
export interface WatchdogEvent {
  ts:          string;
  reason:      string;
  elapsed_min: number;
  rate:        number;
  run_id:      string | null;
}

let lastEvent: WatchdogEvent | null = null;
let killCount = 0;

export function getWatchdogStatus() {
  return {
    enabled:    true,
    maxHangMin: MAX_HANG_MIN,
    hardMaxMin: HARD_MAX_MIN,
    minRateHs:  MIN_RATE_HS,
    checkEveryMin: CHECK_INTERVAL_MS / 60000,
    killCount,
    lastEvent,
  };
}

// ── internals ────────────────────────────────────────────────────────────────

function readStatus(): Record<string, unknown> | null {
  try {
    return JSON.parse(fs.readFileSync(STATUS_FILE, "utf-8"));
  } catch {
    return null;
  }
}

function getScannerPid(): number | null {
  try {
    const pid = parseInt(fs.readFileSync(PID_FILE, "utf-8").trim(), 10);
    if (isNaN(pid)) return null;
    process.kill(pid, 0);
    return pid;
  } catch {
    return null;
  }
}

function killScanner(runId: string | null, reason: string, elapsed: number, rate: number): void {
  console.log(`[watchdog] KILLING stalled scan run_id=${runId} reason="${reason}" elapsed=${elapsed.toFixed(1)}min rate=${rate.toFixed(2)}h/s`);

  try { fs.writeFileSync(STOP_FILE, "1"); } catch {}

  const pid = getScannerPid();
  if (pid) {
    try { process.kill(pid, "SIGTERM"); } catch {}
    setTimeout(() => { try { process.kill(pid, "SIGKILL"); } catch {} }, 3000);
  }
  try { execSync("pkill -f env_scanner.py",             { stdio: "ignore" }); } catch {}
  try { execSync("pkill -f go-scanner/bin/env-scanner", { stdio: "ignore" }); } catch {}
  try { fs.unlinkSync(PID_FILE); } catch {}

  const event: WatchdogEvent = {
    ts:          new Date().toISOString(),
    reason,
    elapsed_min: Math.round(elapsed * 10) / 10,
    rate,
    run_id:      runId,
  };
  lastEvent = event;
  killCount++;

  try {
    fs.appendFileSync(EVENTS_FILE, JSON.stringify(event) + "\n");
  } catch {}
}

function check(): void {
  const st = readStatus();
  if (!st || !st.running) return;

  const startedAt = st.started_at as string | undefined;
  if (!startedAt) return;

  const elapsedMs  = Date.now() - new Date(startedAt).getTime();
  const elapsedMin = elapsedMs / 60000;
  const rate       = (st.rate_per_sec as number | undefined) ?? 0;
  const runId      = (st.run_id as string | undefined) ?? null;

  if (elapsedMin > HARD_MAX_MIN) {
    killScanner(runId, `hard_max: running ${elapsedMin.toFixed(0)}min > ${HARD_MAX_MIN}min ceiling`, elapsedMin, rate);
    return;
  }

  if (elapsedMin > MAX_HANG_MIN && rate < MIN_RATE_HS) {
    killScanner(runId, `stalled: running ${elapsedMin.toFixed(0)}min with rate ${rate.toFixed(2)}<${MIN_RATE_HS}h/s`, elapsedMin, rate);
  }
}

// ── public entry point ───────────────────────────────────────────────────────
export function startScanWatchdog(): void {
  // Load last event from disk so restarts don't lose history
  try {
    const lines = fs.readFileSync(EVENTS_FILE, "utf-8").trim().split("\n").filter(Boolean);
    if (lines.length) {
      lastEvent  = JSON.parse(lines[lines.length - 1]) as WatchdogEvent;
      killCount  = lines.length;
    }
  } catch {}

  console.log(`[watchdog] started — check every ${CHECK_INTERVAL_MS / 60000}min, hang>${MAX_HANG_MIN}min@<${MIN_RATE_HS}h/s OR hard>${HARD_MAX_MIN}min`);
  setInterval(check, CHECK_INTERVAL_MS);
  // Also run one check shortly after startup to catch already-stuck scans
  setTimeout(check, 30_000);
}
