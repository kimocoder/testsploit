import { spawn, execSync } from "child_process";
import fs from "fs";
import path from "path";
import readline from "readline";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// MONITOR_DIR is overridable for tests so the orchestrator can be exercised
// against an isolated temp directory without touching real data/.
const MONITOR_DIR = process.env.AUTO_CHAIN_MONITOR_DIR
  ?? path.resolve(__dirname, "../../../monitor");
const DATA_DIR    = path.join(MONITOR_DIR, "data");
const SETTINGS_FILE = path.join(MONITOR_DIR, "config", "settings.json");
const PUBLIC_STATUS = path.join(DATA_DIR, "status.json");

const DISCOVER_PID  = path.join(DATA_DIR, "discover.pid");
const DISCOVER_RES  = path.join(DATA_DIR, "discover_found.jsonl");
const DISCOVER_STAT = path.join(DATA_DIR, "discover_status.json");
const DISCOVER_INPUT = path.join(DATA_DIR, "discover_input.txt");
const DISCOVER_STOP = path.join(DATA_DIR, "discover_stop");

const ENV_PID    = path.join(DATA_DIR, "env_scan.pid");
const ENV_INPUT  = path.join(DATA_DIR, "env_scan_input.txt");
const ENV_STOP   = path.join(DATA_DIR, "env_scan_stop");
const ENV_OFFSET = path.join(DATA_DIR, "env_scan_input.txt.offset");

const ENGINE_CONFIG_FILE = path.join(DATA_DIR, "engine_config.json");
const GO_BINARY          = path.join(MONITOR_DIR, "go-scanner", "bin", "env-scanner");
const TUNING_FILE        = path.join(DATA_DIR, "scanner_tuning.json");

/** Read host_concurrency_cap_deep from scanner_tuning.json, fallback to 300. */
function readHostConcurrencyCap(): number {
  try {
    const t = JSON.parse(fs.readFileSync(TUNING_FILE, "utf-8")) as Record<string, unknown>;
    const v = t["host_concurrency_cap_deep"];
    if (typeof v === "number" && Number.isFinite(v) && v > 0) return Math.floor(v);
  } catch {}
  return 300;
}

const DEEP_SCAN_PID    = path.join(DATA_DIR, "deep_scan.pid");
const DEEP_SCAN_SCRIPT = path.join(MONITOR_DIR, "deep_scan.py");

const CHAIN_STATE = path.join(DATA_DIR, "auto_chain_state.json");
const TRIGGER_FILE = path.join(DATA_DIR, "trigger_cycle");

/**
 * Read the user's engine choice persisted by env-scan.ts. The auto-chain
 * orchestrator honors this so the UI's tumbler decides what runs in both
 * manual and auto-triggered cycles.
 */
function readEngineConfig(): "py" | "go" {
  try {
    const j = JSON.parse(fs.readFileSync(ENGINE_CONFIG_FILE, "utf-8")) as { engine?: unknown };
    if (j.engine === "go" && fs.existsSync(GO_BINARY)) return "go";
  } catch {}
  return "py";
}

// In test mode, suppress actual subprocess spawning. The state machine still
// transitions phase normally as long as the test writes the relevant pid /
// result files itself — this keeps the unit under test purely the state
// machine, not the python invocation.
const SPAWN_DISABLED = process.env.AUTO_CHAIN_DISABLE_SPAWN === "1";

const PYTHON = process.env.PYTHON_BIN
  ?? "/home/runner/workspace/.pythonlibs/bin/python3";

type ChainPhase = "idle" | "discovery" | "envscan" | "cooldown";
type TriggerSource = "auto" | "manual";

interface ChainState {
  phase: ChainPhase;
  startedAt: number;             // epoch ms when current phase started
  lastCycleAt: number;           // epoch ms when last chain cycle finished
  publicCycleSeenAt: string;     // ISO of public scanner cycle we last reacted to
  message: string;
  manualTriggerPending: boolean;
  lastTriggerSource: TriggerSource | null;
  // 24/7 loop counter: how many discovery→envscan iterations completed in
  // the current "round" (between two public-scanner cycles). Reset to 0
  // when a new round starts (manual trigger or fresh public cycle edge).
  // While < discoveries_per_public_cycle the cooldown→idle transition
  // immediately re-enters discovery instead of waiting for the next public
  // cycle, keeping the env-scanner busy 24/7.
  discoveryCountThisRound: number;
}

function readJson<T>(p: string, fb: T): T {
  try { return JSON.parse(fs.readFileSync(p, "utf-8")) as T; }
  catch { return fb; }
}

function writeJson(p: string, data: unknown): void {
  try {
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify(data, null, 2));
  } catch {}
}

function pidAlive(pidFile: string): boolean {
  try {
    const pid = parseInt(fs.readFileSync(pidFile, "utf-8").trim(), 10);
    if (isNaN(pid)) return false;
    process.kill(pid, 0);
    return true;
  } catch { return false; }
}

function readState(): ChainState {
  const s = readJson<Partial<ChainState>>(CHAIN_STATE, {});
  return {
    phase: s.phase ?? "idle",
    startedAt: s.startedAt ?? 0,
    lastCycleAt: s.lastCycleAt ?? 0,
    publicCycleSeenAt: s.publicCycleSeenAt ?? "",
    message: s.message ?? "idle",
    manualTriggerPending: s.manualTriggerPending ?? false,
    lastTriggerSource: s.lastTriggerSource ?? null,
    discoveryCountThisRound: s.discoveryCountThisRound ?? 0,
  };
}

function writeState(s: ChainState): void {
  writeJson(CHAIN_STATE, s);
}

function readSettings(): Record<string, unknown> {
  return readJson<Record<string, unknown>>(SETTINGS_FILE, {});
}

interface PublicStatus {
  last_cycle_at?: string | null;
  cycle_in_progress?: boolean;
}
function readPublicStatus(): PublicStatus {
  return readJson<PublicStatus>(PUBLIC_STATUS, {});
}

async function readDiscoveredHostPorts(): Promise<string[]> {
  if (!fs.existsSync(DISCOVER_RES)) return [];
  const out = new Set<string>();
  const rl = readline.createInterface({ input: fs.createReadStream(DISCOVER_RES) });
  for await (const line of rl) {
    if (!line.trim()) continue;
    try {
      const j = JSON.parse(line) as { host?: string; port?: number };
      if (j.host && j.port) out.add(`${j.host}:${j.port}`);
    } catch {}
  }
  return [...out];
}

function startDiscovery(ports: string, maxHosts: number): void {
  if (pidAlive(DISCOVER_PID)) {
    console.warn("[auto-chain] discovery already running, refusing to start");
    return;
  }
  fs.mkdirSync(DATA_DIR, { recursive: true });
  try { fs.unlinkSync(DISCOVER_STOP); } catch {}
  try { fs.unlinkSync(DISCOVER_INPUT); } catch {}
  try { fs.unlinkSync(DISCOVER_RES); } catch {}
  try { fs.unlinkSync(DISCOVER_STAT); } catch {}
  try { fs.unlinkSync(DISCOVER_PID); } catch {}

  if (SPAWN_DISABLED) return;

  // back to Python if the binary isn't built yet so a fresh checkout
  // still works without forcing a build step.
  const goBin = path.resolve(MONITOR_DIR, "go-discover/bin/host-discover");
  let useGo = false;
  try { fs.accessSync(goBin, fs.constants.X_OK); useGo = true; } catch {}

  const settings = readSettings();
  const discoverConc = Number(settings["auto_chain_discover_concurrency"] ?? 4000);

  const proc = useGo
    ? spawn(goBin, [
        "-ports",       ports,
        "-timeout",     "1",
        "-concurrency", String(discoverConc),
        "-max-hosts",   String(maxHosts),
      ], { cwd: MONITOR_DIR, detached: true, stdio: "ignore" })
    : spawn(PYTHON, [
        path.join(MONITOR_DIR, "host_discover.py"),
        "--batch", "500",
        "--ports", ports,
        "--timeout", "1",
        "--concurrency", String(Math.min(discoverConc, 2000)),
        "--max-hosts", String(maxHosts),
      ], { cwd: MONITOR_DIR, detached: true, stdio: "ignore" });
  if (proc.pid) fs.writeFileSync(DISCOVER_PID, String(proc.pid));
  proc.on("error", (e) => console.error("[auto-chain] discovery spawn error:", e.message));
  proc.on("exit", () => { try { fs.unlinkSync(DISCOVER_PID); } catch {} });
  proc.unref();
}

function startEnvScan(hostPorts: string[], deepScan: boolean): void {
  if (pidAlive(ENV_PID)) {
    console.warn("[auto-chain] env-scan already running, refusing to start");
    return;
  }
  fs.mkdirSync(DATA_DIR, { recursive: true });
  try { fs.unlinkSync(ENV_STOP); } catch {}
  try { fs.unlinkSync(ENV_OFFSET); } catch {}
  try { fs.unlinkSync(ENV_PID); } catch {}

  fs.writeFileSync(ENV_INPUT, hostPorts.join("\n") + "\n");

  if (SPAWN_DISABLED) return;

  // Ensure path-list JSON files exist for the Go scanner.
  // dump_paths.py is fast (<1s) and idempotent; safe to call every cycle.
  const pathsFast = path.join(DATA_DIR, "env_paths_fast.json");
  const pathsFull = path.join(DATA_DIR, "env_paths_full.json");
  if (!fs.existsSync(pathsFast) || !fs.existsSync(pathsFull)) {
    try {
      execSync(`${PYTHON} dump_paths.py`, { cwd: MONITOR_DIR, stdio: "ignore", timeout: 15000 });
    } catch (e) {
      console.warn("[auto-chain] dump_paths.py failed:", e);
    }
  }

  const engine = readEngineConfig();
  const hostConc = readHostConcurrencyCap();
  const baseEnv = {
    ...process.env,
    PYTHONUNBUFFERED:     "1",
    ENV_SCAN_TRIGGER:     "auto",
    ENV_SCAN_TIMEOUT:     "2",
    ENV_SCAN_CONCURRENCY: String(hostConc),
    ENV_SCAN_MAX_FAIL:    "2",
    ENV_SCAN_FULL:        deepScan ? "1" : "0",
    // Pure-Go DNS resolver — avoids cgo getaddrinfo serialization that
    // becomes a bottleneck above ~200 inflight DNS lookups.
    GODEBUG: process.env.GODEBUG && process.env.GODEBUG.includes("netdns=")
      ? process.env.GODEBUG
      : (process.env.GODEBUG ? `${process.env.GODEBUG},netdns=go+1` : "netdns=go+1"),
  };
  const proc = engine === "go"
    ? spawn(GO_BINARY, [], {
        cwd: MONITOR_DIR, detached: true,
        stdio: ["ignore", "pipe", "pipe"], env: baseEnv,
      })
    : spawn(PYTHON, ["env_scanner.py"], {
        cwd: MONITOR_DIR, detached: true,
        stdio: ["ignore", "pipe", "pipe"], env: baseEnv,
      });
  if (proc.pid) fs.writeFileSync(ENV_PID, String(proc.pid));
  const tag = `[auto-chain env/${engine}]`;
  proc.on("error", (e) => console.error(`${tag} spawn error:`, e.message));
  proc.stdout?.on("data", (d: Buffer) => process.stdout.write(`${tag} ${d}`));
  proc.stderr?.on("data", (d: Buffer) => process.stderr.write(`${tag} ${d}`));
  proc.on("exit", () => { try { fs.unlinkSync(ENV_PID); } catch {} });
  proc.unref();
}

/**
 * Spawn the deep-scan post-processor (Python). Runs one pass over any
 * new rows in env_found.jsonl and exits. Safe to call repeatedly: the
 * worker persists a byte offset and skips rows it already processed.
 *
 * No-op if a previous deep-scan is still running, if SPAWN_DISABLED is
 * set (tests), or if the script file is missing.
 */
function spawnDeepScan(): void {
  if (SPAWN_DISABLED) return;
  if (pidAlive(DEEP_SCAN_PID)) {
    console.log("[auto-chain] deep_scan already running, skipping");
    return;
  }
  if (!fs.existsSync(DEEP_SCAN_SCRIPT)) return;
  try { fs.unlinkSync(DEEP_SCAN_PID); } catch {}

  const proc = spawn(PYTHON, ["deep_scan.py"], {
    cwd: MONITOR_DIR, detached: true,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
  });
  if (proc.pid) fs.writeFileSync(DEEP_SCAN_PID, String(proc.pid));
  const tag = "[auto-chain deep_scan]";
  proc.on("error", (e) => console.error(`${tag} spawn error:`, e.message));
  proc.stdout?.on("data", (d: Buffer) => process.stdout.write(`${tag} ${d}`));
  proc.stderr?.on("data", (d: Buffer) => process.stderr.write(`${tag} ${d}`));
  proc.on("exit", () => { try { fs.unlinkSync(DEEP_SCAN_PID); } catch {} });
  proc.unref();
}

/**
 * Tick the orchestrator state machine. Called every 30 s by setInterval.
 *
 * Trigger model (event-driven, not pure timer):
 *   • idle → discovery starts when EITHER:
 *       (a) manual trigger queued via triggerAutoChain(), OR
 *       (b) auto_chain_enabled === true AND public scanner cycle finished
 *           (status.json.last_cycle_at advanced past publicCycleSeenAt)
 *           AND throttle interval has elapsed.
 *   • discovery → envscan when discover.pid exits and at least one host found.
 *   • envscan → cooldown when env_scan.pid exits.
 *   • cooldown → idle next tick.
 *
 * Skips spawning if any pid file is still alive (manual scan running).
 */
async function tick(): Promise<void> {
  const settings = readSettings();
  const state    = readState();
  const now      = Date.now();

  const intervalSec = Number(settings.auto_chain_interval_seconds ?? 1800);
  const ports       = String(settings.auto_chain_ports ?? "80,443,8080,8443");
  const maxHosts    = Number(settings.auto_chain_max_hosts ?? 200000);
  const deep        = Boolean(settings.auto_chain_deep_scan ?? false);
  const enabled     = settings.auto_chain_enabled === true;
  // How many discovery→envscan iterations to chain after each public-scanner
  // cycle before yielding back to wait for the next one. The user wants the
  // env-scanner running 24/7, so we keep looping discovery (different
  // random IP space each time) before requiring a fresh public cycle.
  const discoveriesPerRound = Math.max(1, Number(settings.auto_chain_discoveries_per_public ?? 3));
  // When true, after a 24/7 round completes, the orchestrator writes the
  // public-scanner's trigger file instead of waiting for its next scheduled
  // cycle. The classic "wait" behavior is preserved when false (default).
  const selfTriggerPublic = settings.auto_chain_self_trigger_public === true;

  switch (state.phase) {
    case "idle": {
      // Adopt an externally-started discovery (user clicked "Start" on the
      // Discovery page directly) into the chain so env-scan auto-starts on
      // completion — same behavior as auto-triggered cycles. We don't spawn
      // anything here; we just attach to the running PID and let the existing
      // discovery → envscan transition fire when it exits.
      if (pidAlive(DISCOVER_PID) && !pidAlive(ENV_PID)) {
        console.log("[auto-chain] adopting externally-started discovery into chain");
        writeState({
          ...state,
          phase: "discovery",
          startedAt: now,
          manualTriggerPending: false,
          lastTriggerSource: "manual",
          message: "adopted manual discovery — env-scan will follow",
        });
        return;
      }

      const pub = readPublicStatus();
      const publicLastCycle = pub.last_cycle_at ?? "";
      const publicCycling   = pub.cycle_in_progress === true;

      let trigger: TriggerSource | null = null;
      let reason = "";

      // Manual trigger has the highest priority — a user pressing "Run Now"
      // mid-round shouldn't wait for the loop to drain. We treat a manual
      // trigger as starting a fresh round (counter resets in the spawn
      // branch below via isFreshRound = !"loop ").
      if (state.manualTriggerPending) {
        trigger = "manual";
        reason  = "manual trigger";
      // Mid-round continuation: previous envscan ended but we're not yet
      // at discoveriesPerRound. Re-enter discovery without waiting for the
      // next public-scanner cycle. This is what keeps the chain running
      // 24/7 between public cycles.
      } else if (enabled && state.discoveryCountThisRound > 0
          && state.discoveryCountThisRound < discoveriesPerRound) {
        trigger = "auto";
        reason  = `loop ${state.discoveryCountThisRound + 1}/${discoveriesPerRound}`;
      } else if (enabled) {
        // When auto-chain is on, the public scanner's own interval timer is
        // disabled inside search_monitor — so we must own the cadence.
        // Check for edge / kick BEFORE the chain-throttle gate, otherwise
        // we'd sit for `intervalSec` not even allowing public to run.
        // The throttle below only gates starting a new CHAIN round (which
        // is heavy: TCP scan → env scan), not the lightweight act of
        // writing trigger_cycle.
        if (publicLastCycle && publicLastCycle === state.publicCycleSeenAt
            && !publicCycling) {
          try {
            fs.writeFileSync(TRIGGER_FILE, String(Date.now()));
            writeState({ ...state, message: "kicked public scanner (auto-chain owns cadence)" });
            console.log("[auto-chain] kicked public via trigger_cycle (no edge yet)");
          } catch (e) {
            console.error("[auto-chain] failed to write trigger_cycle:", e);
          }
          return;
        }
        // Throttle: don't run a new chain round more often than the configured interval.
        if (now - state.lastCycleAt < intervalSec * 1000) {
          const waitSec = Math.ceil((intervalSec * 1000 - (now - state.lastCycleAt)) / 1000);
          const msg = `cooldown ${waitSec}s until next chain cycle`;
          if (state.message !== msg) writeState({ ...state, message: msg });
          return;
        }
        // React to the EDGE of last_cycle_at advancing — even if the public
        // scanner has already started its next cycle (back-to-back cycles
        // happen when interval < cycle duration). Public scanner uses HTTP
        // APIs, our chain uses raw TCP — no socket contention.
        if (publicLastCycle && publicLastCycle !== state.publicCycleSeenAt) {
          trigger = "auto";
          reason  = `public cycle ${publicLastCycle}`;
        } else if (!publicLastCycle) {
          if (state.message !== "awaiting first public cycle") {
            writeState({ ...state, message: "awaiting first public cycle" });
          }
          return;
        } else {
          // Already reacted to this cycle, wait for the next one.
          const msg = publicCycling
            ? "monitoring public cycle (already reacted to last)"
            : "waiting for next public cycle";
          if (state.message !== msg) writeState({ ...state, message: msg });
          return;
        }
      }
      if (!trigger) return;

      if (pidAlive(DISCOVER_PID) || pidAlive(ENV_PID)) {
        // Manual scan in flight — defer; clear pending so we don't hammer.
        writeState({
          ...state,
          message: "deferred: manual scan in progress",
        });
        return;
      }

      console.log(`[auto-chain] starting discovery (${reason})`);
      startDiscovery(ports, maxHosts);
      // Reset the round counter on a fresh public-cycle edge or manual
      // trigger; otherwise (mid-round loop) keep counting up.
      const isFreshRound = !reason.startsWith("loop ");
      writeState({
        ...state,
        phase: "discovery",
        startedAt: now,
        publicCycleSeenAt: publicLastCycle || state.publicCycleSeenAt,
        manualTriggerPending: false,
        lastTriggerSource: trigger,
        message: `discovery (${reason}, max ${maxHosts} hosts)`,
        discoveryCountThisRound: isFreshRound ? 1 : state.discoveryCountThisRound + 1,
      });
      break;
    }

    case "discovery": {
      if (pidAlive(DISCOVER_PID)) return;
      const entries = await readDiscoveredHostPorts();
      if (!entries.length) {
        console.log("[auto-chain] discovery → no hosts, cooldown");
        writeState({
          ...state,
          phase: "cooldown",
          lastCycleAt: now,
          message: "no hosts discovered",
        });
        return;
      }
      console.log(`[auto-chain] discovery → env-scan, ${entries.length} entries (deep=${deep})`);
      startEnvScan(entries, deep);
      writeState({
        ...state,
        phase: "envscan",
        startedAt: now,
        message: `env scan ${entries.length} entries`,
      });
      break;
    }

    case "envscan": {
      if (pidAlive(ENV_PID)) return;
      // Env scan just finished — kick the deep-scan post-processor in the
      // background. It re-runs the full Python pattern set on every new
      // env_found.jsonl entry's content_preview, catching anything the
      // (faster but RE2-limited) Go engine missed (heavy multi-line
      // patterns, future Python-only patterns, etc.). Idempotent: keeps
      // a byte-offset so it only processes new rows.
      spawnDeepScan();
      const remaining = discoveriesPerRound - state.discoveryCountThisRound;
      const willLoop = enabled && remaining > 0;
      // Round just finished: if self-trigger is enabled (or auto-chain is
      // enabled at all — when on, public scanner's own interval timer is
      // disabled inside search_monitor, so we MUST self-trigger or the
      // chain stalls forever waiting for the next public cycle that will
      // never come) and the public scanner isn't already cycling, kick
      // it now.
      let triggeredPublic = false;
      const needSelfTrigger = enabled && (selfTriggerPublic || enabled);
      if (!willLoop && needSelfTrigger) {
        const pub = readPublicStatus();
        if (!pub.cycle_in_progress) {
          try {
            fs.writeFileSync(TRIGGER_FILE, String(Date.now()));
            triggeredPublic = true;
            console.log("[auto-chain] round done — triggered public scanner via trigger_cycle file");
          } catch (e) {
            console.error("[auto-chain] failed to write trigger_cycle:", e);
          }
        } else {
          console.log("[auto-chain] round done — public scanner already cycling, no self-trigger needed");
        }
      }
      console.log(`[auto-chain] env scan complete (round ${state.discoveryCountThisRound}/${discoveriesPerRound}), ${willLoop ? "looping back to discovery" : "round done — awaiting next public cycle"}`);
      writeState({
        ...state,
        phase: "cooldown",
        lastCycleAt: now,
        message: willLoop
          ? `env scan complete — looping (${state.discoveryCountThisRound}/${discoveriesPerRound} done)`
          : triggeredPublic
            ? `round done — triggered public scanner (${discoveriesPerRound} iterations)`
            : `env scan complete — round done (${discoveriesPerRound} iterations)`,
      });
      break;
    }

    case "cooldown": {
      // If we've finished the configured number of discovery iterations
      // for this round, reset the counter so the next public-cycle edge
      // starts a fresh round. Otherwise leave count > 0 so the idle
      // branch immediately re-enters discovery on the next tick.
      const roundDone = state.discoveryCountThisRound >= discoveriesPerRound;
      writeState({
        ...state,
        phase: "idle",
        startedAt: 0,
        message: roundDone ? "idle" : `mid-round (${state.discoveryCountThisRound}/${discoveriesPerRound})`,
        discoveryCountThisRound: roundDone ? 0 : state.discoveryCountThisRound,
      });
      break;
    }
  }
}

// Re-entrancy guard. setInterval fires every 30 s, but tick() does I/O
// and could in theory exceed that. Without this guard two ticks could
// overlap and double-spawn.
let _ticking = false;
async function safeTick(): Promise<void> {
  if (_ticking) return;
  _ticking = true;
  try {
    await tick();
  } catch (e) {
    console.error("[auto-chain]", e);
  } finally {
    _ticking = false;
  }
}

/**
 * Reconcile chain state at startup. If the api-server crashed mid-cycle,
 * the persisted phase may not match reality (no live PID). Drop back to
 * cooldown so the next tick re-evaluates cleanly.
 */
function reconcileStateOnStartup(): void {
  const state = readState();
  if (state.phase === "discovery" && !pidAlive(DISCOVER_PID)) {
    console.log("[auto-chain] reconcile: discovery phase but no live pid → cooldown");
    writeState({ ...state, phase: "cooldown", lastCycleAt: Date.now(), message: "recovered after restart" });
  } else if (state.phase === "envscan" && !pidAlive(ENV_PID)) {
    console.log("[auto-chain] reconcile: envscan phase but no live pid → cooldown");
    writeState({ ...state, phase: "cooldown", lastCycleAt: Date.now(), message: "recovered after restart" });
  }
}

// ──────────────────────────────────────────────────────────────────────────
// Storage cleanup: with 24/7 looping, jsonl logs grow without bound.
// We trim the bulky write-mostly logs to a sane tail-size every hour.
// Keys (found_keys.jsonl) and the small history files are NOT touched
// here — the user wants those preserved.
// ──────────────────────────────────────────────────────────────────────────

const ARCHIVE_DIR = path.join(DATA_DIR, "archive");

// Files trimmed with archive=true have their removed (oldest) lines saved to
// monitor/data/archive/<basename>_YYYY-MM.jsonl before the trim so that
// nothing is ever truly lost. The archive files grow month by month but are
// never auto-deleted — with 458 GB free on the VPS, disk pressure is not a
// concern; data integrity is.
interface TrimSpec { file: string; keep: number; archive?: boolean; }
const TRIM_TARGETS: TrimSpec[] = [
  { file: path.join(DATA_DIR, "results.jsonl"),          keep:   100_000 },  // was 1_000_000 — too large for V8 string
  { file: path.join(DATA_DIR, "new_results.jsonl"),      keep:    50_000 },
  { file: path.join(DATA_DIR, "discover_found.jsonl"),   keep:   200_000 },
  { file: path.join(DATA_DIR, "env_found.jsonl"),        keep:    50_000, archive: true },  // was 200_000
  { file: path.join(DATA_DIR, "env_scan_history.jsonl"), keep:    10_000 },
];

function archiveHead(lines: string[], basename: string): void {
  try {
    fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
    const now  = new Date();
    const tag  = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
    const dest = path.join(ARCHIVE_DIR, `${basename}_${tag}.jsonl`);
    // Append so multiple cleanups in the same month accumulate in one file.
    fs.appendFileSync(dest, lines.join("\n") + "\n");
  } catch (e) {
    console.error(`[auto-chain] archive ${basename} failed:`, e);
  }
}

function trimJsonl(file: string, keep: number, archive = false): { trimmed: boolean; removed: number } {
  try {
    if (!fs.existsSync(file)) return { trimmed: false, removed: 0 };
    // Use shell wc -l so we never load the whole file into a V8 string.
    // V8 string limit is ~512 MB — results.jsonl routinely exceeds that.
    const totalStr = execSync(`wc -l < "${file}"`, { encoding: "utf-8" }).trim();
    const totalLines = parseInt(totalStr, 10);
    if (isNaN(totalLines) || totalLines <= keep) return { trimmed: false, removed: 0 };
    const removed = totalLines - keep;
    if (archive && removed > 0) {
      try {
        fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
        const now = new Date();
        const tag = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
        const dest = path.join(ARCHIVE_DIR, `${path.basename(file, ".jsonl")}_${tag}.jsonl`);
        execSync(`head -n ${removed} "${file}" >> "${dest}"`, { encoding: "utf-8" });
      } catch (archiveErr) {
        console.error(`[auto-chain] archive ${path.basename(file)} failed:`, archiveErr);
      }
    }
    // tail to .tmp then atomic rename — readers always see a complete file.
    const tmp = file + ".tmp";
    execSync(`tail -n ${keep} "${file}" > "${tmp}" && mv "${tmp}" "${file}"`, { encoding: "utf-8" });
    return { trimmed: true, removed };
  } catch (e) {
    console.error(`[auto-chain] trim ${path.basename(file)} failed:`, e);
    return { trimmed: false, removed: 0 };
  }
}

function runStorageCleanup(): void {
  let totalRemoved = 0;
  const trimmed: string[] = [];
  for (const t of TRIM_TARGETS) {
    const r = trimJsonl(t.file, t.keep, t.archive ?? false);
    if (r.trimmed) {
      totalRemoved += r.removed;
      trimmed.push(`${path.basename(t.file)}(-${r.removed})`);
    }
  }
  if (totalRemoved > 0) {
    console.log(`[auto-chain] storage cleanup: removed ${totalRemoved} old lines [${trimmed.join(", ")}]`);
  }
}

export function startAutoChainOrchestrator(): void {
  reconcileStateOnStartup();
  // Kick first tick after 15 s so any manual scans have settled.
  setTimeout(safeTick, 15_000);
  setInterval(safeTick, 30_000);
  // Storage cleanup: run once 5 min after start, then every hour.
  // Keeps results.jsonl etc. from growing unbounded under 24/7 looping.
  setTimeout(runStorageCleanup, 5 * 60_000);
  setInterval(runStorageCleanup, 60 * 60_000);
  console.log("[auto-chain] orchestrator started (24/7 loop + hourly cleanup)");
}

/**
 * Manual trigger from the UI ("Run Now" button). Sets a one-shot flag and
 * kicks the tick loop so the user doesn't wait up to 30 s.
 */
export function triggerAutoChain(): {
  queued: boolean;
  phase: ChainPhase;
  message: string;
} {
  const state = readState();
  if (state.phase !== "idle") {
    return {
      queued: false,
      phase: state.phase,
      message: `chain already in ${state.phase}`,
    };
  }
  if (pidAlive(DISCOVER_PID) || pidAlive(ENV_PID)) {
    // Queue anyway — the tick loop will pick it up once the in-flight
    // scanner exits — but tell the UI it's queued, not running.
    writeState({
      ...state,
      manualTriggerPending: true,
      message: "manual trigger queued (waiting for current scan)",
    });
    return {
      queued: true,
      phase: state.phase,
      message: "queued, waiting for current manual scan to finish",
    };
  }
  writeState({
    ...state,
    manualTriggerPending: true,
    message: "manual trigger queued",
  });
  setImmediate(() => { safeTick().catch(() => {}); });
  return { queued: true, phase: "idle", message: "manual trigger queued" };
}

export function getAutoChainStatus(): {
  phase: ChainPhase;
  message: string;
  startedAt: number;
  lastCycleAt: number;
  publicCycleSeenAt: string;
  manualTriggerPending: boolean;
  lastTriggerSource: TriggerSource | null;
  discoveryRunning: boolean;
  envScanRunning: boolean;
  publicCycleInProgress: boolean;
  publicLastCycleAt: string;
  discoveryCountThisRound: number;
  discoveriesPerRound: number;
} {
  const state = readState();
  const pub = readPublicStatus();
  const settings = readSettings();
  return {
    phase: state.phase,
    message: state.message,
    startedAt: state.startedAt,
    lastCycleAt: state.lastCycleAt,
    publicCycleSeenAt: state.publicCycleSeenAt,
    manualTriggerPending: state.manualTriggerPending,
    lastTriggerSource: state.lastTriggerSource,
    discoveryRunning: pidAlive(DISCOVER_PID),
    envScanRunning:   pidAlive(ENV_PID),
    publicCycleInProgress: pub.cycle_in_progress === true,
    publicLastCycleAt: pub.last_cycle_at ?? "",
    discoveryCountThisRound: state.discoveryCountThisRound,
    discoveriesPerRound: Math.max(1, Number(settings.auto_chain_discoveries_per_public ?? 3)),
  };
}

// Backwards-compat alias used elsewhere.
export const getAutoChainState = getAutoChainStatus;

// ──────────────────────────────────────────────────────────────────────────
// Test-only exports. Not part of the public API. The orchestrator's tick()
// loop is tested by exercising it directly against an isolated temp dir
// (set via AUTO_CHAIN_MONITOR_DIR + AUTO_CHAIN_DISABLE_SPAWN) so the state
// transitions can be verified without any python subprocess running.
export const __test = {
  tick,
  reconcileStateOnStartup,
  readState,
  writeState,
  paths: {
    DATA_DIR,
    SETTINGS_FILE,
    PUBLIC_STATUS,
    DISCOVER_PID,
    DISCOVER_RES,
    ENV_PID,
    ENV_INPUT,
    CHAIN_STATE,
  },
};

/**
 * Called by /api/discover/start right after a manual discovery is spawned.
 * Kicks the orchestrator immediately so the chain adopts the running
 * discovery without waiting up to 30 s for the next interval tick.
 */
export function notifyExternalDiscoveryStarted(): void {
  setImmediate(() => { safeTick().catch(() => {}); });
}

// ──────────────────────────────────────────────────────────────────────────
// Manual Mode — one-click "stop everything & disable autostart" toggle.
//
// When ON:
//   • auto_chain_enabled is forced to false   → orchestrator stops spawning
//   • manual_mode is set to true              → public scanner (search_monitor.py)
//                                                stops starting new cycles
//   • any in-flight discovery / env-scan is killed (stop file + SIGTERM/KILL + pkill)
//   • chain state is reset to idle so nothing is "stuck" mid-phase
//
// When OFF:
//   • auto_chain_enabled is restored to true
//   • manual_mode cleared → public scanner resumes its normal cadence
//   • the orchestrator is kicked immediately so 24/7 looping restarts at once
//
// The previous auto_chain_enabled value is remembered so turning manual mode
// off restores exactly what the user had before (defaults to true).
// ──────────────────────────────────────────────────────────────────────────

function pkillSilent(pattern: string): void {
  try { execSync(`pkill -f "${pattern}"`, { stdio: "ignore" }); } catch {}
}

function killByPidFile(pidFile: string): void {
  try {
    const pid = parseInt(fs.readFileSync(pidFile, "utf-8").trim(), 10);
    if (!isNaN(pid)) {
      try { process.kill(pid, "SIGTERM"); } catch {}
      setTimeout(() => { try { process.kill(pid, "SIGKILL"); } catch {} }, 2000);
    }
  } catch {}
}

/**
 * Forcibly stop every active scan: discovery and env-scan, both Python and Go
 * engines. Writes the stop files first (graceful), then signals by PID, then
 * pkills by process pattern as a backstop. Idempotent and safe to call when
 * nothing is running.
 */
export function stopAllScans(): void {
  // env-scan: graceful stop file + kill pid + pkill both engines
  try { fs.writeFileSync(ENV_STOP, "1"); } catch {}
  killByPidFile(ENV_PID);
  pkillSilent("env_scanner.py");
  pkillSilent("go-scanner/bin/env-scanner");
  try { fs.unlinkSync(ENV_PID); } catch {}

  // discovery: graceful stop file + kill pid + pkill both engines
  try { fs.writeFileSync(DISCOVER_STOP, "1"); } catch {}
  killByPidFile(DISCOVER_PID);
  pkillSilent("host_discover.py");
  pkillSilent("host-discover");
  try { fs.unlinkSync(DISCOVER_PID); } catch {}

  // Reset chain state to idle so the orchestrator doesn't think a phase is
  // still in flight on the next tick.
  const state = readState();
  writeState({
    ...state,
    phase: "idle",
    startedAt: 0,
    manualTriggerPending: false,
    discoveryCountThisRound: 0,
    message: "manual mode: all scans stopped",
  });
}

/** True if manual mode is currently active (reads settings.json). */
export function getManualMode(): boolean {
  const s = readSettings();
  return s.manual_mode === true;
}

/**
 * Toggle manual mode.
 *
 * @param enable true → enter manual mode (stop everything); false → leave it.
 * @returns the resulting state for the UI.
 */
export function setManualMode(enable: boolean): {
  manualMode: boolean;
  autoChainEnabled: boolean;
  stopped: boolean;
} {
  const settings = readSettings();

  if (enable) {
    // Remember what auto_chain_enabled was so we can restore it later.
    const prev = settings.auto_chain_enabled === true;
    const updated = {
      ...settings,
      manual_mode: true,
      auto_chain_enabled: false,
      manual_mode_prev_auto_chain: prev,
    };
    writeJson(SETTINGS_FILE, updated);
    stopAllScans();
    return { manualMode: true, autoChainEnabled: false, stopped: true };
  }

  // Leaving manual mode — restore previous auto-chain setting (default true so
  // 24/7 scanning comes back on even if it was somehow never set before).
  const restore = settings.manual_mode_prev_auto_chain === false ? false : true;
  const updated: Record<string, unknown> = {
    ...settings,
    manual_mode: false,
    auto_chain_enabled: restore,
  };
  delete updated.manual_mode_prev_auto_chain;
  writeJson(SETTINGS_FILE, updated);

  // Kick the orchestrator immediately so 24/7 looping resumes without waiting
  // up to 30 s for the next interval tick.
  setImmediate(() => { safeTick().catch(() => {}); });

  return { manualMode: false, autoChainEnabled: restore, stopped: false };
}
