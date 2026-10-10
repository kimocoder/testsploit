import { Router } from "express";
import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import readline from "readline";
import { execSync } from "child_process";
import { notifyExternalDiscoveryStarted } from "./auto-chain.js";

const MONITOR_DIR  = path.resolve(__dirname, "../../../monitor");
const DATA_DIR     = path.join(MONITOR_DIR, "data");
const STATUS_FILE  = path.join(DATA_DIR, "discover_status.json");
const RESULTS_FILE = path.join(DATA_DIR, "discover_found.jsonl");
const STOP_FILE    = path.join(DATA_DIR, "discover_stop");
const INPUT_FILE   = path.join(DATA_DIR, "discover_input.txt");
const PID_FILE          = path.join(DATA_DIR, "discover.pid");
const UNIQUE_MODE_FILE  = path.join(DATA_DIR, "discover_unique_mode.json");

const PYTHON = process.env.PYTHON_BIN
  ?? "/home/runner/workspace/.pythonlibs/bin/python3";

// Go host-discover binary: built by monitor/go-discover/build.sh. We prefer
// it over the Python script because it sustains 1500-2000 IP/s vs Python's
// asyncio comfortably here). If the binary is missing (fresh checkout, no
// build run) we fall back to Python so the feature never silently breaks.
const GO_DISCOVER_BIN = path.resolve(MONITOR_DIR, "go-discover/bin/host-discover");
function goDiscoverAvailable(): boolean {
  try { fs.accessSync(GO_DISCOVER_BIN, fs.constants.X_OK); return true; }
  catch { return false; }
}

function readStatus(): object {
  try { return JSON.parse(fs.readFileSync(STATUS_FILE, "utf-8")); }
  catch { return { running: false, processed: 0, total: 0, found: 0, currentAction: "idle", updatedAt: null }; }
}

async function readResults(limit = 200, page = 1) {
  if (!fs.existsSync(RESULTS_FILE)) return { items: [], total: 0, page: 1, pages: 0 };
  const lines: string[] = [];
  const rl = readline.createInterface({ input: fs.createReadStream(RESULTS_FILE) });
  for await (const line of rl) { if (line.trim()) lines.push(line); }
  const total = lines.length;
  const pages = Math.max(1, Math.ceil(total / limit));
  const items = lines.slice((page - 1) * limit, page * limit)
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
  return { items, total, page, pages };
}

function getDiscoverPid(): number | null {
  try {
    const pid = parseInt(fs.readFileSync(PID_FILE, "utf-8").trim(), 10);
    if (isNaN(pid)) return null;
    process.kill(pid, 0);
    return pid;
  } catch { return null; }
}

function isRunning(): boolean {
  return getDiscoverPid() !== null;
}

function killDiscover(): void {
  try { fs.writeFileSync(STOP_FILE, "1"); } catch {}
  const pid = getDiscoverPid();
  if (pid) {
    try { process.kill(pid, "SIGTERM"); } catch {}
    setTimeout(() => { try { process.kill(pid, "SIGKILL"); } catch {} }, 2000);
  }
  try { execSync("pkill -f host_discover.py", { stdio: "ignore" }); } catch {}
  try { execSync("pkill -f host-discover",    { stdio: "ignore" }); } catch {}
  try { fs.unlinkSync(PID_FILE); } catch {}
}

export function buildDiscoverRouter() {
  const r = Router();

  r.get("/status", (_req, res) => {
    const st = readStatus() as any;
    res.json({ ...st, running: isRunning(), pid: getDiscoverPid() });
  });

  r.post("/start", (req, res) => {
    if (isRunning()) {
      return res.json({ success: false, message: "Already running" });
    }

    const {
      targets     = "",
      ports       = "80,443,8080,8443",
      timeout     = 1,
      concurrency = 1000,
      maxHosts    = 50000,
      batch       = 500,
      uniqueMode  = null,   // null = use saved setting
    } = req.body ?? {};
    // Read/update unique mode setting
    let skipSeen = true;
    try {
      const saved = JSON.parse(fs.readFileSync(UNIQUE_MODE_FILE, "utf-8"));
      skipSeen = saved.uniqueMode !== false;
    } catch {}
    if (uniqueMode !== null) {
      skipSeen = Boolean(uniqueMode);
      fs.writeFileSync(UNIQUE_MODE_FILE, JSON.stringify({ uniqueMode: skipSeen }));
    }

    fs.mkdirSync(DATA_DIR, { recursive: true });
    try { fs.unlinkSync(STOP_FILE); } catch {}
    try { fs.unlinkSync(PID_FILE);  } catch {}
    // Wipe previous-run artifacts so the "Send all" button only forwards
    // hosts from THIS run. host_discover.py opens RESULTS_FILE in append
    // mode, so without this cleanup old runs leak into the env-scan input
    // (e.g. 2151 entries from 1820 freshly-found hosts + 331 stale).
    try { fs.unlinkSync(RESULTS_FILE); } catch {}
    try { fs.unlinkSync(STATUS_FILE);  } catch {}

    if (targets && targets.trim()) {
      fs.writeFileSync(INPUT_FILE, targets);
    } else {
      try { fs.unlinkSync(INPUT_FILE); } catch {}
    }

    // Engine selection: prefer Go (4-5x throughput) but accept body.engine
    // override for A/B comparison. Go ignores --batch (it streams via a
    // bounded channel instead of asyncio.gather chunks).
    const engineReq = String((req.body ?? {}).engine ?? "go").toLowerCase();
    const useGo = engineReq !== "py" && goDiscoverAvailable();
    const proc = useGo
      ? spawn(GO_DISCOVER_BIN, [
          "-ports",       ports,
          "-timeout",     String(timeout),
          "-concurrency", String(concurrency),
          "-max-hosts",   String(maxHosts),
        ], { cwd: MONITOR_DIR, detached: true, stdio: "ignore" })
      : spawn(PYTHON, [
          path.join(MONITOR_DIR, "host_discover.py"),
          "--batch",       String(batch),
          "--ports",       ports,
          "--timeout",     String(timeout),
          "--concurrency", String(concurrency),
          "--max-hosts",   String(maxHosts),
          skipSeen ? "--skip-seen" : "--no-skip-seen",
        ], { cwd: MONITOR_DIR, detached: true, stdio: "ignore" });

    if (proc.pid) fs.writeFileSync(PID_FILE, String(proc.pid));
    proc.on("exit", () => { try { fs.unlinkSync(PID_FILE); } catch {} });
    proc.unref();

    // Tell the auto-chain orchestrator to adopt this manual discovery so
    // env-scan auto-starts on completion.
    notifyExternalDiscoveryStarted();

    const hostCount = targets?.trim()
      ? targets.split(/[\n,]+/).filter((s: string) => s.trim()).length
      : maxHosts;

    return res.json({ success: true, mode: targets?.trim() ? "custom" : "random", hosts: hostCount, uniqueMode: skipSeen });
  });

  r.post("/stop", (_req, res) => {
    killDiscover();
    try {
      const st = readStatus() as any;
      st.running = false;
      st.currentAction = "stopped by user";
      fs.writeFileSync(STATUS_FILE, JSON.stringify(st));
    } catch {}
    res.json({ success: true });
  });

  r.get("/results", async (req, res) => {
    const limit = Number(req.query.limit ?? 200);
    const page  = Number(req.query.page  ?? 1);
    res.json(await readResults(limit, page));
  });

  r.delete("/results", (_req, res) => {
    try { fs.unlinkSync(RESULTS_FILE); } catch {}
    try { fs.unlinkSync(STATUS_FILE);  } catch {}
    res.json({ success: true });
  });

  r.get("/export", async (_req, res) => {
    const { items } = await readResults(100000);
    const lines = (items as any[]).map((i: any) => i.host || i.url).filter(Boolean);
    res.setHeader("Content-Type", "text/plain");
    res.send(lines.join("\n"));
  });



  // GET /discover/unique-mode ? get current setting
  r.get("/unique-mode", (_req, res) => {
    let uniqueMode = true;
    try {
      const saved = JSON.parse(fs.readFileSync(UNIQUE_MODE_FILE, "utf-8"));
      uniqueMode = saved.uniqueMode !== false;
    } catch {}
    const seenFile = path.join(DATA_DIR, "discover_seen_hosts.txt");
    const seenCount = fs.existsSync(seenFile)
      ? fs.readFileSync(seenFile, "utf-8").trim().split("\n").filter(Boolean).length
      : 0;
    res.json({ uniqueMode, seenCount });
  });

  // POST /discover/unique-mode ? set { uniqueMode: bool }
  r.post("/unique-mode", (req, res) => {
    const uniqueMode = Boolean((req.body ?? {}).uniqueMode);
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(UNIQUE_MODE_FILE, JSON.stringify({ uniqueMode }));
    res.json({ success: true, uniqueMode });
  });

  // GET /discover/seen/count
  r.get("/seen/count", (_req, res) => {
    const seenFile = path.join(DATA_DIR, "discover_seen_hosts.txt");
    try {
      const count = fs.existsSync(seenFile)
        ? fs.readFileSync(seenFile, "utf-8").trim().split("\n").filter(Boolean).length
        : 0;
      res.json({ count });
    } catch { res.json({ count: 0 }); }
  });

  // DELETE /discover/seen
  r.delete("/seen", (_req, res) => {
    const seenFile = path.join(DATA_DIR, "discover_seen_hosts.txt");
    try {
      if (fs.existsSync(seenFile)) fs.unlinkSync(seenFile);
      res.json({ success: true, message: "Cleared seen hosts history" });
    } catch (err) { res.status(500).json({ error: String(err) }); }
  });

  return r;
}
