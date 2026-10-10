import React, { useState, useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { toast } from "sonner";
import {
  Server, RefreshCw, ExternalLink, Wifi, Activity,
  Cpu, MemoryStick, Key, CheckCircle2, Clock, Zap, AlertTriangle,
  ChevronRight, Globe, Radar, BarChart2, Plus, Trash2, TestTube2,
  Settings2, Eye, EyeOff, XCircle, List,
} from "lucide-react";
import { Link } from "wouter";

// ── Types ──────────────────────────────────────────────────────────────────────

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

interface ServerStats {
  keysFound: number;
  keysValid: number;
  keysUnchecked: number;
  keysInvalid: number;
  keysWithBedrock: number;
  serviceBreakdown: Record<string, number>;
}

interface FleetServerEntry {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  addedAt: string;
  online: boolean;
  lastSeenAt: number | null;
  lastError: string | null;
  stats: ServerStats | null;
  status: ServerStatus | null;
  sysInfo: SysInfo | null;
  keysInCache: number;
}

interface FleetStatus {
  enabled: boolean;
  servers: FleetServerEntry[];
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtBytes(b: number): string {
  if (b < 1024) return `${b}B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(0)}KB`;
  return `${(b / 1024 / 1024).toFixed(1)}GB`;
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

function LoadBar({ load, cpus }: { load: number; cpus: number }) {
  const pct = Math.min(100, Math.round((load / cpus) * 100));
  const color = pct < 50 ? "bg-emerald-500" : pct < 80 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2 text-xs font-mono">
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-muted-foreground w-8 text-right">{load.toFixed(1)}</span>
    </div>
  );
}

function MemBar({ avail, total }: { avail: number; total: number }) {
  const used = total - avail;
  const pct = total > 0 ? Math.round((used / total) * 100) : 0;
  const color = pct < 60 ? "bg-sky-500" : pct < 85 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2 text-xs font-mono">
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-muted-foreground">{fmtBytes(used)}/{fmtBytes(total)}</span>
    </div>
  );
}

function ScanActivity({ status }: { status: ServerStatus | null }) {
  if (!status) return <span className="text-muted-foreground/50 font-mono text-[10px]">—</span>;

  const phase = status.autoChainPhase;
  const chainActive = phase === "discovery" || phase === "envscan";

  if (chainActive) {
    const color = phase === "discovery" ? "text-cyan-400" : "text-amber-400";
    const label = phase === "discovery" ? "DISCOVERY" : "ENV SCAN";
    return (
      <div className="flex items-center gap-1.5">
        <span className={`w-1.5 h-1.5 rounded-full ${color.replace("text-", "bg-")} animate-pulse`} />
        <span className={`font-mono text-[10px] ${color} font-bold`}>{label}</span>
        {status.cycleInProgress && status.cycleProgress && (
          <span className="font-mono text-[10px] text-muted-foreground">
            {Math.round((status.cycleProgress.done / Math.max(1, status.cycleProgress.total)) * 100)}%
          </span>
        )}
      </div>
    );
  }

  if (status.running) {
    return (
      <div className="flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
        <span className="font-mono text-[10px] text-primary">SCANNING</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-1.5">
      <span className="w-1.5 h-1.5 rounded-full bg-muted-foreground/40" />
      <span className="font-mono text-[10px] text-muted-foreground">IDLE</span>
    </div>
  );
}

// ── Manage Servers Modal ───────────────────────────────────────────────────────

interface FleetServerCfg {
  id: string;
  name: string;
  url: string;
  password: string;
  enabled: boolean;
  addedAt: string;
}

function ManageServersModal({
  open,
  onClose,
  onChanged,
}: {
  open: boolean;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [servers, setServers]   = useState<FleetServerCfg[]>([]);
  const [loading, setLoading]   = useState(false);
  const [adding, setAdding]     = useState(false);
  const [testRes, setTestRes]   = useState<Record<string, { ok: boolean; msg: string } | "loading">>({});
  const [showPw, setShowPw]     = useState<Record<string, boolean>>({});

  const [newName, setNewName] = useState("");
  const [newUrl, setNewUrl]   = useState("");
  const [newPass, setNewPass] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/fleet/config");
      const d = await r.json() as { servers: FleetServerCfg[] };
      setServers(d.servers ?? []);
    } catch { /* ignore */ }
    finally { setLoading(false); }
  };

  useEffect(() => { if (open) void load(); }, [open]);

  const handleAdd = async () => {
    if (!newUrl || !newPass) { toast.error("URL and password required"); return; }
    setAdding(true);
    try {
      const r = await fetch("/api/fleet/servers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newName || newUrl, url: newUrl, password: newPass }),
      });
      const d = await r.json() as FleetServerCfg & { error?: string };
      if (r.ok) {
        setServers((s) => [...s, d]);
        setNewName(""); setNewUrl(""); setNewPass("");
        toast.success("Server added");
        onChanged();
      } else {
        toast.error(d.error ?? "Failed");
      }
    } catch { toast.error("Network error"); }
    finally { setAdding(false); }
  };

  const handleRemove = async (id: string, name: string) => {
    if (!window.confirm(`Remove "${name}" from fleet?`)) return;
    try {
      await fetch(`/api/fleet/servers/${id}`, { method: "DELETE" });
      setServers((s) => s.filter((x) => x.id !== id));
      toast.success("Removed");
      onChanged();
    } catch { toast.error("Failed"); }
  };

  const handleToggle = async (id: string, enabled: boolean) => {
    try {
      await fetch(`/api/fleet/servers/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled }),
      });
      setServers((s) => s.map((x) => x.id === id ? { ...x, enabled } : x));
      onChanged();
    } catch { toast.error("Failed"); }
  };

  const handleTest = async (id: string) => {
    setTestRes((t) => ({ ...t, [id]: "loading" }));
    try {
      const r = await fetch(`/api/fleet/servers/${id}/test`, { method: "POST" });
      const d = await r.json() as { ok: boolean; keysFound?: number; error?: string };
      setTestRes((t) => ({
        ...t,
        [id]: { ok: d.ok, msg: d.ok ? `✓ Connected · ${d.keysFound ?? 0} keys` : (d.error ?? "Failed") },
      }));
    } catch {
      setTestRes((t) => ({ ...t, [id]: { ok: false, msg: "Network error" } }));
    }
  };

  const handleRegister = async (server: FleetServerCfg) => {
    const myUrl = window.location.origin;
    try {
      const r = await fetch(`/api/fleet/servers/${server.id}/register-on-slave`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ masterUrl: myUrl, masterName: "Main Panel" }),
      });
      if (r.ok) toast.success(`FEDERATED indicator registered on ${server.name}`);
      else toast.error("Registration failed — test connection first");
    } catch { toast.error("Failed"); }
  };

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-w-xl w-full max-h-[85vh] overflow-y-auto bg-card border-border font-mono">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm font-mono">
            <Settings2 className="w-4 h-4 text-primary" />
            <span className="text-primary uppercase">Manage Fleet Servers</span>
            <Badge className="ml-auto bg-muted text-muted-foreground border-border text-xs">
              {servers.length} servers
            </Badge>
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 text-xs">
          {/* Server list */}
          {loading ? (
            <div className="py-6 text-center text-muted-foreground animate-pulse">Loading…</div>
          ) : servers.length === 0 ? (
            <div className="py-4 text-center text-muted-foreground">No servers added yet</div>
          ) : (
            <div className="space-y-2">
              {servers.map((server) => {
                const tr = testRes[server.id];
                const pw = showPw[server.id];
                return (
                  <div key={server.id}
                    className={`border rounded-lg p-3 space-y-2 ${server.enabled ? "border-border" : "border-border/40 opacity-60"}`}>
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <Switch
                          checked={server.enabled}
                          onCheckedChange={(v) => void handleToggle(server.id, v)}
                          className="scale-75 shrink-0"
                        />
                        <div className="min-w-0">
                          <div className="font-bold text-foreground truncate">{server.name}</div>
                          <div className="text-[10px] text-muted-foreground truncate">{server.url}</div>
                        </div>
                      </div>
                      <div className="flex gap-1 shrink-0">
                        <Button variant="ghost" size="sm" className="h-7 text-xs gap-1 text-muted-foreground"
                          onClick={() => void handleTest(server.id)} disabled={tr === "loading"}>
                          {tr === "loading"
                            ? <RefreshCw className="w-3 h-3 animate-spin" />
                            : <TestTube2 className="w-3 h-3" />}
                          Test
                        </Button>
                        <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive/70 hover:text-destructive"
                          onClick={() => void handleRemove(server.id, server.name)}>
                          <Trash2 className="w-3.5 h-3.5" />
                        </Button>
                      </div>
                    </div>

                    {/* Password */}
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-muted-foreground w-14 shrink-0">Password</span>
                      <code className="text-[10px] text-muted-foreground flex-1 truncate">
                        {pw ? server.password : "••••••••"}
                      </code>
                      <button onClick={() => setShowPw((p) => ({ ...p, [server.id]: !p[server.id] }))}
                        className="text-muted-foreground hover:text-foreground shrink-0">
                        {pw ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                      </button>
                      <Button variant="ghost" size="sm" className="h-6 text-[10px] gap-1 text-muted-foreground shrink-0"
                        onClick={() => void handleRegister(server)} title="Send FEDERATED indicator to slave">
                        <Wifi className="w-2.5 h-2.5" /> Register
                      </Button>
                    </div>

                    {/* Test result */}
                    {tr && tr !== "loading" && (
                      <div className={`flex items-center gap-1.5 text-[10px] px-2 py-1 rounded ${tr.ok ? "bg-emerald-500/10 text-emerald-400" : "bg-destructive/10 text-destructive"}`}>
                        {tr.ok ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                        {tr.msg}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Add form */}
          <div className="border border-dashed border-border rounded-lg p-3 space-y-2.5">
            <div className="text-[10px] text-muted-foreground uppercase flex items-center gap-1.5 font-bold">
              <Plus className="w-3 h-3" /> Add Server
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <Label className="text-[10px] text-muted-foreground">Name (optional)</Label>
                <Input value={newName} onChange={(e) => setNewName(e.target.value)}
                  placeholder="Client Server 1" className="h-8 text-xs bg-background" />
              </div>
              <div className="space-y-1">
                <Label className="text-[10px] text-muted-foreground">URL *</Label>
                <Input value={newUrl} onChange={(e) => setNewUrl(e.target.value)}
                  placeholder="http://1.2.3.4:32423" className="h-8 text-xs bg-background" />
              </div>
            </div>
            <div className="space-y-1">
              <Label className="text-[10px] text-muted-foreground">App Password *</Label>
              <Input value={newPass} onChange={(e) => setNewPass(e.target.value)}
                type="password" placeholder="••••••••" className="h-8 text-xs bg-background" />
            </div>
            <Button onClick={handleAdd} disabled={adding || !newUrl || !newPass}
              className="w-full h-8 text-xs gap-1">
              {adding
                ? <><RefreshCw className="w-3 h-3 animate-spin" /> Adding…</>
                : <><Plus className="w-3 h-3" /> Add Server</>}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ── Server Card ────────────────────────────────────────────────────────────────

function ServerCard({
  server,
  onRefresh,
}: {
  server: FleetServerEntry;
  onRefresh: (id: string) => void;
}) {
  const [refreshing, setRefreshing] = useState(false);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await fetch(`/api/fleet/servers/${server.id}/refresh`, { method: "POST" });
      onRefresh(server.id);
    } catch {
      toast.error("Refresh failed");
    } finally {
      setRefreshing(false);
    }
  };

  const lastSeen = server.lastSeenAt
    ? Math.round((Date.now() - server.lastSeenAt) / 1000)
    : null;

  const topServices = Object.entries(server.stats?.serviceBreakdown ?? {})
    .sort(([, a], [, b]) => b - a)
    .slice(0, 4);

  return (
    <div className={`bg-card border rounded-xl overflow-hidden transition-all ${
      server.online
        ? "border-border hover:border-primary/30"
        : "border-destructive/30 opacity-75"
    }`}>
      {/* Header */}
      <div className={`px-4 py-3 border-b flex items-center justify-between ${
        server.online ? "border-border bg-muted/20" : "border-destructive/20 bg-destructive/5"
      }`}>
        <div className="flex items-center gap-2.5 min-w-0">
          <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${
            server.online ? "bg-emerald-400 animate-pulse" : "bg-destructive"
          }`} />
          <div className="min-w-0">
            <div className="font-mono text-sm font-bold text-foreground truncate">{server.name}</div>
            <a
              href={server.url}
              target="_blank"
              rel="noreferrer"
              className="font-mono text-[10px] text-muted-foreground hover:text-primary truncate flex items-center gap-1"
            >
              {server.url} <ExternalLink className="w-2.5 h-2.5 shrink-0" />
            </a>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {server.online ? (
            <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20 text-[10px] font-mono">
              ONLINE
            </Badge>
          ) : (
            <Badge className="bg-destructive/10 text-destructive border-destructive/20 text-[10px] font-mono">
              {lastSeen !== null && lastSeen > 30 ? "OFFLINE" : "UNREACHABLE"}
            </Badge>
          )}
          <Button
            variant="ghost" size="icon"
            className="h-6 w-6 text-muted-foreground hover:text-foreground"
            onClick={handleRefresh}
            disabled={refreshing}
            title="Force refresh"
          >
            <RefreshCw className={`w-3 h-3 ${refreshing ? "animate-spin" : ""}`} />
          </Button>
        </div>
      </div>

      {/* Body */}
      <div className="p-4 space-y-4">
        {/* Error */}
        {!server.online && server.lastError && (
          <div className="flex items-center gap-2 text-xs text-destructive font-mono bg-destructive/5 border border-destructive/20 rounded p-2">
            <AlertTriangle className="w-3 h-3 shrink-0" />
            <span className="truncate">{server.lastError}</span>
          </div>
        )}

        {/* Key stats row */}
        <div className="grid grid-cols-4 gap-2">
          {[
            { label: "TOTAL", value: fmtNum(server.stats?.keysFound ?? 0), color: "text-foreground" },
            { label: "VALID", value: fmtNum(server.stats?.keysValid ?? 0), color: "text-emerald-400" },
            { label: "UNCHECKED", value: fmtNum(server.stats?.keysUnchecked ?? 0), color: "text-muted-foreground" },
            { label: "BEDROCK", value: fmtNum(server.stats?.keysWithBedrock ?? 0), color: "text-orange-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="text-center bg-background border border-border rounded p-2">
              <div className={`text-base font-mono font-bold ${color}`}>{value}</div>
              <div className="text-[9px] text-muted-foreground font-mono mt-0.5">{label}</div>
            </div>
          ))}
        </div>

        {/* System resources */}
        {server.sysInfo && (
          <div className="space-y-2">
            <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground font-mono uppercase">
              <Cpu className="w-3 h-3" /> CPU ({server.sysInfo.cpus} cores)
            </div>
            <LoadBar load={server.sysInfo.loadAvg[0]} cpus={server.sysInfo.cpus} />
            <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground font-mono uppercase">
              <MemoryStick className="w-3 h-3" /> RAM
            </div>
            <MemBar avail={server.sysInfo.memAvail} total={server.sysInfo.memTotal} />
          </div>
        )}

        {/* Scan activity */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground font-mono uppercase">
            <Activity className="w-3 h-3" /> Activity
          </div>
          <ScanActivity status={server.status} />
        </div>

        {/* Top services */}
        {topServices.length > 0 && (
          <div className="space-y-1">
            <div className="text-[10px] text-muted-foreground font-mono uppercase flex items-center gap-1">
              <BarChart2 className="w-3 h-3" /> Top Services
            </div>
            <div className="flex flex-wrap gap-1">
              {topServices.map(([svc, cnt]) => (
                <span key={svc} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">
                  {svc} <span className="text-foreground/60">{fmtNum(cnt)}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Last seen */}
        {lastSeen !== null && (
          <div className="text-[10px] text-muted-foreground font-mono">
            <Clock className="w-2.5 h-2.5 inline mr-1" />
            {lastSeen < 60 ? `${lastSeen}s ago` : lastSeen < 3600 ? `${Math.floor(lastSeen / 60)}m ago` : "offline"}
            {" · "}{server.keysInCache} keys in cache
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="px-4 py-2.5 border-t border-border bg-muted/10 flex items-center justify-between">
        <a
          href={server.url}
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-1 text-[10px] font-mono text-muted-foreground hover:text-primary transition-colors"
        >
          <Globe className="w-3 h-3" /> Open Panel
        </a>
        <Link href={`/fleet-results?server=${server.id}`}>
          <a className="flex items-center gap-1 text-[10px] font-mono text-primary hover:text-primary/80 transition-colors">
            View Keys <ChevronRight className="w-3 h-3" />
          </a>
        </Link>
      </div>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function Fleet() {
  const [fleetStatus, setFleetStatus] = useState<FleetStatus | null>(null);
  const [loading, setLoading]         = useState(true);
  const [refreshing, setRefreshing]   = useState(false);
  const [manageOpen, setManageOpen]   = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchStatus = async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const r = await fetch("/api/fleet/servers/status");
      if (r.ok) setFleetStatus(await r.json() as FleetStatus);
    } catch { /* ignore */ }
    finally { if (!quiet) setLoading(false); }
  };

  useEffect(() => {
    void fetchStatus();
    pollRef.current = setInterval(() => void fetchStatus(true), 15000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  const handleForceRefresh = async () => {
    setRefreshing(true);
    try {
      await fetch("/api/fleet/force-refresh", { method: "POST" });
      await fetchStatus(true);
      toast.success("All servers refreshed");
    } catch { toast.error("Refresh failed"); }
    finally { setRefreshing(false); }
  };

  const handleServerRefresh = () => {
    setTimeout(() => void fetchStatus(true), 1500);
  };

  if (!fleetStatus?.enabled) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4 text-center">
        <Server className="w-12 h-12 text-muted-foreground/30" />
        <div>
          <div className="font-mono text-sm text-muted-foreground">Fleet mode is not enabled</div>
          <div className="font-mono text-xs text-muted-foreground/60 mt-1">
            Go to <Link href="/config"><a className="text-primary hover:underline">Config → Server Fleet</a></Link> to enable and add servers
          </div>
        </div>
      </div>
    );
  }

  const servers = fleetStatus.servers;
  const online  = servers.filter((s) => s.online).length;
  const totalKeys  = servers.reduce((acc, s) => acc + (s.stats?.keysFound ?? 0), 0);
  const validKeys  = servers.reduce((acc, s) => acc + (s.stats?.keysValid ?? 0), 0);
  const bedrockKeys = servers.reduce((acc, s) => acc + (s.stats?.keysWithBedrock ?? 0), 0);

  return (
    <div className="space-y-5">
      {/* Manage Servers Modal */}
      <ManageServersModal
        open={manageOpen}
        onClose={() => setManageOpen(false)}
        onChanged={() => setTimeout(() => void fetchStatus(true), 1000)}
      />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Wifi className="w-5 h-5 text-primary" />
          <h1 className="font-mono text-lg font-bold text-primary uppercase tracking-wider">SERVER FLEET</h1>
          <Badge className="bg-primary/10 text-primary border-primary/30 font-mono text-xs">
            {online}/{servers.length} ONLINE
          </Badge>
        </div>
        <div className="flex items-center gap-2">
          <Link href="/fleet-results">
            <Button variant="outline" size="sm" className="font-mono text-xs gap-1 border-primary/30 text-primary hover:bg-primary/10">
              <List className="w-3.5 h-3.5" /> Fleet Keys
            </Button>
          </Link>
          <Button
            variant="outline" size="sm"
            className="font-mono text-xs gap-1"
            onClick={() => setManageOpen(true)}
          >
            <Settings2 className="w-3.5 h-3.5" /> Manage Servers
          </Button>
          <Button
            variant="outline" size="sm"
            className="font-mono text-xs gap-1"
            onClick={handleForceRefresh}
            disabled={refreshing}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`} />
            Refresh All
          </Button>
        </div>
      </div>

      {/* Global summary bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "SERVERS ONLINE", value: `${online}/${servers.length}`, icon: Server, color: "text-primary" },
          { label: "TOTAL KEYS", value: fmtNum(totalKeys), icon: Key, color: "text-foreground" },
          { label: "VALID KEYS", value: fmtNum(validKeys), icon: CheckCircle2, color: "text-emerald-400" },
          { label: "BEDROCK ACCESS", value: fmtNum(bedrockKeys), icon: Zap, color: "text-orange-400" },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-card border border-border rounded-lg p-3 text-center">
            <Icon className={`w-4 h-4 mx-auto mb-1 ${color}`} />
            <div className={`text-xl font-mono font-bold ${color}`}>{value}</div>
            <div className="text-[10px] text-muted-foreground font-mono mt-0.5">{label}</div>
          </div>
        ))}
      </div>

      {/* Server grid */}
      {loading && servers.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground font-mono animate-pulse">
          <RefreshCw className="w-5 h-5 mx-auto mb-2 animate-spin" />
          Loading fleet status…
        </div>
      ) : servers.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground font-mono">
          No servers added yet. Go to Config → Server Fleet.
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
          {servers.map((server) => (
            <ServerCard
              key={server.id}
              server={server}
              onRefresh={handleServerRefresh}
            />
          ))}
        </div>
      )}

      {/* Active scans ticker */}
      {(() => {
        const activeScans = servers.filter((s) =>
          s.online && (s.status?.autoChainPhase === "discovery" || s.status?.autoChainPhase === "envscan" || s.status?.running)
        );
        if (activeScans.length === 0) return null;
        return (
          <div className="bg-card border border-primary/20 rounded-lg p-3 space-y-1">
            <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground mb-2">
              <Radar className="w-3.5 h-3.5 text-primary animate-spin" />
              <span>ACTIVE SCANS ({activeScans.length})</span>
            </div>
            {activeScans.map((s) => {
              const phase = s.status?.autoChainPhase ?? "scanning";
              const cp = s.status?.cycleProgress;
              const pct = cp && cp.total > 0 ? Math.round((cp.done / cp.total) * 100) : null;
              return (
                <div key={s.id} className="flex items-center gap-3 text-xs font-mono">
                  <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse shrink-0" />
                  <span className="text-foreground/70 w-32 truncate">{s.name}</span>
                  <span className={`font-bold ${phase === "discovery" ? "text-cyan-400" : "text-amber-400"}`}>
                    {phase.toUpperCase()}
                  </span>
                  {pct !== null && (
                    <div className="flex-1 flex items-center gap-2">
                      <div className="flex-1 h-1 bg-muted rounded-full overflow-hidden">
                        <div className="h-full bg-primary rounded-full" style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-muted-foreground">{pct}%</span>
                    </div>
                  )}
                  {s.status?.autoChainMessage && !pct && (
                    <span className="text-muted-foreground truncate flex-1">{s.status.autoChainMessage}</span>
                  )}
                </div>
              );
            })}
          </div>
        );
      })()}
    </div>
  );
}
