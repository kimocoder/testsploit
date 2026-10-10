import React, { useState, useEffect, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Radar, Play, Square, Trash2, ExternalLink, Copy, ChevronDown, ChevronRight,
  Server, Key, AlertCircle, CheckCircle, Loader2, FileText, Download, Search, X,
  History as HistoryIcon, Zap, Hand, Clock, ShieldCheck
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface DnsStats {
  udpResolvers: number;
  blacklisted: number;
  dohEnabled: boolean;
  dohProviders: number;
  strategy: string;
  totalFetched: number;
  totalProbed: number;
  totalWorking: number;
  initTimeS: number;
  errorRate: number;
  cacheSource?: "fresh" | "cached" | "stale" | null;
  cacheAgeSeconds?: number;
  cacheTtlSeconds?: number;
}

type Engine = "py" | "go";

interface ScanStatus {
  running: boolean;
  engine?: Engine | string;
  runId: string | null;
  trigger: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  deepScan: boolean;
  concurrency: number | null;
  stopped: boolean;
  currentAction: string;
  processed: number;
  total: number;
  found: number;
  keys: number;
  elapsedSeconds: number;
  ratePerSec: number;
  etaSeconds: number;
  updatedAt: string | null;
  dns?: DnsStats;
}

interface HistoryRun {
  runId: string;
  trigger: string;
  startedAt: string;
  finishedAt: string;
  total: number;
  processed: number;
  found: number;
  keys: number;
  elapsedSeconds: number;
  ratePerSec: number;
  deepScan: boolean;
  concurrency: number | null;
  stopped: boolean;
  dnsInitSeconds?: number;
  dnsCacheSource?: "fresh" | "cached" | "stale" | "skipped" | null;
}

interface FoundItem {
  host: string;
  mode: string;
  path: string;
  url: string;
  contentPreview: string;
  contentLength: number;
  keysFound: number;
  deepKeysCount?: number;
  keyCategories: string[];
  keyServices: string[];
  keysPreview?: Array<{
    service?: string;
    category?: string;
    masked?: string;
    snippet?: string;
    source?: string;
  }>;
  foundAt: string;
  // Aliases are other URLs on the same host that returned identical content
  // (e.g. http vs https, alternate ports, alias paths). Backend collapses
  // them into one row and surfaces the rest here so the UI can disclose
  // them on demand without re-cluttering the list.
  aliases?: string[];
  aliasCount?: number;
  isHoneypot?: boolean;
}

interface ResultsPage {
  items: FoundItem[];
  total: number;
  page: number;
  pages: number;
}

interface WatchdogEvent {
  ts:          string;
  reason:      string;
  elapsed_min: number;
  rate:        number;
  run_id:      string | null;
}

interface WatchdogStatus {
  enabled:       boolean;
  maxHangMin:    number;
  hardMaxMin:    number;
  minRateHs:     number;
  checkEveryMin: number;
  killCount:     number;
  lastEvent:     WatchdogEvent | null;
}

function formatDuration(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

function shortRunId(id: string | null | undefined): string {
  if (!id) return "—";
  // run_id format: "<unix-ts>-<6-hex>" → show last 8 chars
  return id.length > 10 ? id.slice(-10) : id;
}

function formatTimeAgo(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (isNaN(t)) return "—";
  const sec = Math.floor((Date.now() - t) / 1000);
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

function formatLocalTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

const MODE_COLORS: Record<string, string> = {
  "https": "bg-blue-500/20 text-blue-400 border-blue-500/30",
  "http": "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  "https-dns": "bg-purple-500/20 text-purple-400 border-purple-500/30",
};

export default function Scanner() {
  const [hostsInput, setHostsInput] = useState("");
  const [timeout, setTimeout_] = useState(2);
  const [concurrency, setConcurrency] = useState(60);
  const [maxFail, setMaxFail] = useState(3);
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [results, setResults] = useState<FoundItem[]>([]);
  const [totalFound, setTotalFound] = useState(0);
  const [rawTotal, setRawTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [filterMode, setFilterMode] = useState("all");
  const [filterKeys, setFilterKeys] = useState("all");
  const [filterCat, setFilterCat] = useState("all");
  const [filterQ, setFilterQ] = useState("");
  const [filterRunId, setFilterRunId] = useState<string>("");
  const [hideHoneypots, setHideHoneypots] = useState(false);
  const [deepScan, setDeepScan] = useState(false);
  const [engine, setEngine] = useState<Engine>("py");
  const [goBinaryAvailable, setGoBinaryAvailable] = useState(false);
  const [history, setHistory] = useState<HistoryRun[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [watchdog, setWatchdog] = useState<WatchdogStatus | null>(null);

  const toggleDeepScan = (val: boolean) => {
    setDeepScan(val);
    setTimeout_(val ? 1 : 2);
    setConcurrency(val ? 60 : 60);
    setMaxFail(val ? 2 : 2);
  };

  // Persist engine choice on the server so auto-chain runs and reloads
  // both honor the user's selection.
  const changeEngine = async (next: Engine) => {
    setEngine(next);
    try {
      const r = await fetch("/api/env-scan/engine", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ engine: next }),
      });
      const data = await r.json() as { success?: boolean; message?: string };
      if (!data.success && data.message) {
        toast({ title: "Engine not available", description: data.message, variant: "destructive" });
        // Roll back: server rejected (e.g. Go binary missing).
        setEngine(prev => (prev === next ? "py" : prev));
      }
    } catch (err) {
      toast({ title: "Engine save failed", description: String(err), variant: "destructive" });
    }
  };

  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // All filter values that the polling interval needs to read are mirrored
  // into refs. The interval is registered ONCE on mount with empty deps, so
  // a plain state read from the callback would always see the initial render
  // values ("all", "all", page=1) and stomp on whatever the user has since
  // selected — that's exactly the "filter resets" bug users hit.
  const filterQRef = useRef(filterQ);
  filterQRef.current = filterQ;
  const { toast } = useToast();

  const filterCatRef = useRef(filterCat);
  filterCatRef.current = filterCat;

  const filterRunIdRef = useRef(filterRunId);
  filterRunIdRef.current = filterRunId;

  const filterModeRef = useRef(filterMode);
  filterModeRef.current = filterMode;

  const filterKeysRef = useRef(filterKeys);
  filterKeysRef.current = filterKeys;

  const hideHoneypotsRef = useRef(hideHoneypots);
  hideHoneypotsRef.current = hideHoneypots;

  const pageRef = useRef(page);
  pageRef.current = page;

  const buildParams = (
    p: number,
    mode = filterModeRef.current,
    keys = filterKeysRef.current,
    q = filterQRef.current,
    cat = filterCatRef.current,
    runId = filterRunIdRef.current,
    hp = hideHoneypotsRef.current,
  ) => {
    const params = new URLSearchParams({ limit: "50", page: String(p) });
    if (mode  && mode  !== "all") params.set("mode",     mode);
    if (keys  && keys  !== "all") params.set("hasKeys",  keys === "with-keys" ? "yes" : "no");
    if (cat   && cat   !== "all") params.set("category", cat);
    if (q.trim()) params.set("q", q.trim());
    if (runId) params.set("runId", runId);
    if (hp) params.set("hideHoneypots", "yes");
    return params.toString();
  };

  const fetchStatus = async () => {
    try {
      const r = await fetch("/api/env-scan/status");
      if (r.ok) setStatus(await r.json());
    } catch {}
  };

  const fetchHistory = async () => {
    try {
      const r = await fetch("/api/env-scan/history?limit=20");
      if (r.ok) {
        const data = await r.json() as { items: HistoryRun[] };
        setHistory(data.items ?? []);
      }
    } catch {}
  };

  const fetchWatchdog = async () => {
    try {
      const r = await fetch("/api/env-scan/watchdog");
      if (r.ok) setWatchdog(await r.json() as WatchdogStatus);
    } catch {}
  };

  const fetchResults = async (
    p = pageRef.current,
    mode = filterModeRef.current,
    keys = filterKeysRef.current,
    q = filterQRef.current,
    cat = filterCatRef.current,
    runId = filterRunIdRef.current,
    hp = hideHoneypotsRef.current,
  ) => {
    try {
      const r = await fetch(`/api/env-scan/results?${buildParams(p, mode, keys, q, cat, runId, hp)}`);
      if (r.ok) {
        const data: ResultsPage = await r.json();
        setResults(data.items);
        setRawTotal(data.total);
        setTotalFound(data.total);
        setTotalPages(data.pages);
      }
    } catch {}
  };

  useEffect(() => {
    fetchStatus();
    fetchResults(1);
    fetchHistory();
    fetchWatchdog();
    // Hydrate engine selection from server-side config (single source of truth).
    (async () => {
      try {
        const r = await fetch("/api/env-scan/engine");
        if (r.ok) {
          const data = await r.json() as { engine?: Engine; goBinaryAvailable?: boolean };
          if (data.engine === "go" || data.engine === "py") setEngine(data.engine);
          setGoBinaryAvailable(Boolean(data.goBinaryAvailable));
        }
      } catch {}
    })();
    pollingRef.current = setInterval(() => {
      fetchStatus();
      // No args → fetchResults uses the refs (latest filter values), not the
      // stale closure from this initial render.
      fetchResults();
      fetchHistory();
      fetchWatchdog();
    }, 2000);
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, []);

  useEffect(() => {
    setExpanded(new Set());
    fetchResults(page);
  }, [page]);

  const applyFilters = (mode: string, keys: string, q: string, cat = filterCat, runId = filterRunId, hp = hideHoneypots) => {
    setPage(1);
    setExpanded(new Set());
    fetchResults(1, mode, keys, q, cat, runId, hp);
  };

  const handleDeleteHost = async (host: string) => {
    if (!window.confirm(
      `Delete ALL stored results for:\n${host}\n\nThis removes it from env results AND found keys.\nThis action cannot be undone.`
    )) return;
    try {
      const [r1, r2] = await Promise.all([
        fetch(`/api/env-scan/results/by-host?host=${encodeURIComponent(host)}`, { method: "DELETE" }),
        fetch(`/api/monitor/results/by-filter?host=${encodeURIComponent(host)}`, { method: "DELETE" }),
      ]);
      const d1 = r1.ok ? (await r1.json() as {removed?:number}) : { removed: 0 };
      const d2 = r2.ok ? (await r2.json() as {removed?:number}) : { removed: 0 };
      const total = (d1.removed ?? 0) + (d2.removed ?? 0);
      toast({ title: `Deleted ${total} records for ${host}`, description: `env: ${d1.removed ?? 0}, keys: ${d2.removed ?? 0}` });
      fetchResults();
      fetchStatus();
    } catch (err) {
      toast({ title: "Delete failed", description: String(err), variant: "destructive" });
    }
  };



  const filterByRun = (runId: string) => {
    setFilterRunId(runId);
    setShowHistory(false);
    applyFilters(filterMode, filterKeys, filterQ, filterCat, runId);
  };

  const clearRunFilter = () => {
    setFilterRunId("");
    applyFilters(filterMode, filterKeys, filterQ, filterCat, "");
  };

  const handleStart = async () => {
    if (!hostsInput.trim()) {
      toast({ title: "No hosts provided", description: "Paste IP addresses or hostnames", variant: "destructive" });
      return;
    }
    setLoading(true);
    try {
      const r = await fetch("/api/env-scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          hosts: hostsInput,
          timeout,
          concurrency,
          maxFail,
          deepScan,
          engine,
        }),
      });
      const data = await r.json();
      if (data.success) {
        toast({ title: `Scan started`, description: `${data.hosts} hosts queued` });
        setHostsInput("");
        // Force-clear stale progress in the UI immediately so the user
        // doesn't see numbers from the previous run while Python boots.
        setStatus(prev => prev ? {
          ...prev,
          running: true,
          runId: null, trigger: "manual",
          startedAt: new Date().toISOString(), finishedAt: null,
          stopped: false,
          currentAction: "spawning scanner…",
          processed: 0, total: 0, found: 0, keys: 0,
          elapsedSeconds: 0, ratePerSec: 0, etaSeconds: 0,
        } : prev);
        // Drop any active run filter so we follow the new run.
        setFilterRunId("");
        setTimeout(fetchStatus, 800);
      } else {
        toast({ title: "Error", description: data.message, variant: "destructive" });
      }
    } catch (err) {
      toast({ title: "Connection error", description: String(err), variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    await fetch("/api/env-scan/stop", { method: "POST" });
    toast({ title: "Stop signal sent" });
    setTimeout(fetchStatus, 500);
  };

  const handleClear = async () => {
    await fetch("/api/env-scan/results", { method: "DELETE" });
    setResults([]);
    setTotalFound(0);
    setRawTotal(0);
    setPage(1);
    toast({ title: "Results cleared" });
  };

  const handleDownload = async () => {
    const params = new URLSearchParams();
    if (filterMode && filterMode !== "all") params.set("mode", filterMode);
    if (filterKeys && filterKeys !== "all") params.set("hasKeys", filterKeys === "with-keys" ? "yes" : "no");
    if (filterQ.trim()) params.set("q", filterQ.trim());
    const url = `/api/env-scan/export?${params.toString()}`;
    const a = document.createElement("a");
    a.href = url;
    a.download = "env_scan_results.txt";
    a.click();
  };

  const toggleExpand = (idx: number) => {
    setExpanded(prev => {
      const n = new Set(prev);
      n.has(idx) ? n.delete(idx) : n.add(idx);
      return n;
    });
  };

  const copyUrl = (text: string) => {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).catch(() => copyFallback(text));
    } else {
      copyFallback(text);
    }
    toast({ title: "Copied" });
  };

  const copyFallback = (text: string) => {
    const el = document.createElement("textarea");
    el.value = text;
    el.style.cssText = "position:fixed;top:-9999px;left:-9999px;opacity:0";
    document.body.appendChild(el);
    el.focus();
    el.select();
    try { document.execCommand("copy"); } catch {}
    document.body.removeChild(el);
  };

  const progressPct = status && status.total > 0
    ? Math.round((status.processed / status.total) * 100)
    : 0;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm text-muted-foreground uppercase">
          <Radar className="w-4 h-4 text-primary" />
          <span>ENV File Scanner</span>
        </div>
        {results.length > 0 && (
          <Button variant="ghost" size="sm" onClick={handleClear} className="text-xs text-muted-foreground">
            <Trash2 className="w-3.5 h-3.5 mr-1.5" /> Clear results
          </Button>
        )}
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        {/* Input panel */}
        <Card className="bg-card border-border">
          <CardHeader className="pb-3">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase flex items-center gap-2">
              <Server className="w-3.5 h-3.5 text-primary" /> Hosts to scan
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Textarea
              placeholder={"192.168.1.1\n10.0.0.0/24\nexample.com\nhttps://myapp.io\n...one per line"}
              value={hostsInput}
              onChange={(e) => setHostsInput(e.target.value)}
              className="font-mono text-xs bg-background border-border resize-none h-40"
            />
            <div className="text-xs text-muted-foreground">
              {hostsInput.trim() ? (
                <span className="text-primary">
                  {hostsInput.split(/[\n,]+/).filter(s => s.trim()).length} hosts
                </span>
              ) : "Accepts IPs, domains, one per line or comma-separated"}
            </div>

            {/* Options */}
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: "Timeout (s)", value: timeout, set: setTimeout_, min: 1, max: 30 },
                { label: "Concurrency", value: concurrency, set: setConcurrency, min: 10, max: 4000 },
                { label: "Max fails / mode", value: maxFail, set: setMaxFail, min: 1, max: 20 },
              ].map(({ label, value, set, min, max }) => (
                <div key={label}>
                  <div className="text-xs text-muted-foreground mb-1">{label}</div>
                  <input
                    type="number"
                    min={min}
                    max={max}
                    value={value}
                    onChange={(e) => set(Number(e.target.value))}
                    className="w-full bg-background border border-border rounded px-2 py-1 text-sm font-mono text-foreground"
                  />
                </div>
              ))}
            </div>

            {/* Concurrency presets */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs text-muted-foreground">Concurrency presets:</span>
              {[60, 500, 1000, 2000].map((preset) => (
                <button
                  key={preset}
                  type="button"
                  onClick={() => setConcurrency(preset)}
                  className={`px-2 py-0.5 text-xs rounded border font-mono transition-colors ${
                    concurrency === preset
                      ? "bg-primary text-primary-foreground border-primary"
                      : "bg-background text-muted-foreground border-border hover:text-foreground"
                  }`}
                >
                  {preset}
                </button>
              ))}
              <span className="text-[10px] text-muted-foreground/70 ml-auto">
                значения &gt;1000 требуют поднятых лимитов ОС
              </span>
            </div>

            {/* Fast / Deep toggle */}
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => toggleDeepScan(false)}
                className={`flex-1 py-1.5 text-xs rounded border transition-colors ${
                  !deepScan
                    ? "bg-primary text-primary-foreground border-primary"
                    : "bg-background text-muted-foreground border-border hover:text-foreground"
                }`}
              >
                ⚡ Fast (34 paths)
              </button>
              <button
                type="button"
                onClick={() => toggleDeepScan(true)}
                className={`flex-1 py-1.5 text-xs rounded border transition-colors ${
                  deepScan
                    ? "bg-orange-500/80 text-white border-orange-500"
                    : "bg-background text-muted-foreground border-border hover:text-foreground"
                }`}
              >
                🔍 Deep (1 700+ paths)
              </button>
            </div>

            {/* Engine: Python ⟷ Go.
                Disabled while a scan is running: switching mid-scan would
                misrepresent the currently-running engine in /status (the
                running process keeps writing under its own engine field) and
                cause the next /resume to spawn a different engine than the
                one whose offset/state is on disk. */}
            <div>
              <div className="text-xs text-muted-foreground mb-1 flex items-center justify-between">
                <span>Движок сканера</span>
                {!goBinaryAvailable ? (
                  <span className="text-[10px] text-yellow-500/80">
                    Go-бинарь не найден — соберите monitor/go-scanner/build.sh
                  </span>
                ) : status?.running ? (
                  <span className="text-[10px] text-muted-foreground">
                    заблокировано во время скана
                  </span>
                ) : null}
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => changeEngine("py")}
                  disabled={Boolean(status?.running)}
                  className={`flex-1 py-1.5 text-xs rounded border transition-colors ${
                    engine === "py"
                      ? "bg-primary text-primary-foreground border-primary"
                      : "bg-background text-muted-foreground border-border hover:text-foreground"
                  } ${status?.running ? "opacity-40 cursor-not-allowed" : ""}`}
                >
                  🐍 Python (asyncio)
                </button>
                <button
                  type="button"
                  onClick={() => changeEngine("go")}
                  disabled={!goBinaryAvailable || Boolean(status?.running)}
                  className={`flex-1 py-1.5 text-xs rounded border transition-colors ${
                    engine === "go"
                      ? "bg-cyan-500/80 text-white border-cyan-500"
                      : "bg-background text-muted-foreground border-border hover:text-foreground"
                  } ${(!goBinaryAvailable || status?.running) ? "opacity-40 cursor-not-allowed" : ""}`}
                >
                  🐹 Go (goroutines)
                </button>
              </div>
            </div>

            <div className="text-xs text-muted-foreground border border-border/50 rounded p-2 bg-muted/20 space-y-0.5">
              <div><span className="text-primary">3 modes:</span> HTTPS · HTTP · HTTPS-DNS (reverse lookup + Host header)</div>
              {deepScan
                ? <div><span className="text-orange-400">1 700+ paths</span> per host — ~2 hosts/s. URL-encoded duplicates skipped automatically when canonical path is found.</div>
                : <div><span className="text-primary">34 paths</span> per host — ~22 hosts/s. .env variants · .git/config · wp-config.php · .npmrc · settings.py · docker-compose · SSH keys · editor swap files.</div>
              }
              {status?.dns && (status.dns.udpResolvers > 0 || status.dns.dohEnabled) && (
                <div className="pt-0.5 border-t border-border/30 mt-1 space-y-0.5">
                  <div>
                    <span className="text-primary">DNS:</span>{" "}
                    {status.dns.udpResolvers > 0 ? (
                      <><span className="text-green-400 font-medium">{status.dns.udpResolvers.toLocaleString()}</span> UDP resolvers active</>
                    ) : (
                      <span className="text-yellow-400">DoH only</span>
                    )}
                    {status.dns.blacklisted > 0 && (
                      <> · <span className="text-orange-400">{status.dns.blacklisted}</span> blacklisted</>
                    )}
                    {" · "}
                    <span className="text-muted-foreground">{status.dns.strategy}</span>
                  </div>
                  {status.dns.totalFetched > 0 && (
                    <div className="text-muted-foreground">
                      <span className="text-primary">{status.dns.totalFetched.toLocaleString()}</span> fetched →{" "}
                      <span className="text-primary">{status.dns.totalProbed.toLocaleString()}</span> probed →{" "}
                      <span className="text-green-400">{status.dns.totalWorking.toLocaleString()}</span> working
                      {status.dns.initTimeS > 0 && (
                        <> · init <span className="text-foreground">{status.dns.initTimeS}s</span></>
                      )}
                      {status.dns.errorRate > 0 && (
                        <> · err rate <span className={status.dns.errorRate > 0.1 ? "text-red-400" : "text-muted-foreground"}>
                          {(status.dns.errorRate * 100).toFixed(1)}%
                        </span></>
                      )}
                    </div>
                  )}
                  {status.dns.cacheSource && (
                    <div className="text-muted-foreground">
                      cache:{" "}
                      {status.dns.cacheSource === "cached" ? (
                        <span className="text-green-400">
                          loaded from disk ({Math.round((status.dns.cacheAgeSeconds ?? 0) / 60)}m old) — refreshing in background
                        </span>
                      ) : status.dns.cacheSource === "stale" ? (
                        <span className="text-yellow-400">stale, full refresh in progress</span>
                      ) : (
                        <span className="text-muted-foreground">fresh probe (will be cached)</span>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex gap-2">
              {status?.running ? (
                <Button onClick={handleStop} variant="destructive" className="flex-1">
                  <Square className="w-4 h-4 mr-2" /> Stop Scan
                </Button>
              ) : (
                <Button
                  onClick={handleStart}
                  disabled={loading || !hostsInput.trim()}
                  className="flex-1 bg-primary text-primary-foreground hover:bg-primary/90"
                >
                  {loading
                    ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Starting…</>
                    : <><Play className="w-4 h-4 mr-2" /> Start Scan</>}
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Status panel */}
        <Card className="bg-card border-border">
          <CardHeader className="pb-3">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase flex items-center gap-2">
              <AlertCircle className="w-3.5 h-3.5 text-primary" /> Scan Status
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {status ? (
              <>
                <div className="flex items-center gap-2 flex-wrap">
                  <div className={`w-2 h-2 rounded-full flex-shrink-0 ${status.running ? "bg-primary animate-pulse" : status.stopped ? "bg-orange-400" : "bg-muted-foreground"}`} />
                  <span className={`text-sm font-mono ${status.running ? "text-primary" : status.stopped ? "text-orange-400" : "text-muted-foreground"}`}>
                    {status.running ? "SCANNING" : status.stopped ? "STOPPED" : status.finishedAt ? "DONE" : "IDLE"}
                  </span>
                  {status.trigger && (
                    <Badge
                      className={`text-[10px] font-mono uppercase border ${
                        status.trigger === "auto"
                          ? "bg-purple-500/15 text-purple-300 border-purple-500/30"
                          : "bg-cyan-500/15 text-cyan-300 border-cyan-500/30"
                      }`}
                    >
                      {status.trigger === "auto" ? <Zap className="w-2.5 h-2.5 mr-1 inline" /> : <Hand className="w-2.5 h-2.5 mr-1 inline" />}
                      {status.trigger}
                    </Badge>
                  )}
                  {status.deepScan && (
                    <Badge className="text-[10px] font-mono uppercase bg-orange-500/15 text-orange-300 border-orange-500/30">
                      deep
                    </Badge>
                  )}
                  {/* Engine badge: which scanner produced this run.
                      Python → yellow (matches its snake brand), Go → cyan
                      (matches the gopher). Fallback to "py" if older scans
                      didn't stamp the field — that's the only engine that
                      existed before this UI. */}
                  {(() => {
                    const eng = status.engine === "go" ? "go" : "py";
                    return (
                      <Badge
                        title={eng === "go" ? "Go scanner (goroutines)" : "Python scanner (asyncio)"}
                        className={`text-[10px] font-mono uppercase border ${
                          eng === "go"
                            ? "bg-cyan-500/15 text-cyan-300 border-cyan-500/40"
                            : "bg-yellow-500/10 text-yellow-300 border-yellow-500/30"
                        }`}
                      >
                        {eng === "go" ? "🐹 go" : "🐍 py"}
                      </Badge>
                    );
                  })()}
                  {status.runId && (
                    <span className="text-[10px] font-mono text-muted-foreground border border-border/50 rounded px-1.5 py-0.5">
                      run {shortRunId(status.runId)}
                    </span>
                  )}
                </div>

                {(status.startedAt || status.concurrency) && (
                  <div className="text-[10px] font-mono text-muted-foreground flex items-center gap-2 flex-wrap">
                    {status.startedAt && (
                      <span><Clock className="w-2.5 h-2.5 inline mr-1" />started {formatLocalTime(status.startedAt)} ({formatTimeAgo(status.startedAt)})</span>
                    )}
                    {status.concurrency && (
                      <span>· conc {status.concurrency}</span>
                    )}
                    {status.finishedAt && !status.running && (
                      <span>· finished {formatLocalTime(status.finishedAt)}</span>
                    )}
                  </div>
                )}

                <div className="text-xs text-muted-foreground font-mono truncate">
                  {status.currentAction || "—"}
                </div>

                {status.total > 0 && (
                  <>
                    <Progress value={progressPct} className="h-1.5" />
                    <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                      <div className="bg-muted/30 rounded p-2">
                        <div className="text-muted-foreground">Progress</div>
                        <div className="text-foreground text-sm mt-0.5">{status.processed} / {status.total}</div>
                      </div>
                      <div className="bg-muted/30 rounded p-2">
                        <div className="text-muted-foreground">Found</div>
                        <div className="text-green-400 text-sm mt-0.5">{status.found} files · {status.keys} keys</div>
                      </div>
                      <div className="bg-muted/30 rounded p-2">
                        <div className="text-muted-foreground">Rate</div>
                        <div className="text-foreground text-sm mt-0.5">{status.ratePerSec} hosts/s</div>
                      </div>
                      <div className="bg-muted/30 rounded p-2">
                        <div className="text-muted-foreground">ETA</div>
                        <div className="text-foreground text-sm mt-0.5">
                          {status.running && status.etaSeconds > 0
                            ? formatDuration(status.etaSeconds)
                            : status.elapsedSeconds > 0
                            ? `done in ${formatDuration(status.elapsedSeconds)}`
                            : "—"}
                        </div>
                      </div>
                    </div>
                  </>
                )}

                {status.total === 0 && !status.running && (
                  <div className="text-center text-muted-foreground text-xs py-6 border border-dashed border-border/40 rounded">
                    <Radar className="w-6 h-6 mx-auto mb-2 opacity-30" />
                    No scan running. Paste hosts and press <strong>Start Scan</strong>.
                  </div>
                )}

                {/* Watchdog indicator */}
                {watchdog && (
                  <div className={`rounded border p-2 text-[10px] font-mono flex flex-col gap-1 ${
                    watchdog.killCount > 0
                      ? "bg-orange-500/10 border-orange-500/30"
                      : "bg-green-500/8 border-green-500/20"
                  }`}>
                    <div className="flex items-center gap-1.5">
                      <ShieldCheck className={`w-3 h-3 flex-shrink-0 ${watchdog.killCount > 0 ? "text-orange-400" : "text-green-500"}`} />
                      <span className={watchdog.killCount > 0 ? "text-orange-300" : "text-green-400"}>
                        WATCHDOG ACTIVE
                      </span>
                      <span className="text-muted-foreground ml-auto">
                        check every {watchdog.checkEveryMin}min · kill after {watchdog.maxHangMin}min stall / {watchdog.hardMaxMin}min hard
                      </span>
                    </div>
                    {watchdog.killCount > 0 && watchdog.lastEvent && (
                      <div className="text-orange-300/80 pl-4">
                        killed {watchdog.killCount}× · last: {formatTimeAgo(watchdog.lastEvent.ts)} — {watchdog.lastEvent.reason}
                      </div>
                    )}
                  </div>
                )}
              </>
            ) : (
              <div className="text-center text-muted-foreground text-xs py-8">
                <Loader2 className="w-5 h-5 mx-auto mb-2 animate-spin opacity-40" />
                Loading…
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Run history */}
      <Card className="bg-card border-border">
        <CardHeader
          className="pb-3 cursor-pointer select-none"
          onClick={() => setShowHistory(s => !s)}
        >
          <CardTitle className="text-xs font-medium text-muted-foreground uppercase flex items-center gap-2">
            <HistoryIcon className="w-3.5 h-3.5 text-primary" />
            Run history
            <Badge className="bg-muted/40 text-muted-foreground border-border/50 text-[10px]">
              {history.length}
            </Badge>
            {filterRunId && (
              <Badge className="bg-cyan-500/15 text-cyan-300 border-cyan-500/30 text-[10px] ml-auto mr-2 font-mono">
                filter: {shortRunId(filterRunId)}
                <button
                  onClick={(e) => { e.stopPropagation(); clearRunFilter(); }}
                  className="ml-1.5 hover:text-white"
                  title="Clear run filter"
                >
                  <X className="w-2.5 h-2.5 inline" />
                </button>
              </Badge>
            )}
            <span className={`ml-auto text-muted-foreground ${filterRunId ? "" : "ml-auto"}`}>
              {showHistory ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
            </span>
          </CardTitle>
        </CardHeader>
        {showHistory && (
          <CardContent className="space-y-1 pt-0">
            {history.length === 0 ? (
              <div className="text-center text-muted-foreground text-xs py-6 border border-dashed border-border/40 rounded">
                No completed runs yet.
              </div>
            ) : (
              <div className="overflow-x-auto -mx-2 px-2">
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className="text-[10px] text-muted-foreground uppercase border-b border-border/40">
                      <th className="text-left py-1.5 px-2">Run</th>
                      <th className="text-left py-1.5 px-2">Trigger</th>
                      <th className="text-left py-1.5 px-2">Started</th>
                      <th className="text-right py-1.5 px-2">Hosts</th>
                      <th className="text-right py-1.5 px-2">Files</th>
                      <th className="text-right py-1.5 px-2">Keys</th>
                      <th className="text-right py-1.5 px-2">Took</th>
                      <th className="text-right py-1.5 px-2">Rate</th>
                      <th className="text-right py-1.5 px-2"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((h) => {
                      const isActive = filterRunId === h.runId;
                      return (
                        <tr
                          key={h.runId}
                          className={`border-b border-border/20 hover:bg-muted/20 cursor-pointer ${isActive ? "bg-cyan-500/5" : ""}`}
                          onClick={() => filterByRun(h.runId)}
                        >
                          <td className="py-1.5 px-2 text-foreground whitespace-nowrap">{shortRunId(h.runId)}</td>
                          <td className="py-1.5 px-2 whitespace-nowrap">
                            <span className={
                              h.trigger === "auto"
                                ? "text-purple-300"
                                : "text-cyan-300"
                            }>
                              {h.trigger === "auto" ? "⚡" : "✋"} {h.trigger}
                            </span>
                            {/* Engine marker per row so users can compare
                                Python vs Go runs side-by-side in history. */}
                            <span
                              className={`ml-1.5 ${
                                (h as { engine?: string }).engine === "go"
                                  ? "text-cyan-300"
                                  : "text-yellow-300"
                              }`}
                              title={(h as { engine?: string }).engine === "go" ? "Go scanner" : "Python scanner"}
                            >
                              {(h as { engine?: string }).engine === "go" ? "🐹 go" : "🐍 py"}
                            </span>
                            {h.deepScan && <span className="ml-1.5 text-orange-400">deep</span>}
                            {h.stopped && <span className="ml-1.5 text-orange-400">stopped</span>}
                          </td>
                          <td className="py-1.5 px-2 text-muted-foreground whitespace-nowrap" title={h.startedAt}>
                            {formatTimeAgo(h.startedAt)}
                          </td>
                          <td className="py-1.5 px-2 text-right text-foreground whitespace-nowrap">
                            {h.processed}/{h.total}
                          </td>
                          <td className="py-1.5 px-2 text-right whitespace-nowrap">
                            <span className={h.found > 0 ? "text-green-400" : "text-muted-foreground"}>{h.found}</span>
                          </td>
                          <td className="py-1.5 px-2 text-right whitespace-nowrap">
                            <span className={h.keys > 0 ? "text-yellow-400" : "text-muted-foreground"}>{h.keys}</span>
                          </td>
                          <td className="py-1.5 px-2 text-right text-muted-foreground whitespace-nowrap">{formatDuration(h.elapsedSeconds)}</td>
                          <td className="py-1.5 px-2 text-right text-muted-foreground whitespace-nowrap">{h.ratePerSec}/s</td>
                          <td className="py-1.5 px-2 text-right whitespace-nowrap">
                            {isActive ? (
                              <span className="text-cyan-300 text-[10px]">active</span>
                            ) : (
                              <span className="text-muted-foreground text-[10px] hover:text-cyan-300">filter →</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        )}
      </Card>

      {/* Results — keep visible while any filter is active so filters don't disappear on 0-result searches */}
      {(rawTotal > 0 || filterMode !== "all" || filterKeys !== "all" || filterCat !== "all" || filterQ !== "") && (
        <div className="space-y-2">
          {/* Filter bar */}
          <div className="flex flex-wrap items-center gap-2 pb-1">
            <div className="flex items-center gap-1.5 flex-1 min-w-0">
              <FileText className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
              <span className="text-xs text-muted-foreground uppercase flex-shrink-0">Found .env files</span>
              <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-xs flex-shrink-0">
                {totalFound}
              </Badge>
            </div>

            {/* Mode filter */}
            <select
              value={filterMode}
              onChange={e => { setFilterMode(e.target.value); applyFilters(e.target.value, filterKeys, filterQ); }}
              className="bg-background border border-border/60 rounded px-2 py-1 text-xs font-mono text-foreground"
            >
              <option value="all">All modes</option>
              <option value="https">HTTPS</option>
              <option value="http">HTTP</option>
              <option value="https-dns">HTTPS-DNS</option>
            </select>

            {/* Has secrets filter */}
            <select
              value={filterKeys}
              onChange={e => { setFilterKeys(e.target.value); applyFilters(filterMode, e.target.value, filterQ); }}
              className="bg-background border border-border/60 rounded px-2 py-1 text-xs font-mono text-foreground"
            >
              <option value="all">All results</option>
              <option value="with-keys">With secrets</option>
              <option value="no-keys">No secrets</option>
            </select>

            {/* Category filter */}
            <select
              value={filterCat}
              onChange={e => { setFilterCat(e.target.value); applyFilters(filterMode, filterKeys, filterQ, e.target.value); }}
              className="bg-background border border-border/60 rounded px-2 py-1 text-xs font-mono text-foreground"
            >
              <option value="all">All categories</option>
              <option value="ai">AI</option>
              <option value="payments">Payments</option>
              <option value="crypto">Crypto</option>
              <option value="email">Email</option>
              <option value="cloud">Cloud</option>
              <option value="auth">Auth</option>
              <option value="messaging">Messaging</option>
              <option value="database">Database</option>
              <option value="storage">Storage</option>
            </select>

            {/* URL search */}
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search URL…"
                value={filterQ}
                onChange={e => setFilterQ(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter") applyFilters(filterMode, filterKeys, filterQ); }}
                className="bg-background border border-border/60 rounded pl-6 pr-6 py-1 text-xs font-mono text-foreground w-36"
              />
              {filterQ && (
                <button
                  onClick={() => { setFilterQ(""); applyFilters(filterMode, filterKeys, ""); }}
                  className="absolute right-1.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>

            {/* Hide honeypots toggle */}
            <button
              onClick={() => {
                const next = !hideHoneypots;
                setHideHoneypots(next);
                applyFilters(filterMode, filterKeys, filterQ, filterCat, filterRunId, next);
              }}
              title="Honeypots: hosts returning the same response on 4+ paths (catch-all / fake env files). Toggle to hide them."
              className={`flex items-center gap-1 px-2 py-1 text-xs font-mono border rounded transition-colors ${
                hideHoneypots
                  ? "bg-amber-500/20 border-amber-500/40 text-amber-300"
                  : "border-border/60 text-muted-foreground hover:text-foreground hover:border-border"
              }`}
            >
              🍯 {hideHoneypots ? "Honeypots hidden" : "Show all"}
            </button>

            {/* Download */}
            <button
              onClick={handleDownload}
              className="flex items-center gap-1 px-2 py-1 text-xs font-mono border border-border/60 rounded text-muted-foreground hover:text-foreground hover:border-border"
              title="Download filtered results as TXT"
            >
              <Download className="w-3 h-3" /> TXT
            </button>

            {/* Pagination top */}
            {totalPages > 1 && (
              <div className="flex items-center gap-1 text-xs font-mono text-muted-foreground ml-auto">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}
                  className="px-2 py-0.5 border border-border/50 rounded hover:border-border disabled:opacity-30 disabled:cursor-not-allowed">‹</button>
                <span className="text-foreground px-1">PG {page}/{totalPages}</span>
                <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
                  className="px-2 py-0.5 border border-border/50 rounded hover:border-border disabled:opacity-30 disabled:cursor-not-allowed">›</button>
              </div>
            )}
          </div>

          {results.map((item, idx) => (
            <Card key={`${page}-${idx}`} className="bg-card border-green-500/20 bg-green-500/5">
              <CardContent className="pt-3 pb-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-2 min-w-0 flex-1">
                    <button
                      onClick={() => toggleExpand(idx)}
                      className="text-muted-foreground hover:text-foreground mt-0.5 flex-shrink-0"
                      title={expanded.has(idx) ? "Collapse" : "Expand"}
                    >
                      {expanded.has(idx)
                        ? <ChevronDown className="w-4 h-4" />
                        : <ChevronRight className="w-4 h-4" />}
                    </button>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5 mb-1">
                        <Badge className={`text-xs ${MODE_COLORS[item.mode] ?? "bg-muted text-muted-foreground"}`}>
                          {item.mode}
                        </Badge>
                        {item.keysFound > 0 && (
                          <button
                            type="button"
                            onClick={() => toggleExpand(idx)}
                            title={expanded.has(idx)
                              ? "Hide content & keys"
                              : `Show ${item.keysFound} secret${item.keysFound > 1 ? "s" : ""} in content`}
                            className="inline-flex items-center bg-primary/20 hover:bg-primary/30 text-primary border border-primary/30 hover:border-primary/60 text-xs rounded px-1.5 py-0.5 cursor-pointer transition-colors"
                          >
                            <Key className="w-2.5 h-2.5 mr-1" /> {item.keysFound} secret{item.keysFound > 1 ? "s" : ""}
                            {expanded.has(idx) ? (
                              <ChevronDown className="w-2.5 h-2.5 ml-1" />
                            ) : (
                              <ChevronRight className="w-2.5 h-2.5 ml-1" />
                            )}
                          </button>
                        )}
                        {(item.deepKeysCount ?? 0) > 0 && (
                          <Badge
                            className="text-xs bg-purple-500/15 text-purple-300 border-purple-500/30"
                            title={`Python deep-scan found ${item.deepKeysCount} additional key${(item.deepKeysCount ?? 0) > 1 ? "s" : ""} that the Go engine missed`}
                          >
                            DEEP +{item.deepKeysCount}
                          </Badge>
                        )}
                        {(item.keyCategories ?? []).map(cat => (
                          <Badge key={cat} className="text-xs bg-muted/60 text-muted-foreground border-border/50">
                            {cat}
                          </Badge>
                        ))}
                        {(item.keyServices ?? []).slice(0, 3).map(svc => (
                          <Badge key={svc} className="text-xs bg-secondary/10 text-secondary border-secondary/20">
                            {svc}
                          </Badge>
                        ))}
                        <span className="text-xs text-muted-foreground">{item.contentLength} bytes</span>
                        <span className="text-xs text-muted-foreground">{item.foundAt}</span>
                        {item.isHoneypot && (
                          <Badge
                            className="text-xs bg-amber-500/15 text-amber-400 border-amber-500/40"
                            title="Suspected honeypot: this host returns a near-identical response on 4+ different paths (catch-all / fake env file). Keys are likely fake."
                          >
                            🍯 HONEYPOT
                          </Badge>
                        )}
                        {(item.aliasCount ?? 0) > 0 && (
                          <Badge
                            className="text-xs bg-amber-500/10 text-amber-300 border-amber-500/30"
                            title={`Same content also exposed at ${item.aliasCount} other URL${(item.aliasCount ?? 0) > 1 ? "s" : ""} on this host`}
                          >
                            +{item.aliasCount} URL{(item.aliasCount ?? 0) > 1 ? "s" : ""}
                          </Badge>
                        )}
                      </div>
                      <div className="font-mono text-sm text-foreground truncate">{item.url}</div>
                      <div className="text-xs text-muted-foreground mt-0.5">/{item.path}</div>

                      {expanded.has(idx) && (item.aliases?.length ?? 0) > 0 && (
                        <div className="mt-2 text-xs font-mono border border-amber-500/20 bg-amber-500/5 rounded p-2">
                          <div className="text-amber-300/80 mb-1 uppercase tracking-wider">
                            Same content at {item.aliases?.length} other URL{(item.aliases?.length ?? 0) > 1 ? "s" : ""}:
                          </div>
                          <div className="space-y-0.5 max-h-32 overflow-auto">
                            {item.aliases?.map(u => (
                              <div key={u} className="flex items-center gap-2 group">
                                <a href={u} target="_blank" rel="noreferrer" className="text-muted-foreground hover:text-foreground truncate flex-1">{u}</a>
                                <button
                                  onClick={() => copyUrl(u)}
                                  className="opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-foreground flex-shrink-0"
                                  title="Copy URL"
                                >
                                  <Copy className="w-3 h-3" />
                                </button>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {expanded.has(idx) && (item.keysPreview?.length ?? 0) > 0 && (
                        <div className="mt-2 border border-primary/30 bg-primary/5 rounded p-2">
                          <div className="text-primary/80 mb-1.5 uppercase tracking-wider text-xs flex items-center gap-1">
                            <Key className="w-3 h-3" /> Extracted secrets ({item.keysPreview!.length})
                          </div>
                          <div className="space-y-2">
                            {item.keysPreview!.map((k, ki) => (
                              <div key={ki} className="text-xs">
                                <div className="flex flex-wrap items-center gap-1.5 mb-0.5">
                                  {k.service && (
                                    <Badge className="bg-secondary/20 text-secondary border-secondary/30 text-[10px]">
                                      {k.service}
                                    </Badge>
                                  )}
                                  {k.category && (
                                    <Badge className="bg-muted/60 text-muted-foreground border-border/50 text-[10px]">
                                      {k.category}
                                    </Badge>
                                  )}
                                  {k.source === "deep" && (
                                    <Badge
                                      className="bg-purple-500/15 text-purple-300 border-purple-500/30 text-[10px]"
                                      title="Found by Python deep-scan pass"
                                    >
                                      DEEP
                                    </Badge>
                                  )}
                                  <code className="font-mono text-primary bg-black/40 px-1.5 py-0.5 rounded select-all break-all">
                                    {k.masked || "(masked)"}
                                  </code>
                                  {k.masked && (
                                    <button
                                      onClick={() => copyUrl(k.masked!)}
                                      className="text-muted-foreground hover:text-foreground"
                                      title="Copy masked key"
                                    >
                                      <Copy className="w-3 h-3" />
                                    </button>
                                  )}
                                </div>
                                {k.snippet && (
                                  <pre className="font-mono text-[11px] text-muted-foreground bg-black/30 border border-border/30 rounded p-1.5 whitespace-pre-wrap break-all max-h-24 overflow-auto">
                                    {k.snippet}
                                  </pre>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {expanded.has(idx) && item.contentPreview && (
                        <details className="mt-2">
                          <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground select-none">
                            Raw content preview ({item.contentLength} bytes)
                          </summary>
                          <pre className="mt-1 text-xs font-mono bg-black/40 border border-border/50 rounded p-2 whitespace-pre-wrap break-all max-h-48 overflow-auto text-green-300">
                            {item.contentPreview}
                          </pre>
                        </details>
                      )}
                    </div>
                  </div>

                  <div className="flex gap-1.5 flex-shrink-0">
                    <button
                      onClick={() => copyUrl(item.url)}
                      className="p-1.5 text-muted-foreground hover:text-foreground border border-border/50 rounded"
                      title="Copy URL"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                    <a
                      href={item.url}
                      target="_blank"
                      rel="noreferrer"
                      className="p-1.5 text-muted-foreground hover:text-foreground border border-border/50 rounded"
                      title="Open in new tab"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                    <button
                      onClick={() => handleDeleteHost(item.host)}
                      className="p-1.5 text-muted-foreground hover:text-red-400 border border-border/50 rounded transition-colors"
                      title={`Delete all results for ${item.host}`}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}

          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-1 text-xs text-muted-foreground font-mono border-t border-border/30">
              <span>Showing {(page - 1) * 50 + 1}–{Math.min(page * 50, totalFound)} of {totalFound}</span>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setPage(1)}
                  disabled={page <= 1}
                  className="px-2 py-1 border border-border/50 rounded hover:border-border disabled:opacity-30 disabled:cursor-not-allowed"
                >FIRST</button>
                <button
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page <= 1}
                  className="px-2 py-1 border border-border/50 rounded hover:border-border disabled:opacity-30 disabled:cursor-not-allowed"
                >PREV</button>
                <span className="px-3 py-1 text-foreground">PG {page} / {totalPages}</span>
                <button
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  className="px-2 py-1 border border-border/50 rounded hover:border-border disabled:opacity-30 disabled:cursor-not-allowed"
                >NEXT</button>
                <button
                  onClick={() => setPage(totalPages)}
                  disabled={page >= totalPages}
                  className="px-2 py-1 border border-border/50 rounded hover:border-border disabled:opacity-30 disabled:cursor-not-allowed"
                >LAST</button>
              </div>
            </div>
          )}
        </div>
      )}

      {totalFound === 0 && status && !status.running && status.total > 0 && (
        <div className="text-center text-muted-foreground text-sm py-10 border border-dashed border-border/40 rounded-lg">
          <CheckCircle className="w-8 h-8 mx-auto mb-2 opacity-30" />
          Scan complete — no exposed .env files found on {status.total} hosts.
        </div>
      )}
    </div>
  );
}
