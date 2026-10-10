import React, { useState, useEffect, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Wifi, Play, Square, Trash2, ExternalLink, Copy,
  Loader2, Globe, Server, ArrowRight, Download, Shuffle
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface DiscoverStatus {
  running: boolean;
  mode: string;
  currentAction: string;
  processed: number;
  total: number;
  found: number;
  elapsedSeconds: number;
  ratePerSec: number;
  etaSeconds: number;
  updatedAt: string | null;
}

interface FoundHost {
  host: string;
  port: number;
  url: string;
  discoveredAt: string;
}

interface ResultsPage {
  items: FoundHost[];
  total: number;
  page: number;
  pages: number;
}

function formatDuration(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

const PORT_COLORS: Record<number, string> = {
  80:   "bg-slate-500/20 text-slate-300 border-slate-500/30",
  443:  "bg-blue-500/20 text-blue-400 border-blue-500/30",
  8080: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  8443: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  3000: "bg-green-500/20 text-green-400 border-green-500/30",
  8000: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  5000: "bg-pink-500/20 text-pink-400 border-pink-500/30",
};

const PRESET_PORTS = [
  { label: "Web (80, 443)", value: "80,443" },
  { label: "Common (80,443,8080,8443)", value: "80,443,8080,8443" },
  { label: "Full (80,443,8080,8443,3000,5000,8000,9000)", value: "80,443,8080,8443,3000,5000,8000,9000" },
];

export default function Discover() {
  const [status, setStatus] = useState<DiscoverStatus | null>(null);
  const [results, setResults] = useState<FoundHost[]>([]);
  const [totalFound, setTotalFound] = useState(0);
  const [loading, setLoading] = useState(false);
  const [selectedPorts, setSelectedPorts] = useState("80,443,8080,8443");
  const [concurrency, setConcurrency] = useState(1000);
  const [timeout, setTimeout_] = useState(1);
  const [maxHosts, setMaxHosts] = useState(50000);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [deepScan, setDeepScan] = useState(false);
  const [uniqueMode, setUniqueMode] = useState(true);
  const [seenCount, setSeenCount] = useState(0);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const { toast } = useToast();

  const fetchStatus = async () => {
    try {
      const r = await fetch("/api/discover/status");
      if (r.ok) setStatus(await r.json());
    } catch {}
  };

  const fetchResults = async () => {
    try {
      const r = await fetch("/api/discover/results?limit=200");
      if (r.ok) {
        const data: ResultsPage = await r.json();
        setResults(data.items);
        setTotalFound(data.total);
      }
    } catch {}
  };

  useEffect(() => {
    fetchStatus();
    fetchResults();
    fetchUniqueMode();
    pollingRef.current = setInterval(() => {
      fetchStatus();
      fetchResults();
    }, 1500);
    return () => { if (pollingRef.current) clearInterval(pollingRef.current); };
  }, []);

  const fetchUniqueMode = async () => {
    try {
      const r = await fetch("/api/discover/unique-mode");
      if (r.ok) {
        const d = await r.json() as { uniqueMode: boolean; seenCount: number };
        setUniqueMode(d.uniqueMode);
        setSeenCount(d.seenCount ?? 0);
      }
    } catch {}
  };

  const toggleUniqueMode = async (val: boolean) => {
    setUniqueMode(val);
    try {
      await fetch("/api/discover/unique-mode", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ uniqueMode: val }),
      });
    } catch {}
  };

  const clearSeenHosts = async () => {
    if (!window.confirm(`Clear history of ${seenCount.toLocaleString()} seen IPs?\nNext scan will probe all IPs again.`)) return;
    try {
      await fetch("/api/discover/seen", { method: "DELETE" });
      setSeenCount(0);
    } catch {}
  };

  const handleStart = async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/discover/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targets: "",
          ports: selectedPorts,
          timeout,
          concurrency,
          maxHosts,
          batch: 500,
          uniqueMode,
        }),
      });
      const data = await r.json();
      if (data.success) {
        toast({ title: "Discovery started", description: `Scanning ${data.hosts.toLocaleString()} random IPs for open HTTP/HTTPS ports` });
        fetchStatus();
      } else {
        toast({ title: "Error", description: data.message, variant: "destructive" });
      }
    } catch (e) {
      toast({ title: "Connection error", description: String(e), variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    await fetch("/api/discover/stop", { method: "POST" });
    toast({ title: "Stop signal sent" });
    setTimeout(fetchStatus, 800);
  };

  const handleClear = async () => {
    await fetch("/api/discover/results", { method: "DELETE" });
    setResults([]);
    setTotalFound(0);
    setSelected(new Set());
    toast({ title: "Results cleared" });
  };

  const sendToEnvScanner = async () => {
    // Send host:port pairs (preserves all discovered ports including 8080/8443)
    let entries: { host: string; port: number }[];
    if (selected.size > 0) {
      entries = results.filter((_, i) => selected.has(i)).map(h => ({ host: h.host, port: h.port }));
    } else {
      try {
        const r = await fetch(`/api/discover/results?limit=${totalFound || 99999}`);
        const data: ResultsPage = await r.json();
        entries = data.items.map(h => ({ host: h.host, port: h.port }));
      } catch {
        entries = results.map(h => ({ host: h.host, port: h.port }));
      }
    }
    // Dedup by host:port
    const unique = [...new Set(entries.map(e => `${e.host}:${e.port}`))];
    const uniqueHosts = new Set(entries.map(e => e.host)).size;
    if (!unique.length) return;

    const r = await fetch("/api/env-scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hosts: unique.join("\n"), timeout: 2, concurrency: 60, maxFail: 2, deepScan }),
    });
    const data = await r.json();
    if (data.success) {
      toast({
        title: `Sent ${unique.length} entries to ENV Scanner`,
        description: `${uniqueHosts} unique hosts × ports → ENV scan in progress`,
      });
    } else {
      toast({ title: "ENV Scanner busy", description: data.message, variant: "destructive" });
    }
  };

  const exportTxt = async () => {
    const r = await fetch("/api/discover/export");
    const txt = await r.text();
    const blob = new Blob([txt], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "discovered_hosts.txt";
    a.click();
  };

  const toggleSelect = (i: number) => {
    setSelected(prev => {
      const n = new Set(prev);
      n.has(i) ? n.delete(i) : n.add(i);
      return n;
    });
  };

  const toggleAll = () => {
    if (selected.size === results.length) setSelected(new Set());
    else setSelected(new Set(results.map((_, i) => i)));
  };

  const progressPct = status && status.total > 0
    ? Math.round((status.processed / status.total) * 100)
    : 0;

  const activeHosts = selected.size > 0 ? selected.size : totalFound;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm text-muted-foreground uppercase">
          <Wifi className="w-4 h-4 text-primary" />
          <span>Host Discovery</span>
        </div>
        {totalFound > 0 && (
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={exportTxt} className="text-xs text-muted-foreground">
              <Download className="w-3.5 h-3.5 mr-1.5" /> Export .txt
            </Button>
            <Button variant="ghost" size="sm" onClick={handleClear} className="text-xs text-muted-foreground">
              <Trash2 className="w-3.5 h-3.5 mr-1.5" /> Clear
            </Button>
          </div>
        )}
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        {/* Control panel */}
        <Card className="bg-card border-border">
          <CardHeader className="pb-3">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase flex items-center gap-2">
              <Shuffle className="w-3.5 h-3.5 text-primary" /> Auto Discovery
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* How it works */}
            <div className="rounded border border-primary/20 bg-primary/5 p-3 text-xs space-y-1">
              <div className="text-primary font-medium">Как работает</div>
              <div className="text-muted-foreground">Генерирует случайные публичные IP-адреса и проверяет открытые HTTP/HTTPS порты. Живые веб-серверы сохраняются и могут быть отправлены в ENV Scanner.</div>
            </div>

            {/* Port preset */}
            <div>
              <div className="text-xs text-muted-foreground mb-2">Порты для проверки</div>
              <div className="flex flex-col gap-1.5">
                {PRESET_PORTS.map(({ label, value }) => (
                  <button
                    key={value}
                    onClick={() => setSelectedPorts(value)}
                    className={`text-left text-xs px-3 py-2 rounded border transition-colors font-mono ${
                      selectedPorts === value
                        ? "border-primary/60 bg-primary/10 text-primary"
                        : "border-border/50 bg-muted/20 text-muted-foreground hover:border-border"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {/* Params */}
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: "Timeout (s)", value: timeout, set: setTimeout_, min: 0.5, max: 10 },
                { label: "Concurrency", value: concurrency, set: setConcurrency, min: 50, max: 3000 },
                { label: "Max IPs", value: maxHosts, set: setMaxHosts, min: 1000, max: 500000, step: 1000 },
              ].map(({ label, value, set, min, max, step }) => (
                <div key={label}>
                  <div className="text-xs text-muted-foreground mb-1">{label}</div>
                  <input
                    type="number"
                    min={min} max={max} step={step ?? 1}
                    value={value}
                    onChange={e => set(Number(e.target.value))}
                    className="w-full bg-background border border-border rounded px-2 py-1 text-sm font-mono text-foreground"
                  />
                </div>
              ))}
            </div>


            {/* Unique mode toggle */}
            <div className="flex items-center justify-between p-3 bg-muted/20 border border-border/50 rounded-lg">
              <div className="flex items-center gap-2">
                <div className="flex flex-col">
                  <span className="text-sm font-medium text-foreground">Unique IPs only</span>
                  <span className="text-xs text-muted-foreground">
                    {uniqueMode
                      ? `Skip ${seenCount.toLocaleString()} already-scanned IPs`
                      : "Probe all IPs including previously scanned"}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {uniqueMode && seenCount > 0 && (
                  <button
                    onClick={clearSeenHosts}
                    className="text-xs text-muted-foreground hover:text-destructive border border-border/50 rounded px-2 py-1 transition-colors"
                    title="Clear scan history"
                  >
                    Clear history
                  </button>
                )}
                <button
                  onClick={() => toggleUniqueMode(!uniqueMode)}
                  className={`relative w-11 h-6 rounded-full transition-colors focus:outline-none ${
                    uniqueMode ? "bg-primary" : "bg-muted"
                  }`}
                >
                  <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${
                    uniqueMode ? "translate-x-5" : "translate-x-0"
                  }`} />
                </button>
              </div>
            </div>

            {status?.running ? (
              <Button onClick={handleStop} variant="destructive" className="w-full">
                <Square className="w-4 h-4 mr-2" /> Остановить
              </Button>
            ) : (
              <Button
                onClick={handleStart}
                disabled={loading}
                className="w-full bg-primary text-primary-foreground hover:bg-primary/90 text-sm font-medium"
              >
                {loading
                  ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Запуск…</>
                  : <><Play className="w-4 h-4 mr-2" /> Начать сканирование</>}
              </Button>
            )}
          </CardContent>
        </Card>

        {/* Status panel */}
        <Card className="bg-card border-border">
          <CardHeader className="pb-3">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase flex items-center gap-2">
              <Globe className="w-3.5 h-3.5 text-primary" /> Прогресс
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {status ? (
              <>
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full flex-shrink-0 ${status.running ? "bg-primary animate-pulse" : "bg-muted-foreground"}`} />
                  <span className={`text-sm font-mono ${status.running ? "text-primary" : "text-muted-foreground"}`}>
                    {status.running ? (status.mode === "random" ? "RANDOM SCAN" : "CUSTOM SCAN") : "IDLE"}
                  </span>
                </div>

                <div className="text-xs text-muted-foreground font-mono truncate min-h-[1.2em]">
                  {status.currentAction || "—"}
                </div>

                {status.total > 0 && (
                  <>
                    <Progress value={progressPct} className="h-1.5" />
                    <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                      <div className="bg-muted/30 rounded p-2">
                        <div className="text-muted-foreground">Проверено</div>
                        <div className="text-foreground text-sm mt-0.5">{status.processed.toLocaleString()} / {status.total.toLocaleString()}</div>
                      </div>
                      <div className="bg-muted/30 rounded p-2">
                        <div className="text-muted-foreground">Живых хостов</div>
                        <div className="text-green-400 text-sm mt-0.5">{status.found.toLocaleString()}</div>
                      </div>
                      <div className="bg-muted/30 rounded p-2">
                        <div className="text-muted-foreground">Скорость</div>
                        <div className="text-foreground text-sm mt-0.5">{status.ratePerSec} IP/s</div>
                      </div>
                      <div className="bg-muted/30 rounded p-2">
                        <div className="text-muted-foreground">ETA</div>
                        <div className="text-foreground text-sm mt-0.5">
                          {status.running && status.etaSeconds > 0
                            ? formatDuration(status.etaSeconds)
                            : status.elapsedSeconds > 0
                            ? `за ${formatDuration(status.elapsedSeconds)}`
                            : "—"}
                        </div>
                      </div>
                    </div>
                  </>
                )}

                {status.total === 0 && !status.running && (
                  <div className="text-center text-muted-foreground text-xs py-8 border border-dashed border-border/40 rounded">
                    <Wifi className="w-6 h-6 mx-auto mb-2 opacity-30" />
                    Нажми <strong>Начать сканирование</strong> — система сама найдёт живые веб-хосты в интернете
                  </div>
                )}
              </>
            ) : (
              <div className="text-center text-muted-foreground text-xs py-8">
                <Loader2 className="w-5 h-5 mx-auto mb-2 animate-spin opacity-40" />
                Загрузка…
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Results */}
      {totalFound > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs text-muted-foreground uppercase">
              <Server className="w-3.5 h-3.5 text-green-400" />
              <span>Живые веб-серверы</span>
              <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-xs">
                {totalFound.toLocaleString()}
              </Badge>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              {totalFound > 0 && (
                <button onClick={toggleAll} className="text-xs text-muted-foreground hover:text-foreground">
                  {selected.size === results.length ? "Снять всё" : "Выбрать всё"}
                </button>
              )}
              <div className="flex rounded overflow-hidden border border-border/50 text-xs">
                <button
                  type="button"
                  onClick={() => setDeepScan(false)}
                  className={`px-2 py-1 transition-colors ${!deepScan ? "bg-primary text-primary-foreground" : "bg-background text-muted-foreground hover:text-foreground"}`}
                  title="20 топовых путей — быстро"
                >
                  ⚡ Fast
                </button>
                <button
                  type="button"
                  onClick={() => setDeepScan(true)}
                  className={`px-2 py-1 transition-colors border-l border-border/50 ${deepScan ? "bg-orange-500/80 text-white" : "bg-background text-muted-foreground hover:text-foreground"}`}
                  title="1700+ путей — медленно, но полно"
                >
                  🔍 Deep
                </button>
              </div>
              <Button
                size="sm"
                onClick={sendToEnvScanner}
                className="text-xs bg-primary/20 text-primary border border-primary/30 hover:bg-primary/30"
              >
                <ArrowRight className="w-3.5 h-3.5 mr-1.5" />
                {selected.size > 0 ? `Отправить ${selected.size} в ENV Scanner` : `Отправить все (${totalFound}) в ENV Scanner`}
              </Button>
            </div>
          </div>

          <div className="grid gap-1.5 max-h-[420px] overflow-y-auto pr-1">
            {results.map((item, idx) => (
              <div
                key={idx}
                onClick={() => toggleSelect(idx)}
                className={`flex items-center gap-3 px-3 py-2 rounded border cursor-pointer transition-colors ${
                  selected.has(idx)
                    ? "border-primary/50 bg-primary/10"
                    : "border-border/40 bg-card hover:border-border"
                }`}
              >
                <div className={`w-3 h-3 rounded border flex-shrink-0 flex items-center justify-center ${
                  selected.has(idx) ? "border-primary bg-primary" : "border-muted-foreground"
                }`}>
                  {selected.has(idx) && <div className="w-1.5 h-1.5 bg-background rounded-sm" />}
                </div>

                <Badge className={`text-xs flex-shrink-0 ${PORT_COLORS[item.port] ?? "bg-muted text-muted-foreground border-muted"}`}>
                  :{item.port}
                </Badge>

                <span className="font-mono text-sm text-foreground flex-1 truncate">{item.host}</span>

                <span className="text-xs text-muted-foreground flex-shrink-0 hidden sm:block">
                  {new Date(item.discoveredAt).toLocaleTimeString()}
                </span>

                <div className="flex gap-1 flex-shrink-0">
                  <button
                    onClick={e => { e.stopPropagation(); navigator.clipboard.writeText(item.url); }}
                    className="p-1 text-muted-foreground hover:text-foreground"
                    title="Copy URL"
                  >
                    <Copy className="w-3 h-3" />
                  </button>
                  <a
                    href={item.url}
                    target="_blank"
                    rel="noreferrer"
                    onClick={e => e.stopPropagation()}
                    className="p-1 text-muted-foreground hover:text-foreground"
                    title="Open"
                  >
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
