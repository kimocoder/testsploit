import React from "react";
import { useGetMonitorStats, useGetNewResults, useGetSourceStatuses } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Activity, Key, CheckCircle, XCircle, HelpCircle, Shield, Globe, Hand, Play, Loader2, OctagonPause } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

// ── Manual Mode toggle ──────────────────────────────────────────────────────
// One button that stops every active scan + disables autostart so you can work
// by hand, then re-enables 24/7 scanning when pressed again. Uses raw fetch
// (same pattern as the logout button) so it needs no API-client regeneration.
function ManualModeCard() {
  const [manualMode, setManualMode] = React.useState<boolean | null>(null);
  const [busy, setBusy] = React.useState(false);

  const refresh = React.useCallback(async () => {
    try {
      const r = await fetch("/api/monitor/manual-mode", { credentials: "same-origin" });
      const d = (await r.json()) as { manualMode?: boolean };
      setManualMode(Boolean(d.manualMode));
    } catch {
      /* keep previous state */
    }
  }, []);

  React.useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 5000);
    return () => clearInterval(t);
  }, [refresh]);

  const toggle = React.useCallback(async () => {
    if (manualMode === null) return;
    const enable = !manualMode;
    if (enable) {
      const ok = window.confirm(
        "Включить РУЧНОЙ РЕЖИМ?\n\n" +
        "• Все активные сканы (Discovery + ENV Scanner) будут остановлены\n" +
        "• Автозапуск (Auto-Chain) и публичный сканер будут поставлены на паузу\n\n" +
        "Вы сможете работать вручную. Нажмите кнопку ещё раз, чтобы вернуть автозапуск."
      );
      if (!ok) return;
    }
    setBusy(true);
    try {
      const r = await fetch("/api/monitor/manual-mode", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enable }),
      });
      const d = (await r.json()) as { manualMode?: boolean };
      setManualMode(Boolean(d.manualMode));
    } catch {
      /* leave state, user can retry */
    } finally {
      setBusy(false);
      void refresh();
    }
  }, [manualMode, refresh]);

  const isManual = manualMode === true;

  return (
    <Card
      className={`border ${
        isManual
          ? "border-amber-500/60 bg-amber-500/5"
          : "border-border bg-card"
      }`}
    >
      <CardContent className="flex flex-col gap-3 py-4 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-3">
          {isManual ? (
            <Hand className="h-6 w-6 text-amber-400" />
          ) : (
            <Activity className="h-6 w-6 text-primary" />
          )}
          <div>
            <div className="text-sm font-bold uppercase tracking-wider">
              {isManual ? (
                <span className="text-amber-400">Ручной режим — АКТИВЕН</span>
              ) : (
                <span className="text-primary">Автозапуск — РАБОТАЕТ</span>
              )}
            </div>
            <div className="mt-0.5 text-xs text-muted-foreground">
              {manualMode === null
                ? "Проверка состояния…"
                : isManual
                ? "Все сканы остановлены, автозапуск на паузе. Можно работать вручную."
                : "Auto-Chain и публичный сканер работают 24/7."}
            </div>
          </div>
        </div>

        <button
          onClick={toggle}
          disabled={busy || manualMode === null}
          className={`flex items-center justify-center gap-2 rounded border px-4 py-2 text-sm font-bold uppercase tracking-wider transition-colors disabled:opacity-50 ${
            isManual
              ? "border-primary/50 bg-primary/10 text-primary hover:bg-primary/20"
              : "border-amber-500/50 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20"
          }`}
          title={
            isManual
              ? "Вернуть автозапуск (Auto-Chain снова работает 24/7)"
              : "Остановить все сканы и отключить автозапуск"
          }
        >
          {busy ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : isManual ? (
            <Play className="h-4 w-4" />
          ) : (
            <OctagonPause className="h-4 w-4" />
          )}
          {busy
            ? "Применяю…"
            : isManual
            ? "Возобновить автозапуск"
            : "Стоп сканы / ручной режим"}
        </button>
      </CardContent>
    </Card>
  );
}

export default function Dashboard() {
  const { data: stats } = useGetMonitorStats({
    query: { refetchInterval: 5000 }
  });

  const { data: newResults } = useGetNewResults({
    query: { refetchInterval: 5000 }
  });

  const { data: sources } = useGetSourceStatuses({
    query: { refetchInterval: 5000 }
  });

  const chartData = React.useMemo(() => {
    if (!stats?.serviceBreakdown) return [];
    return Object.entries(stats.serviceBreakdown)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);
  }, [stats?.serviceBreakdown]);

  const activeSources = sources?.filter(s => s.enabled && typeof s.status === 'string' && s.status.startsWith('ok')).length || 0;
  const errorSources = sources?.filter(s => s.enabled && typeof s.status === 'string' && !s.status.startsWith('ok')).length || 0;

  return (
    <div className="space-y-6">
      <ManualModeCard />
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="bg-card border-border">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase">Keys Found</CardTitle>
            <Key className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono">{stats?.keysFound || 0}</div>
            <p className="text-xs text-muted-foreground mt-1 text-primary">
              +{stats?.totalNew || 0} new in last cycle
            </p>
          </CardContent>
        </Card>
        
        <Card className="bg-card border-border">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase">Validation</CardTitle>
            <CheckCircle className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono text-emerald-500">{stats?.keysValid || 0}</div>
            <div className="flex space-x-2 mt-1 text-xs font-mono">
              <span className="text-destructive flex items-center"><XCircle className="w-3 h-3 mr-1"/> {stats?.keysInvalid || 0}</span>
              <span className="text-muted-foreground flex items-center"><HelpCircle className="w-3 h-3 mr-1"/> {stats?.keysUnchecked || 0}</span>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase">Scan Cycles</CardTitle>
            <Activity className="h-4 w-4 text-secondary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono">{stats?.totalCycles || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">
              Total queries run: <span className="text-secondary font-mono">{stats?.totalQueries || 0}</span>
            </p>
          </CardContent>
        </Card>

        <Card className="bg-card border-border">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase">Active Sources</CardTitle>
            <Globe className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono">{activeSources} / {stats?.totalSources || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">
              Source errors: <span className={errorSources > 0 ? "text-destructive font-mono" : "text-muted-foreground font-mono"}>{errorSources}</span>
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <Card className="col-span-4 bg-card border-border">
          <CardHeader>
            <CardTitle className="text-sm uppercase text-muted-foreground tracking-wider flex items-center">
              <Shield className="w-4 h-4 mr-2 text-primary" /> Service Breakdown
            </CardTitle>
          </CardHeader>
          <CardContent className="pl-0">
            <div className="h-[300px] w-full mt-4">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                  <XAxis dataKey="name" stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} />
                  <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip 
                    cursor={{fill: 'hsl(var(--muted))'}} 
                    contentStyle={{ backgroundColor: 'hsl(var(--popover))', border: '1px solid hsl(var(--border))', borderRadius: '4px' }}
                    itemStyle={{ color: 'hsl(var(--primary))' }}
                  />
                  <Bar dataKey="count" fill="hsl(var(--primary))" radius={[4, 4, 0, 0]} maxBarSize={40} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card className="col-span-3 bg-card border-border overflow-hidden flex flex-col">
          <CardHeader className="bg-muted/30 border-b border-border">
            <CardTitle className="text-sm uppercase text-muted-foreground tracking-wider flex items-center justify-between">
              <span className="flex items-center">
                <Activity className="w-4 h-4 mr-2 text-secondary" /> Live Feed
              </span>
              <div className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-secondary opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-secondary"></span>
              </div>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 flex-1 overflow-auto">
            {newResults && newResults.length > 0 ? (
              <div className="divide-y divide-border">
                {newResults.map(result => (
                  <div key={result.id} className="p-4 hover:bg-muted/50 transition-colors">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-bold text-primary px-2 py-0.5 bg-primary/10 rounded border border-primary/20">
                        {result.service || 'UNKNOWN'}
                      </span>
                      <span className="text-xs text-muted-foreground font-mono">
                        {new Date(result.firstSeenAt).toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="text-sm font-mono mt-2 break-all text-foreground">
                      {result.keyMasked || result.url}
                    </div>
                    <div className="text-xs text-muted-foreground mt-2 truncate">
                      Source: {result.source}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center text-muted-foreground flex flex-col items-center justify-center h-full">
                <Activity className="w-8 h-8 mb-2 opacity-20" />
                <p>Waiting for new signals...</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
