import React, { useState, useEffect } from "react";
import { useGetSourceStatuses, getGetSourceStatusesQueryKey } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Search, Server, Power, AlertTriangle, CheckCircle, Globe } from "lucide-react";

export default function Sources() {
  const { data: sources, isLoading } = useGetSourceStatuses();
  const [filter, setFilter] = useState('');
  const [category, setCategory] = useState('all');
  const [proxyEnabled, setProxyEnabled] = useState(false);
  const [proxyPoolSize, setProxyPoolSize] = useState(0);
  const [proxySaving, setProxySaving] = useState(false);

  // Load proxy config on mount, refresh pool size every 15s when enabled.
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const r = await fetch("/api/monitor/proxy-config");
        const j = await r.json();
        if (!alive) return;
        setProxyEnabled(!!j.enabled);
        setProxyPoolSize(Number(j.poolSize) || 0);
      } catch { /* ignore */ }
    };
    load();
    const id = setInterval(load, 15000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const toggleProxy = async (next: boolean) => {
    setProxySaving(true);
    try {
      const r = await fetch("/api/monitor/proxy-config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: next }),
      });
      const j = await r.json();
      setProxyEnabled(!!j.enabled);
    } catch { /* ignore */ }
    finally { setProxySaving(false); }
  };

  const categories = React.useMemo(() => {
    if (!sources) return [];
    const cats = new Set(sources.map(s => s.category));
    return Array.from(cats).sort();
  }, [sources]);

  const filteredSources = React.useMemo(() => {
    if (!sources) return [];
    return sources.filter(s => {
      const matchFilter = s.name.toLowerCase().includes(filter.toLowerCase()) || 
                          s.category.toLowerCase().includes(filter.toLowerCase());
      const matchCategory = category === 'all' || s.category === category;
      return matchFilter && matchCategory;
    });
  }, [sources, filter, category]);

  const isOk = (status: string) => typeof status === 'string' && status.startsWith('ok');
  const activeCount = sources?.filter(s => s.enabled && isOk(s.status)).length || 0;
  const errorCount = sources?.filter(s => s.enabled && !isOk(s.status)).length || 0;
  const disabledCount = sources?.filter(s => !s.enabled).length || 0;

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <Card className="bg-card border-border">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-muted-foreground uppercase font-bold tracking-wider mb-1">Active / OK</p>
              <p className="text-2xl font-mono text-emerald-500">{activeCount}</p>
            </div>
            <CheckCircle className="w-8 h-8 text-emerald-500 opacity-20" />
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-muted-foreground uppercase font-bold tracking-wider mb-1">Errors</p>
              <p className="text-2xl font-mono text-destructive">{errorCount}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-destructive opacity-20" />
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <p className="text-xs text-muted-foreground uppercase font-bold tracking-wider mb-1">Disabled</p>
              <p className="text-2xl font-mono text-muted-foreground">{disabledCount}</p>
            </div>
            <Power className="w-8 h-8 text-muted-foreground opacity-20" />
          </CardContent>
        </Card>
      </div>

      {/* ── Free-proxy retry toggle ───────────────────────────────────── */}
      <Card className="bg-card border-border">
        <CardContent className="p-4 flex items-center justify-between gap-4">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <Globe className="w-5 h-5 text-muted-foreground shrink-0 mt-0.5" />
            <div className="min-w-0">
              <p className="text-sm font-bold uppercase tracking-wider">Free-proxy retry</p>
              <p className="text-xs text-muted-foreground mt-1">
                On 403/418/429/451 (likely IP bans), retry through rotating free public proxies.
                Default <span className="font-mono">OFF</span> — free proxies have ~0.4% liveness on this network and can
                slow things down. Toggle takes effect on the next cycle.
              </p>
              <p className="text-xs font-mono text-muted-foreground mt-1">
                pool: <span className={proxyPoolSize > 0 ? "text-emerald-500" : "text-muted-foreground"}>{proxyPoolSize}</span> working
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Badge
              variant="outline"
              className={`text-[10px] font-mono ${proxyEnabled ? "border-emerald-500/30 text-emerald-500 bg-emerald-500/10" : "bg-background"}`}
            >
              {proxyEnabled ? "ON" : "OFF"}
            </Badge>
            <Switch checked={proxyEnabled} onCheckedChange={toggleProxy} disabled={proxySaving} />
          </div>
        </CardContent>
      </Card>

      <div className="flex gap-4 items-center bg-card p-4 border border-border rounded-lg">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input 
            placeholder="Search sources..." 
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="pl-9 bg-background border-border font-mono text-sm"
          />
        </div>
        <Select value={category} onValueChange={setCategory}>
          <SelectTrigger className="w-[200px] bg-background border-border font-mono text-xs uppercase">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">ALL CATEGORIES</SelectItem>
            {categories.map(c => (
              <SelectItem key={c} value={c}>{c.toUpperCase()}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {isLoading ? (
          <div className="col-span-full py-10 text-center text-muted-foreground font-mono">LOADING SOURCES...</div>
        ) : filteredSources.length === 0 ? (
          <div className="col-span-full py-10 text-center text-muted-foreground font-mono">NO SOURCES MATCH FILTERS</div>
        ) : (
          filteredSources.map(source => (
            <Card key={source.name} className={`bg-card border-border overflow-hidden ${!source.enabled ? 'opacity-60 grayscale' : ''}`}>
              <div className={`h-1 w-full ${!source.enabled ? 'bg-muted-foreground' : isOk(source.status) ? 'bg-emerald-500' : 'bg-destructive'}`} />
              <CardHeader className="p-4 pb-2">
                <div className="flex items-start justify-between">
                  <CardTitle className="text-sm font-bold truncate pr-2 flex items-center">
                    <Server className="w-3 h-3 mr-2 text-muted-foreground" />
                    {source.name}
                  </CardTitle>
                  {!source.enabled ? (
                    <Badge variant="outline" className="text-[10px] font-mono bg-background">OFF</Badge>
                  ) : isOk(source.status) ? (
                    <Badge variant="outline" className="text-[10px] font-mono border-emerald-500/30 text-emerald-500 bg-emerald-500/10">OK</Badge>
                  ) : (
                    <Badge variant="outline" className="text-[10px] font-mono border-destructive/30 text-destructive bg-destructive/10">ERR</Badge>
                  )}
                </div>
              </CardHeader>
              <CardContent className="p-4 pt-0">
                <div className="text-xs text-muted-foreground font-mono mt-2 flex justify-between">
                  <span>CAT:</span>
                  <span className="text-foreground uppercase">{source.category}</span>
                </div>
                <div className="text-xs text-muted-foreground font-mono mt-1 flex justify-between">
                  <span>STATUS:</span>
                  <span className={isOk(source.status) ? 'text-emerald-500' : 'text-destructive max-w-[120px] truncate'} title={source.status}>
                    {source.status.toUpperCase()}
                  </span>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}
