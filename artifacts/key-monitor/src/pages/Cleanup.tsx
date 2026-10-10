import React, { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Trash2, RefreshCw, AlertTriangle, ShieldAlert, CheckCircle2, Bug, Info } from "lucide-react";

interface CleanupStats {
  total: number;
  envDetected: number;
  highVolume: number;
  honeypotHosts: string[];
  honeypotHostKeys: number;
  confirmedInvalid: number;
  testJunk: number;
  // high-volume host list with counts
  highVolumeHosts?: Array<{ host: string; count: number }>;
}

interface HoneypotHostInfo {
  host: string;
  count: number;
  isHighVolume: boolean;
}

export default function Cleanup() {
  const [stats, setStats] = useState<CleanupStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [purging, setPurging] = useState<string | null>(null);
  const [showHosts, setShowHosts] = useState(false);

  const fetchStats = async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/env-scan/results/stats?detailed=1");
      if (r.ok) {
        const d = await r.json() as CleanupStats;
        setStats(d);
      } else {
        toast.error("Failed to load cleanup stats");
      }
    } catch (e) {
      toast.error(`Error: ${String(e)}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void fetchStats(); }, []);

  const handlePurgeHoneypots = async () => {
    if (!stats) return;
    const count = stats.honeypotHostKeys;
    if (count === 0) { toast.info("No honeypot keys to purge"); return; }

    if (!window.confirm(
      `DELETE ${count.toLocaleString()} honeypot keys?\n\n` +
      `These are keys from ${(stats.envDetected + stats.highVolume).toLocaleString()} hosts that ` +
      `return catch-all responses (same content for every URL).\n\n` +
      `This CANNOT be undone.`
    )) return;

    setPurging("honeypots");
    try {
      const r = await fetch("/api/env-scan/results/purge-honeypots", { method: "POST" });
      if (r.ok) {
        const d = await r.json() as { removed?: number; message?: string };
        toast.success(`Removed ${(d.removed ?? 0).toLocaleString()} honeypot keys`);
        void fetchStats();
      } else {
        toast.error("Purge failed");
      }
    } catch (e) {
      toast.error(`Error: ${String(e)}`);
    } finally {
      setPurging(null);
    }
  };

  const handlePurgeInvalid = async () => {
    if (!stats || stats.confirmedInvalid === 0) { toast.info("No confirmed-invalid keys to purge"); return; }

    if (!window.confirm(
      `DELETE ${stats.confirmedInvalid.toLocaleString()} confirmed-invalid keys?\n\nThis cannot be undone.`
    )) return;

    setPurging("invalid");
    try {
      const r = await fetch("/api/env-scan/results/purge-invalid", { method: "POST" });
      if (r.ok) {
        const d = await r.json() as { removed?: number };
        toast.success(`Removed ${(d.removed ?? 0).toLocaleString()} invalid keys`);
        void fetchStats();
      } else {
        toast.error("Purge failed");
      }
    } catch (e) {
      toast.error(`Error: ${String(e)}`);
    } finally {
      setPurging(null);
    }
  };

  const handlePurgeJunk = async () => {
    if (!stats || stats.testJunk === 0) { toast.info("No test/junk keys to purge"); return; }

    if (!window.confirm(
      `DELETE ${stats.testJunk.toLocaleString()} test/junk keys?\n\nThis cannot be undone.`
    )) return;

    setPurging("junk");
    try {
      const r = await fetch("/api/env-scan/results/purge-junk", { method: "POST" });
      if (r.ok) {
        const d = await r.json() as { removed?: number };
        toast.success(`Removed ${(d.removed ?? 0).toLocaleString()} junk keys`);
        void fetchStats();
      } else {
        toast.error("Purge failed");
      }
    } catch (e) {
      toast.error(`Error: ${String(e)}`);
    } finally {
      setPurging(null);
    }
  };

  const honeyHosts: HoneypotHostInfo[] = React.useMemo(() => {
    if (!stats) return [];
    const highVolumeSet = new Set(stats.highVolumeHosts?.map(h => h.host) ?? []);
    return stats.honeypotHosts.slice(0, 100).map(host => ({
      host,
      count: stats.highVolumeHosts?.find(h => h.host === host)?.count ?? 0,
      isHighVolume: highVolumeSet.has(host),
    }));
  }, [stats]);

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center h-48 text-muted-foreground font-mono animate-pulse">
        <RefreshCw className="w-4 h-4 mr-2 animate-spin" /> LOADING CLEANUP STATS…
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 text-amber-400" />
          <h1 className="text-lg font-mono font-bold text-amber-400 uppercase tracking-wider">
            DATABASE CLEANUP
          </h1>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={fetchStats}
          disabled={loading}
          className="text-muted-foreground font-mono text-xs gap-1"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {/* Overview stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-card border border-border rounded-lg p-3 text-center">
            <div className="text-2xl font-mono font-bold text-foreground">{stats.total.toLocaleString()}</div>
            <div className="text-[10px] text-muted-foreground font-mono uppercase mt-1">TOTAL ENV KEYS</div>
          </div>
          <div className={`bg-card border rounded-lg p-3 text-center ${stats.honeypotHostKeys > 0 ? "border-red-500/40 bg-red-500/5" : "border-border"}`}>
            <div className={`text-2xl font-mono font-bold ${stats.honeypotHostKeys > 0 ? "text-red-400" : "text-muted-foreground"}`}>
              {stats.honeypotHostKeys.toLocaleString()}
            </div>
            <div className="text-[10px] text-muted-foreground font-mono uppercase mt-1">HONEYPOT KEYS</div>
            <div className="text-[9px] text-muted-foreground/60 mt-0.5">
              {stats.envDetected} catch-all + {stats.highVolume} high-vol hosts
            </div>
          </div>
          <div className={`bg-card border rounded-lg p-3 text-center ${stats.confirmedInvalid > 0 ? "border-destructive/30 bg-destructive/5" : "border-border"}`}>
            <div className={`text-2xl font-mono font-bold ${stats.confirmedInvalid > 0 ? "text-destructive" : "text-muted-foreground"}`}>
              {stats.confirmedInvalid.toLocaleString()}
            </div>
            <div className="text-[10px] text-muted-foreground font-mono uppercase mt-1">CONFIRMED INVALID</div>
          </div>
          <div className={`bg-card border rounded-lg p-3 text-center ${stats.testJunk > 0 ? "border-yellow-500/30 bg-yellow-500/5" : "border-border"}`}>
            <div className={`text-2xl font-mono font-bold ${stats.testJunk > 0 ? "text-yellow-400" : "text-muted-foreground"}`}>
              {stats.testJunk.toLocaleString()}
            </div>
            <div className="text-[10px] text-muted-foreground font-mono uppercase mt-1">TEST / JUNK</div>
          </div>
        </div>
      )}

      {/* Honeypot section */}
      {stats && (
        <div className="bg-card border border-red-500/20 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-red-500/20 flex items-center justify-between bg-red-500/5">
            <div className="flex items-center gap-2">
              <Bug className="w-4 h-4 text-red-400" />
              <span className="font-mono text-sm text-red-400 font-bold uppercase">Honeypot / Catch-All Hosts</span>
              <Badge className="bg-red-500/20 text-red-400 border-red-500/30 text-xs font-mono">
                {(stats.envDetected + stats.highVolume).toLocaleString()} hosts · {stats.honeypotHostKeys.toLocaleString()} keys
              </Badge>
            </div>
            <div className="flex gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowHosts(s => !s)}
                className="text-xs font-mono text-muted-foreground"
              >
                <Info className="w-3 h-3 mr-1" />
                {showHosts ? "Hide" : "Show"} hosts
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={handlePurgeHoneypots}
                disabled={purging !== null || stats.honeypotHostKeys === 0}
                className="text-xs font-mono gap-1"
              >
                {purging === "honeypots"
                  ? <RefreshCw className="w-3 h-3 animate-spin" />
                  : <Trash2 className="w-3 h-3" />}
                Purge All ({stats.honeypotHostKeys.toLocaleString()})
              </Button>
            </div>
          </div>

          <div className="p-4 space-y-3">
            <p className="text-xs text-muted-foreground font-mono">
              Hosts returning <span className="text-foreground">identical content</span> for 4+ different URL paths
              (catch-all honeypots that respond to every request with fake credentials).
              URL encoding variants (/.git/config = /%2egit/config) are treated as the same path.
            </p>

            {/* Honeypot host list */}
            {showHosts && honeyHosts.length > 0 && (
              <div className="border border-border rounded bg-background max-h-48 overflow-y-auto">
                <div className="grid grid-cols-[1fr_auto_auto] text-[10px] font-mono text-muted-foreground border-b border-border px-3 py-1 bg-muted/50">
                  <span>HOST</span>
                  <span className="text-right pr-4">TYPE</span>
                  <span className="text-right">KEYS</span>
                </div>
                {honeyHosts.map(({ host, count, isHighVolume }) => (
                  <div key={host} className="grid grid-cols-[1fr_auto_auto] text-[11px] font-mono px-3 py-1 border-b border-border/50 hover:bg-muted/30">
                    <span className="text-foreground/80 truncate">{host}</span>
                    <span className={`text-right pr-4 text-[10px] ${isHighVolume ? "text-red-400" : "text-amber-400"}`}>
                      {isHighVolume ? "HIGH-VOL" : "CATCH-ALL"}
                    </span>
                    <span className="text-right text-muted-foreground">
                      {count > 0 ? count.toLocaleString() : "—"}
                    </span>
                  </div>
                ))}
                {stats.honeypotHosts.length > 100 && (
                  <div className="px-3 py-2 text-[10px] text-muted-foreground font-mono">
                    … and {(stats.honeypotHosts.length - 100).toLocaleString()} more
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Confirmed invalid section */}
      {stats && stats.confirmedInvalid > 0 && (
        <div className="bg-card border border-destructive/20 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-destructive/20 flex items-center justify-between bg-destructive/5">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-destructive" />
              <span className="font-mono text-sm text-destructive font-bold uppercase">Confirmed Invalid</span>
              <Badge className="bg-destructive/20 text-destructive border-destructive/30 text-xs font-mono">
                {stats.confirmedInvalid.toLocaleString()} keys
              </Badge>
            </div>
            <Button
              variant="destructive"
              size="sm"
              onClick={handlePurgeInvalid}
              disabled={purging !== null}
              className="text-xs font-mono gap-1 opacity-80 hover:opacity-100"
            >
              {purging === "invalid"
                ? <RefreshCw className="w-3 h-3 animate-spin" />
                : <Trash2 className="w-3 h-3" />}
              Purge ({stats.confirmedInvalid.toLocaleString()})
            </Button>
          </div>
          <div className="p-4">
            <p className="text-xs text-muted-foreground font-mono">
              Keys with <span className="text-foreground">status = invalid</span> from validator results.
              Safe to delete only if you trust the validator results (ensure SigV4 was working when validated).
            </p>
          </div>
        </div>
      )}

      {/* Test/junk section */}
      {stats && stats.testJunk > 0 && (
        <div className="bg-card border border-yellow-500/20 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-yellow-500/20 flex items-center justify-between bg-yellow-500/5">
            <div className="flex items-center gap-2">
              <Bug className="w-4 h-4 text-yellow-400" />
              <span className="font-mono text-sm text-yellow-400 font-bold uppercase">Test / Junk Keys</span>
              <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30 text-xs font-mono">
                {stats.testJunk.toLocaleString()} keys
              </Badge>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={handlePurgeJunk}
              disabled={purging !== null}
              className="text-xs font-mono gap-1 text-yellow-400 hover:text-yellow-300 border border-yellow-500/30 hover:bg-yellow-500/10"
            >
              {purging === "junk"
                ? <RefreshCw className="w-3 h-3 animate-spin" />
                : <Trash2 className="w-3 h-3" />}
              Purge ({stats.testJunk.toLocaleString()})
            </Button>
          </div>
          <div className="p-4">
            <p className="text-xs text-muted-foreground font-mono">
              Keys matching known placeholder/honeypot values (FUCK_YOU_BLACKHAT, AWS_EXAMPLE_KEY, wJalrX…).
            </p>
          </div>
        </div>
      )}

      {/* All clean */}
      {stats && stats.honeypotHostKeys === 0 && stats.confirmedInvalid === 0 && stats.testJunk === 0 && (
        <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-6 flex items-center gap-3">
          <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
          <div>
            <div className="font-mono text-sm text-emerald-400 font-bold">DATABASE IS CLEAN</div>
            <div className="font-mono text-xs text-muted-foreground mt-1">
              No honeypots, invalid, or junk keys detected.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
