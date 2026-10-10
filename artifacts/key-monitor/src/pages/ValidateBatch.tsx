import React, { useState, useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Play, Square, RefreshCw, CheckCircle2, AlertCircle, Zap, Key } from "lucide-react";

// ── Services available for bulk validation ────────────────────────────────────
const BULK_SERVICES = [
  { id: "aws",          label: "AWS",          color: "text-orange-400 border-orange-500/40 bg-orange-500/10" },
  { id: "openai",       label: "OpenAI",       color: "text-green-400 border-green-500/40 bg-green-500/10" },
  { id: "anthropic",    label: "Anthropic",    color: "text-purple-400 border-purple-500/40 bg-purple-500/10" },
  { id: "stripe",       label: "Stripe",       color: "text-emerald-400 border-emerald-500/40 bg-emerald-500/10" },
  { id: "github",       label: "GitHub",       color: "text-sky-400 border-sky-500/40 bg-sky-500/10" },
  { id: "sendgrid",     label: "SendGrid",     color: "text-blue-400 border-blue-500/40 bg-blue-500/10" },
  { id: "mailgun",      label: "Mailgun",      color: "text-red-400 border-red-500/40 bg-red-500/10" },
  { id: "telegram",     label: "Telegram",     color: "text-cyan-400 border-cyan-500/40 bg-cyan-500/10" },
  { id: "digitalocean", label: "DigitalOcean", color: "text-blue-400 border-blue-500/40 bg-blue-500/10" },
  { id: "resend",       label: "Resend",       color: "text-violet-400 border-violet-500/40 bg-violet-500/10" },
  { id: "groq",         label: "Groq",         color: "text-amber-400 border-amber-500/40 bg-amber-500/10" },
  { id: "mistral",      label: "Mistral",      color: "text-amber-400 border-amber-500/40 bg-amber-500/10" },
  { id: "deepseek",     label: "DeepSeek",     color: "text-teal-400 border-teal-500/40 bg-teal-500/10" },
  { id: "xai",          label: "xAI",          color: "text-zinc-300 border-zinc-500/40 bg-zinc-500/10" },
];

interface BulkState {
  running: boolean;
  service: string;
  total: number;
  processed: number;
  valid: number;
  errors: number;
  startedAt: string | null;
  finishedAt: string | null;
  keysPerMin: number;
}

interface ServiceCount {
  unchecked: number;
  total: number;
}

export default function ValidateBatch() {
  const [selectedService, setSelectedService] = useState("aws");
  const [maxKeys, setMaxKeys] = useState(500);
  const [status, setStatus] = useState<BulkState | null>(null);
  const [counts, setCounts] = useState<Record<string, ServiceCount>>({});
  const [loadingCounts, setLoadingCounts] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchStatus = async () => {
    try {
      const r = await fetch("/api/monitor/validate-bulk/status");
      if (r.ok) setStatus(await r.json() as BulkState);
    } catch { /* ignore */ }
  };

  const fetchCounts = async () => {
    setLoadingCounts(true);
    try {
      const r = await fetch("/api/monitor/validate-bulk/counts");
      if (r.ok) setCounts(await r.json() as Record<string, ServiceCount>);
    } catch { /* ignore */ }
    finally { setLoadingCounts(false); }
  };

  useEffect(() => {
    void fetchStatus();
    void fetchCounts();
    // Poll status every 2s
    pollRef.current = setInterval(fetchStatus, 2000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleStart = async () => {
    try {
      const r = await fetch("/api/monitor/validate-bulk/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ service: selectedService, maxKeys }),
      });
      const d = await r.json() as { success?: boolean; message?: string; error?: string };
      if (d.success) {
        toast.success(d.message ?? "Started");
        setTimeout(fetchStatus, 800);
      } else {
        toast.error(d.error ?? d.message ?? "Failed to start");
      }
    } catch (e) {
      toast.error(`Error: ${String(e)}`);
    }
  };

  const handleStop = async () => {
    try {
      await fetch("/api/monitor/validate-bulk/stop", { method: "POST" });
      toast.info("Stopping after current batch…");
    } catch (e) {
      toast.error(`Error: ${String(e)}`);
    }
  };

  const isRunning = status?.running ?? false;
  const progress = status && status.total > 0
    ? Math.round((status.processed / status.total) * 100)
    : 0;

  const elapsedSec = status?.startedAt
    ? Math.round((Date.now() - new Date(status.startedAt).getTime()) / 1000)
    : 0;

  return (
    <div className="space-y-6 max-w-3xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Zap className={`w-5 h-5 ${isRunning ? "text-primary animate-pulse" : "text-muted-foreground"}`} />
            <h1 className="text-lg font-mono font-bold text-primary uppercase tracking-wider">
              BULK VALIDATION
            </h1>
          </div>
          {isRunning && (
            <div className="flex items-center gap-2">
              {/* Double-pulse animation indicator */}
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-primary" />
              </span>
              <Badge className="bg-primary/20 text-primary border-primary/40 font-mono text-xs animate-pulse">
                RUNNING — {status?.service?.toUpperCase()}
              </Badge>
              {status && status.keysPerMin > 0 && (
                <span className="text-xs text-muted-foreground font-mono">
                  {status.keysPerMin} keys/min
                </span>
              )}
            </div>
          )}
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => { void fetchCounts(); void fetchStatus(); }}
          className="text-muted-foreground font-mono text-xs"
          disabled={loadingCounts}
        >
          {loadingCounts ? <RefreshCw className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
        </Button>
      </div>

      {/* Service selector */}
      <div className="bg-card border border-border rounded-lg p-4 space-y-3">
        <div className="text-xs font-mono text-muted-foreground mb-3">SELECT SERVICE TO VALIDATE</div>
        <div className="flex flex-wrap gap-2">
          {BULK_SERVICES.map((svc) => {
            const c = counts[svc.id];
            const unchecked = c?.unchecked ?? 0;
            const isSelected = selectedService === svc.id;
            return (
              <button
                key={svc.id}
                onClick={() => setSelectedService(svc.id)}
                disabled={isRunning}
                className={`flex items-center gap-2 px-3 py-1.5 text-xs font-mono border rounded transition-all disabled:opacity-50 disabled:cursor-not-allowed ${
                  isSelected
                    ? `${svc.color} border-opacity-100`
                    : "border-border text-muted-foreground hover:text-foreground hover:border-foreground/30 bg-background"
                }`}
              >
                <Key className="w-3 h-3" />
                <span>{svc.label}</span>
                {unchecked > 0 && (
                  <span className={`ml-1 text-[10px] px-1 py-0.5 rounded font-bold ${
                    isSelected ? "bg-background/30" : "bg-muted"
                  }`}>
                    {unchecked.toLocaleString()}
                  </span>
                )}
                {unchecked === 0 && c && (
                  <CheckCircle2 className="w-3 h-3 text-emerald-400 ml-1" />
                )}
              </button>
            );
          })}
        </div>

        {/* Max keys input */}
        <div className="flex items-center gap-3 pt-2">
          <span className="text-xs font-mono text-muted-foreground">MAX KEYS:</span>
          {[100, 500, 1000, 5000].map((n) => (
            <button
              key={n}
              onClick={() => setMaxKeys(n)}
              disabled={isRunning}
              className={`px-2 py-1 text-xs font-mono border rounded transition-colors disabled:opacity-50 ${
                maxKeys === n
                  ? "bg-primary/20 text-primary border-primary/50"
                  : "border-border text-muted-foreground hover:text-foreground bg-background"
              }`}
            >
              {n.toLocaleString()}
            </button>
          ))}
        </div>
      </div>

      {/* Progress panel — shown when running or after a run */}
      {status && (status.running || status.processed > 0) && (
        <div className={`border rounded-lg p-4 space-y-3 ${
          isRunning
            ? "bg-primary/5 border-primary/30"
            : status.finishedAt ? "bg-emerald-500/5 border-emerald-500/20" : "bg-card border-border"
        }`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono text-xs text-muted-foreground uppercase">
              <span>Service:</span>
              <span className="text-foreground font-bold">{status.service || "—"}</span>
            </div>
            {status.finishedAt && !isRunning && (
              <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30 text-xs">
                FINISHED
              </Badge>
            )}
          </div>

          {/* Progress bar */}
          {status.total > 0 && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs font-mono text-muted-foreground">
                <span>{status.processed.toLocaleString()} / {status.total.toLocaleString()} keys</span>
                <span>{progress}%</span>
              </div>
              <div className="w-full bg-muted rounded-full h-2 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${isRunning ? "bg-primary animate-pulse" : "bg-emerald-500"}`}
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}

          {/* Stats grid */}
          <div className="grid grid-cols-4 gap-3">
            <div className="bg-background border border-border rounded p-2 text-center">
              <div className="text-lg font-mono font-bold text-emerald-400">
                {status.valid.toLocaleString()}
              </div>
              <div className="text-[10px] text-muted-foreground font-mono uppercase mt-0.5">VALID</div>
            </div>
            <div className="bg-background border border-border rounded p-2 text-center">
              <div className="text-lg font-mono font-bold text-destructive">
                {(status.processed - status.valid - status.errors).toLocaleString()}
              </div>
              <div className="text-[10px] text-muted-foreground font-mono uppercase mt-0.5">INVALID</div>
            </div>
            <div className="bg-background border border-border rounded p-2 text-center">
              <div className="text-lg font-mono font-bold text-red-400">
                {status.errors.toLocaleString()}
              </div>
              <div className="text-[10px] text-muted-foreground font-mono uppercase mt-0.5">ERRORS</div>
            </div>
            <div className="bg-background border border-border rounded p-2 text-center">
              <div className="text-lg font-mono font-bold text-primary">
                {isRunning ? status.keysPerMin : "—"}
              </div>
              <div className="text-[10px] text-muted-foreground font-mono uppercase mt-0.5">KEYS/MIN</div>
            </div>
          </div>

          {isRunning && elapsedSec > 0 && (
            <div className="text-xs font-mono text-muted-foreground">
              Elapsed: {elapsedSec < 60 ? `${elapsedSec}s` : `${Math.floor(elapsedSec / 60)}m ${elapsedSec % 60}s`}
              {status.total > 0 && status.keysPerMin > 0 && (() => {
                const remaining = status.total - status.processed;
                const etaSec = Math.round((remaining / status.keysPerMin) * 60);
                return etaSec > 0
                  ? ` · ETA: ${etaSec < 60 ? `${etaSec}s` : `${Math.floor(etaSec / 60)}m`}`
                  : null;
              })()}
            </div>
          )}
        </div>
      )}

      {/* Action buttons */}
      <div className="flex gap-3">
        {!isRunning ? (
          <Button
            onClick={handleStart}
            className="font-mono text-xs bg-primary hover:bg-primary/90 gap-2"
            disabled={isRunning}
          >
            <Play className="w-4 h-4" />
            START VALIDATION — {selectedService.toUpperCase()} ({maxKeys.toLocaleString()} max)
          </Button>
        ) : (
          <Button
            onClick={handleStop}
            variant="destructive"
            className="font-mono text-xs gap-2"
          >
            <Square className="w-4 h-4" />
            STOP
          </Button>
        )}
      </div>

      {/* Info block */}
      <div className="bg-card border border-border rounded-lg p-4 space-y-2 text-xs font-mono text-muted-foreground">
        <div className="flex items-center gap-2 text-foreground/70 mb-2">
          <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
          <span>HOW BULK VALIDATION WORKS</span>
        </div>
        <ul className="space-y-1 ml-5 list-disc">
          <li>Validates all <span className="text-foreground">unchecked</span> keys for the selected service</li>
          <li>AWS: uses <span className="text-orange-400">STS GetCallerIdentity</span> with SigV4 signing (requires proxy)</li>
          <li>AWS valid keys also check for <span className="text-orange-400">Amazon Bedrock access</span></li>
          <li>Runs in batches of 5 to avoid rate limiting — typically 100–500 keys/min</li>
          <li>Results are written immediately — see <span className="text-primary">Results → VALID</span></li>
        </ul>
      </div>
    </div>
  );
}
