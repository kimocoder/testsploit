import React, { useState, useCallback, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { getGetMonitorResultsQueryKey, useTriggerCycle } from "@workspace/api-client-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Trash2, Copy, RefreshCw, AlertCircle, CheckCircle2, HelpCircle, ExternalLink, Play, Clock, Download, DatabaseZap, Eye, EyeOff, Info, Server, FileCode, Hash, Globe, Key, Layers, ChevronRight, Search, X, AlertTriangle } from "lucide-react";
import { toast } from "sonner";

// ── Category / service catalogue ─────────────────────────────────────────────
const CATEGORIES = [
  { id: "ai",        label: "AI",        color: "bg-violet-500/20 text-violet-400 border-violet-500/30" },
  { id: "payments",  label: "Payments",  color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  { id: "crypto",    label: "Crypto",    color: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
  { id: "email",     label: "Email",     color: "bg-sky-500/20 text-sky-400 border-sky-500/30" },
  { id: "cloud",     label: "Cloud",     color: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  { id: "auth",      label: "Auth",      color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  { id: "messaging", label: "Messaging", color: "bg-pink-500/20 text-pink-400 border-pink-500/30" },
  { id: "database",  label: "Database",  color: "bg-red-500/20 text-red-400 border-red-500/30" },
  { id: "storage",   label: "Storage",   color: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
] as const;

const SERVICES_BY_CATEGORY: Record<string, string[]> = {
  ai:        ["openai", "anthropic", "openrouter", "google-gemini", "huggingface", "groq", "perplexity", "replicate", "mistral", "cohere", "deepseek", "xai", "moonshot", "dashscope", "minimax", "zhipuai"],
  payments:  ["stripe", "stripe-publishable", "paypal", "square", "shopify", "paddle", "braintree"],
  crypto:    ["ethereum", "bitcoin", "solana", "bip39_seed", "binance", "coinbase", "kraken", "metamask_vault"],
  email:     ["sendgrid", "mailgun", "resend", "postmark"],
  cloud:     ["aws", "digitalocean", "cloudflare"],
  auth:      ["github", "gitlab", "jwt"],
  messaging: ["telegram", "slack-webhook", "discord-webhook", "twilio"],
  database:  ["postgresql", "mysql", "mongodb", "redis"],
  storage:   [],
};

const ALL_SERVICES = Object.values(SERVICES_BY_CATEGORY).flat();

function getCategoryColor(cat: string | null | undefined) {
  return CATEGORIES.find(c => c.id === cat)?.color ?? "bg-muted text-muted-foreground border-border";
}
function getCategoryLabel(cat: string | null | undefined) {
  return CATEGORIES.find(c => c.id === cat)?.label ?? (cat ?? "?");
}

// ── Clipboard helper (works on HTTP and HTTPS) ────────────────────────────────
// navigator.clipboard.writeText requires HTTPS (secure context).
// On HTTP we use execCommand('copy') — deprecated but still works in all major
// browsers when called from a user-gesture handler (button click).

function clipboardCopy(text: string, label = "Copied") {
  if (!text) return;
  // Modern API — HTTPS only
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text)
      .then(() => toast.success(label))
      .catch(() => execCopy(text, label));
    return;
  }
  execCopy(text, label);
}

function execCopy(text: string, label: string) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    // Must be visible + in viewport for execCommand to work in all browsers.
    // opacity:0.001 (not 0) satisfies Chrome's "element must be visible" check.
    ta.style.cssText = [
      "position:fixed", "top:0", "left:0",
      "width:2em", "height:2em",
      "padding:0", "border:none", "outline:none",
      "box-shadow:none", "background:transparent",
      "opacity:0.001", "z-index:9999",
    ].join(";");
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    if (ok) {
      toast.success(label);
    } else {
      // Last resort: show the text in a toast so user can manually copy
      toast.info(`Скопируй вручную (Ctrl+C): ${text.length > 50 ? text.slice(0, 50) + "…" : text}`);
    }
  } catch {
    toast.error("Copy failed — use Ctrl+A, Ctrl+C manually");
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function getStatusBadge(status: string) {
  switch (status) {
    case "valid":        return <Badge className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20 hover:bg-emerald-500/20"><CheckCircle2 className="w-3 h-3 mr-1"/> VALID</Badge>;
    case "invalid":      return <Badge variant="destructive" className="bg-destructive/10 text-destructive border-destructive/20 hover:bg-destructive/20"><AlertCircle className="w-3 h-3 mr-1"/> INVALID</Badge>;
    case "rate_limited": return <Badge className="bg-yellow-500/10 text-yellow-500 border-yellow-500/20 hover:bg-yellow-500/20"><Clock className="w-3 h-3 mr-1"/> RATE LTD</Badge>;
    case "honeypot":     return <Badge className="bg-purple-500/10 text-purple-400 border-purple-500/20 hover:bg-purple-500/20"><AlertTriangle className="w-3 h-3 mr-1"/> HONEYPOT</Badge>;
    default:             return <Badge variant="secondary" className="bg-muted text-muted-foreground border-border hover:bg-muted/80"><HelpCircle className="w-3 h-3 mr-1"/> UNCHECKED</Badge>;
  }
}

// Highlight the key value inside a text block
function highlightKeyInText(text: string, keyValue: string): React.ReactNode {
  if (!keyValue || keyValue.length < 8) return <>{text}</>;
  const idx = text.indexOf(keyValue);
  if (idx === -1) return <>{text}</>;
  return (
    <>
      {text.slice(0, idx)}
      <mark className="bg-primary/30 text-primary rounded px-0.5">{text.slice(idx, idx + keyValue.length)}</mark>
      {text.slice(idx + keyValue.length)}
    </>
  );
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface ResultItem {
  id: string;
  type: string;
  key?: string | null;
  keyMasked?: string | null;
  service?: string | null;
  category?: string | null;
  source: string;
  url?: string;
  status: string;
  firstSeenAt: string;
  validatedAt?: string | null;
}

interface ResultDetail extends ResultItem {
  query?: string;
  title?: string;
  snippet?: string;
  runId?: string | null;
  validatedAt?: string | null;
  publishedAt?: string | null;
  // AWS-specific validation fields
  awsAccountId?: string | null;
  awsArn?: string | null;
  awsKeyType?: string | null;
  awsBedrockAccess?: boolean;
  envDetail?: {
    host?: string | null;
    path?: string | null;
    url?: string | null;
    mode?: string | null;
    contentPreview?: string | null;
    contentLength?: number | null;
    keysFound?: number;
    keyCategories?: string[];
    keyServices?: string[];
    foundAt?: string | null;
  } | null;
}

// ── AWS credentials extraction ────────────────────────────────────────────────

interface AwsCreds {
  accessKeyId: string;
  secretKey: string;
  bedrockToken: string;
  sessionToken: string;
  region: string;
}

function extractAwsCreds(text: string, fallbackKeyId: string): AwsCreds {
  const g = (re: RegExp) => { const m = re.exec(text); return m ? m[1].trim() : ""; };
  const accessKeyId =
    g(/AWS_ACCESS_KEY_ID\s*[=:]\s*["']?([A-Z0-9]{20})["']?/i) || fallbackKeyId;
  const secretKey =
    g(/AWS_SECRET_ACCESS_KEY\s*[=:]\s*["']?([A-Za-z0-9/+=]{20,60})["']?/i);
  const bedrockToken =
    g(/AWS_BEARER_TOKEN_BEDROCK\s*[=:]\s*["']?([A-Za-z0-9/+=]{40,})["']?/i);
  const sessionToken =
    g(/AWS_SESSION_TOKEN\s*[=:]\s*["']?([A-Za-z0-9/+=]{50,})["']?/i);
  const region =
    g(/AWS_(?:DEFAULT_)?REGION\s*[=:]\s*["']?([a-z0-9-]{4,20})["']?/i) || "us-east-1";
  return { accessKeyId, secretKey, bedrockToken, sessionToken, region };
}

function maskValue(v: string): string {
  if (!v) return "";
  if (v.length <= 8) return "*".repeat(v.length);
  return v.slice(0, 6) + "…" + v.slice(-4);
}

/** Build copyable AWS credentials block (env format) */
function buildAwsCredsText(creds: AwsCreds): string {
  const lines: string[] = [];
  if (creds.accessKeyId)  lines.push(`AWS_ACCESS_KEY_ID=${creds.accessKeyId}`);
  if (creds.secretKey)    lines.push(`AWS_SECRET_ACCESS_KEY=${creds.secretKey}`);
  if (creds.bedrockToken) lines.push(`AWS_BEARER_TOKEN_BEDROCK=${creds.bedrockToken}`);
  if (creds.sessionToken) lines.push(`AWS_SESSION_TOKEN=${creds.sessionToken}`);
  if (creds.region)       lines.push(`AWS_DEFAULT_REGION=${creds.region}`);
  return lines.join("\n");
}

interface ResultsPage {
  items: ResultItem[];
  total: number;
  page: number;
  pages: number;
}

// ── Group type ────────────────────────────────────────────────────────────────
interface GroupEntry {
  groupKey: string;
  host: string;
  service: string;
  category: string | null;
  source: string;
  count: number;
  statuses: { valid: number; invalid: number; rate_limited: number; unchecked: number };
  newestAt: string;
  items: ResultItem[];
}

function extractHost(item: ResultItem): string {
  if (item.url) {
    try { return new URL(item.url).hostname; } catch { /* fall through */ }
  }
  return item.source || "unknown";
}

function computeGroups(items: ResultItem[]): GroupEntry[] {
  const map = new Map<string, GroupEntry>();
  for (const item of items) {
    const host = extractHost(item);
    const svc  = item.service ?? "unknown";
    const key  = `${host}||${svc}`;
    if (!map.has(key)) {
      map.set(key, {
        groupKey: key, host, service: svc,
        category: item.category ?? null,
        source: item.source,
        count: 0,
        statuses: { valid: 0, invalid: 0, rate_limited: 0, unchecked: 0 },
        newestAt: item.firstSeenAt,
        items: [],
      });
    }
    const g = map.get(key)!;
    g.count++;
    g.items.push(item);
    const st = item.status as keyof typeof g.statuses;
    if (st in g.statuses) g.statuses[st]++;
    else g.statuses.unchecked++;
    if (item.firstSeenAt > g.newestAt) g.newestAt = item.firstSeenAt;
  }
  return Array.from(map.values()).sort((a, b) => b.count - a.count);
}

function GroupStatusSummary({ s }: { s: GroupEntry["statuses"] }) {
  const parts: React.ReactNode[] = [];
  if (s.valid)        parts.push(<span key="v" className="text-emerald-400">{s.valid}✓</span>);
  if (s.invalid)      parts.push(<span key="i" className="text-destructive">{s.invalid}✗</span>);
  if (s.rate_limited) parts.push(<span key="r" className="text-yellow-400">{s.rate_limited}⏱</span>);
  if (s.unchecked)    parts.push(<span key="u" className="text-muted-foreground">{s.unchecked}?</span>);
  return <div className="flex gap-1.5 font-mono text-xs">{parts}</div>;
}

// ── Detail Modal ──────────────────────────────────────────────────────────────

function DetailModal({
  itemId,
  open,
  onClose,
  onValidate,
  validating,
}: {
  itemId: string | null;
  open: boolean;
  onClose: () => void;
  onValidate: (id: string) => void;
  validating: string | null;
}) {
  const [detail, setDetail] = useState<ResultDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [revealed, setRevealed] = useState(false);
  const [liveContent, setLiveContent] = useState<string | null>(null);
  const [liveLoading, setLiveLoading] = useState(false);

  React.useEffect(() => {
    if (!open || !itemId) { setDetail(null); setRevealed(false); setLiveContent(null); return; }
    setLoading(true);
    fetch(`/api/monitor/results/${itemId}`)
      .then(r => r.json())
      .then((d: ResultDetail) => setDetail(d))
      .catch(() => toast.error("Failed to load details"))
      .finally(() => setLoading(false));
  }, [open, itemId]);

  // Auto-fetch full content from the leaked URL when the stored secret is truncated
  React.useEffect(() => {
    if (!open || !itemId || !detail || liveContent !== null || liveLoading) return;
    if (detail.service !== "aws") return;

    const rawContent = detail.envDetail?.contentPreview ?? detail.snippet ?? "";
    const existingSecret = extractAwsCreds(rawContent, detail.key ?? "").secretKey;
    const needsFull = !existingSecret || existingSecret.length < 40;

    if (!needsFull) return; // secret already complete

    setLiveLoading(true);
    fetch(`/api/monitor/results/${itemId}/live-content`, { method: "POST" })
      .then(r => r.json())
      .then((d: { content?: string }) => {
        if (d?.content) setLiveContent(d.content);
      })
      .catch(() => { /* keep truncated */ })
      .finally(() => setLiveLoading(false));
  }, [open, itemId, detail, liveContent, liveLoading]);

  const copyToClipboard = (text: string, label = "Copied") => clipboardCopy(text, label);

  const isEnv  = detail?.source === "ENV Scanner" || !!detail?.runId;
  const envUrl = detail?.envDetail?.url ?? detail?.url ?? "";
  const host   = detail?.envDetail?.host ?? detail?.query ?? "";
  // Extract path from URL when envDetail lookup missed (env_found.jsonl cleaned up)
  const filePath = detail?.envDetail?.path ?? (() => {
    if (!isEnv || !envUrl) return "";
    try { return new URL(envUrl).pathname; } catch { return ""; }
  })();
  const mode   = detail?.envDetail?.mode ?? "";
  // For ENV Scanner: use contentPreview if available, else fall back to snippet
  // (env_found.jsonl entries get trimmed by hourly cleanup; snippet is always saved in found_keys.jsonl)
  const content = liveContent ?? (detail?.envDetail?.contentPreview ?? (isEnv ? (detail?.snippet ?? "") : ""));
  const snippet = detail?.snippet ?? "";

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-w-2xl w-full max-h-[90vh] overflow-y-auto bg-card border-border font-mono">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm font-mono">
            <Key className="w-4 h-4 text-primary" />
            <span className="text-primary uppercase">{detail?.service ?? "…"}</span>
            {detail?.category && (
              <Badge className={`text-xs ${getCategoryColor(detail.category)}`}>
                {getCategoryLabel(detail.category)}
              </Badge>
            )}
            <span className="ml-auto">{detail ? getStatusBadge(detail.status) : null}</span>
          </DialogTitle>
        </DialogHeader>

        {loading && (
          <div className="py-10 text-center text-muted-foreground text-xs animate-pulse">LOADING…</div>
        )}

        {!loading && detail && (() => {
          // For AWS keys: extract full credentials from FILE CONTENT.
          // Prefer live-fetched content (full secret), then envDetail, then snippet.
          const isAws = detail.service === "aws";
          const rawContent =
            (isAws ? (liveContent ?? detail.envDetail?.contentPreview ?? detail.snippet ?? "") : (detail.envDetail?.contentPreview ?? detail.snippet ?? ""));
          const awsCreds = isAws ? extractAwsCreds(rawContent, detail.key ?? "") : null;
          const awsCredsText = awsCreds ? buildAwsCredsText(awsCreds) : "";
          const hasAwsSecret = awsCreds ? awsCreds.secretKey.length > 0 : false;

          return (
          <div className="space-y-4 text-xs">

            {/* AWS CREDENTIALS section — replaces plain KEY for AWS service */}
            {isAws && awsCreds ? (
              <section className="space-y-1">
                <div className="text-muted-foreground flex items-center gap-1 mb-1">
                  <Hash className="w-3 h-3" />
                  <span>AWS CREDENTIALS</span>
                  {detail.awsBedrockAccess && (
                    <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded border border-orange-500/50 bg-orange-500/10 text-orange-300 font-mono">
                      🟠 BEDROCK
                    </span>
                  )}
                  {detail.awsAccountId && (
                    <span className="ml-1 text-[10px] px-1.5 py-0.5 rounded border border-border bg-muted text-muted-foreground font-mono">
                      {detail.awsAccountId}
                    </span>
                  )}
                  <div className="ml-auto flex gap-1">
                    <Button variant="ghost" size="icon" className="h-6 w-6 shrink-0 text-muted-foreground hover:text-foreground"
                      onClick={() => setRevealed(r => !r)} title={revealed ? "Hide" : "Reveal all"}>
                      {revealed ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    </Button>
                    <Button variant="ghost" size="icon" className="h-6 w-6 shrink-0 text-muted-foreground hover:text-foreground"
                      onClick={() => copyToClipboard(awsCredsText || (detail.key ?? ""), "AWS credentials copied")}
                      title="Copy all credentials">
                      <Copy className="w-3 h-3" />
                    </Button>
                  </div>
                </div>
                <div className="bg-background border border-orange-500/20 rounded p-3 space-y-1.5 font-mono text-[11px]">
                  {/* Row 1: ACCESS KEY ID */}
                  <div className="flex items-start gap-2">
                    <span className="text-muted-foreground/60 w-[190px] shrink-0">AWS_ACCESS_KEY_ID</span>
                    <code className="flex-1 break-all select-all text-primary font-bold">
                      {revealed ? (awsCreds.accessKeyId || detail.key || "—") : (detail.keyMasked ?? maskValue(awsCreds.accessKeyId))}
                    </code>
                    <Button variant="ghost" size="icon" className="h-5 w-5 shrink-0 text-muted-foreground hover:text-foreground"
                      onClick={() => copyToClipboard(awsCreds.accessKeyId || (detail.key ?? ""), "Access Key ID copied")}>
                      <Copy className="w-2.5 h-2.5" />
                    </Button>
                  </div>
                  {/* Row 2: SECRET ACCESS KEY */}
                  {(revealed ? awsCreds.secretKey : maskValue(awsCreds.secretKey)) && (
                    <div className="flex items-start gap-2">
                      <span className="text-muted-foreground/60 w-[190px] shrink-0">AWS_SECRET_ACCESS_KEY</span>
                      <code className={`flex-1 break-all select-all ${revealed ? "text-amber-300" : "text-muted-foreground"}`}>
                        {revealed ? awsCreds.secretKey : maskValue(awsCreds.secretKey)}
                      </code>
                      <Button variant="ghost" size="icon" className="h-5 w-5 shrink-0 text-muted-foreground hover:text-foreground"
                        onClick={() => copyToClipboard(awsCreds.secretKey, "Secret Key copied")}>
                        <Copy className="w-2.5 h-2.5" />
                      </Button>
                    </div>
                  )}
                  {/* Row 3: BEDROCK TOKEN */}
                  {awsCreds.bedrockToken && (
                    <div className="flex items-start gap-2">
                      <span className="text-muted-foreground/60 w-[190px] shrink-0">AWS_BEARER_TOKEN_BEDROCK</span>
                      <code className={`flex-1 break-all select-all ${revealed ? "text-orange-300" : "text-muted-foreground"}`}>
                        {revealed ? awsCreds.bedrockToken : maskValue(awsCreds.bedrockToken)}
                      </code>
                      <Button variant="ghost" size="icon" className="h-5 w-5 shrink-0 text-muted-foreground hover:text-foreground"
                        onClick={() => copyToClipboard(awsCreds.bedrockToken, "Bedrock token copied")}>
                        <Copy className="w-2.5 h-2.5" />
                      </Button>
                    </div>
                  )}
                  {/* Row 4: SESSION TOKEN (if present) */}
                  {awsCreds.sessionToken && (
                    <div className="flex items-start gap-2">
                      <span className="text-muted-foreground/60 w-[190px] shrink-0">AWS_SESSION_TOKEN</span>
                      <code className={`flex-1 break-all select-all ${revealed ? "text-cyan-300" : "text-muted-foreground"}`}>
                        {revealed ? awsCreds.sessionToken : maskValue(awsCreds.sessionToken)}
                      </code>
                      <Button variant="ghost" size="icon" className="h-5 w-5 shrink-0 text-muted-foreground hover:text-foreground"
                        onClick={() => copyToClipboard(awsCreds.sessionToken, "Session token copied")}>
                        <Copy className="w-2.5 h-2.5" />
                      </Button>
                    </div>
                  )}
                  {/* Region */}
                  {awsCreds.region && (
                    <div className="flex items-center gap-2 pt-1 border-t border-border/40">
                      <span className="text-muted-foreground/60 w-[190px] shrink-0">AWS_DEFAULT_REGION</span>
                      <code className="text-muted-foreground">{awsCreds.region}</code>
                    </div>
                  )}
                  {/* Copy all button */}
                  {hasAwsSecret && (
                    <div className="pt-2 border-t border-border/40">
                      <Button
                        variant="outline" size="sm"
                        className="w-full h-7 text-[10px] font-mono border-orange-500/30 text-orange-300 hover:bg-orange-500/10 gap-1"
                        onClick={() => copyToClipboard(awsCredsText, "All AWS credentials copied ✓")}
                      >
                        <Copy className="w-3 h-3" />
                        COPY ALL {awsCreds.bedrockToken ? "3" : "2"} CREDENTIALS
                      </Button>
                    </div>
                  )}
                </div>
                {/* ARN info */}
                {detail.awsArn && (
                  <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-mono px-1">
                    <span className="text-muted-foreground/50">ARN:</span>
                    <span className="text-foreground/60 break-all">{detail.awsArn}</span>
                    {detail.awsKeyType && (
                      <span className="ml-auto text-[9px] px-1 py-0.5 rounded bg-muted border border-border uppercase">
                        {detail.awsKeyType}
                      </span>
                    )}
                  </div>
                )}
                {/* Warning: secret truncated in stored snippet */}
                {hasAwsSecret && awsCreds.secretKey.length < 40 && (
                  <div className={`flex items-center gap-2 text-[10px] font-mono px-1 py-1.5 rounded border ${
                    liveContent
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                      : "border-amber-500/30 bg-amber-500/10 text-amber-400"
                  }`}>
                    {liveLoading ? (
                      <>
                        <RefreshCw className="w-3 h-3 shrink-0 animate-spin" />
                        Fetching full content from URL…
                      </>
                    ) : liveContent ? (
                      <>
                        <CheckCircle2 className="w-3 h-3 shrink-0" />
                        Full secret loaded ({awsCreds.secretKey.length}/40 chars)
                      </>
                    ) : (
                      <>
                        <AlertCircle className="w-3 h-3 shrink-0" />
                        Secret truncated ({awsCreds.secretKey.length}/40 chars) — live fetch failed, open URL manually
                      </>
                    )}
                  </div>
                )}
              </section>
            ) : (
              /* Standard KEY section for non-AWS */
              <section className="space-y-1">
                <div className="text-muted-foreground flex items-center gap-1 mb-1">
                  <Hash className="w-3 h-3" /> KEY
                </div>
                <div className="flex items-center gap-2 bg-background border border-border rounded p-2">
                  <code className="flex-1 break-all text-foreground select-all">
                    {revealed ? (detail.key ?? detail.keyMasked) : detail.keyMasked}
                  </code>
                  <Button variant="ghost" size="icon" className="h-6 w-6 shrink-0 text-muted-foreground hover:text-foreground"
                    onClick={() => setRevealed(r => !r)} title={revealed ? "Hide" : "Reveal"}>
                    {revealed ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                  </Button>
                  <Button variant="ghost" size="icon" className="h-6 w-6 shrink-0 text-muted-foreground hover:text-foreground"
                    onClick={() => copyToClipboard(detail.key ?? detail.keyMasked ?? "", "Key copied")}>
                    <Copy className="w-3 h-3" />
                  </Button>
                </div>
              </section>
            )}

            {/* Source info */}
            <section className="space-y-2">
              <div className="text-muted-foreground flex items-center gap-1 mb-1">
                <Info className="w-3 h-3" /> SOURCE
              </div>
              <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 bg-background border border-border rounded p-3">
                <span className="text-muted-foreground">Scanner</span>
                <span className="text-foreground">{detail.source}</span>

                {isEnv && host && (
                  <>
                    <span className="text-muted-foreground flex items-center gap-1"><Server className="w-3 h-3" />Host</span>
                    <span className="text-primary break-all flex items-center gap-1">
                      {host}
                      <Button variant="ghost" size="icon" className="h-5 w-5 text-muted-foreground hover:text-foreground"
                        onClick={() => copyToClipboard(host, "Host copied")}>
                        <Copy className="w-2.5 h-2.5" />
                      </Button>
                    </span>
                  </>
                )}

                {isEnv && filePath && (
                  <>
                    <span className="text-muted-foreground flex items-center gap-1"><FileCode className="w-3 h-3" />Path</span>
                    <span className="text-amber-400 break-all">{filePath}</span>
                  </>
                )}

                {isEnv && mode && (
                  <>
                    <span className="text-muted-foreground">Mode</span>
                    <span className="text-foreground uppercase">{mode}</span>
                  </>
                )}

                {envUrl && (
                  <>
                    <span className="text-muted-foreground flex items-center gap-1"><Globe className="w-3 h-3" />URL</span>
                    <span className="break-all">
                      <a href={envUrl} target="_blank" rel="noreferrer"
                        className="text-secondary hover:underline inline-flex items-center gap-1">
                        {envUrl.length > 80 ? envUrl.slice(0, 80) + "…" : envUrl}
                        <ExternalLink className="w-3 h-3 shrink-0" />
                      </a>
                      <Button variant="ghost" size="icon" className="h-5 w-5 ml-1 text-muted-foreground hover:text-foreground"
                        onClick={() => copyToClipboard(envUrl, "URL copied")}>
                        <Copy className="w-2.5 h-2.5" />
                      </Button>
                    </span>
                  </>
                )}

                {!isEnv && detail.query && (
                  <>
                    <span className="text-muted-foreground">Query</span>
                    <span className="text-foreground break-all">{detail.query}</span>
                  </>
                )}

                {detail.firstSeenAt && (
                  <>
                    <span className="text-muted-foreground">First seen</span>
                    <span className="text-foreground">{new Date(detail.firstSeenAt).toLocaleString()}</span>
                  </>
                )}

                {detail.runId && (
                  <>
                    <span className="text-muted-foreground">Run ID</span>
                    <span className="text-muted-foreground/70">{detail.runId}</span>
                  </>
                )}
              </div>
            </section>

            {/* ENV file content preview */}
            {isEnv && content && (
              <section className="space-y-1">
                <div className="text-muted-foreground flex items-center gap-2 mb-1">
                  <FileCode className="w-3 h-3" />
                  <span>FILE CONTENT</span>
                  {detail.envDetail?.contentLength != null && (
                    <span className="text-muted-foreground/50">({detail.envDetail.contentLength} bytes)</span>
                  )}
                  <Button variant="ghost" size="icon" className="h-5 w-5 ml-auto text-muted-foreground hover:text-foreground"
                    onClick={() => copyToClipboard(content, "Content copied")}>
                    <Copy className="w-2.5 h-2.5" />
                  </Button>
                </div>
                <pre className="bg-background border border-border rounded p-3 overflow-x-auto text-[11px] leading-relaxed whitespace-pre-wrap break-all text-foreground/80 max-h-48">
                  {highlightKeyInText(content, detail.key ?? "")}
                </pre>
              </section>
            )}

            {/* Snippet (public scanner) */}
            {!isEnv && snippet && (
              <section className="space-y-1">
                <div className="text-muted-foreground flex items-center gap-1 mb-1">
                  <FileCode className="w-3 h-3" /> SNIPPET
                </div>
                <pre className="bg-background border border-border rounded p-3 overflow-x-auto text-[11px] leading-relaxed whitespace-pre-wrap break-all text-foreground/80 max-h-48">
                  {highlightKeyInText(snippet, detail.key ?? "")}
                </pre>
              </section>
            )}

            {/* Actions */}
            <div className="flex gap-2 pt-1 border-t border-border">
              {detail.type === "key" && (
                <Button size="sm" variant="outline"
                  className="h-7 text-xs font-mono border-primary/30 text-primary hover:bg-primary/10"
                  onClick={() => onValidate(detail.id)}
                  disabled={validating === detail.id}>
                  {validating === detail.id ? <RefreshCw className="w-3 h-3 mr-1 animate-spin" /> : <CheckCircle2 className="w-3 h-3 mr-1" />}
                  {validating === detail.id ? "VALIDATING…" : "VALIDATE NOW"}
                </Button>
              )}
              {envUrl && (
                <Button size="sm" variant="outline"
                  className="h-7 text-xs font-mono border-secondary/30 text-secondary hover:bg-secondary/10"
                  onClick={() => window.open(envUrl, "_blank", "noreferrer")}>
                  <ExternalLink className="w-3 h-3 mr-1" /> OPEN URL
                </Button>
              )}
              <Button size="sm" variant="ghost" className="h-7 text-xs font-mono ml-auto text-muted-foreground" onClick={onClose}>
                CLOSE
              </Button>
            </div>
          </div>
          );
        })()}
      </DialogContent>
    </Dialog>
  );
}

// ── Group Modal ───────────────────────────────────────────────────────────────

const GROUP_PAGE_SIZE = 50;

function GroupModal({
  group,
  open,
  onClose,
  onValidate,
  validating,
  onOpenDetail,
}: {
  group: GroupEntry | null;
  open: boolean;
  onClose: () => void;
  onValidate: (id: string) => void;
  validating: string | null;
  onOpenDetail: (id: string) => void;
}) {
  const [gPage, setGPage] = useState(1);
  const [deleting, setDeleting] = useState(false);
  React.useEffect(() => { setGPage(1); }, [group?.groupKey]);

  const handleDeleteHost = async () => {
    if (!group) return;
    const confirmed = window.confirm(
      `Delete ALL ${group.count.toLocaleString()} keys from host:\n${group.host}\n\nThis removes them from found_keys.jsonl and env_found.jsonl.\nThis CANNOT be undone.`
    );
    if (!confirmed) return;
    setDeleting(true);
    try {
      const [r1, r2] = await Promise.all([
        fetch(`/api/monitor/results/by-filter?host=${encodeURIComponent(group.host)}`, { method: "DELETE" }),
        fetch(`/api/env-scan/results/by-host?host=${encodeURIComponent(group.host)}`, { method: "DELETE" }),
      ]);
      const d1 = r1.ok ? (await r1.json() as { removed?: number }) : { removed: 0 };
      const d2 = r2.ok ? (await r2.json() as { removed?: number }) : { removed: 0 };
      const total = (d1.removed ?? 0) + (d2.removed ?? 0);
      onClose();
      window.location.reload();
      window.alert(`Deleted ${total.toLocaleString()} records for ${group.host}`);
    } catch (err) {
      alert(`Delete failed: ${String(err)}`);
    } finally {
      setDeleting(false);
    }
  };

  if (!group) return null;
  const totalPages = Math.ceil(group.items.length / GROUP_PAGE_SIZE);
  const pageItems  = group.items.slice((gPage - 1) * GROUP_PAGE_SIZE, gPage * GROUP_PAGE_SIZE);

  return (
    <Dialog open={open} onOpenChange={v => { if (!v) onClose(); }}>
      <DialogContent className="max-w-3xl w-full max-h-[88vh] flex flex-col bg-card border-amber-500/40 border font-mono">
        <DialogHeader className="shrink-0">
          <DialogTitle className="flex items-center gap-2 text-sm font-mono">
            <Layers className="w-4 h-4 text-amber-400" />
            <span className="text-amber-400 uppercase">{group.host}</span>
            <span className="text-muted-foreground">/</span>
            <span className="text-primary uppercase">{group.service}</span>
            {group.category && (
              <Badge className={`text-xs ${getCategoryColor(group.category)}`}>
                {getCategoryLabel(group.category)}
              </Badge>
            )}
            <Badge className="ml-auto bg-amber-500/20 text-amber-400 border-amber-500/30 font-mono">
              {group.count} keys
            </Badge>
            <button
              onClick={handleDeleteHost}
              disabled={deleting}
              className="flex items-center gap-1 px-2 py-1 text-xs bg-red-500/10 text-red-400 border border-red-500/30 hover:bg-red-500/20 hover:border-red-500/50 rounded font-mono disabled:opacity-50 disabled:cursor-not-allowed transition-colors ml-1"
              title={`Delete ALL ${group.count.toLocaleString()} keys from ${group.host}`}
            >
              <Trash2 className="w-3 h-3" />
              {deleting ? "Deleting?" : "Delete host"}
            </button>
          </DialogTitle>
          <div className="flex items-center gap-4 pt-1 text-xs text-muted-foreground">
            <GroupStatusSummary s={group.statuses} />
            <span>·</span>
            <span>{group.source}</span>
            <span>·</span>
            <span>newest: {new Date(group.newestAt).toLocaleString()}</span>
          </div>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto border border-border rounded-lg mt-2">
          <Table>
            <TableHeader className="bg-muted/50 sticky top-0 z-10">
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="font-mono text-xs text-muted-foreground w-[40px]">#</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground min-w-[220px]">KEY</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground">STATUS</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground">PATH</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground text-right w-[130px]">SEEN</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground text-right w-[90px]">ACTION</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pageItems.map((item, idx) => {
                let urlPath = "";
                try { urlPath = new URL(item.url ?? "").pathname; } catch { /* ignore */ }
                const absIdx = (gPage - 1) * GROUP_PAGE_SIZE + idx + 1;
                return (
                  <TableRow key={item.id} className="border-border hover:bg-muted/30">
                    <TableCell className="text-xs text-muted-foreground font-mono">{absIdx}</TableCell>
                    <TableCell className="font-mono text-xs">
                      <code className="bg-background px-2 py-1 rounded border border-border text-foreground">
                        {item.keyMasked ?? item.key ?? "—"}
                      </code>
                    </TableCell>
                    <TableCell>{getStatusBadge(item.status)}</TableCell>
                    <TableCell className="font-mono text-xs text-amber-400/80 max-w-[200px] truncate" title={urlPath}>
                      {urlPath || "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground text-right">
                      {new Date(item.firstSeenAt).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-primary"
                          title="Full details" onClick={() => { onClose(); onOpenDetail(item.id); }}>
                          <Info className="h-3.5 w-3.5" />
                        </Button>
                        {item.type === "key" && (
                          <Button variant="outline" size="sm"
                            className="h-7 text-xs font-mono border-primary/30 text-primary hover:bg-primary/10"
                            onClick={() => onValidate(item.id)}
                            disabled={validating === item.id}>
                            {validating === item.id ? "…" : "VAL"}
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>

        {totalPages > 1 && (
          <div className="shrink-0 flex items-center justify-between pt-3 border-t border-border mt-2">
            <span className="text-xs text-muted-foreground font-mono">
              {(gPage - 1) * GROUP_PAGE_SIZE + 1}–{Math.min(gPage * GROUP_PAGE_SIZE, group.count)} of {group.count}
            </span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => setGPage(p => Math.max(1, p - 1))} disabled={gPage === 1} className="font-mono text-xs h-7">PREV</Button>
              <div className="px-3 flex items-center text-xs font-mono bg-background border border-border rounded">PG {gPage}/{totalPages}</div>
              <Button variant="outline" size="sm" onClick={() => setGPage(p => Math.min(totalPages, p + 1))} disabled={gPage >= totalPages} className="font-mono text-xs h-7">NEXT</Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Results() {
  const [page, setPage]           = useState(1);
  const [type, setType]           = useState("all");
  const [status, setStatus]       = useState("valid");
  const [category, setCategory]   = useState("all");
  const [service, setService]     = useState("all");
  const [awsOnly, setAwsOnly]         = useState(false);
  const [bedrockOnly, setBedrockOnly] = useState(false);
  const [keySearch, setKeySearch] = useState("");
  const [keySearchInput, setKeySearchInput] = useState("");
  const debounceRef               = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [data, setData]           = useState<ResultsPage | null>(null);
  const [loading, setLoading]     = useState(false);
  const [validating, setValidating] = useState<string | null>(null);
  const [detailId, setDetailId]   = useState<string | null>(null);

  const queryClient   = useQueryClient();
  const triggerCycle  = useTriggerCycle();

  // ── Group mode state ──────────────────────────────────────────────────────
  const [groupMode,    setGroupMode]    = useState(false);
  const [groupData,    setGroupData]    = useState<ResultItem[] | null>(null);
  const [groupLoading, setGroupLoading] = useState(false);
  const [groupPage,    setGroupPage]    = useState(1);
  const [activeGroup,  setActiveGroup]  = useState<GroupEntry | null>(null);
  const [groupModalOpen, setGroupModalOpen] = useState(false);

  const GROUP_VIEW_SIZE = 25; // groups per page in the main table

  const fetchGroupData = useCallback(
    async (params: { type: string; status: string; category: string; service: string; bedrockOnly?: boolean }) => {
      setGroupLoading(true);
      try {
        const q = new URLSearchParams({
          export: "1",
          ...(params.type     !== "all" ? { type:     params.type }     : {}),
          ...(params.status   !== "all" ? { status:   params.status }   : {}),
          ...(params.category !== "all" ? { category: params.category } : {}),
          ...(params.service  !== "all" ? { service:  params.service }  : {}),
          ...(params.bedrockOnly ? { bedrock: "1" } : {}),
        });
        const r = await fetch(`/api/monitor/results?${q}`);
        const d: ResultsPage = await r.json();
        setGroupData(d.items);
        setGroupPage(1);
      } catch {
        toast.error("Failed to load group data");
      } finally {
        setGroupLoading(false);
      }
    }, []
  );

  // Re-fetch group data when filters change while group mode is on
  React.useEffect(() => {
    if (groupMode) fetchGroupData({ type, status, category, service, bedrockOnly });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groupMode, type, status, category, service, bedrockOnly]);

  const allGroups = React.useMemo(
    () => groupData ? computeGroups(groupData) : [],
    [groupData]
  );
  const pagedGroups = allGroups.slice((groupPage - 1) * GROUP_VIEW_SIZE, groupPage * GROUP_VIEW_SIZE);
  const groupTotalPages = Math.ceil(allGroups.length / GROUP_VIEW_SIZE);

  const openGroup = (g: GroupEntry) => { setActiveGroup(g); setGroupModalOpen(true); };
  const toggleGroupMode = () => {
    const next = !groupMode;
    setGroupMode(next);
    if (next) fetchGroupData({ type, status, category, service, bedrockOnly });
    else { setGroupData(null); setGroupPage(1); }
  };

  const fetchResults = useCallback(
    async (params: { page: number; type: string; status: string; category: string; service: string; bedrockOnly?: boolean; keySearch?: string }) => {
      setLoading(true);
      try {
        const ks = params.keySearch ?? "";
        const q = new URLSearchParams({
          page: String(params.page),
          limit: "50",
          ...(ks ? { type: "keys" } : (params.type !== "all" ? { type: params.type } : {})),
          ...(params.status   !== "all" ? { status:   params.status }   : {}),
          ...(params.category !== "all" ? { category: params.category } : {}),
          ...(params.service  !== "all" ? { service:  params.service }  : {}),
          ...(params.bedrockOnly ? { bedrock: "1" } : {}),
          ...(ks ? { keySearch: ks } : {}),
        });
        const r = await fetch(`/api/monitor/results?${q}`);
        const d: ResultsPage = await r.json();
        setData(d);
      } catch {
        toast.error("Failed to load results");
      } finally {
        setLoading(false);
      }
    },
    []
  );

  React.useEffect(() => {
    fetchResults({ page, type, status, category, service, bedrockOnly, keySearch });
  }, [fetchResults, page, type, status, category, service, bedrockOnly, keySearch]);

  const handleCategoryChange = (val: string) => { setCategory(val); setService("all"); setAwsOnly(false); setPage(1); };
  const handleServiceChange  = (val: string) => { setService(val); setAwsOnly(val === "aws"); setPage(1); };
  const handleTypeChange     = (val: string) => { setType(val);     setPage(1); };
  const handleStatusChange   = (val: string) => { setStatus(val);   setPage(1); };
  const handleBedrockToggle  = () => { setBedrockOnly(b => !b); setPage(1); };
  const handleAwsToggle      = () => {
    setAwsOnly(a => {
      if (!a) { setCategory("cloud"); setService("aws"); } // enable: snap to aws
      else   { setService("all"); setCategory("all"); }    // disable: reset
      return !a;
    });
    setPage(1);
  };

  const handleKeySearchInputChange = (val: string) => {
    setKeySearchInput(val);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setKeySearch(val);
      setPage(1);
    }, 400);
  };
  const clearKeySearch = () => {
    setKeySearchInput("");
    setKeySearch("");
    setPage(1);
  };

  const handleValidate = async (id: string) => {
    setValidating(id);
    try {
      const r = await fetch(`/api/monitor/validate/${id}`, { method: "POST" });
      const d = await r.json();
      toast.success(`Validation: ${d.status}`);
      fetchResults({ page, type, status, category, service });
      queryClient.invalidateQueries({ queryKey: getGetMonitorResultsQueryKey() });
    } catch {
      toast.error("Validation failed");
    } finally {
      setValidating(null);
    }
  };

  const handleTriggerCycle = () => {
    toast.promise(triggerCycle.mutateAsync(), {
      loading: "Запуск цикла сканирования…",
      success: "Цикл запущен — паблик-сканер начнёт обход источников в течение 1–2 секунд",
      error: (err: unknown) =>
        `Не удалось запустить цикл: ${err instanceof Error ? err.message : String(err)}`,
    });
  };

  const copyToClipboard = (text: string, label = "Copied to clipboard") => clipboardCopy(text, label);

  const handleExport = async () => {
    toast.info("Подготовка экспорта…");
    try {
      const filterDesc = [
        type     !== "all" ? `type=${type}`         : null,
        status   !== "all" ? `status=${status}`     : null,
        category !== "all" ? `category=${category}` : null,
        service  !== "all" ? `service=${service}`   : null,
      ].filter(Boolean).join(", ") || "all";

      // ── Group mode: use already-loaded groupData, export every item grouped ──
      if (groupMode && groupData && groupData.length > 0) {
        const groups = computeGroups(groupData);
        const lines: string[] = [
          `KMON_NOC Export (Grouped by Host)`,
          `Date   : ${new Date().toISOString()}`,
          `Filters: ${filterDesc}`,
          `Groups : ${groups.length}`,
          `Total  : ${groupData.length}`,
          "=".repeat(80), "",
        ];
        let globalIdx = 1;
        groups.forEach((g) => {
          const statusStr = [
            g.statuses.valid        ? `${g.statuses.valid} valid`        : null,
            g.statuses.invalid      ? `${g.statuses.invalid} invalid`    : null,
            g.statuses.rate_limited ? `${g.statuses.rate_limited} rl`    : null,
            g.statuses.unchecked    ? `${g.statuses.unchecked} unchecked`: null,
          ].filter(Boolean).join(", ");
          lines.push(`${"─".repeat(60)}`);
          lines.push(`HOST   : ${g.host}`);
          lines.push(`SERVICE: ${g.service.toUpperCase()}  CATEGORY: ${(g.category ?? "?").toUpperCase()}`);
          lines.push(`COUNT  : ${g.count}  (${statusStr})`);
          lines.push(`SOURCE : ${g.source}  NEWEST: ${new Date(g.newestAt).toLocaleString()}`);
          lines.push("");
          g.items.forEach((item) => {
            const ts = new Date(item.firstSeenAt).toLocaleString();
            let urlPath = "";
            try { urlPath = new URL(item.url ?? "").pathname; } catch { /* ignore */ }
            lines.push(`  [${globalIdx++}] ${item.status.toUpperCase()} | ${ts}`);
            lines.push(`       KEY : ${item.key || item.keyMasked || ""}`);
            if (urlPath) lines.push(`       PATH: ${urlPath}`);
            lines.push("");
          });
        });
        const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a");
        const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
        a.href = url; a.download = `kmon-grouped-${stamp}.txt`;
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast.success(`Экспортировано ${groupData.length} ключей из ${groups.length} групп`);
        return;
      }

      // ── Normal mode: flat list via server ─────────────────────────────────────
      const q = new URLSearchParams({
        export: "1",
        ...(keySearch ? { type: "keys", keySearch } : (type !== "all" ? { type } : {})),
        ...(status   !== "all" ? { status }   : {}),
        ...(category !== "all" ? { category } : {}),
        ...(service  !== "all" ? { service }  : {}),
      });
      const r = await fetch(`/api/monitor/results?${q}`);
      const d: ResultsPage = await r.json();
      const lines: string[] = [
        `KMON_NOC Export`, `Date   : ${new Date().toISOString()}`,
        `Filters: ${filterDesc}`, `Total  : ${d.total}`, "=".repeat(80), "",
      ];
      d.items.forEach((item, i) => {
        const ts = new Date(item.firstSeenAt).toLocaleString();
        if (item.type === "key") {
          lines.push(`[${i + 1}] ${(item.service ?? "?").toUpperCase()} | ${(item.category ?? "?").toUpperCase()} | ${item.status.toUpperCase()} | ${item.source} | ${ts}`);
          lines.push(`    ${item.key || item.keyMasked || ""}`);
        } else {
          lines.push(`[${i + 1}] URL | ${item.status.toUpperCase()} | ${item.source} | ${ts}`);
          lines.push(`    ${item.url || ""}`);
        }
        lines.push("");
      });
      const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      a.href = url; a.download = `kmon-export-${stamp}.txt`;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      URL.revokeObjectURL(url);
    toast.success(`Экспортировано ${d.total} записей`);
  } catch {
    toast.error("Ошибка экспорта");
  }
  };

  const handlePurgeService = async (svc: string) => {
    if (!svc || svc === "all") {
      toast.error("Select a specific service to purge");
      return;
    }
    try {
      const cr = await fetch(`/api/monitor/results/count-by-filter?service=${encodeURIComponent(svc)}`);
      const cd = cr.ok ? (await cr.json() as {total?:number; valid?:number}) : { total: 0, valid: 0 };
      const total = cd.total ?? 0;
      const valid = cd.valid ?? 0;
      const warn = valid > 0 ? `\n\n⚠ WARNING: ${valid} VALID keys will be deleted!` : "";
      if (!window.confirm(
        `Delete ALL ${total} keys for service: ${svc}?${warn}\n\nThis cannot be undone.`
      )) return;
      const r = await fetch(`/api/monitor/results/by-filter?service=${encodeURIComponent(svc)}`, { method: "DELETE" });
      const d = r.ok ? (await r.json() as {removed?:number}) : { removed: 0 };
      toast.success(`Deleted ${d.removed ?? 0} ${svc} keys`);
      queryClient.invalidateQueries({ queryKey: getGetMonitorResultsQueryKey() });
    } catch (err) {
      toast.error(`Purge failed: ${String(err)}`);
    }
  };

  const [exportingAll, setExportingAll] = useState(false);

  const handleExportAllEnv = async () => {
    setExportingAll(true);
    toast.info("Загружаю все записи ENV Scanner…");
    try {
      const q = new URLSearchParams({ export: "1", type: "keys", source: "ENV Scanner" });
      const r = await fetch(`/api/monitor/results?${q}`);
      const d: ResultsPage = await r.json();

      const csvEscape = (v: string) => `"${String(v ?? "").replace(/"/g, '""')}"`;

      const header = ["#", "category", "service", "key", "status", "url", "host", "path", "first_seen", "validated_at"];
      const rows = d.items.map((item, i) => {
        let host = "";
        let urlPath = "";
        try {
          const u = new URL(String(item.url ?? ""));
          host = u.hostname;
          urlPath = u.pathname;
        } catch { /* ignore */ }
        return [
          i + 1,
          item.category ?? "",
          item.service ?? "",
          item.key || item.keyMasked || "",
          item.status,
          item.url ?? "",
          host,
          urlPath,
          item.firstSeenAt ? new Date(item.firstSeenAt).toISOString() : "",
          item.validatedAt  ? new Date(item.validatedAt as string).toISOString() : "",
        ].map((v, ci) => ci === 0 ? v : csvEscape(String(v)));
      });

      const csv = [header.join(","), ...rows.map(r => r.join(","))].join("\n");
      const blob = new Blob(["\uFEFF" + csv, /* BOM for Excel */], { type: "text/csv;charset=utf-8" });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      a.href = url; a.download = `kmon-env-all-${stamp}.csv`;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success(`Экспортировано ${d.total} ENV-записей → CSV`);
    } catch {
      toast.error("Ошибка экспорта ENV");
    } finally {
      setExportingAll(false);
    }
  };

  const serviceOptions =
    category !== "all" ? (SERVICES_BY_CATEGORY[category] ?? ALL_SERVICES) : ALL_SERVICES;

  return (
    <div className="space-y-4 h-full flex flex-col">
      {/* Detail modal — unchanged */}
      <DetailModal
        itemId={detailId}
        open={detailId !== null}
        onClose={() => setDetailId(null)}
        onValidate={(id) => { handleValidate(id); }}
        validating={validating}
      />
      {/* Group modal */}
      <GroupModal
        group={activeGroup}
        open={groupModalOpen}
        onClose={() => setGroupModalOpen(false)}
        onValidate={handleValidate}
        validating={validating}
        onOpenDetail={(id) => { setGroupModalOpen(false); setDetailId(id); }}
      />

      {/* Key search bar */}
      <div className="relative flex items-center gap-2 bg-card px-4 py-2.5 border border-border rounded-lg">
        <Search className="w-4 h-4 text-muted-foreground shrink-0" />
        <Input
          value={keySearchInput}
          onChange={(e) => handleKeySearchInputChange(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Escape") clearKeySearch(); }}
          placeholder="Search by key value or URL fragment…"
          className="flex-1 h-7 bg-transparent border-none shadow-none focus-visible:ring-0 font-mono text-xs text-foreground placeholder:text-muted-foreground/50 px-0"
          spellCheck={false}
          autoComplete="off"
        />
        {keySearchInput && (
          <button onClick={clearKeySearch} className="shrink-0 text-muted-foreground hover:text-foreground transition-colors">
            <X className="w-3.5 h-3.5" />
          </button>
        )}
        {keySearch && (
          <span className="shrink-0 text-[10px] font-mono text-primary border border-primary/30 bg-primary/10 rounded px-1.5 py-0.5">
            {data?.total ?? "…"} results
          </span>
        )}
      </div>

      {/* Filter bar */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-card p-4 border border-border rounded-lg">
        <div className="flex flex-wrap items-center gap-3">
          <Select value={type} onValueChange={handleTypeChange}>
            <SelectTrigger className="w-[130px] bg-background border-border font-mono text-xs uppercase">
              <SelectValue placeholder="Type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">ALL TYPES</SelectItem>
              <SelectItem value="keys">KEYS ONLY</SelectItem>
              <SelectItem value="urls">URLS ONLY</SelectItem>
            </SelectContent>
          </Select>

          <Select value={status} onValueChange={handleStatusChange}>
            <SelectTrigger className="w-[155px] bg-background border-border font-mono text-xs uppercase">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">ALL STATUSES</SelectItem>
              <SelectItem value="valid">VALID</SelectItem>
              <SelectItem value="invalid">INVALID</SelectItem>
              <SelectItem value="rate_limited">RATE LIMITED</SelectItem>
              <SelectItem value="unchecked">UNCHECKED</SelectItem>
              <SelectItem value="honeypot">HONEYPOT</SelectItem>
            </SelectContent>
          </Select>

          <Select value={category} onValueChange={handleCategoryChange}>
            <SelectTrigger className="w-[145px] bg-background border-border font-mono text-xs uppercase">
              <SelectValue placeholder="Category" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">ALL CATEGORIES</SelectItem>
              {CATEGORIES.map(c => (
                <SelectItem key={c.id} value={c.id}>{c.label.toUpperCase()}</SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={service} onValueChange={handleServiceChange}>
            <SelectTrigger className="w-[165px] bg-background border-border font-mono text-xs uppercase">
              <SelectValue placeholder="Service" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">ALL SERVICES</SelectItem>
              {category === "all" ? (
                CATEGORIES.map(cat => (
                  <SelectGroup key={cat.id}>
                    <SelectLabel className="text-xs text-muted-foreground">{cat.label}</SelectLabel>
                    {(SERVICES_BY_CATEGORY[cat.id] ?? []).map(svc => (
                      <SelectItem key={svc} value={svc}>{svc.toUpperCase()}</SelectItem>
                    ))}
                  </SelectGroup>
                ))
              ) : (
                serviceOptions.map(svc => (
                  <SelectItem key={svc} value={svc}>{svc.toUpperCase()}</SelectItem>
                ))
              )}
            </SelectContent>
          </Select>

          {/* AWS quick filter */}
          <button
            onClick={handleAwsToggle}
            title="Show only AWS keys (service=aws, category=cloud)"
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono border rounded transition-colors ${
              awsOnly
                ? "bg-amber-500/20 text-amber-300 border-amber-500/50 hover:bg-amber-500/30"
                : "bg-background text-muted-foreground border-border hover:text-foreground hover:border-foreground/30"
            }`}
          >
            <span className="text-[10px]">☁️</span>
            AWS{awsOnly ? " ✓" : ""}
          </button>

          {/* Bedrock filter toggle */}
          <button
            onClick={handleBedrockToggle}
            title="Show only AWS keys with Bedrock access"
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono border rounded transition-colors ${
              bedrockOnly
                ? "bg-orange-500/20 text-orange-300 border-orange-500/50 hover:bg-orange-500/30"
                : "bg-background text-muted-foreground border-border hover:text-foreground hover:border-foreground/30"
            }`}
          >
            <span className="text-[10px]">🟠</span>
            BEDROCK{bedrockOnly ? " ✓" : ""}
          </button>
        </div>

        <div className="flex gap-2 flex-wrap">
          <Button variant="outline" size="sm" onClick={() => {
            if (!groupMode) fetchResults({ page, type, status, category, service, bedrockOnly });
            else fetchGroupData({ type, status, category, service, bedrockOnly });
          }}>
            <RefreshCw className="w-4 h-4 mr-2" /> Refresh
          </Button>
          <Button
            variant="outline" size="sm"
            onClick={toggleGroupMode}
            className={groupMode
              ? "border-amber-500/70 text-amber-400 bg-amber-500/10 hover:bg-amber-500/20"
              : "border-border text-muted-foreground hover:text-foreground"}
            title="Group results by host+service — collapses honeypot/bulk entries into one row"
          >
            {groupLoading
              ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              : <Layers className="w-4 h-4 mr-2" />}
            {groupMode ? "Grouped" : "Group by Host"}
          </Button>
                        {service !== "all" && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => handlePurgeService(service)}
                  className="text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 border border-red-500/20"
                  title={`Delete all ${service} keys from database`}
                >
                  <Trash2 className="w-3.5 h-3.5 mr-1.5" />
                  Purge {service}
                </Button>
              )}
<Button variant="outline" size="sm" onClick={handleExport}
               title="Export filtered results to TXT">
            <Download className="w-4 h-4 mr-2" /> Export TXT
          </Button>
          <Button
            variant="outline" size="sm"
            onClick={handleExportAllEnv}
            disabled={exportingAll}
            title="Экспорт ВСЕХ найденных ключей из ENV Scanner (все категории, все сервисы) → CSV"
            className="border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/10 hover:text-cyan-300"
          >
            {exportingAll
              ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              : <DatabaseZap className="w-4 h-4 mr-2" />}
            {exportingAll ? "Экспорт…" : "Export All ENV"}
          </Button>
          <Button size="sm" onClick={handleTriggerCycle} disabled={triggerCycle.isPending}>
            {triggerCycle.isPending
              ? <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              : <Play className="w-4 h-4 mr-2" />}
            {triggerCycle.isPending ? "Запуск…" : "Force Scan"}
          </Button>
        </div>
      </div>

      {/* Table */}
      <div className="border border-border rounded-lg bg-card flex-1 overflow-hidden flex flex-col">
        <div className="flex-1 overflow-auto">
          <Table>
            <TableHeader className="bg-muted/50 sticky top-0 z-10">
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="font-mono text-xs text-muted-foreground w-[110px]">CATEGORY</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground w-[120px]">SERVICE</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground min-w-[280px]">PAYLOAD</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground">STATUS</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground">SOURCE</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground text-right w-[140px]">SEEN</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground text-right w-[110px]">ACTION</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {/* ── GROUP MODE ── */}
              {groupMode ? (
                groupLoading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-10 text-amber-400/70 font-mono animate-pulse">
                      <Layers className="w-4 h-4 inline mr-2" />LOADING ALL DATA FOR GROUPING…
                    </TableCell>
                  </TableRow>
                ) : allGroups.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-10 text-muted-foreground font-mono">NO RESULTS FOUND</TableCell>
                  </TableRow>
                ) : (
                  pagedGroups.map((g) => {
                    const isMulti = g.count > 1;
                    if (!isMulti) {
                      // Single key — render as normal row
                      const item = g.items[0];
                      return (
                        <TableRow key={g.groupKey} className="border-border hover:bg-muted/30 cursor-pointer"
                          onClick={() => setDetailId(item.id)}>
                          <TableCell>
                            {item.category ? (
                              <Badge className={`text-xs ${getCategoryColor(item.category)}`}>{getCategoryLabel(item.category)}</Badge>
                            ) : <span className="text-xs text-muted-foreground font-mono">—</span>}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-primary font-bold">{item.service || item.type.toUpperCase()}</TableCell>
                          <TableCell className="font-mono text-xs">
                            <div className="flex items-center group" onClick={e => e.stopPropagation()}>
                              <code className="bg-background px-2 py-1 rounded border border-border text-foreground group-hover:text-primary transition-colors">
                                {item.keyMasked}
                              </code>
                              <Button variant="ghost" size="icon" className="h-6 w-6 ml-2 opacity-0 group-hover:opacity-100 transition-opacity"
                                onClick={e => { e.stopPropagation(); copyToClipboard(item.key || item.keyMasked || ""); }}>
                                <Copy className="h-3 w-3" />
                              </Button>
                            </div>
                          </TableCell>
                          <TableCell onClick={e => e.stopPropagation()}>{getStatusBadge(item.status)}</TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground max-w-[180px] truncate">{item.source}</TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground text-right">{new Date(item.firstSeenAt).toLocaleString()}</TableCell>
                          <TableCell className="text-right" onClick={e => e.stopPropagation()}>
                            <div className="flex items-center justify-end gap-1">
                              <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-primary"
                                onClick={() => setDetailId(item.id)}><Info className="h-3.5 w-3.5" /></Button>
                              {item.type === "key" && (
                                <Button variant="outline" size="sm"
                                  className="h-7 text-xs font-mono border-primary/30 text-primary hover:bg-primary/10"
                                  onClick={() => handleValidate(item.id)} disabled={validating === item.id}>
                                  {validating === item.id ? "…" : "VAL"}
                                </Button>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    }
                    // Multi-key group — amber group row
                    return (
                      <TableRow key={g.groupKey}
                        className="border-l-2 border-l-amber-500/60 bg-amber-500/5 hover:bg-amber-500/10 cursor-pointer"
                        onClick={() => openGroup(g)}>
                        <TableCell>
                          {g.category ? (
                            <Badge className={`text-xs ${getCategoryColor(g.category)}`}>{getCategoryLabel(g.category)}</Badge>
                          ) : <span className="text-xs text-muted-foreground font-mono">—</span>}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-primary font-bold">
                          <div className="flex items-center gap-2">
                            {g.service}
                            <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30 text-[10px] font-mono">{g.count}</Badge>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          <div className="flex items-center gap-2 text-amber-300">
                            <Layers className="h-3 w-3 shrink-0 opacity-70" />
                            <span className="font-semibold">{g.host}</span>
                            <ChevronRight className="h-3 w-3 opacity-50" />
                          </div>
                        </TableCell>
                        <TableCell><GroupStatusSummary s={g.statuses} /></TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">{g.source}</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground text-right">
                          {new Date(g.newestAt).toLocaleString()}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button variant="ghost" size="icon" className="h-7 w-7 text-amber-400 hover:text-amber-300"
                            onClick={e => { e.stopPropagation(); openGroup(g); }}>
                            <ChevronRight className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )
              ) : (
                /* ── NORMAL MODE ── */
                loading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-10 text-muted-foreground font-mono">LOADING DATA...</TableCell>
                  </TableRow>
                ) : data?.items.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-10 text-muted-foreground font-mono">NO RESULTS FOUND</TableCell>
                  </TableRow>
                ) : (
                  data?.items.map((item) => (
                    <TableRow key={item.id} className="border-border hover:bg-muted/30 cursor-pointer"
                      onClick={() => setDetailId(item.id)}>
                      <TableCell>
                        {item.type === "key" && item.category ? (
                          <Badge className={`text-xs ${getCategoryColor(item.category)}`}>{getCategoryLabel(item.category)}</Badge>
                        ) : <span className="text-xs text-muted-foreground font-mono">—</span>}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-primary font-bold">
                        {item.service || item.type.toUpperCase()}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {item.type === "key" ? (
                          <div className="flex items-center group" onClick={e => e.stopPropagation()}>
                            <code className="bg-background px-2 py-1 rounded border border-border text-foreground group-hover:text-primary transition-colors">
                              {item.keyMasked}
                            </code>
                            <Button variant="ghost" size="icon"
                              className="h-6 w-6 ml-2 opacity-0 group-hover:opacity-100 transition-opacity"
                              onClick={e => { e.stopPropagation(); copyToClipboard(item.key || item.keyMasked || ""); }}>
                              <Copy className="h-3 w-3" />
                            </Button>
                          </div>
                        ) : (
                          <div className="flex items-center group" onClick={e => e.stopPropagation()}>
                            <a href={item.url} target="_blank" rel="noreferrer"
                              className="text-secondary hover:underline max-w-[280px] truncate block"
                              onClick={e => e.stopPropagation()}>
                              {item.url}
                            </a>
                            <ExternalLink className="h-3 w-3 ml-2 text-muted-foreground opacity-0 group-hover:opacity-100" />
                          </div>
                        )}
                      </TableCell>
                      <TableCell onClick={e => e.stopPropagation()}>{getStatusBadge(item.status)}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground max-w-[180px] truncate" title={item.source}>
                        {item.source}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground text-right">
                        {new Date(item.firstSeenAt).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1">
                          <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-primary"
                            title="View details" onClick={() => setDetailId(item.id)}>
                            <Info className="h-3.5 w-3.5" />
                          </Button>
                          {item.type === "key" && (
                            <Button variant="outline" size="sm"
                              className="h-7 text-xs font-mono border-primary/30 text-primary hover:bg-primary/10 hover:text-primary"
                              onClick={() => handleValidate(item.id)} disabled={validating === item.id}>
                              {validating === item.id ? "…" : "VAL"}
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )
              )}
            </TableBody>
          </Table>
        </div>

        {/* Pagination */}
        <div className="border-t border-border p-4 bg-muted/20 flex items-center justify-between">
          {groupMode ? (
            <>
              <div className="text-xs text-muted-foreground font-mono">
                {allGroups.length > 0 ? (
                  <>
                    Groups {(groupPage - 1) * GROUP_VIEW_SIZE + 1}–{Math.min(groupPage * GROUP_VIEW_SIZE, allGroups.length)} of {allGroups.length}
                    <span className="ml-2 text-amber-400/70">({groupData?.length ?? 0} total keys)</span>
                  </>
                ) : "—"}
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setGroupPage(p => Math.max(1, p - 1))} disabled={groupPage === 1} className="font-mono text-xs h-8">PREV</Button>
                <div className="px-4 flex items-center text-xs font-mono font-bold bg-background border border-amber-500/30 rounded text-amber-400">
                  PG {groupPage}
                </div>
                <Button variant="outline" size="sm" onClick={() => setGroupPage(p => Math.min(groupTotalPages, p + 1))} disabled={groupPage >= groupTotalPages} className="font-mono text-xs h-8">NEXT</Button>
              </div>
            </>
          ) : (
            <>
              <div className="text-xs text-muted-foreground font-mono">
                {data ? (
                  <>Showing {(page - 1) * 50 + 1}–{Math.min(page * 50, data.total)} of {data.total}</>
                ) : "—"}
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="font-mono text-xs h-8">
                  PREV
                </Button>
                <div className="px-4 flex items-center text-xs font-mono font-bold bg-background border border-border rounded">
                  PG {page}
                </div>
                <Button variant="outline" size="sm" onClick={() => setPage(p => p + 1)} disabled={page >= (data?.pages ?? 1)} className="font-mono text-xs h-8">
                  NEXT
                </Button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
