import React, { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  CheckCircle, XCircle, AlertCircle, Key, Loader2, Copy,
  Eye, EyeOff, ChevronDown, ChevronUp,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

// ── Service catalogue ────────────────────────────────────────────────────────

interface ServiceDef {
  id: string;
  label: string;
  category: string;
  placeholder?: string;
}

const CATEGORIES: { id: string; label: string; color: string }[] = [
  { id: "all",       label: "All",       color: "text-foreground" },
  { id: "ai",        label: "AI",        color: "text-cyan-400" },
  { id: "payments",  label: "Payments",  color: "text-green-400" },
  { id: "email",     label: "Email",     color: "text-blue-400" },
  { id: "cloud",     label: "Cloud",     color: "text-orange-400" },
  { id: "auth",      label: "Auth",      color: "text-purple-400" },
  { id: "messaging", label: "Messaging", color: "text-yellow-400" },
  { id: "database",  label: "Database",  color: "text-red-400" },
];

const CATEGORY_BORDER: Record<string, string> = {
  ai:        "border-cyan-500/30 hover:border-cyan-500/60",
  payments:  "border-green-500/30 hover:border-green-500/60",
  email:     "border-blue-500/30 hover:border-blue-500/60",
  cloud:     "border-orange-500/30 hover:border-orange-500/60",
  auth:      "border-purple-500/30 hover:border-purple-500/60",
  messaging: "border-yellow-500/30 hover:border-yellow-500/60",
  database:  "border-red-500/30 hover:border-red-500/60",
  other:     "border-border hover:border-border/80",
};

const CATEGORY_ACTIVE: Record<string, string> = {
  ai:        "bg-cyan-500/15 border-cyan-500/50 text-cyan-300",
  payments:  "bg-green-500/15 border-green-500/50 text-green-300",
  email:     "bg-blue-500/15 border-blue-500/50 text-blue-300",
  cloud:     "bg-orange-500/15 border-orange-500/50 text-orange-300",
  auth:      "bg-purple-500/15 border-purple-500/50 text-purple-300",
  messaging: "bg-yellow-500/15 border-yellow-500/50 text-yellow-300",
  database:  "bg-red-500/15 border-red-500/50 text-red-300",
  other:     "bg-muted/30 border-border text-foreground",
};

const SERVICES: ServiceDef[] = [
  { id: "auto",            label: "Auto-detect",   category: "all" },
  // AI
  { id: "openai",          label: "OpenAI",         category: "ai",        placeholder: "sk-proj-... or sk-..." },
  { id: "anthropic",       label: "Anthropic",      category: "ai",        placeholder: "sk-ant-api03-..." },
  { id: "openrouter",      label: "OpenRouter",     category: "ai",        placeholder: "sk-or-v1-..." },
  { id: "google",          label: "Google AI",      category: "ai",        placeholder: "AIza..." },
  { id: "huggingface",     label: "HuggingFace",    category: "ai",        placeholder: "hf_..." },
  { id: "groq",            label: "Groq",           category: "ai",        placeholder: "gsk_..." },
  { id: "perplexity",      label: "Perplexity",     category: "ai",        placeholder: "pplx-..." },
  { id: "replicate",       label: "Replicate",      category: "ai",        placeholder: "r8_..." },
  { id: "cohere",          label: "Cohere",         category: "ai",        placeholder: "CO...." },
  { id: "deepseek",        label: "DeepSeek",       category: "ai",        placeholder: "sk-..." },
  { id: "mistral",         label: "Mistral",        category: "ai",        placeholder: "msk-..." },
  { id: "xai",             label: "xAI / Grok",     category: "ai",        placeholder: "xai-..." },
  // Payments
  { id: "stripe",          label: "Stripe",         category: "payments",  placeholder: "sk_live_... or sk_test_..." },
  // Email
  { id: "sendgrid",        label: "SendGrid",       category: "email",     placeholder: "SG.xxx.xxx" },
  { id: "mailgun",         label: "Mailgun",        category: "email",     placeholder: "key-..." },
  { id: "resend",          label: "Resend",         category: "email",     placeholder: "re_..." },
  { id: "postmark",        label: "Postmark",       category: "email",     placeholder: "POSTMARK_..." },
  // Cloud
  { id: "aws",             label: "AWS",            category: "cloud",     placeholder: "AKIA..." },
  { id: "digitalocean",    label: "DigitalOcean",   category: "cloud",     placeholder: "dop_v1_..." },
  { id: "cloudflare",      label: "Cloudflare",     category: "cloud",     placeholder: "cf_..." },
  // Auth
  { id: "github",          label: "GitHub",         category: "auth",      placeholder: "ghp_... or gho_..." },
  { id: "gitlab",          label: "GitLab",         category: "auth",      placeholder: "glpat-..." },
  { id: "jwt",             label: "JWT Token",      category: "auth",      placeholder: "eyJ..." },
  // Messaging
  { id: "telegram",        label: "Telegram Bot",   category: "messaging", placeholder: "12345678:AA..." },
  { id: "twilio",          label: "Twilio",         category: "messaging", placeholder: "SK..." },
  { id: "slack_webhook",   label: "Slack Webhook",  category: "messaging", placeholder: "https://hooks.slack.com/..." },
  { id: "discord_webhook", label: "Discord Webhook",category: "messaging", placeholder: "https://discord.com/api/webhooks/..." },
  // Database
  { id: "postgresql",      label: "PostgreSQL",     category: "database",  placeholder: "postgresql://user:pass@host/db" },
  { id: "mysql",           label: "MySQL",          category: "database",  placeholder: "mysql://user:pass@host/db" },
  { id: "mongodb",         label: "MongoDB",        category: "database",  placeholder: "mongodb+srv://user:pass@host/db" },
  { id: "redis",           label: "Redis",          category: "database",  placeholder: "redis://:pass@host:6379" },
];

// ── Detection helper (client-side) ───────────────────────────────────────────

function detectService(key: string): string {
  if (key.startsWith("sk-proj-"))                      return "OpenAI";
  if (key.startsWith("sk-ant-"))                       return "Anthropic";
  if (key.startsWith("sk-or-v1-"))                     return "OpenRouter";
  if (key.startsWith("AIza"))                          return "Google AI";
  if (key.startsWith("hf_"))                           return "HuggingFace";
  if (key.startsWith("r8_"))                           return "Replicate";
  if (key.startsWith("gsk_"))                          return "Groq";
  if (key.startsWith("pplx-"))                         return "Perplexity";
  if (key.startsWith("CO."))                           return "Cohere";
  if (key.startsWith("msk-"))                          return "Mistral";
  if (key.startsWith("xai-"))                          return "xAI";
  if (key.startsWith("sk_live_") || key.startsWith("sk_test_") ||
      key.startsWith("rk_live_") || key.startsWith("rk_test_"))  return "Stripe";
  if (key.startsWith("SG.") && key.includes("."))      return "SendGrid";
  if (key.startsWith("re_") && key.length > 32)        return "Resend";
  if (key.startsWith("POSTMARK_"))                     return "Postmark";
  if (key.startsWith("AKIA"))                          return "AWS";
  if (key.startsWith("dop_v1_"))                       return "DigitalOcean";
  if (key.startsWith("cf_"))                           return "Cloudflare";
  if (key.startsWith("ghp_") || key.startsWith("gho_") ||
      key.startsWith("ghs_") || key.startsWith("github_pat_"))    return "GitHub";
  if (key.startsWith("glpat-"))                        return "GitLab";
  if (key.startsWith("eyJ") && key.split(".").length === 3)       return "JWT";
  if (/^\d{8,10}:AA[A-Za-z0-9_-]{33}/.test(key))     return "Telegram Bot";
  if (key.includes("hooks.slack.com"))                 return "Slack Webhook";
  if (key.includes("discord.com/api/webhooks"))        return "Discord Webhook";
  if (key.startsWith("postgres://") || key.startsWith("postgresql://")) return "PostgreSQL";
  if (key.startsWith("mysql://") || key.startsWith("mysql2://"))        return "MySQL";
  if (key.startsWith("mongodb://") || key.startsWith("mongodb+srv://"))  return "MongoDB";
  if (key.startsWith("redis://") || key.startsWith("rediss://"))         return "Redis";
  if (key.startsWith("sk-") && key.length === 51)     return "OpenAI";
  return "Unknown";
}

// ── Types ────────────────────────────────────────────────────────────────────

interface CheckResult {
  key: string;
  rawKey: string;
  service: string;
  category: string;
  status: "valid" | "invalid" | "error" | "rate_limited";
  message: string;
  httpStatus?: number | null;
  meta?: Record<string, unknown>;
  checkedAt: string;
}

// ── Component ────────────────────────────────────────────────────────────────

export default function Check() {
  const [keyInput, setKeyInput]         = useState("");
  const [selectedSvc, setSelectedSvc]   = useState("auto");
  const [activeCat, setActiveCat]       = useState("all");
  const [loading, setLoading]           = useState(false);
  const [results, setResults]           = useState<CheckResult[]>([]);
  const [showKeys, setShowKeys]         = useState<Record<number, boolean>>({});
  const [expandedMeta, setExpandedMeta] = useState<Record<number, boolean>>({});
  const { toast } = useToast();

  const trimmed = keyInput.trim();
  const detectedLabel = trimmed ? detectService(trimmed) : null;

  // Current placeholder from selected service
  const activeSvcDef = SERVICES.find((s) => s.id === selectedSvc);
  const currentPlaceholder = activeSvcDef?.placeholder ?? "sk-... or eyJ... or postgres://... etc.";

  // Visible services for selected category
  const visibleServices = activeCat === "all"
    ? SERVICES
    : SERVICES.filter((s) => s.id === "auto" || s.category === activeCat);

  const handleCheck = async () => {
    if (!trimmed) return;
    setLoading(true);
    try {
      const bodyPayload: Record<string, string> = { key: trimmed };
      if (selectedSvc !== "auto") bodyPayload.service = selectedSvc;

      const resp = await fetch("/api/monitor/check-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(bodyPayload),
      });
      const data = await resp.json() as Record<string, unknown>;

      setResults((prev) => [{
        key:        String(data.key ?? trimmed.slice(0, 8) + "…"),
        rawKey:     trimmed,
        service:    String(data.service ?? "unknown"),
        category:   String(data.category ?? "other"),
        status:     data.status as CheckResult["status"],
        message:    String(data.message ?? ""),
        httpStatus: data.httpStatus as number | null | undefined,
        meta:       data.meta as Record<string, unknown> | undefined,
        checkedAt:  new Date().toLocaleTimeString(),
      }, ...prev]);
      setKeyInput("");
    } catch (err) {
      toast({ title: "Connection error", description: String(err), variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setKeyInput(text.trim());
    } catch {
      toast({ title: "Clipboard unavailable", description: "Paste manually with Ctrl+V" });
    }
  };

  const copyKey = (key: string) =>
    navigator.clipboard.writeText(key).then(() => toast({ title: "Copied to clipboard" }));

  const statusIcon = (s: string) => {
    if (s === "valid")        return <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />;
    if (s === "invalid")      return <XCircle     className="w-5 h-5 text-red-400 flex-shrink-0" />;
    if (s === "rate_limited") return <AlertCircle className="w-5 h-5 text-orange-400 flex-shrink-0" />;
    return                           <AlertCircle className="w-5 h-5 text-yellow-400 flex-shrink-0" />;
  };

  const statusBadge = (s: string) => {
    if (s === "valid")        return <Badge className="bg-green-500/20  text-green-400  border-green-500/30">VALID</Badge>;
    if (s === "invalid")      return <Badge className="bg-red-500/20    text-red-400    border-red-500/30">INVALID</Badge>;
    if (s === "rate_limited") return <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30">RATE LIMITED</Badge>;
    return                           <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">ERROR</Badge>;
  };

  const categoryColor = (cat: string) => {
    const c = CATEGORIES.find((x) => x.id === cat);
    return c?.color ?? "text-muted-foreground";
  };

  const cardBorder = (r: CheckResult) => {
    if (r.status === "valid")        return "border-green-500/30  bg-green-500/5";
    if (r.status === "invalid")      return "border-red-500/30    bg-red-500/5";
    if (r.status === "rate_limited") return "border-orange-500/30 bg-orange-500/5";
    return                                  "border-yellow-500/30 bg-yellow-500/5";
  };

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      {/* Input card */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center text-sm font-medium text-muted-foreground uppercase">
            <Key className="w-4 h-4 mr-2 text-primary" />
            Secret Validator
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">

          {/* Textarea */}
          <div>
            <div className="text-xs text-muted-foreground mb-1.5 uppercase">Paste secret / key / token / connection string</div>
            <Textarea
              placeholder={currentPlaceholder}
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              className="font-mono text-sm bg-background border-border resize-none h-20"
              onKeyDown={(e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) handleCheck(); }}
            />
            {trimmed && detectedLabel && (
              <div className="mt-1 text-xs text-muted-foreground">
                Detected: <span className="text-primary">{detectedLabel}</span>
                {" · "}Length: <span className="text-primary">{trimmed.length}</span>
              </div>
            )}
          </div>

          {/* Category tabs */}
          <div>
            <div className="text-xs text-muted-foreground mb-1.5 uppercase">Category</div>
            <div className="flex flex-wrap gap-1.5">
              {CATEGORIES.map((cat) => (
                <button
                  key={cat.id}
                  onClick={() => { setActiveCat(cat.id); if (selectedSvc !== "auto") setSelectedSvc("auto"); }}
                  className={`px-2.5 py-0.5 text-xs border rounded transition-colors font-mono ${
                    activeCat === cat.id
                      ? "bg-primary/20 border-primary/50 text-primary"
                      : "border-border text-muted-foreground hover:text-foreground hover:border-border/70"
                  }`}
                >
                  {cat.label}
                </button>
              ))}
            </div>
          </div>

          {/* Service override */}
          <div>
            <div className="text-xs text-muted-foreground mb-1.5 uppercase">Service (override)</div>
            <div className="flex flex-wrap gap-1.5">
              {visibleServices.map((s) => {
                const isActive = selectedSvc === s.id;
                const cat = s.category === "all" ? "other" : s.category;
                return (
                  <button
                    key={s.id}
                    onClick={() => setSelectedSvc(s.id)}
                    className={`px-2.5 py-1 text-xs border rounded transition-colors ${
                      isActive
                        ? (CATEGORY_ACTIVE[cat] ?? CATEGORY_ACTIVE.other)
                        : `border-border text-muted-foreground ${CATEGORY_BORDER[cat] ?? CATEGORY_BORDER.other} hover:text-foreground`
                    }`}
                  >
                    {s.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Actions */}
          <div className="flex gap-2 pt-1">
            <Button
              onClick={handleCheck}
              disabled={loading || !trimmed}
              className="bg-primary text-primary-foreground hover:bg-primary/90"
            >
              {loading
                ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Checking…</>
                : <><CheckCircle className="w-4 h-4 mr-2" /> Check</>}
            </Button>
            <Button variant="outline" onClick={handlePaste} className="border-border">
              Paste from Clipboard
            </Button>
            {results.length > 0 && (
              <Button variant="ghost" onClick={() => setResults([])}
                className="ml-auto text-muted-foreground hover:text-foreground text-xs">
                Clear history
              </Button>
            )}
          </div>

          <div className="text-xs text-muted-foreground border border-border/50 rounded p-2 bg-muted/20">
            <span className="text-primary">TIP:</span> Supports API keys, JWT tokens, DB connection strings, webhooks.
            Press <kbd className="px-1 py-0.5 bg-muted rounded text-xs">Ctrl+Enter</kbd> to check.
            Nothing is stored permanently.
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      {results.length > 0 && (
        <div className="space-y-3">
          <div className="text-xs text-muted-foreground uppercase">Check History</div>
          {results.map((r, idx) => (
            <Card key={idx} className={`bg-card border transition-colors ${cardBorder(r)}`}>
              <CardContent className="pt-4 pb-4">
                <div className="flex items-start gap-3">
                  {statusIcon(r.status)}
                  <div className="min-w-0 flex-1">
                    {/* Header row */}
                    <div className="flex items-center gap-2 flex-wrap">
                      {statusBadge(r.status)}
                      <span className={`text-xs font-mono capitalize border border-border/50 rounded px-2 py-0.5 ${categoryColor(r.category)}`}>
                        {r.service}
                      </span>
                      <span className="text-xs text-muted-foreground border border-border/30 rounded px-2 py-0.5 uppercase">
                        {r.category}
                      </span>
                      <span className="text-xs text-muted-foreground">{r.checkedAt}</span>
                      {r.httpStatus != null && (
                        <span className="text-xs text-muted-foreground">HTTP {r.httpStatus}</span>
                      )}
                    </div>

                    {/* Key display */}
                    <div className="mt-2 font-mono text-sm text-foreground flex items-center gap-2">
                      <span className="truncate">{showKeys[idx] ? r.rawKey : r.key}</span>
                      <button onClick={() => setShowKeys((p) => ({ ...p, [idx]: !p[idx] }))}
                        className="text-muted-foreground hover:text-foreground flex-shrink-0"
                        title={showKeys[idx] ? "Hide" : "Show full secret"}>
                        {showKeys[idx] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                      <button onClick={() => copyKey(showKeys[idx] ? r.rawKey : r.key)}
                        className="text-muted-foreground hover:text-foreground flex-shrink-0" title="Copy">
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    {/* Message */}
                    <div className="mt-1 text-xs text-muted-foreground">{r.message}</div>

                    {/* Meta (JWT / DB) expandable */}
                    {r.meta && Object.keys(r.meta).length > 0 && (
                      <div className="mt-2">
                        <button
                          onClick={() => setExpandedMeta((p) => ({ ...p, [idx]: !p[idx] }))}
                          className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
                        >
                          {expandedMeta[idx] ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                          {expandedMeta[idx] ? "Hide" : "Show"} details
                        </button>
                        {expandedMeta[idx] && (
                          <div className="mt-1.5 font-mono text-xs bg-muted/30 rounded p-2 space-y-0.5">
                            {Object.entries(r.meta).map(([k, v]) =>
                              v != null ? (
                                <div key={k}>
                                  <span className="text-muted-foreground">{k}:</span>{" "}
                                  <span className="text-foreground">{String(v)}</span>
                                </div>
                              ) : null
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {results.length === 0 && (
        <div className="text-center text-muted-foreground text-sm py-12 border border-dashed border-border/40 rounded-lg">
          <Key className="w-8 h-8 mx-auto mb-3 opacity-30" />
          <div>No checks yet. Paste a secret above and click <strong>Check</strong>.</div>
          <div className="mt-2 text-xs opacity-60">
            Supports: AI keys · Stripe · SendGrid · Mailgun · AWS · GitHub · JWT · Telegram · Webhooks · DB connections
          </div>
        </div>
      )}
    </div>
  );
}
