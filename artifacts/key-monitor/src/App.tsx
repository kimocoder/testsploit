import { useEffect, useState, useCallback } from "react";
import { Switch, Route, Router as WouterRouter, Link, useLocation } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as SonnerToaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Activity, LayoutDashboard, List, Settings, ShieldAlert, Zap, KeyRound, Radar, Wifi, Workflow, LogOut, Loader2, Shield, Trash2, Server, Globe2 } from "lucide-react";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import Results from "@/pages/Results";
import Sources from "@/pages/Sources";
import Config from "@/pages/Config";
import Check from "@/pages/Check";
import Scanner from "@/pages/Scanner";
import Discover from "@/pages/Discover";
import ValidateBatch from "@/pages/ValidateBatch";
import Cleanup from "@/pages/Cleanup";
import Fleet from "@/pages/Fleet";
import FleetResults from "@/pages/FleetResults";
import NotFound from "@/pages/not-found";
import {
  useGetMonitorStatus,
  getGetMonitorStatusQueryKey,
  useGetAutoChainStatus,
  getGetAutoChainStatusQueryKey,
  useGetMonitorStats,
  getGetMonitorStatsQueryKey,
} from "@workspace/api-client-react";

const queryClient = new QueryClient();

// ── Fleet status (slave indicator + main panel enabled flag) ─────────────────
function useFleetStatus() {
  const [reg, setReg]         = useState<{ masterUrl: string | null; masterName?: string } | null>(null);
  const [fleetEnabled, setFleetEnabled] = useState(false);

  const recheckFleet = () => {
    fetch("/api/fleet/config")
      .then((r) => r.json())
      .then((d: { enabled: boolean }) => setFleetEnabled(d.enabled === true))
      .catch(() => { /* ignore */ });
  };

  useEffect(() => {
    // Check if this server is registered as a slave
    fetch("/api/fleet/registration")
      .then((r) => r.json())
      .then((d: { masterUrl: string | null; masterName?: string }) => setReg(d))
      .catch(() => { /* ignore */ });

    recheckFleet();

    // Listen for fleet-config-changed events dispatched by Config page
    window.addEventListener("fleet-config-changed", recheckFleet);
    return () => window.removeEventListener("fleet-config-changed", recheckFleet);
  }, []);

  return { reg, fleetEnabled };
}

function Shell({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const { reg: fleetReg, fleetEnabled } = useFleetStatus();
  const { data: status } = useGetMonitorStatus({
    query: {
      queryKey: getGetMonitorStatusQueryKey(),
      refetchInterval: 2000
    }
  });
  const { data: chain } = useGetAutoChainStatus({
    query: {
      queryKey: getGetAutoChainStatusQueryKey(),
      refetchInterval: 3000,
    },
  });
  // Drives the green "valid keys found" counter next to the Results link.
  // 5s cadence is enough — validation is async and rarely changes faster.
  const { data: stats } = useGetMonitorStats({
    query: {
      queryKey: getGetMonitorStatsQueryKey(),
      refetchInterval: 5000,
    },
  });
  const validCount = stats?.keysValid ?? 0;

  const chainActive = chain?.phase === "discovery" || chain?.phase === "envscan";
  const chainHref =
    chain?.phase === "discovery" ? "/discover" :
    chain?.phase === "envscan"   ? "/scanner"  : "/config";
  const chainColor =
    chain?.phase === "discovery" ? "text-cyan-400 bg-cyan-400" :
    chain?.phase === "envscan"   ? "text-amber-400 bg-amber-400" :
    chain?.phase === "cooldown"  ? "text-slate-400 bg-slate-400" :
    "text-muted-foreground bg-muted-foreground";

  const totalCount = stats?.keysFound ?? 0;

  const links: Array<{
    href: string;
    label: string;
    icon: typeof LayoutDashboard;
    badge?: number;
  }> = [
    { href: "/", label: "Dashboard", icon: LayoutDashboard },
    { href: "/results", label: "Results", icon: List, badge: totalCount },
    { href: "/sources", label: "Sources", icon: Activity },
    { href: "/discover", label: "Discovery", icon: Wifi },
    { href: "/scanner", label: "ENV Scanner", icon: Radar },
    { href: "/validate", label: "Bulk Validate", icon: Shield },
    { href: "/cleanup", label: "Cleanup", icon: Trash2 },
    // Fleet — only shown when fleet mode is enabled
    ...(fleetEnabled ? [
      { href: "/fleet", label: "Fleet", icon: Server },
    ] : []),
    { href: "/check", label: "Check Key", icon: KeyRound },
    { href: "/config", label: "Config", icon: Settings },
  ];

  return (
    <div className="flex h-screen w-full bg-background text-foreground overflow-hidden font-mono">
      {/* Sidebar */}
      <aside className="w-64 border-r border-border bg-sidebar flex flex-col">
        <div className="h-16 flex items-center px-4 border-b border-border">
          <ShieldAlert className="w-6 h-6 text-primary mr-2" />
          <span className="font-bold text-lg tracking-wider text-primary terminal-glow">KMON_NOC</span>
        </div>
        
        <div className="flex-1 overflow-y-auto py-4 px-3 space-y-1">
          {links.map((link) => {
            const Icon = link.icon;
            const isActive = location === link.href;
            const showBadge = typeof link.badge === "number" && link.badge > 0;
            return (
              <Link key={link.href} href={link.href} className={`flex items-center px-3 py-2 text-sm border border-transparent transition-colors ${isActive ? 'bg-primary/10 text-primary border-primary/30 terminal-border-glow' : 'text-muted-foreground hover:bg-muted hover:text-foreground'}`}>
                <Icon className="w-4 h-4 mr-3" />
                <span className="flex-1">{link.label}</span>
                {showBadge && (
                  <span
                    title={`${link.badge?.toLocaleString()} keys found`}
                    className="ml-2 inline-flex items-center justify-center min-w-[1.25rem] h-5 px-1.5 rounded-full text-[10px] font-bold tabular-nums bg-green-500/20 text-green-400 border border-green-500/40"
                  >
                    {link.badge! >= 1000
                      ? `${(link.badge! / 1000).toFixed(link.badge! >= 10000 ? 0 : 1)}k`
                      : link.badge}
                  </span>
                )}
              </Link>
            );
          })}
        </div>

        <div className="p-4 border-t border-border space-y-3">
          <div>
            <div className="text-xs text-muted-foreground mb-2">PUBLIC SCANNER</div>
            <div className="flex items-center space-x-2 text-sm">
              <div className={`w-2 h-2 rounded-full ${status?.running ? 'bg-primary animate-pulse' : 'bg-muted-foreground'}`} />
              <span className={status?.running ? 'text-primary' : 'text-muted-foreground'}>
                {status?.running ? 'ACTIVE' : 'IDLE'}
              </span>
            </div>
            {status?.running && (
              <div className="mt-1 text-xs text-muted-foreground truncate">
                {status.currentAction}
              </div>
            )}
          </div>

          <Link
            href={chainHref}
            className="block hover:opacity-80 transition-opacity"
            title={chain?.message || "Auto-Chain pipeline"}
          >
            <div className="text-xs text-muted-foreground mb-2">AUTO-CHAIN</div>
            <div className="flex items-center space-x-2 text-sm">
              <div className={`w-2 h-2 rounded-full ${chainColor.split(' ')[1]} ${chainActive ? 'animate-pulse' : ''}`} />
              <span className={chainColor.split(' ')[0]}>
                {chain?.phase ? chain.phase.toUpperCase() : "—"}
              </span>
              {chain?.manualTriggerPending && (
                <span className="text-[10px] text-yellow-300 ml-1">[Q]</span>
              )}
            </div>
            <div className="mt-1 text-[10px] text-muted-foreground truncate">
              {chain?.message ?? "—"}
            </div>
          </Link>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col h-full overflow-hidden relative bg-card">
        {/* Topbar */}
        <header className="h-16 border-b border-border flex items-center justify-between px-6 bg-background/50 backdrop-blur-sm z-10 relative">
          <div className="flex items-center text-sm text-muted-foreground">
            <Zap className="w-4 h-4 mr-2 text-secondary" />
            <span className="uppercase">{
              location === '/' ? 'DASHBOARD'
              : location === '/check' ? 'CHECK KEY'
              : location.substring(1)
            }</span>
          </div>
          
          <div className="flex items-center space-x-4 text-sm">
            {chainActive && (
              <Link
                href={chainHref}
                className="flex items-center space-x-2 px-2 py-1 border border-current rounded hover:opacity-80 transition-opacity"
                title="Open active scanner page"
              >
                <Workflow className={`w-3 h-3 ${chainColor.split(' ')[0]}`} />
                <span className={`uppercase font-bold animate-pulse ${chainColor.split(' ')[0]}`}>
                  CHAIN: {chain?.phase}
                </span>
              </Link>
            )}
            {chain?.manualTriggerPending && !chainActive && (
              <div className="text-yellow-300 uppercase font-bold text-xs px-2 py-1 border border-yellow-300/40 rounded">
                CHAIN QUEUED
              </div>
            )}
            {/* Slave FEDERATED indicator */}
            {fleetReg?.masterUrl && (
              <a
                href={fleetReg.masterUrl}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1.5 px-2 py-1 border border-primary/30 rounded text-[10px] font-mono text-primary hover:bg-primary/5 transition-colors"
                title={`Connected to fleet: ${fleetReg.masterUrl}`}
              >
                <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                FEDERATED
                {fleetReg.masterName && <span className="text-muted-foreground">→ {fleetReg.masterName}</span>}
              </a>
            )}
            {status?.secondsUntilNext !== undefined && !status?.cycleInProgress && (
              <div className="text-muted-foreground">
                T-MINUS: <span className="text-primary font-bold">{status.secondsUntilNext}s</span>
              </div>
            )}
            <button
              onClick={async () => {
                await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
                window.location.reload();
              }}
              className="flex items-center text-muted-foreground hover:text-primary transition-colors"
              title="Выйти"
            >
              <LogOut className="w-4 h-4" />
            </button>
            {status?.cycleInProgress && (() => {
              const cp = status.cycleProgress;
              const done = cp?.done ?? 0;
              const total = cp?.total ?? 0;
              const pct = total > 0 ? Math.floor((done / total) * 100) : 0;
              const eta = cp?.etaSeconds;
              const etaTxt =
                eta == null ? "" :
                eta < 60 ? ` · ETA ${eta}s` :
                eta < 3600 ? ` · ETA ${Math.floor(eta / 60)}m` :
                ` · ETA ${Math.floor(eta / 3600)}h${Math.floor((eta % 3600) / 60)}m`;
              const cat = (cp as { currentCategory?: string | null } | undefined)?.currentCategory;
              return (
                <div className="flex items-center space-x-2">
                  <span className="text-secondary animate-pulse uppercase font-bold text-xs">
                    SCAN IN PROGRESS
                  </span>
                  {cat && (
                    <span
                      className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border border-primary/40 text-primary bg-primary/10"
                      title={`Category rotation: scanning "${cat}" this cycle`}
                    >
                      {cat}
                    </span>
                  )}
                  {total > 0 && (
                    <span className="text-xs text-muted-foreground tabular-nums">
                      {done}/{total} ({pct}%){etaTxt}
                    </span>
                  )}
                </div>
              );
            })()}
          </div>
        </header>

        {/* Page Content */}
        <div className="flex-1 overflow-auto p-6 relative">
          {children}
        </div>
      </main>
    </div>
  );
}

function Router() {
  return (
    <Shell>
      <Switch>
        <Route path="/" component={Dashboard} />
        <Route path="/results" component={Results} />
        <Route path="/sources" component={Sources} />
        <Route path="/discover" component={Discover} />
        <Route path="/scanner" component={Scanner} />
        <Route path="/validate" component={ValidateBatch} />
        <Route path="/cleanup" component={Cleanup} />
        <Route path="/fleet" component={Fleet} />
        <Route path="/fleet-results" component={FleetResults} />
        <Route path="/check" component={Check} />
        <Route path="/config" component={Config} />
        <Route component={NotFound} />
      </Switch>
    </Shell>
  );
}

function AuthGate({ children }: { children: React.ReactNode }) {
  // null = checking, false = unauthenticated, true = authenticated
  const [authed, setAuthed] = useState<boolean | null>(null);

  const recheck = useCallback(async () => {
    try {
      const r = await fetch("/api/auth/status", { credentials: "same-origin" });
      const d = (await r.json()) as { authenticated?: boolean };
      setAuthed(Boolean(d.authenticated));
    } catch {
      setAuthed(false);
    }
  }, []);

  useEffect(() => { void recheck(); }, [recheck]);

  if (authed === null) {
    return (
      <div className="min-h-screen w-full flex items-center justify-center bg-background">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (!authed) return <Login onSuccess={() => { void recheck(); }} />;
  return <>{children}</>;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <AuthGate>
          <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
            <Router />
          </WouterRouter>
        </AuthGate>
        <Toaster />
        <SonnerToaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
