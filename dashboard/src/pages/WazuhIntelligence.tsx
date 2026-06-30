/**
 * WazuhIntelligence — Centro de inteligencia Wazuh para SOC/Threat Hunting.
 * Diseño oscuro, moderno, orientado a analistas.
 * Sección destacada: Usuarios SSH Inválidos (reglas 5710-5758).
 */
import { motion, AnimatePresence } from "framer-motion";
import { useMemo, useState, useCallback } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useTrinoNamed, useTrinoNamedBatch, type BatchSpec } from "@/hooks/useTrinoQuery";
import { formatNumber, formatDateTimePy } from "@/lib/format";
import {
  Shield,
  AlertTriangle,
  Terminal,
  Activity,
  Eye,
  Search,
  RefreshCw,
  ChevronUp,
  ChevronDown,
  Database,
  Server,
  Bug,
  Zap,
  CheckCircle2,
  Loader2,
  ArrowUpDown,
  Cpu,
  FileCode2,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  BarRow,
  DetailHeader,
  EmptyState,
  KpiTile,
  LoadingRows,
  SectionCard,
} from "./detection/_components";

// ── Constantes ────────────────────────────────────────────────────────────────

// Cache tuning 2026-04-17: detección es data histórica agregada por ventanas
// de horas/días — no necesita tick frecuente. Subimos stale de 5m→10m y
// gcTime 15m→30m para reducir carga sobre Trino sin afectar UX (operador
// siempre puede pulsar refresh manual si necesita frescura inmediata).
const STALE_5M = { staleTime: 10 * 60 * 1000, gcTime: 30 * 60 * 1000 } as const;

const WAZUH_SPECS = [
  { key: "sev",     id: "lh.wazuh.severity_buckets_24h" },
  { key: "rules",   id: "lh.wazuh.top_rules_24h",          params: { limit: 15 } },
  { key: "agents",  id: "lh.wazuh.top_agents_24h",         params: { limit: 12 } },
  { key: "cveCrit", id: "lh.wazuh.critical_cves_24h",      params: { limit: 50 } },
  { key: "cveHost", id: "lh.wazuh.critical_cve_hosts_24h", params: { limit: 20 } },
] as const satisfies BatchSpec[];
const STALE_2M = { staleTime: 5 * 60 * 1000, gcTime: 15 * 60 * 1000 } as const;

const SEV_BG: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low:      "border-border bg-muted/60 text-muted-foreground dark:bg-zinc-700/50 dark:text-zinc-400 dark:border-zinc-600/30",
};

// ── Tipos ─────────────────────────────────────────────────────────────────────


interface AuditdAggRow {
  command:         string;
  exe:             string;
  agent_name:      string;
  execution_count: number;
  first_seen:      string;
  last_seen:       string;
  uid_list:        string;
  euid_list:       string;
  top_rule_id:     string;
  top_mitre:       string;
}

type AuditdSortKey = "execution_count" | "command" | "agent_name" | "last_seen";
type SortDir = "asc" | "desc";

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtTs(ts: string): string {
  if (!ts || ts === "—") return "—";
  return formatDateTimePy(ts);
}

function fmtAgo(ts: string): string {
  if (!ts || ts === "—") return "";
  try {
    const diff = Date.now() - new Date(ts).getTime();
    const m = Math.floor(diff / 60_000);
    if (m < 1) return "hace < 1 min";
    if (m < 60) return `hace ${m} min`;
    const h = Math.floor(m / 60);
    if (h < 24) return `hace ${h} h`;
    return `hace ${Math.floor(h / 24)} d`;
  } catch {
    return "";
  }
}

// ── Mini-componentes ──────────────────────────────────────────────────────────
// KpiCard local eliminado — se usa KpiTile de detection/_components en el
// page principal. SeveritySection (donut) también eliminado — reemplazado
// por un CSS bar list en el page.

function SeverityBadge({ level }: { level: string }) {
  const cls = SEV_BG[level.toLowerCase()] ?? SEV_BG.low;
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${cls}`}>
      {level}
    </span>
  );
}

function TableSkeleton({ cols, rows = 5 }: { cols: number; rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, i) => (
        <TableRow key={i} className="border-border/60 dark:border-white/5">
          {Array.from({ length: cols }).map((_, j) => (
            <TableCell key={j}>
              <div className="h-3 animate-pulse rounded bg-muted dark:bg-white/8" style={{ width: `${55 + ((i * j * 7) % 40)}%` }} />
            </TableCell>
          ))}
        </TableRow>
      ))}
    </>
  );
}

// ── Sección: Diagnóstico wazuh_alerts ─────────────────────────────────────────

function WazuhAlertsDiagSection() {
  const [open, setOpen] = useState(false);

  const anyRow   = useTrinoNamed(["wazuh", "diag-any"],    "lh.wazuh_alerts.diag_any_row",        {}, { enabled: open, staleTime: 60_000 });
  const count    = useTrinoNamed(["wazuh", "diag-count"],   "lh.wazuh_alerts.diag_count_recent",   { days: 3 }, { enabled: open, staleTime: 60_000 });
  const sshRaw   = useTrinoNamed(["wazuh", "diag-ssh-raw"], "lh.wazuh_alerts.diag_ssh_rules_raw",  { limit: 10 }, { enabled: open, staleTime: 60_000 });
  const ruleIds  = useTrinoNamed(["wazuh", "diag-rules"],   "lh.wazuh_alerts.diag_top_rule_ids_today", { limit: 15 }, { enabled: open, staleTime: 60_000 });

  const row0     = anyRow.data?.[0];
  const cnt0     = count.data?.[0];
  const totalRows   = Number(cnt0?.total_rows    ?? 0);
  const distinctRules = Number(cnt0?.distinct_rule_ids ?? 0);

  return (
    <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-3 dark:border-amber-500/15">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between text-left"
      >
        <span className="font-mono text-xs font-semibold text-amber-600 dark:text-amber-400">
          🔍 diagnóstico · wazuh_alerts
        </span>
        <span className="text-xs text-muted-foreground dark:text-zinc-500">
          {open ? "▲ cerrar" : "▼ expandir"}
        </span>
      </button>

      {open && (
        <div className="mt-3 space-y-3">
          {/* Estado general */}
          <div>
            <p className="mb-1.5 font-mono text-[11px] font-semibold text-amber-600 dark:text-amber-400">Estado tabla · últimos 3 días</p>
            {count.isLoading ? (
              <p className="text-xs text-muted-foreground">Consultando…</p>
            ) : count.isError ? (
              <p className="text-xs text-red-500">{count.error?.message ?? "Error"}</p>
            ) : (
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                <div className="rounded-lg border border-border bg-card p-3 dark:border-white/10">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Filas totales</p>
                  <p className="mt-1 font-mono text-xl font-bold text-foreground">{totalRows.toLocaleString()}</p>
                </div>
                <div className="rounded-lg border border-border bg-card p-3 dark:border-white/10">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Rule IDs distintos</p>
                  <p className="mt-1 font-mono text-xl font-bold text-foreground">{distinctRules}</p>
                </div>
                <div className="rounded-lg border border-border bg-card p-3 dark:border-white/10">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Desde</p>
                  <p className="mt-1 font-mono text-sm font-medium text-foreground">{formatDateTimePy(cnt0?.oldest_ts as string | undefined)}</p>
                </div>
                <div className="rounded-lg border border-border bg-card p-3 dark:border-white/10">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Hasta</p>
                  <p className="mt-1 font-mono text-sm font-medium text-foreground">{formatDateTimePy(cnt0?.newest_ts as string | undefined)}</p>
                </div>
              </div>
            )}
          </div>

          {/* Formato ingest_time */}
          {row0 && (
            <div>
              <p className="mb-1.5 font-mono text-[11px] font-semibold text-amber-600 dark:text-amber-400">Formato ingest_time · muestra</p>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                <div className="rounded-lg border border-border bg-card p-3 dark:border-white/10">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Raw</p>
                  <p className="mt-1 break-all font-mono text-xs font-medium text-amber-600 dark:text-amber-400">{String(row0.ingest_time_raw ?? "NULL")}</p>
                </div>
                <div className="rounded-lg border border-border bg-card p-3 dark:border-white/10">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Parsed</p>
                  <p className={`mt-1 font-mono text-xs font-medium ${row0.ingest_ts_parsed ? "text-emerald-600 dark:text-emerald-400" : "text-red-500"}`}>{String(row0.ingest_ts_parsed ?? "NULL ← problema de parsing!")}</p>
                </div>
                <div className="rounded-lg border border-border bg-card p-3 dark:border-white/10">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Rule ID / Level</p>
                  <p className="mt-1 font-mono text-xs font-medium text-foreground">{String(row0.rule_id ?? "—")} / {String(row0.rule_level ?? "—")}</p>
                </div>
              </div>
            </div>
          )}

          {/* Reglas SSH detectadas (sin filtro srcip) */}
          <div>
            <p className="mb-1.5 font-mono text-[11px] font-semibold text-amber-600 dark:text-amber-400">Reglas SSH 5710–5758 · este mes</p>
            {sshRaw.isLoading ? (
              <p className="text-xs text-muted-foreground">Consultando…</p>
            ) : sshRaw.isError ? (
              <p className="text-xs text-red-500">{sshRaw.error?.message ?? "Error"}</p>
            ) : (sshRaw.data ?? []).length === 0 ? (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
                <p className="text-xs font-medium text-amber-600 dark:text-amber-400">
                  ⚠ Sin reglas 5710–5758 en wazuh_alerts este mes
                </p>
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  Los logs SSH podrían estar en otra tabla o no haberse ingestado.
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {(sshRaw.data ?? []).map((r, i) => (
                  <div key={i} className="rounded-lg border border-border bg-card p-3 dark:border-white/10">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-sm font-bold text-primary">{String(r.rule_id)}</span>
                      <span className="rounded-full bg-primary/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-primary">{Number(r.hits).toLocaleString()} hits</span>
                    </div>
                    <p className="mt-1 truncate text-xs text-foreground/70">{String(r.rule_desc ?? "—")}</p>
                    <div className="mt-2 flex gap-3 text-[10px]">
                      <span className={Number(r.with_srcip) === 0 ? "text-red-500" : "text-emerald-600 dark:text-emerald-400"}>
                        srcip: {Number(r.with_srcip).toLocaleString()}
                      </span>
                      <span className="text-muted-foreground">
                        srcuser: {Number(r.with_srcuser).toLocaleString()}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Otras reglas SSH vistas hoy (por descripción) */}
          {(ruleIds.data ?? []).length > 0 && (
            <div>
              <p className="mb-1.5 font-mono text-[11px] font-semibold text-amber-600 dark:text-amber-400">Reglas ssh / brute / auth fail · hoy</p>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {(ruleIds.data ?? []).map((r, i) => (
                  <div key={i} className="rounded-lg border border-border bg-card p-3 dark:border-white/10">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-sm font-bold text-primary">{String(r.rule_id)}</span>
                      <span className="rounded-full bg-primary/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-primary">{Number(r.hits).toLocaleString()} hits</span>
                    </div>
                    <p className="mt-1 truncate text-xs text-foreground/70">{String(r.description ?? "—")}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Sección: Auditd — Comandos y Procesos Sospechosos ─────────────────────────

function AuditdSection() {
  const [hours, setHours]         = useState(24);
  const [search, setSearch]       = useState("");
  const [sortKey, setSortKey]     = useState<AuditdSortKey>("execution_count");
  const [sortDir, setSortDir]     = useState<SortDir>("desc");
  const [enriching, setEnriching] = useState<Set<string>>(new Set());
  const [enriched, setEnriched]   = useState<Set<string>>(new Set());
  const queryClient = useQueryClient();

  const auditd = useTrinoNamed(
    ["wazuh", "auditd-agg", hours],
    "lh.wazuh_alerts.hunt_auditd_commands_agg",
    { hours, limit: 200 },
    STALE_2M,
  );

  const rows = useMemo<AuditdAggRow[]>(() => {
    if (!auditd.data) return [];
    return auditd.data.map((r) => ({
      command:         String(r.command         ?? "—"),
      exe:             String(r.exe             ?? "—"),
      agent_name:      String(r.agent_name      ?? "—"),
      execution_count: Number(r.execution_count ?? 0),
      first_seen:      String(r.first_seen      ?? "—"),
      last_seen:       String(r.last_seen       ?? "—"),
      uid_list:        String(r.uid_list        ?? "—"),
      euid_list:       String(r.euid_list       ?? "—"),
      top_rule_id:     String(r.top_rule_id     ?? "—"),
      top_mitre:       String(r.top_mitre       ?? "—"),
    }));
  }, [auditd.data]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    const base = q
      ? rows.filter(
          (r) =>
            r.command.toLowerCase().includes(q) ||
            r.exe.toLowerCase().includes(q) ||
            r.agent_name.toLowerCase().includes(q) ||
            r.uid_list.includes(q) ||
            r.euid_list.includes(q),
        )
      : rows;
    return [...base].sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      const cmp =
        typeof av === "number"
          ? av - (bv as number)
          : String(av).localeCompare(String(bv));
      return sortDir === "desc" ? -cmp : cmp;
    });
  }, [rows, search, sortKey, sortDir]);

  const toggleSort = useCallback((k: AuditdSortKey) => {
    setSortKey((prev) => {
      if (prev === k) setSortDir((d) => (d === "desc" ? "asc" : "desc"));
      else setSortDir("desc");
      return k;
    });
  }, []);

  const mutation = useMutation({
    mutationFn: async (row: AuditdAggRow) => {
      const res = await fetch("/api/wazuh/enrich-auditd-command", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(row),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Network error" }));
        throw new Error(err.error ?? "Error al enriquecer");
      }
      return res.json();
    },
    onMutate: (row) => {
      const key = `${row.agent_name}|${row.command}`;
      setEnriching((prev) => new Set([...prev, key]));
    },
    onSuccess: (_data, row) => {
      const key = `${row.agent_name}|${row.command}`;
      setEnriching((prev) => { const s = new Set(prev); s.delete(key); return s; });
      setEnriched((prev)  => new Set([...prev, key]));
      queryClient.invalidateQueries({ queryKey: ["wazuh", "auditd-agg"] });
    },
    onError: (_err, row) => {
      const key = `${row.agent_name}|${row.command}`;
      setEnriching((prev) => { const s = new Set(prev); s.delete(key); return s; });
    },
  });

  const hasRoot = (euidList: string) =>
    euidList.split(",").map((s) => s.trim()).some((e) => e === "0" || e === "root");

  const uniqueCommands = rows.length;
  const rootExecs      = rows.filter((r) => hasRoot(r.euid_list)).length;
  const totalExecs     = rows.reduce((s, r) => s + r.execution_count, 0);
  const topAgent       = rows[0]?.agent_name ?? "—";

  function AuditdSortBtn({ col }: { col: AuditdSortKey }) {
    const active = sortKey === col;
    return (
      <button
        onClick={() => toggleSort(col)}
        className={`inline-flex items-center gap-1 transition-colors hover:text-primary ${
          active ? "text-primary" : "text-muted-foreground"
        }`}
      >
        {active ? (
          sortDir === "desc" ? <ChevronDown className="h-3 w-3" /> : <ChevronUp className="h-3 w-3" />
        ) : (
          <ArrowUpDown className="h-3 w-3 opacity-40" />
        )}
      </button>
    );
  }

  return (
    <section className="flex flex-col gap-4">
      {/* Header */}
      <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-destructive/10 p-2 ring-1 ring-destructive/25">
            <Cpu className="h-4 w-4 text-destructive" />
          </div>
          <div>
            <h2 className="font-mono text-sm font-semibold text-foreground">
              auditd · <span className="text-primary">comandos_procesos_sospechosos</span>
            </h2>
            <p className="font-mono text-[11px] text-muted-foreground">
              // Wazuh rules 80700–80799 · group by command + exe + agent · syscalls execve/setuid
            </p>
          </div>
          {auditd.isLoading && (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          )}
        </div>
        <div className="flex items-center gap-2">
          <select
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            className="h-8 rounded-md border border-border bg-card px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
          >
            <option value={6}>Últimas 6 h</option>
            <option value={24}>Últimas 24 h</option>
            <option value={72}>Últimas 72 h</option>
            <option value={168}>7 días</option>
          </select>
          <Button
            variant="outline"
            size="sm"
            onClick={() => queryClient.invalidateQueries({ queryKey: ["wazuh", "auditd-agg"] })}
            className="h-8 gap-1.5 text-xs"
          >
            <RefreshCw className="h-3 w-3" />
            Actualizar
          </Button>
        </div>
      </div>

      {/* KPIs — inline para control total del tema Nexus Dark */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {/* Comandos únicos — primary (lima) */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="relative overflow-hidden rounded-xl border border-border bg-gradient-to-b from-card to-background/70 p-4 shadow-sm"
        >
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/50 to-transparent" />
          <div className="mb-3 inline-flex rounded-lg bg-primary/10 p-2 ring-1 ring-primary/20">
            <Terminal className="h-4 w-4 text-primary" />
          </div>
          <p className="text-2xl font-bold tabular-nums tracking-tight text-primary">
            {auditd.isLoading ? "…" : formatNumber(uniqueCommands)}
          </p>
          <p className="mt-0.5 text-xs font-medium text-muted-foreground">Comandos únicos</p>
        </motion.div>

        {/* Ejecuciones root — destructive (rosa-roja) */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="relative overflow-hidden rounded-xl border border-border bg-gradient-to-b from-card to-background/70 p-4 shadow-sm"
        >
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-destructive/50 to-transparent" />
          <div className="mb-3 inline-flex rounded-lg bg-destructive/10 p-2 ring-1 ring-destructive/25">
            <Zap className="h-4 w-4 text-destructive" />
          </div>
          <p className="text-2xl font-bold tabular-nums tracking-tight text-destructive">
            {auditd.isLoading ? "…" : formatNumber(rootExecs)}
          </p>
          <p className="mt-0.5 text-xs font-medium text-muted-foreground">Ejecuciones root</p>
          <p className="mt-0.5 text-[11px] text-muted-foreground/55">UID / EUID = 0</p>
        </motion.div>

        {/* Total ejecuciones — warning (ámbar) */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="relative overflow-hidden rounded-xl border border-border bg-gradient-to-b from-card to-background/70 p-4 shadow-sm"
        >
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-amber-500/50 to-transparent" />
          <div className="mb-3 inline-flex rounded-lg bg-amber-500/10 p-2 ring-1 ring-amber-500/20">
            <Activity className="h-4 w-4 text-amber-400" />
          </div>
          <p className="text-2xl font-bold tabular-nums tracking-tight text-amber-300">
            {auditd.isLoading ? "…" : formatNumber(totalExecs)}
          </p>
          <p className="mt-0.5 text-xs font-medium text-muted-foreground">Total ejecuciones</p>
        </motion.div>

        {/* Agente top — secondary (teal) */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="relative overflow-hidden rounded-xl border border-border bg-gradient-to-b from-card to-background/70 p-4 shadow-sm"
        >
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-teal-500/40 to-transparent" />
          <div className="mb-3 inline-flex rounded-lg bg-teal-500/10 p-2 ring-1 ring-teal-500/20">
            <Server className="h-4 w-4 text-teal-400" />
          </div>
          <p className="mt-1 truncate font-mono text-sm font-bold text-teal-300">{topAgent}</p>
          <p className="mt-0.5 text-xs font-medium text-muted-foreground">Agente top</p>
        </motion.div>
      </div>

      {/* Tabla — card con glow sutil Nexus */}
      <Card className="overflow-hidden border-border bg-card shadow-[inset_0_1px_0_0_var(--nexus-glow-primary),0_0_28px_-8px_var(--nexus-glow-secondary)]">
        {/* Búsqueda */}
        <div className="flex items-center gap-3 border-b border-border px-4 py-3">
          <Search className="h-4 w-4 flex-shrink-0 text-muted-foreground" />
          <Input
            placeholder="Filtrar por comando, exe, agente, UID…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-7 flex-1 border-0 bg-transparent p-0 text-sm text-foreground placeholder:text-muted-foreground focus-visible:ring-0"
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              className="text-xs text-muted-foreground hover:text-foreground"
            >
              ✕
            </button>
          )}
          <span className="text-xs text-muted-foreground/55">
            {filtered.length} / {rows.length}
          </span>
        </div>

        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="text-xs font-medium text-muted-foreground">
                  <div className="flex items-center gap-1">Comando / Exe<AuditdSortBtn col="command" /></div>
                </TableHead>
                <TableHead className="text-right text-xs font-medium text-muted-foreground">
                  <div className="flex items-center justify-end gap-1">Ejecuciones<AuditdSortBtn col="execution_count" /></div>
                </TableHead>
                <TableHead className="text-xs font-medium text-muted-foreground">UIDs / EUIDs</TableHead>
                <TableHead className="text-xs font-medium text-muted-foreground">Primer evento</TableHead>
                <TableHead className="text-xs font-medium text-muted-foreground">
                  <div className="flex items-center gap-1">Último evento<AuditdSortBtn col="last_seen" /></div>
                </TableHead>
                <TableHead className="text-xs font-medium text-muted-foreground">
                  <div className="flex items-center gap-1">Agente<AuditdSortBtn col="agent_name" /></div>
                </TableHead>
                <TableHead className="text-xs font-medium text-muted-foreground">Regla / MITRE</TableHead>
                <TableHead className="text-center text-xs font-medium text-muted-foreground">Acción</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {auditd.isLoading ? (
                <TableSkeleton cols={8} rows={6} />
              ) : auditd.isError ? (
                <TableRow className="border-border">
                  <TableCell colSpan={8} className="py-8 text-center text-sm text-destructive">
                    {auditd.error?.message ?? "Error al consultar Trino"}
                  </TableCell>
                </TableRow>
              ) : filtered.length === 0 ? (
                <TableRow className="border-border">
                  <TableCell colSpan={8} className="py-12 text-center">
                    <Cpu className="mx-auto mb-2 h-8 w-8 text-muted-foreground/30" />
                    <p className="text-sm text-muted-foreground">
                      {search
                        ? "Sin resultados para el filtro aplicado"
                        : "No se detectaron comandos auditd en la ventana seleccionada"}
                    </p>
                  </TableCell>
                </TableRow>
              ) : (
                <AnimatePresence initial={false}>
                  {filtered.map((row, i) => {
                    const key    = `${row.agent_name}|${row.command}`;
                    const isEnr  = enriching.has(key);
                    const isDone = enriched.has(key);
                    const isRoot = hasRoot(row.euid_list);
                    const threat =
                      row.execution_count >= 50 ? "critical" :
                      row.execution_count >= 10 ? "high" : "medium";
                    return (
                      <motion.tr
                        key={key}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ delay: Math.min(i * 0.015, 0.2) }}
                        className="border-border transition-colors hover:bg-accent"
                      >
                        {/* Comando / Exe */}
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <span className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${
                              isRoot            ? "bg-destructive shadow-[0_0_5px_1px_color-mix(in_oklab,var(--color-destructive)_55%,transparent)]" :
                              threat === "high" ? "bg-amber-500"  : "bg-primary/50"
                            }`} />
                            <div>
                              <div className="flex items-center gap-1.5">
                                <FileCode2 className="h-3 w-3 flex-shrink-0 text-muted-foreground" />
                                <span className="font-mono text-sm text-primary">{row.command}</span>
                              </div>
                              {row.exe !== "—" && row.exe !== row.command && (
                                <p className="max-w-[220px] truncate pl-[18px] font-mono text-[10px] text-muted-foreground" title={row.exe}>
                                  {row.exe}
                                </p>
                              )}
                            </div>
                          </div>
                        </TableCell>
                        {/* Ejecuciones */}
                        <TableCell className="text-right">
                          <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-sm font-bold tabular-nums ${
                            threat === "critical" ? "bg-destructive/15 text-destructive"    :
                            threat === "high"     ? "bg-amber-500/15   text-amber-400"      :
                                                   "bg-primary/10      text-primary"
                          }`}>
                            {formatNumber(row.execution_count)}
                          </span>
                        </TableCell>
                        {/* UIDs / EUIDs */}
                        <TableCell>
                          <div className="flex flex-col gap-0.5">
                            <span className="font-mono text-[11px] text-foreground/85">
                              uid:{" "}
                              <span className={row.uid_list.includes("0") ? "font-bold text-destructive" : ""}>
                                {row.uid_list || "—"}
                              </span>
                            </span>
                            <span className="font-mono text-[11px] text-muted-foreground">
                              euid:{" "}
                              <span className={isRoot ? "font-bold text-destructive" : ""}>
                                {row.euid_list || "—"}
                              </span>
                            </span>
                          </div>
                        </TableCell>
                        {/* Primer evento */}
                        <TableCell>
                          <span className="font-mono text-xs text-muted-foreground">{fmtTs(row.first_seen)}</span>
                        </TableCell>
                        {/* Último evento */}
                        <TableCell>
                          <div>
                            <span className="font-mono text-xs text-foreground/85">{fmtTs(row.last_seen)}</span>
                            <p className="text-[10px] text-muted-foreground/60">{fmtAgo(row.last_seen)}</p>
                          </div>
                        </TableCell>
                        {/* Agente */}
                        <TableCell>
                          <div className="flex items-center gap-1.5">
                            <Server className="h-3 w-3 text-muted-foreground" />
                            <span className="text-xs text-muted-foreground">{row.agent_name}</span>
                          </div>
                        </TableCell>
                        {/* Regla / MITRE */}
                        <TableCell>
                          <div className="flex flex-col gap-1">
                            {row.top_rule_id !== "—" && (
                              <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
                                {row.top_rule_id}
                              </span>
                            )}
                            {row.top_mitre !== "—" && (
                              <span className="rounded border border-violet-500/20 bg-violet-500/10 px-1.5 py-0.5 font-mono text-[10px] text-violet-400">
                                {row.top_mitre}
                              </span>
                            )}
                          </div>
                        </TableCell>
                        {/* Acción */}
                        <TableCell className="text-center">
                          {isDone ? (
                            <span className="inline-flex items-center gap-1 text-xs text-primary">
                              <CheckCircle2 className="h-3.5 w-3.5" />
                              Guardado
                            </span>
                          ) : (
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={isEnr}
                              onClick={() => mutation.mutate(row)}
                              className="h-7 gap-1.5 text-xs hover:border-primary/40 hover:bg-primary/10 hover:text-primary disabled:opacity-50"
                            >
                              {isEnr
                                ? <Loader2 className="h-3 w-3 animate-spin" />
                                : <Database className="h-3 w-3" />}
                              {isEnr ? "Guardando…" : "Enriquecer"}
                            </Button>
                          )}
                        </TableCell>
                      </motion.tr>
                    );
                  })}
                </AnimatePresence>
              )}
            </TableBody>
          </Table>
        </div>
        {filtered.length > 0 && (
          <div className="border-t border-border px-4 py-2 text-xs text-muted-foreground/60">
            Tabla: <code className="rounded bg-muted px-1 text-[10px] text-muted-foreground">minio.hunting.wazuh_alerts</code> ·
            Reglas auditd 80700–80799 · UID/EUID=0 indica ejecución privilegiada ·
            Guardado en: <code className="rounded bg-muted px-1 text-[10px] text-muted-foreground">minio_iceberg.hunting.auditd_suspicious_commands</code>
          </div>
        )}
      </Card>
    </section>
  );
}

// ── Página principal ──────────────────────────────────────────────────────────

export function WazuhIntelligencePage() {
  const { results, isLoading, isFetching, refetch } = useTrinoNamedBatch(
    ["wazuh", "detail"],
    WAZUH_SPECS,
    STALE_5M,
  );

  const sevRows = useMemo(() => {
    const data = results.sev.data ?? [];
    return data.map((r) => ({ name: String(r.bucket ?? ""), value: Number(r.c ?? 0) }));
  }, [results.sev.data]);

  const totalAlerts = useMemo(() => sevRows.reduce((s, d) => s + d.value, 0), [sevRows]);
  const critCount   = useMemo(() => sevRows.find((d) => d.name === "critical")?.value ?? 0, [sevRows]);
  const highCount   = useMemo(() => sevRows.find((d) => d.name === "high")?.value    ?? 0, [sevRows]);
  const sevMax      = useMemo(() => Math.max(1, ...sevRows.map((d) => d.value)), [sevRows]);

  const rulesData = useMemo(() => {
    const data = results.rules.data ?? [];
    return data.map((r) => ({
      rule:        String(r.rule_id     ?? "—"),
      description: String(r.description ?? "—"),
      hits:        Number(r.hits        ?? 0),
    }));
  }, [results.rules.data]);

  const agentsData = useMemo(() => {
    const data = results.agents.data ?? [];
    return data.map((r) => ({
      host:   String(r.agent ?? "—"),
      alerts: Number(r.hits  ?? 0),
    }));
  }, [results.agents.data]);

  const maxHits   = useMemo(() => Math.max(1, ...rulesData.map((r) => r.hits)),   [rulesData]);
  const maxAlerts = useMemo(() => Math.max(1, ...agentsData.map((a) => a.alerts)), [agentsData]);

  const cveRows = useMemo(() => {
    if (!results.cveCrit.data) return [];
    return results.cveCrit.data.map((r) => ({
      ingest_time:       String(r.ingest_time       ?? "—"),
      cve_id:            String(r.cve_id            ?? "—"),
      cvss_score:        Number(r.cvss_score        ?? 0),
      cvss_source:       String(r.cvss_source       ?? ""),
      severity:          String(r.severity          ?? "—"),
      host_ip:           String(r.host_ip           ?? "—"),
      host_name:         String(r.host_name         ?? "—"),
      rule_description:  String(r.rule_description  ?? "—"),
      incident_taxonomy: String(r.incident_taxonomy ?? "—"),
    }));
  }, [results.cveCrit.data]);

  const cveHostRows = useMemo(() => {
    if (!results.cveHost.data) return [];
    return results.cveHost.data.map((r) => ({
      host_ip:      String(r.host_ip      ?? "—"),
      host_name:    String(r.host_name    ?? "—"),
      distinct_cves: Number(r.distinct_cves ?? 0),
      alert_count:  Number(r.alert_count  ?? 0),
      max_cvss_seen: Number(r.max_cvss_seen ?? 0),
    }));
  }, [results.cveHost.data]);

  const hasErr = Object.values(results).some((r) => r.error);

  return (
    <div className="flex flex-col gap-5 p-6">
      <DetailHeader
        icon={Shield}
        title="Wazuh"
        subtitle="HIDS · wazuh_alerts · threat hunting · últimas 24 h"
        right={
          <Button
            variant="outline" size="sm" className="h-7 gap-1 text-[11px]"
            onClick={() => void refetch()} disabled={isFetching}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
            {isFetching ? "Actualizando…" : "Refrescar"}
          </Button>
        }
      />

      {hasErr && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-2 text-xs text-destructive">
          Algunas secciones fallaron — reintenta o revisa el proxy Trino.
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiTile label="Alertas totales" value={totalAlerts}     icon={AlertTriangle} tone="info"     loading={isLoading} />
        <KpiTile label="Críticas (≥12)"  value={critCount}       icon={Zap}           tone="critical" loading={isLoading} />
        <KpiTile label="Alta severidad"  value={highCount}       icon={Eye}           tone="warning"  loading={isLoading} />
        <KpiTile label="CVE críticos"    value={cveRows.length}  icon={Bug}           tone="critical" loading={isLoading} sub="CVSS ≥ 9" />
      </div>

      {/* Diagnóstico wazuh_alerts (conservado sin cambios — se auto-gestiona) */}
      <WazuhAlertsDiagSection />

      {/* Auditd — Comandos sospechosos */}
      <AuditdSection />

      {/* Severidad + Hosts activos */}
      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard title="Distribución de severidad" subtitle={`${totalAlerts.toLocaleString("es-ES")} alertas en 24 h`}>
          {isLoading ? <LoadingRows rows={4} /> : sevRows.length === 0 ? (
            <EmptyState message="Sin alertas en la ventana — revise ingesta Wazuh" />
          ) : (
            <div className="flex flex-col">
              {sevRows.map((d, i) => (
                <BarRow
                  key={i}
                  label={<span className="capitalize">{d.name}</span>}
                  value={d.value}
                  max={sevMax}
                  tone={d.name === "critical" ? "critical" : d.name === "high" ? "warning" : d.name === "medium" ? "info" : "muted"}
                />
              ))}
            </div>
          )}
        </SectionCard>

        <SectionCard title="Hosts / agentes más activos" subtitle="Volumen de alertas por agente">
          {isLoading ? <LoadingRows/> : agentsData.length === 0 ? (
            <EmptyState message="Sin datos de agentes" />
          ) : (
            <div className="flex flex-col">
              {agentsData.map((a, i) => (
                <BarRow
                  key={i}
                  label={<span className="truncate font-mono" title={a.host}>{a.host}</span>}
                  value={a.alerts}
                  max={maxAlerts}
                  tone="info"
                />
              ))}
            </div>
          )}
        </SectionCard>
      </div>

      {/* Top rules */}
      <SectionCard title="Top reglas activadas" subtitle="Las más disparadas — 24 h">
        {isLoading ? <LoadingRows/> : rulesData.length === 0 ? (
          <EmptyState message="Sin datos de reglas" />
        ) : (
          <div className="flex flex-col">
            {rulesData.map((r, i) => (
              <BarRow
                key={`${r.rule}-${i}`}
                label={
                  <span className="flex items-center gap-2 min-w-0">
                    <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">{r.rule}</span>
                    <span className="truncate text-[11px]" title={r.description}>{r.description}</span>
                  </span>
                }
                value={r.hits}
                max={maxHits}
                tone="info"
              />
            ))}
          </div>
        )}
      </SectionCard>

      {/* CVE críticos */}
      <SectionCard
        title="CVE críticos detectados"
        subtitle="vulnerability-detector · CVSSv2/v3 ≥ 9 o Critical"
        right={<Badge variant="outline" className="border-purple-500/30 bg-purple-500/10 text-[10px] text-purple-400">CVSS ≥ 9</Badge>}
      >
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                {["Hora", "CVE", "CVSS", "Sev.", "IP host", "Host", "Descripción", "Taxonomía"].map((h) => (
                  <TableHead key={h}>{h}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading && <TableRow><TableCell colSpan={8} className="py-4 text-xs text-muted-foreground">Cargando…</TableCell></TableRow>}
              {!isLoading && cveRows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={8} className="py-8 text-center">
                    <Bug className="mx-auto mb-2 h-6 w-6 text-muted-foreground/50" />
                    <p className="text-xs text-muted-foreground">Sin CVE críticos en la ventana</p>
                  </TableCell>
                </TableRow>
              )}
              {cveRows.map((r, i) => (
                <TableRow key={`${r.cve_id}-${i}`}>
                  <TableCell className="whitespace-nowrap font-mono text-[11px] text-muted-foreground">{fmtTs(r.ingest_time)}</TableCell>
                  <TableCell><span className="font-mono text-xs font-semibold text-purple-400">{r.cve_id}</span></TableCell>
                  <TableCell className="text-right">
                    <span className={cn("font-mono text-xs font-bold", r.cvss_score >= 9 ? "text-red-400" : r.cvss_score >= 7 ? "text-orange-400" : "text-yellow-400")}>
                      {r.cvss_score.toFixed(1)}
                    </span>
                    {r.cvss_source && <span className="ml-1 text-[10px] text-muted-foreground">{r.cvss_source}</span>}
                  </TableCell>
                  <TableCell><SeverityBadge level={r.severity} /></TableCell>
                  <TableCell className="font-mono text-xs">{r.host_ip}</TableCell>
                  <TableCell className="max-w-[140px] truncate text-[11px] text-muted-foreground" title={r.host_name}>{r.host_name}</TableCell>
                  <TableCell className="max-w-[200px] truncate text-[11px] text-muted-foreground" title={r.rule_description}>{r.rule_description}</TableCell>
                  <TableCell className="max-w-[160px] truncate font-mono text-[10px] text-muted-foreground" title={r.incident_taxonomy}>{r.incident_taxonomy || "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </SectionCard>

      {/* CVE hosts resumen */}
      {cveHostRows.length > 0 && (
        <SectionCard title="Resumen por host afectado" subtitle="CVE críticos — agrupado por host">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  {["IP", "Host", "CVEs únicos", "Alertas", "CVSS máx"].map((h) => (
                    <TableHead key={h}>{h}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {cveHostRows.map((r, i) => (
                  <TableRow key={`${r.host_ip}-${i}`}>
                    <TableCell className="font-mono text-xs">{r.host_ip}</TableCell>
                    <TableCell className="max-w-[180px] truncate text-[11px] text-muted-foreground" title={r.host_name}>{r.host_name}</TableCell>
                    <TableCell className="font-mono text-xs tabular-nums text-teal-400">{r.distinct_cves}</TableCell>
                    <TableCell className="font-mono text-xs tabular-nums">{formatNumber(r.alert_count)}</TableCell>
                    <TableCell>
                      <span className={cn("font-mono text-xs font-bold", r.max_cvss_seen >= 9 ? "text-red-400" : "text-orange-400")}>
                        {r.max_cvss_seen.toFixed(1)}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </SectionCard>
      )}
    </div>
  );
}
