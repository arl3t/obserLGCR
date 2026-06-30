/**
 * HuntPage — `/hunt` (Sprint 2 de docs/HUNT-PIVOTS.md).
 *
 * Permite al operador navegar rankings agregados por entidad (top IPs
 * atacantes, agentes más atacados, CVEs críticos) y abrir un caso desde
 * cualquier fila — sin copiar/pegar IOCs entre rutas.
 *
 * Flujo:
 *   1. Tab + tabla con queryId top-N (cache 60s).
 *   2. Click fila → PivotPreviewModal (consulta /api/hunt/preview).
 *   3. Click "Investigar" → OpenCaseModal pre-poblado con suggestedCase.
 *   4. Submit OpenCaseModal → POST /api/incidents/open-from-flow → redirect
 *      a /gestion?investigate=<caseId>.
 *
 * Sprint 3 agregará tabs: Phishing senders, Outliers, Puertos.
 */
import { useMemo, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Activity, Bug, FileSearch, Mail, Search, Shield, ShipWheel, Users } from "lucide-react";
import { api } from "@/api/client";
import { useTrinoNamedBatch, type BatchSpec } from "@/hooks/useTrinoQuery";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { PivotPreviewModal, type PivotSelection } from "@/components/hunt/PivotPreviewModal";

type ExistingCase = {
  caseId: string;
  status: string;
  severity: string;
  score: number;
  lastSeen: string;
  occurrenceCount: number;
};
type CaseStatusResponse = { ok: true; byValue: Record<string, ExistingCase> };

// Cadencia 2026-06-26: los rankings de 24h NO necesitan ser en vivo (las MV
// que los alimentan se refrescan cada hora). Antes refrescaban cada 60s, lo que
// martillaba a Trino (1 nodo) sin valor. Ahora cada 3h y sin refetch con la
// pestaña oculta. El operador igual ve datos al abrir y puede recargar la página.
const STALE_3H = {
  staleTime: 3 * 60 * 60_000,
  refetchInterval: 3 * 60 * 60_000,
  refetchIntervalInBackground: false,
} as const;
// Optimización 2026-06-25: rankings acotados al TOP 10 (antes 20). El `limit` se aplica
// server-side en la named query (no es slice de cliente), así que reduce filas devueltas,
// transferencia y —sobre todo— el batch de /hunt/case-status, que hace 1 lookup en PG por
// IOC del ranking. Top 10 es lo accionable para arrancar una investigación; el resto era ruido.
const TOP_LIMIT = 10;

type TabKey = "ips" | "agents" | "cves" | "phishing" | "outliers" | "ports";

interface TabSpec {
  key:        TabKey;
  label:      string;
  icon:       typeof Shield;
  queryId:    string;
  /** Convierte una fila del query a la selección de pivote. Devolver `null`
   *  marca la fila como no-clickable (solo lectura) — caso típico: tab
   *  "Puertos atacados" que no abre caso, solo navega. */
  toSelection: (row: Record<string, unknown>) => PivotSelection | null;
  /** Columnas a renderizar. `render` opcional para columnas custom (chips,
   *  badges) en lugar del format por defecto. */
  columns: Array<{
    key:     string;
    label:   string;
    align?:  "left" | "right";
    render?: (row: Record<string, unknown>) => React.ReactNode;
  }>;
  /** Acción especial al click — si está, NO abre modal de preview.
   *  Usado por "Puertos atacados" para navegar a /gestion con filtro. */
  onClickInstead?: (row: Record<string, unknown>, navigate: ReturnType<typeof useNavigate>) => void;
}

/** Mapea entity_type del outlier → pivot canónico del backend. Las entidades
 *  no mapeables (user, hour, country) se filtran del tab. */
function mapOutlierEntity(entityType: string, entityValue: string): PivotSelection | null {
  switch (entityType) {
    case "ip":
      return { pivot: "src_ip", value: entityValue, label: entityValue,
               outlierEntity: { entity_type: entityType, entity_value: entityValue } };
    case "host":
      return { pivot: "agent_name", value: entityValue, label: entityValue,
               outlierEntity: { entity_type: entityType, entity_value: entityValue } };
    case "domain":
      return { pivot: "sender_domain", value: entityValue, label: entityValue,
               outlierEntity: { entity_type: entityType, entity_value: entityValue } };
    default:
      return null;
  }
}

// Mapeo tab → query + columnas. Manténtelos sincronizados con
// legacyhunt-api/trino/registry.mjs (existencia del queryId).
const TABS: TabSpec[] = [
  {
    key: "ips",
    label: "IPs Atacantes",
    icon: Shield,
    queryId: "lh.fg.top_blocked_ips_24h_mat",
    toSelection: (r) => ({
      pivot: "src_ip",
      value: String(r.src_ip ?? ""),
      label: String(r.src_ip ?? ""),
    }),
    columns: [
      { key: "src_ip",         label: "IP origen" },
      { key: "hits",           label: "Hits 24h",      align: "right" },
      { key: "ports_targeted", label: "Puertos dist.", align: "right" },
    ],
  },
  {
    key: "agents",
    label: "Agentes Atacados",
    icon: Users,
    queryId: "lh.wazuh.top_agents_24h",
    toSelection: (r) => ({
      pivot: "agent_name",
      value: String(r.agent ?? ""),
      label: String(r.agent ?? ""),
    }),
    columns: [
      { key: "agent", label: "Agente / host" },
      { key: "hits",  label: "Alertas 24h", align: "right" },
    ],
  },
  {
    key: "cves",
    label: "CVEs Críticos",
    icon: Bug,
    // Ranking real por CVE (1 row = 1 CVE, hosts_count agregado).
    // El query per-evento `lh.wazuh.critical_cves_24h` sigue vivo para
    // WazuhIntelligence, que sí necesita el feed cronológico.
    queryId: "lh.wazuh.critical_cves_aggregated_24h",
    toSelection: (r) => ({
      pivot: "cve",
      value: String(r.cve_id ?? ""),
      label: String(r.cve_id ?? ""),
    }),
    columns: [
      { key: "cve_id",      label: "CVE" },
      { key: "cvss_score",  label: "CVSS",        align: "right" },
      {
        key:   "hosts_count",
        label: "Hosts afect.",
        render: (r) => <HostsCell row={r} />,
      },
      { key: "alert_count", label: "Alertas",     align: "right" },
    ],
  },
  {
    key: "phishing",
    label: "Phishing senders",
    icon: Mail,
    queryId: "lh.pmg.top_senders_24h",
    toSelection: (r) => {
      // Sender IP es el pivote preferido. Si vino como "(desconocida)" usamos
      // dominio. Si ambos son placeholder, no hay nada para investigar.
      const ip     = String(r.sender_ip ?? "");
      const domain = String(r.sender_domain ?? "");
      if (ip && ip !== "(desconocida)") {
        return { pivot: "sender_ip", value: ip, label: ip };
      }
      if (domain && domain !== "(sin dominio)") {
        return { pivot: "sender_domain", value: domain, label: domain };
      }
      return null;
    },
    columns: [
      { key: "sender_ip",      label: "IP / Dominio" },
      { key: "blocked",        label: "Blocked",       align: "right" },
      { key: "max_spam_score", label: "Max spam",      align: "right" },
      { key: "unique_recipients", label: "Recipients", align: "right" },
    ],
  },
  {
    key: "outliers",
    label: "Outliers",
    icon: Activity,
    // top_entities con days=1 usa la vista v_outliers_last_24h (más rápida).
    queryId: "lh.outliers.top_entities",
    toSelection: (r) => {
      const entityType  = String(r.entity_type  ?? "");
      const entityValue = String(r.entity_value ?? "");
      if (!entityType || !entityValue) return null;
      return mapOutlierEntity(entityType, entityValue);
    },
    columns: [
      { key: "entity_type",   label: "Tipo" },
      { key: "entity_value",  label: "Entidad" },
      { key: "severity",      label: "Severity" },
      { key: "score",         label: "Score",     align: "right" },
      { key: "anomaly_type",  label: "Anomalía" },
    ],
  },
  {
    key: "ports",
    label: "Puertos Atacados",
    icon: ShipWheel,
    queryId: "lh.fg.top_dest_ports_24h_mat",
    // No abre caso. Solo navega al /gestion con un hint en el search.
    toSelection: () => null,
    onClickInstead: (r, navigate) => {
      const port  = String(r.dest_port ?? "");
      const proto = String(r.proto ?? "tcp");
      if (!port) return;
      navigate(`/gestion?search=${encodeURIComponent(`dport:${port}`)}&_hint=${encodeURIComponent(proto)}`);
    },
    columns: [
      { key: "dest_port",      label: "Puerto",       align: "right" },
      { key: "proto",          label: "Proto" },
      { key: "hits",           label: "Hits",         align: "right" },
      { key: "unique_src_ips", label: "IPs distintas", align: "right" },
    ],
  },
];

const TOP_ENTITIES_PARAMS = { days: 1, limit: TOP_LIMIT } as const;

export function HuntPage() {
  const [activeTab, setActiveTab] = useState<TabKey>("ips");
  const [selection, setSelection] = useState<PivotSelection | null>(null);
  const navigate = useNavigate();

  return (
    <div className="space-y-4 p-6">
      <header className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Search className="h-5 w-5 text-cyan-400" />
          <h1 className="text-lg font-bold">Hunt Pivots</h1>
          <span className="text-xs text-muted-foreground">
            Iniciá investigaciones desde rankings agregados de 24h.
          </span>
        </div>
      </header>

      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as TabKey)}>
        <TabsList>
          {TABS.map((t) => (
            <TabsTrigger key={t.key} value={t.key} className="gap-2">
              <t.icon className="h-3.5 w-3.5" />
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>

        {TABS.map((t) => (
          <TabsContent key={t.key} value={t.key} className="mt-3">
            <RankingTabBody
              tab={t}
              enabled={activeTab === t.key}
              onRowClick={(sel) => setSelection(sel)}
              onRowAltClick={(row) => t.onClickInstead?.(row, navigate)}
            />
          </TabsContent>
        ))}
      </Tabs>

      {selection && (
        <PivotPreviewModal
          selection={selection}
          onClose={() => setSelection(null)}
        />
      )}
    </div>
  );
}

interface RankingTabBodyProps {
  tab:           TabSpec;
  enabled:       boolean;
  onRowClick:    (sel: PivotSelection) => void;
  /** Alternativa: click cuando el tab navega en vez de abrir modal. */
  onRowAltClick: (row: Record<string, unknown>) => void;
}

function RankingTabBody({ tab, enabled, onRowClick, onRowAltClick }: RankingTabBodyProps) {
  // Una sola named query por tab — cargada solo cuando la tab está activa.
  // Outliers usa params específicos (days/limit); el resto solo {limit}.
  const params = tab.key === "outliers" ? TOP_ENTITIES_PARAMS : { limit: TOP_LIMIT };
  const specs = useMemo(
    () => [{ key: "top", id: tab.queryId, params }] as const satisfies BatchSpec[],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [tab.queryId],
  );
  const { results, isLoading, isError } = useTrinoNamedBatch<"top">(
    ["hunt", tab.key],
    specs,
    { ...STALE_3H, enabled },
  );

  const rows = results.top.data ?? [];

  // Lookup batch de "caso abierto" para cada fila. Solo se dispara cuando
  // hay filas con un IOC investigable (los tabs onClickInstead — puertos —
  // devuelven null y se filtran). Cache 60s para alinearse con el ranking.
  const iocValues = useMemo(() => {
    const out: string[] = [];
    for (const r of rows) {
      const sel = tab.toSelection(r as Record<string, unknown>);
      if (sel?.value) out.push(sel.value);
    }
    return out;
  }, [rows, tab]);
  const { data: statusData } = useQuery<CaseStatusResponse>({
    queryKey: ["hunt", "case-status", tab.key, iocValues],
    queryFn: async () => {
      const res = await api.post<CaseStatusResponse>("/api/hunt/case-status", { values: iocValues });
      return res.data;
    },
    enabled: enabled && iocValues.length > 0,
    staleTime: 3 * 60 * 60_000,   // alineado a la cadencia del ranking (3h)
  });
  const byValue = statusData?.byValue ?? {};

  if (isLoading) {
    return (
      <div className="space-y-1">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-9 w-full" />
        ))}
      </div>
    );
  }

  if (isError || results.top.error) {
    return (
      <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-xs text-destructive">
        Error al cargar el ranking. {results.top.error ?? ""}
      </div>
    );
  }

  if (rows.length === 0) {
    return (
      <div className="rounded-md border border-dashed border-border p-6 text-center text-xs text-muted-foreground">
        Sin datos en la ventana de 24 h.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-md border border-border bg-card/40">
      <table className="w-full text-sm">
        <thead className="bg-muted/40 text-[11px] uppercase tracking-wide text-muted-foreground">
          <tr>
            {tab.columns.map((c) => (
              <th key={c.key} className={`px-3 py-2 ${c.align === "right" ? "text-right" : "text-left"}`}>
                {c.label}
              </th>
            ))}
            <th className="px-3 py-2 text-left">Estado</th>
            <th className="w-10" />
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => {
            const row = r as Record<string, unknown>;
            const sel = tab.toSelection(row);
            // Tabs con `onClickInstead` (puertos) NO usan modal — clic
            // navega directamente. Las filas sin pivote mapeable (outlier
            // de tipo user/country/etc.) tampoco abren modal.
            const handleClick = tab.onClickInstead
              ? () => onRowAltClick(row)
              : sel
                ? () => onRowClick(sel)
                : undefined;
            const isClickable = !!handleClick;
            return (
              <tr
                key={`${i}-${(sel?.value ?? row[tab.columns[0].key]) || ""}`}
                onClick={handleClick}
                className={cn(
                  "border-t border-border/40 transition-colors",
                  isClickable ? "cursor-pointer hover:bg-muted/20" : "opacity-60",
                )}
                title={
                  tab.onClickInstead
                    ? "Click para abrir el filtro en /gestion"
                    : isClickable
                      ? "Click para previsualizar e investigar"
                      : "Pivote no investigable desde este tab"
                }
              >
                {tab.columns.map((c) => (
                  <td
                    key={c.key}
                    className={`px-3 py-2 font-mono text-[12px] ${c.align === "right" ? "text-right" : ""}`}
                  >
                    {c.render
                      ? c.render(r as Record<string, unknown>)
                      : formatCell((r as Record<string, unknown>)[c.key])}
                  </td>
                ))}
                <td className="px-3 py-2">
                  {sel?.value && byValue[sel.value] ? (
                    <ExistingCaseBadge existing={byValue[sel.value]} />
                  ) : (
                    <span className="text-[11px] text-muted-foreground/60">—</span>
                  )}
                </td>
                <td className="px-2 py-2 text-right text-muted-foreground">
                  <ArrowRight className="ml-auto h-3.5 w-3.5" />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function formatCell(v: unknown): string {
  if (v == null) return "—";
  if (typeof v === "number") return new Intl.NumberFormat("es-AR").format(v);
  return String(v);
}

/** Renderiza hasta 3 hosts inline + badge "+N" con tooltip que muestra el
 *  resto. Si el query devolvió `top_hosts` array, se usa esa lista; si solo
 *  llegó `hosts_count`, cae al número plano (compat con tabs sin lista). */
function HostsCell({ row }: { row: Record<string, unknown> }) {
  const hosts = Array.isArray(row.top_hosts) ? (row.top_hosts as string[]) : [];
  const count = typeof row.hosts_count === "number" ? row.hosts_count : hosts.length;
  if (hosts.length === 0) {
    return <span className="text-right">{count > 0 ? new Intl.NumberFormat("es-AR").format(count) : "—"}</span>;
  }
  const visible = hosts.slice(0, 3);
  const extra = Math.max(0, count - visible.length);
  return (
    <div className="flex flex-wrap items-center gap-1">
      {visible.map((h) => (
        <span
          key={h}
          title={h}
          className="max-w-[180px] truncate rounded border border-border bg-muted/40 px-1.5 py-0.5 text-[10px] font-normal text-foreground/80"
        >
          {h}
        </span>
      ))}
      {extra > 0 && (
        <span
          title={hosts.slice(3).join("\n")}
          className="rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 text-[10px] font-medium text-cyan-300"
        >
          +{extra}
        </span>
      )}
    </div>
  );
}

/** Badge "Caso abierto" con link a /gestion?investigate=<id>. stopPropagation
 *  para que clickear el badge no dispare el row-click (modal de preview). */
function ExistingCaseBadge({ existing }: { existing: ExistingCase }) {
  return (
    <Link
      to={`/gestion?investigate=${existing.caseId}`}
      onClick={(e) => e.stopPropagation()}
      title={`Caso ${existing.caseId.slice(0, 8)} · ${existing.status} · ${existing.occurrenceCount} ocurrencias`}
      className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-300 hover:bg-amber-500/20"
    >
      <FileSearch className="h-3 w-3" />
      Caso abierto
    </Link>
  );
}
