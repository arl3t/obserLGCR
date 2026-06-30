/**
 * useSurveillanceWorkspace — hooks de la Ola B (histórico, anotaciones, export).
 *
 * Centralizados en un único módulo para evitar 5 archivos chiquitos. Cada hook
 * es independiente y consume su endpoint específico.
 */

import { useEffect, useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type {
  AnalystFinding,
  SurveillanceDomainResult,
} from "@/types/digital-surveillance";
import { RISK_ENGINE_VERSION } from "@/components/digital-surveillance/risk-engine/calculateRiskScore";
import {
  useWatchlistStore,
  type WatchlistChannel,
  type WatchlistEntry,
  type WatchlistFrequency,
} from "@/store/surveillance-watchlist-store";
import type { ThreatKind } from "@/types/digital-surveillance";
import { authFetch } from "@/lib/auth-fetch";

const KNOWN_THREAT_KINDS: ReadonlySet<ThreatKind> = new Set<ThreatKind>([
  "ct-impersonation",
  "typosquatting",
  "leak-velocity",
  "phishing-kit",
  "impersonation-confidence",
]);

// ─────────────────────────────────────────────────────────────────────────────
// #1 Histórico de análisis
// ─────────────────────────────────────────────────────────────────────────────

export type AnalysisRow = {
  id: string;
  domain: string;
  queried_at: string;
  operator_ci: string | null;
  risk_score: number;
  risk_band: "low" | "medium" | "high";
  findings_summary: Record<string, number>;
  findings_critical: number;
  findings_high: number;
  findings_total: number;
};

export type AnalysisDiff = {
  ok: true;
  domain: string;
  from: { id: string; queriedAt: string; riskScore: number };
  to:   { id: string; queriedAt: string; riskScore: number };
  delta: {
    riskScore: number;
    findingsCritical: number;
    findingsHigh: number;
    findingsTotal: number;
  };
};

export const analysesKey = (domain: string) => ["surveillance-analyses", domain] as const;

/** Lista los últimos N análisis para un dominio. */
export function useAnalysisHistory(domain: string, limit = 20) {
  return useQuery<AnalysisRow[]>({
    queryKey: [...analysesKey(domain), limit],
    queryFn: async () => {
      const r = await authFetch(
        `/api/surveillance/analyses?domain=${encodeURIComponent(domain)}&limit=${limit}`,
      );
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      return j.analyses ?? [];
    },
    enabled: domain.length > 0,
    staleTime: 60_000,
  });
}

/**
 * Auto-record: cuando el Provider tiene un análisis fresh (data + findings),
 * dispara POST /analyses una sola vez por (domain, queriedAt). Usa una ref
 * para no re-fetch al volver a la página.
 */
export function useAutoRecordAnalysis(args: {
  domain: string;
  data: SurveillanceDomainResult | undefined;
  findings: AnalystFinding[];
  riskScore: number;
  riskBand: "low" | "medium" | "high";
  operatorCi?: string | null;
}) {
  const { domain, data, findings, riskScore, riskBand, operatorCi } = args;
  const lastRecordedKey = useRef<string | null>(null);
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!data?.queriedAt || !domain) return;
    const key = `${domain}|${data.queriedAt}`;
    if (lastRecordedKey.current === key) return;
    lastRecordedKey.current = key;

    const findingsSummary: Record<string, number> = {};
    let critical = 0, high = 0;
    for (const f of findings) {
      const k = `${f.kind}-${f.severity}`;
      findingsSummary[k] = (findingsSummary[k] ?? 0) + 1;
      if (f.severity === "critical") critical += 1;
      if (f.severity === "high")     high += 1;
    }

    // Findings comprimidos para diff temporal (feature #3 — "¿qué cambió?").
    // Truncamos a 500 priorizando severidades altas para evitar JSONB bloat —
    // los low/info pueden quedar fuera; los críticos/highs siempre entran.
    const findingsForSnapshot = compactFindingsForSnapshot(findings, 500);

    const body = {
      domain,
      operatorCi: operatorCi ?? null,
      riskScore,
      riskBand,
      findingsSummary,
      findingsCritical: critical,
      findingsHigh: high,
      findingsTotal: findings.length,
      dataSnapshot: {
        domain,
        queriedAt: data.queriedAt,
        findings: findingsForSnapshot,
      },
      engineVersion: RISK_ENGINE_VERSION,
    };

    void authFetch("/api/surveillance/analyses", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((r) => r.ok ? r.json() : null)
      .then(() => {
        // Invalida la lista de histórico para que se refresque.
        queryClient.invalidateQueries({ queryKey: analysesKey(domain) });
      })
      .catch(() => { /* silencioso — no bloquear UX */ });
  }, [domain, data?.queriedAt, findings, riskScore, riskBand, operatorCi, queryClient]);
}

/**
 * Findings comprimidos para guardar en `dataSnapshot.findings`. Mantiene solo
 * los campos necesarios para diff temporal (id/kind/severity/title/evidence) +
 * trunca a `maxItems` priorizando severidades altas para evitar JSONB bloat.
 */
function compactFindingsForSnapshot(
  findings: AnalystFinding[],
  maxItems: number,
): Array<{
  id: string;
  kind: AnalystFinding["kind"];
  severity: AnalystFinding["severity"];
  title: string;
  evidence: string;
}> {
  const compact = findings.map((f) => ({
    id: f.id,
    kind: f.kind,
    severity: f.severity,
    title: f.title,
    evidence: f.evidence,
  }));
  if (compact.length <= maxItems) return compact;
  const rank: Record<AnalystFinding["severity"], number> = {
    critical: 4, high: 3, medium: 2, low: 1, info: 0,
  };
  return [...compact]
    .sort((a, b) => rank[b.severity] - rank[a.severity])
    .slice(0, maxItems);
}

// ─────────────────────────────────────────────────────────────────────────────
// #3 frontend — Diff temporal "¿qué cambió?"
// Endpoint: GET /api/surveillance/findings/diff?domain=X
// ─────────────────────────────────────────────────────────────────────────────

export type FindingDiffStatus = "new" | "severity-up" | "severity-down" | "unchanged";

export type FindingsDiffResponse =
  | { ok: true; domain: string; hasPrevious: false }
  | {
      ok: true;
      domain: string;
      hasPrevious: true;
      prev: { id: string; queriedAt: string };
      curr: { id: string; queriedAt: string };
      newIds: string[];
      severityUp: Array<{
        id: string;
        prevSeverity: AnalystFinding["severity"];
        currSeverity: AnalystFinding["severity"];
      }>;
      severityDown: Array<{
        id: string;
        prevSeverity: AnalystFinding["severity"];
        currSeverity: AnalystFinding["severity"];
      }>;
      resolved: Array<{
        id: string;
        kind: AnalystFinding["kind"];
        severity: AnalystFinding["severity"];
        title: string;
        evidence: string;
      }>;
    };

export function useFindingsDiff(domain: string) {
  return useQuery<FindingsDiffResponse>({
    queryKey: ["surveillance-findings-diff", domain],
    queryFn: async () => {
      const r = await authFetch(`/api/surveillance/findings/diff?domain=${encodeURIComponent(domain)}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    },
    enabled: domain.length > 0,
    staleTime: 30_000,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// #6 — Correlaciones cross-watchlist (campañas)
// Endpoint: GET /api/surveillance/watchlist/correlations
// ─────────────────────────────────────────────────────────────────────────────

export type WatchlistCampaign = {
  kind: AnalystFinding["kind"];
  evidence: string;
  severity: AnalystFinding["severity"];
  domains: string[];
  domainCount: number;
  findingIds: string[];
  sampleTitle: string | null;
};

export type WatchlistCorrelationsResponse = {
  ok: true;
  totalDomains: number;
  analyzedDomains: number;
  campaigns: WatchlistCampaign[];
};

export function useWatchlistCorrelations() {
  return useQuery<WatchlistCorrelationsResponse>({
    queryKey: ["surveillance", "watchlist", "correlations"],
    queryFn: async () => {
      const r = await authFetch("/api/surveillance/watchlist/correlations");
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    },
    staleTime: 60_000,
  });
}

/** Diff entre 2 análisis específicos. */
export function useAnalysisDiff(fromId: string | null, toId: string | null) {
  return useQuery<AnalysisDiff>({
    queryKey: ["surveillance-analysis-diff", fromId, toId],
    queryFn: async () => {
      const r = await authFetch(`/api/surveillance/analyses/diff?from=${fromId}&to=${toId}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    },
    enabled: !!fromId && !!toId,
    staleTime: 60_000,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// #3 Anotaciones por finding
// ─────────────────────────────────────────────────────────────────────────────

export type AnnotationState = "triaged" | "false-positive" | "resolved";

export type AnnotationRow = {
  id: string;
  finding_id: string;
  domain: string;
  state: AnnotationState;
  note: string | null;
  operator_ci: string;
  operator_label: string | null;
  /** Version OCC. Cada update server-side incrementa +1. */
  version: number;
  created_at: string;
  updated_at: string;
};

/** Error específico de conflict OCC — el cliente puede branchear sobre `kind`. */
export class AnnotationVersionConflict extends Error {
  kind = "annotation-version-conflict" as const;
  currentVersion: number;
  constructor(currentVersion: number) {
    super("version conflict: otro operador editó esta anotación");
    this.currentVersion = currentVersion;
  }
}

export const annotationsKey = (domain: string) =>
  ["surveillance-annotations", domain] as const;

export function useAnnotations(domain: string) {
  return useQuery<AnnotationRow[]>({
    queryKey: annotationsKey(domain),
    queryFn: async () => {
      const r = await authFetch(`/api/surveillance/findings/${encodeURIComponent(domain)}/annotations`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      return j.annotations ?? [];
    },
    enabled: domain.length > 0,
    staleTime: 30_000,
  });
}

export function useUpsertAnnotation() {
  const queryClient = useQueryClient();
  return useMutation<
    AnnotationRow,
    Error,
    {
      findingId: string;
      domain: string;
      state: AnnotationState;
      note?: string | null;
      operatorCi: string;
      operatorLabel?: string | null;
      /** OCC: version esperada (0 si es nuevo). Si no matchea → 412 → throw
       *  AnnotationVersionConflict para que la UI re-fetchee y reintente. */
      expectedVersion?: number;
    }
  >({
    mutationFn: async (input) => {
      const r = await authFetch(
        `/api/surveillance/findings/${encodeURIComponent(input.findingId)}/annotations`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(input),
        },
      );
      if (r.status === 412) {
        const j = await r.json().catch(() => ({}));
        throw new AnnotationVersionConflict(j?.currentVersion ?? 0);
      }
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        throw new Error(j?.error ?? `HTTP ${r.status}`);
      }
      const j = await r.json();
      return j.annotation;
    },
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: annotationsKey(vars.domain) });
    },
  });
}

export function useDeleteAnnotation() {
  const queryClient = useQueryClient();
  return useMutation<void, Error, { findingId: string; domain: string }>({
    mutationFn: async ({ findingId, domain }) => {
      const r = await authFetch(
        `/api/surveillance/findings/${encodeURIComponent(findingId)}/annotations?domain=${encodeURIComponent(domain)}`,
        { method: "DELETE" },
      );
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
    },
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: annotationsKey(vars.domain) });
    },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// #8 Export findings (CSV/JSON/STIX)
// ─────────────────────────────────────────────────────────────────────────────

export type ExportFormat = "json" | "csv" | "stix" | "navigator";

export function useExportFindings() {
  return useMutation<
    void,
    Error,
    {
      domain: string;
      findings: AnalystFinding[];
      format: ExportFormat;
      actorCi?: string | null;
      /** Solo para format="navigator" — conteo de findings por kind. */
      mitreByKind?: Record<string, number>;
      /** Solo para format="navigator" — catálogo MITRE_BY_KIND del cliente. */
      mitreCatalog?: Record<string, unknown>;
    }
  >({
    mutationFn: async (input) => {
      const r = await authFetch("/api/surveillance/findings/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(input),
      });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        throw new Error(j?.error ?? `HTTP ${r.status}`);
      }
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = inferFilename(r.headers.get("content-disposition"))
        ?? `vigilancia-${input.domain}.${input.format === "stix" ? "stix.json" : input.format === "navigator" ? "navigator.json" : input.format}`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 0);
    },
  });
}

function inferFilename(cd: string | null): string | null {
  if (!cd) return null;
  const m = cd.match(/filename="([^"]+)"/);
  return m ? m[1] : null;
}

// ─────────────────────────────────────────────────────────────────────────────
// #9 Audit log (admin)
// ─────────────────────────────────────────────────────────────────────────────

export type AuditEvent = {
  id: string;
  action: string;
  actor_ci: string | null;
  target_domain: string | null;
  target_ref: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
};

export function useAuditLog(opts: {
  actor?: string;
  domain?: string;
  action?: string;
  since?: string;
  until?: string;
  limit?: number;
}) {
  const params = new URLSearchParams();
  if (opts.actor)  params.set("actor", opts.actor);
  if (opts.domain) params.set("domain", opts.domain);
  if (opts.action) params.set("action", opts.action);
  if (opts.since)  params.set("since", opts.since);
  if (opts.until)  params.set("until", opts.until);
  if (opts.limit)  params.set("limit", String(opts.limit));
  const qs = params.toString();

  return useQuery<AuditEvent[]>({
    queryKey: ["surveillance-audit", qs],
    queryFn: async () => {
      const r = await authFetch(`/api/surveillance/audit${qs ? `?${qs}` : ""}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      return j.events ?? [];
    },
    staleTime: 30_000,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Watchlist sync (server-side persistence — feed para el cron de notificaciones
// y fuente de verdad multi-operador)
// ─────────────────────────────────────────────────────────────────────────────

const watchlistKey = ["surveillance", "watchlist"] as const;

/** Shape de una sub que devuelve `GET /api/surveillance/watchlist`. */
type ApiWatchlistSub = {
  id: string;
  domain: string;
  owner_label: string;
  owner_ci: string | null;
  frequency: WatchlistFrequency;
  channel: WatchlistChannel;
  alert_on: string[];
  notes: string | null;
  added_at: string;
  last_notified_at: string | null;
  last_analyzed_at?: string | null;
  notify_email?: string | null;
  webhook_url?: string | null;
  auto_open_severity?: "never" | "medium" | "high" | "critical";
  visibility?: "private" | "shared" | "global";
};

function mapSubToEntry(s: ApiWatchlistSub): WatchlistEntry {
  const alertOn = Array.isArray(s.alert_on)
    ? (s.alert_on.filter((k): k is ThreatKind =>
        KNOWN_THREAT_KINDS.has(k as ThreatKind),
      ))
    : [];
  return {
    domain: s.domain,
    ownerLabel: s.owner_label,
    addedAt: s.added_at,
    frequency: s.frequency,
    channel: s.channel,
    alertOn: alertOn.length > 0 ? alertOn : undefined,
    notes: s.notes ?? undefined,
    notifyEmail: s.notify_email ?? undefined,
    webhookUrl: s.webhook_url ?? undefined,
    autoOpenSeverity: s.auto_open_severity ?? "medium",
    visibility: s.visibility ?? "shared",
  };
}

/**
 * Hidrata el `useWatchlistStore` desde el backend en cada mount (con
 * staleTime de 30s para evitar refetch en navegaciones cortas). El store
 * local sigue funcionando como cache offline si la petición falla.
 *
 * Llamar desde cualquier página que pinte la watchlist. Múltiples llamadas
 * comparten la misma query gracias a react-query.
 */
export function useHydrateWatchlist() {
  const hydrate = useWatchlistStore((s) => s.hydrate);
  const q = useQuery<{ ok: boolean; subs: ApiWatchlistSub[] }>({
    queryKey: watchlistKey,
    queryFn: async () => {
      const r = await authFetch("/api/surveillance/watchlist");
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    },
    staleTime: 30_000,
    retry: 1,
  });

  useEffect(() => {
    if (!q.data?.ok || !Array.isArray(q.data.subs)) return;
    hydrate(q.data.subs.map(mapSubToEntry));
  }, [q.data, hydrate]);

  return q;
}

export function useSyncWatchlist() {
  const qc = useQueryClient();
  return useMutation<
    void,
    Error,
    {
      domain: string;
      ownerLabel: string;
      ownerCi?: string | null;
      frequency: "instant" | "hourly" | "daily" | "weekly";
      channel: "email" | "slack" | "teams" | "sms" | "webhook";
      alertOn?: string[];
      notes?: string | null;
      addedAt: string;
      notifyEmail?: string | null;
      webhookUrl?: string | null;
      autoOpenSeverity?: "never" | "medium" | "high" | "critical";
      visibility?: "private" | "shared" | "global";
    }
  >({
    mutationFn: async (input) => {
      const r = await authFetch("/api/surveillance/watchlist", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(input),
      });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        throw new Error(j?.error ?? `HTTP ${r.status}`);
      }
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: watchlistKey });
    },
  });
}

export function useDeleteWatchlistSub() {
  const qc = useQueryClient();
  return useMutation<void, Error, { domain: string }>({
    mutationFn: async ({ domain }) => {
      const r = await authFetch(
        `/api/surveillance/watchlist?domain=${encodeURIComponent(domain)}`,
        { method: "DELETE" },
      );
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: watchlistKey });
    },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Item 8 — Test alert + notification history (debugging del operador)
// ─────────────────────────────────────────────────────────────────────────────

export type WatchlistTestResult = {
  ok: true;
  domain: string;
  subExists: boolean;
  signals: {
    hasUrgent: boolean;
    score: number;
    summary: string[];
    detectedKinds: string[];
    findingIds: string[];
  };
  decision: {
    wouldSend: boolean;
    reason: string;
    channel: string;
    destination: string;
    previewSubject: string;
    previewBodyShort: string;
  };
};

/**
 * Mutation que dispara una corrida de prueba del análisis para un dominio
 * sin tocar la DB ni enviar notificación real. Devuelve qué se HABRÍA
 * enviado y por qué (o por qué no).
 */
export function useTestWatchlistAlert() {
  return useMutation<WatchlistTestResult, Error, { domain: string }>({
    mutationFn: async ({ domain }) => {
      const r = await authFetch("/api/surveillance/watchlist/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        throw new Error(j?.error ?? `HTTP ${r.status}`);
      }
      return r.json();
    },
  });
}

export type WatchlistLogEntry = {
  id: string;
  channel: string;
  status: "sent" | "skipped" | "failed";
  severity_max: string | null;
  finding_ids: string[];
  detail: string | null;
  sent_at: string;
};

/** Lee notification_log para un dominio. Sirve a la vista "por qué no me llegó alerta". */
export function useWatchlistLog(domain: string, limit = 20) {
  return useQuery<{ ok: true; domain: string; entries: WatchlistLogEntry[] }>({
    queryKey: ["surveillance", "watchlist", "log", domain, limit],
    enabled: Boolean(domain),
    queryFn: async () => {
      const r = await authFetch(
        `/api/surveillance/watchlist/log?domain=${encodeURIComponent(domain)}&limit=${limit}`,
      );
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    },
    staleTime: 30_000,
  });
}
