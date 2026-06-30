/**
 * useCaseInvestigation.ts
 * Hooks for DFIR-IRIS inspired case investigation.
 * All data from /api/cases/* (PostgreSQL backed).
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import { normalizeFullCase, normalizeTraceability } from "./case-normalize";

// ── Types ──────────────────────────────────────────────────────────────────────

export type TaskPhase   = "DETECTION" | "CONTAINMENT" | "ERADICATION" | "RECOVERY" | "POST_INCIDENT";
export type TaskStatus  = "OPEN" | "IN_PROGRESS" | "DONE" | "SKIPPED";
export type AssetType   = "HOST" | "USER" | "ACCOUNT" | "ENDPOINT" | "NETWORK" | "OTHER";
export type EvidenceType = "LOG" | "PCAP" | "SCREENSHOT" | "DUMP" | "ARTIFACT" | "OTHER";
export type TlpLevel    = "WHITE" | "GREEN" | "AMBER" | "RED";

export interface CaseTask {
  id:          string;
  case_id:     string;
  title:       string;
  description: string | null;
  phase:       TaskPhase;
  status:      TaskStatus;
  assignee:    string | null;
  due_at:      string | null;
  completed_at: string | null;
  sort_order:  number;
  created_by:  string | null;
  created_at:  string;
}

export interface CaseAsset {
  id:                 string;
  case_id:            string;
  asset_type:         AssetType;
  asset_value:        string;
  hostname:           string | null;
  ip_address:         string | null;
  domain:             string | null;
  os:                 string | null;
  description:        string | null;
  compromised:        boolean;
  containment_status: string | null;
  enrichment_data:    Record<string, unknown>;
  added_by:           string | null;
  created_at:         string;
}

export interface CaseIoc {
  id:           string;
  case_id:      string;
  ioc_type:     string;
  ioc_value:    string;
  tlp:          TlpLevel;
  description:  string | null;
  tags:         string[];
  is_primary:   boolean;
  vt_malicious: number | null;
  vt_permalink: string | null;
  abuse_score:  number | null;
  in_misp:      boolean | null;
  shodan_summary: string | null;
  enriched_at:  string | null;
  added_by:     string | null;
  created_at:   string;
}

export interface CaseEvidence {
  id:             string;
  case_id:        string;
  evidence_type:  EvidenceType;
  name:           string;
  description:    string | null;
  collected_by:   string;
  collected_at:   string;
  hash_sha256:    string | null;
  size_bytes:     number | null;
  storage_path:   string | null;
  tags:           string[];
  created_at:     string;
}

export interface TimelineEvent {
  id:               string;
  event_ts:         string;
  event_type:       string;
  phase:            string | null;
  title:            string | null;
  description:      string | null;
  operator_ci:      string | null;
  source:           string;
  metadata:         Record<string, unknown>;
  related_asset:    string | null;
  related_ioc:      string | null;
  related_evidence: string | null;
}

export interface CaseTemplate {
  id:                  string;
  name:                string;
  description:         string | null;
  trigger_categories:  string[];
  trigger_severities:  string[];
  mitre_tactics:       string[];
  default_tags:        string[];
  tasks_template:      Array<{ title: string; description?: string; phase: TaskPhase }>;
  is_builtin:          boolean;
  created_by:          string | null;
  created_at:          string;
}

export interface FullCase {
  id:                  string;
  severity:            string;
  status:              string;
  score:               number;
  operator_id:         string | null;
  adopted_at:          string | null;
  created_at:          string;
  updated_at:          string;
  ioc_value:           string | null;
  ioc_type:            string | null;
  source_log:          string | null;
  mitre_tactic_id:     string | null;
  mitre_tactic_name:   string | null;
  mitre_technique_id:  string | null;
  escalation_level:    string | null;
  escalated_to:        string | null;
  escalated_at:        string | null;
  escalation_reason:   string | null;
  template_id:         string | null;
  /** Plantilla recomendada por táctica MITRE (la marca el selector de Tareas). */
  recommended_template_id: string | null;
  incident_category:   string | null;
  functional_impact:   string | null;
  information_impact:  string | null;
  recoverability:      string | null;
  root_cause:          string | null;
  lessons_learned:     string | null;
  containment_status:  string | null;
  recommended_action:  string | null;
  slack_notified_at:   string | null;
  /** Recurrencia/dedup: nº de veces visto y última aparición (barra de decisión). */
  occurrence_count?:   number | null;
  last_seen?:          string | null;
  enrichment_data:     Record<string, unknown>;
  /** Clasificación eCSIRT/MISP derivada (backend). */
  incidentClass?:      import("./types").IncidentClass | null;
  tasks:               CaseTask[];
  assets:              CaseAsset[];
  iocs:                CaseIoc[];
  evidences:           CaseEvidence[];
  timeline:            TimelineEvent[];
}

export interface StatusDistRow {
  status:   string;
  severity: string;
  cnt:      string | number;
}

// ── Hooks ──────────────────────────────────────────────────────────────────────

const STALE_30 = { staleTime: 30_000, gcTime: 5 * 60_000 } as const;

export function useFullCase(caseId: string | null) {
  return useQuery<FullCase>({
    queryKey: ["case-investigation", caseId],
    queryFn: async () => {
      const { data } = await api.get<FullCase>(`/api/cases/${caseId!}`);
      return normalizeFullCase(data);
    },
    enabled: !!caseId,
    ...STALE_30,
  });
}

export function useTemplates() {
  return useQuery<CaseTemplate[]>({
    queryKey: ["case-templates"],
    queryFn: async () => {
      const { data } = await api.get<CaseTemplate[]>("/api/cases/templates/all");
      return data;
    },
    staleTime: 5 * 60_000,
    gcTime:    10 * 60_000,
  });
}

export function useSuggestedTemplates(severity: string, category?: string) {
  return useQuery<CaseTemplate[]>({
    queryKey: ["case-templates-suggest", severity, category],
    queryFn: async () => {
      const p = new URLSearchParams({ severity });
      if (category) p.set("category", category);
      const { data } = await api.get<CaseTemplate[]>(`/api/cases/templates/suggest?${p}`);
      return data;
    },
    enabled: !!severity,
    staleTime: 5 * 60_000,
  });
}

export function useStatusDist() {
  return useQuery<StatusDistRow[]>({
    queryKey: ["case-status-dist"],
    queryFn: async () => {
      const { data } = await api.get<StatusDistRow[]>("/api/cases/status-dist");
      return data;
    },
    // Donut de distribución por estado — el operador lo usa como radar
    // general, no necesita tick por segundo. Socket.IO invalida cuando
    // hay cambio relevante.
    staleTime:       2 * 60_000,
    refetchInterval: 5 * 60_000,
    refetchOnWindowFocus: false,
  });
}

// ── Supresión por caso ────────────────────────────────────────────────────────

export type SuppressionReason = "FALSO_POSITIVO" | "CERRADO" | "AUTO_CLOSED" | "OPERATOR";

export interface CaseSuppressionRow {
  dedup_key:         string;
  reason:            SuppressionReason;
  severity:          string | null;
  suppressed_until:  string;
  suppressed_by:     string;
  minutes_remaining: number | null;
  window_days:       number | null;
  original_case_id:  string | null;
  original_ioc:      string | null;
  created_at:        string;
  updated_at:        string;
  active:            boolean;
}

export interface CaseSuppressionResponse {
  case_id:   string;
  dedup_key: string | null;
  severity:  string | null;
  status:    string | null;
  ioc_value: string | null;
  suppression: CaseSuppressionRow | null;
  expected_ttl_days: {
    fp_days:          number | null;
    closed_days:      number | null;
    auto_closed_days: number | null;
  };
  /**
   * Lista de objetos PG no presentes en este entorno (ej: `incident_cases_pg.dedup_key`,
   * `legacyhunt_soc.case_suppressions`, `legacyhunt_soc.suppression_days`). Si está
   * presente, la supresión está parcialmente o totalmente desactivada hasta aplicar
   * las migrations correspondientes.
   */
  infra_missing: string[] | null;
}

export function useCaseSuppression(caseId: string | null) {
  return useQuery<CaseSuppressionResponse>({
    queryKey: ["case-suppression", caseId],
    queryFn: async () => {
      const { data } = await api.get<CaseSuppressionResponse>(`/api/cases/${caseId!}/suppression`);
      return data;
    },
    enabled: !!caseId,
    // Tick del countdown — 1 min es suficiente; la ventana es de días.
    refetchInterval: 60_000,
    staleTime: 30_000,
  });
}

// ── Fase 2: raw event / trazabilidad / narrative ──────────────────────────────

export interface RawEventResponse {
  table:       string;
  kind:        "hive-json" | "iceberg-row";
  found:       boolean;
  matched_on?: string;
  queried_at:  string;
  event?:      Record<string, unknown>;
  query_window?: { center_ts: string; days: string };
}

export interface TraceabilityRow {
  src_table:   string;
  ts:          string | null;
  host:        string | null;
  src_ip:      string | null;
  dst_ip:      string | null;
  msg_preview: string | null;
}

export interface TraceabilityResponse {
  ioc:        string;
  hours:      number;
  window:     { from: string; to: string };
  count:      number;
  events:     TraceabilityRow[];
  queried_at: string;
}

export interface CaseEventRow {
  ts:          string | null;
  src_table:   string | null;
  host:        string | null;
  src_ip:      string | null;
  dst_ip:      string | null;
  lvl:         number | null;
  severity:    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NEGLIGIBLE" | null;
  rule_id:     string | null;
  rule_desc:   string | null;
  msg_preview: string | null;
}

export interface CaseEventsResponse {
  ok:         true;
  ioc:        string;
  source:     string;
  kind:       string;
  hours:      number;
  window:     { from: string; to: string };
  count:      number;
  hasMore:    boolean;
  offset:     number;
  limit:      number;
  severity:   string | null;
  events:     CaseEventRow[];
  queried_at: string;
}

export interface NarrativeResponse {
  enabled:       boolean;
  cached?:       boolean;
  reason?:       string;
  headline?:     string;
  reasons?:      string[];
  generated_at?: string;
  model?:        string;
  error?:        string;
}

/** Raw event desde Iceberg/Hive. El caso no cambia dentro de su ciclo de
 *  vida — cacheamos agresivamente para que re-abrir el mismo caso no
 *  re-query Trino. Desactivable vía fetch=false para no gatillar en
 *  contextos donde el panel no se muestra. */
export function useCaseRawEvent(caseId: string | null, fetch: boolean = true) {
  return useQuery<RawEventResponse>({
    queryKey: ["case-raw-event", caseId],
    queryFn: async () => {
      const { data } = await api.get<RawEventResponse>(`/api/incidents/${caseId!}/raw_event`);
      return data;
    },
    enabled: !!caseId && fetch,
    staleTime: 10 * 60_000, // 10 min — casos suelen vivir horas
    gcTime:    60 * 60_000, // 1 h en memoria
    refetchOnMount: false,  // re-montar el panel no debe re-query
    refetchOnWindowFocus: false,
    retry: 0,
  });
}

/** Trazabilidad 24 h. Opt-in: sólo se dispara al hacer click en el botón. */
export function useCaseTraceability(caseId: string | null, fetch: boolean) {
  return useQuery<TraceabilityResponse>({
    queryKey: ["case-traceability", caseId],
    queryFn: async () => {
      const { data } = await api.get<TraceabilityResponse>(`/api/incidents/${caseId!}/traceability?hours=24`);
      return normalizeTraceability(data);
    },
    enabled: !!caseId && fetch,
    staleTime: 5 * 60_000,  // 5 min — ventana deslizante, pero pocos casos requieren refresco inmediato
    gcTime:    30 * 60_000,
    refetchOnMount: false,
    refetchOnWindowFocus: false,
    retry: 0,
  });
}

/** Eventos paginados de la fuente del caso. Util cuando el snapshot Hunt
 *  Pivots reportó N alertas (5,959) y el operador quiere recorrerlas — el
 *  endpoint pagina dentro de UNA fuente (la del caso), cap 500/página.
 *
 *  Cache por combinación (caseId, hours, severity, offset, limit). React
 *  Query auto-deduplica entre tabs/refetches. `keepPreviousData` evita
 *  flicker al cambiar de página. */
export function useCaseEvents(
  caseId: string | null,
  opts: { hours?: number; limit?: number; offset?: number; severity?: string | null; enabled?: boolean },
) {
  const hours    = opts.hours    ?? 24;
  const limit    = opts.limit    ?? 50;
  const offset   = opts.offset   ?? 0;
  const severity = opts.severity ?? null;
  const enabled  = opts.enabled  ?? true;
  return useQuery<CaseEventsResponse>({
    queryKey: ["case-events", caseId, hours, limit, offset, severity],
    queryFn: async () => {
      const params = new URLSearchParams({ hours: String(hours), limit: String(limit), offset: String(offset) });
      if (severity) params.set("severity", severity);
      const { data } = await api.get<CaseEventsResponse>(`/api/incidents/${caseId!}/events?${params}`);
      return data;
    },
    enabled: !!caseId && enabled,
    staleTime: 60_000,       // 1 min — ventana corre lento, basta refetch ocasional
    gcTime:    10 * 60_000,
    placeholderData: (prev) => prev,
    refetchOnWindowFocus: false,
    retry: 0,
  });
}

/** Narrativa LLM. Opt-in. Si el LLM está deshabilitado responde
 *  { enabled:false } sin error. Cache muy agresivo porque el LLM es caro
 *  y el backend ya persiste en enrichment_data.narrative (TTL 24 h). */
export function useCaseNarrative(caseId: string | null, fetch: boolean = true) {
  return useQuery<NarrativeResponse>({
    queryKey: ["case-narrative", caseId],
    queryFn: async () => {
      const { data } = await api.get<NarrativeResponse>(`/api/incidents/${caseId!}/narrative`);
      return data;
    },
    enabled: !!caseId && fetch,
    staleTime: 30 * 60_000,  // 30 min — LLM caro; backend cachea 24h en PG
    gcTime:    60 * 60_000,
    refetchOnMount: false,
    refetchOnWindowFocus: false,
    retry: 0,
  });
}

// ── Mutations ─────────────────────────────────────────────────────────────────

export function useApplyTemplate(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ templateId, operatorCi }: { templateId: string; operatorCi?: string }) => {
      const { data } = await api.post(`/api/cases/${caseId}/apply-template`, { templateId, operatorCi });
      return data as { ok: boolean; templateName: string; tasksCreated: number };
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["case-investigation", caseId] });
    },
  });
}

export function useAddTask(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (task: { title: string; description?: string; phase: TaskPhase; operatorCi?: string }) => {
      const { data } = await api.post(`/api/cases/${caseId}/tasks`, task);
      return data as { id: string };
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["case-investigation", caseId] }),
  });
}

export function useUpdateTask(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ taskId, ...update }: { taskId: string; status?: TaskStatus; assignee?: string; operatorCi?: string }) => {
      const { data } = await api.patch(`/api/cases/${caseId}/tasks/${taskId}`, update);
      return data;
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["case-investigation", caseId] }),
  });
}

export function useAddAsset(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (asset: { assetType?: AssetType; assetValue: string; hostname?: string; ipAddress?: string; domain?: string; description?: string; compromised?: boolean; addedBy?: string }) => {
      const { data } = await api.post(`/api/cases/${caseId}/assets`, asset);
      return data as { id: string };
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["case-investigation", caseId] }),
  });
}

export function useAddIoc(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (ioc: { iocType: string; iocValue: string; tlp?: TlpLevel; description?: string; isPrimary?: boolean; addedBy?: string }) => {
      const { data } = await api.post(`/api/cases/${caseId}/iocs`, ioc);
      return data as { id: string };
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["case-investigation", caseId] }),
  });
}

export function useAddEvidence(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (ev: { evidenceType?: EvidenceType; name: string; description?: string; collectedBy: string; hashSha256?: string; sizeBytes?: number; storagePath?: string }) => {
      const { data } = await api.post(`/api/cases/${caseId}/evidences`, ev);
      return data as { id: string };
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["case-investigation", caseId] }),
  });
}

export function useAddTimelineEvent(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (ev: { eventType?: string; phase?: string; title?: string; description?: string; operatorCi?: string }) => {
      const { data } = await api.post(`/api/cases/${caseId}/timeline`, ev);
      return data as { id: string };
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["case-investigation", caseId] }),
  });
}

export function useUpdateCaseMeta(caseId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (meta: Record<string, unknown>) => {
      const { data } = await api.patch(`/api/cases/${caseId}`, meta);
      return data;
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["case-investigation", caseId] }),
  });
}
