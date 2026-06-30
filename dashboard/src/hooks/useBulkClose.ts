/**
 * useBulkClose — hooks del Asistente de cierre masivo (sólo Shift Manager activo).
 *
 * Endpoints dedicados (NO reusa /api/incidents/open):
 *   POST /api/incidents/bulk-close/preview  (dry-run + confirmToken)
 *   POST /api/incidents/bulk-close          (ejecuta el set tokenizado)
 */
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { useShiftManager } from "./useSocWorkflow";

export interface BulkCloseCriteria {
  mitreTacticId?: string | null;
  mitreTechniqueId?: string | null;
  netClass?: "internal" | "public" | null;
  firewallAction?: "blocked" | "allowed" | "none" | null;
  techClass?: "recon" | "threat" | "other" | null;
  severityIn?: string[];
  statusIn?: string[];
  iocType?: string | null;
  iocPattern?: string;
  sourceLog?: string;
  matchTrustedOrigins?: boolean;
  maxAgeDays?: number;
  includeHighSeverity?: boolean;
  limit?: number;
}

export interface BulkClosePreviewSample {
  id: string;
  ioc_value: string | null;
  ioc_type: string | null;
  severity: string;
  status: string;
  mitre_tactic_id: string | null;
  mitre_technique_id?: string | null;
  firewall_action?: string | null;
  source_log: string | null;
  score: number | null;
  confidence?: number;
  veto?: string | null;
}

export type ClusterAction = "close_and_suppress" | "close_and_watchlist" | "manual_review" | "review";

export interface BulkCluster {
  key: string;
  label: string;
  netclass: "internal" | "public" | "other";
  fwClass: "blocked" | "allowed" | "none";
  techClass: "recon" | "threat" | "other";
  count: number;
  sampledCount?: number;
  vetoed: number;
  avgConfidence: number | null;
  action: ClusterAction;
  caseIds: string[];
  sampleIds: string[];
}

export type BulkAction = "close" | "watchlist" | "close_and_watchlist";

export interface BulkRecommendation {
  action: BulkAction;
  closeStatus: "FALSO_POSITIVO" | "CERRADO";
  classification: string;
  rationale: string;
}

export interface BulkClosePreview {
  ok: boolean;
  matchCount: number;
  matchCountTotal?: number;
  cappedAt: number;
  capped: boolean;
  bySeverity: Record<string, number>;
  byStatus: Record<string, number>;
  blocked: { highSeverity: number };
  recommendation?: BulkRecommendation;
  clusters?: BulkCluster[];
  sample: BulkClosePreviewSample[];
  caseIds: string[];
  confirmToken: string;
  expiresAt: string;
}

export interface BulkCloseClosure {
  status: "FALSO_POSITIVO" | "CERRADO";
  classification: string;
  reason: string;
  createSuppressions: boolean;
  suppressionDays: number;
  includeHighSeverity: boolean;
  smartSuppressions?: boolean;  // M4: TTL cluster-aware (default true)
  forceVetoed?: boolean;        // M2: forzar casos vetados (amenaza/CRITICAL)
}

export interface BulkCloseResult {
  ok: boolean;
  opId?: string | null;
  closed: number;
  skipped: number;
  suppressionsCreated: number;
  suppressionsSkippedPublic?: number;
  errors: Array<{ caseId: string; error: string }>;
  detail?: { skipped: Array<{ caseId: string; reason: string }> };
}

export interface BulkDrainResult {
  ok: boolean;
  opId?: string | null;
  closed: number;
  iterations: number;
  reachedCap: boolean;
  skipped: number;
  errors: number;
  suppressionsCreated: number;
  suppressionsSkippedPublic: number;
}

export interface BulkUndoResult {
  ok: boolean;
  opId: string;
  reopened: number;
  suppressionsExpired: number;
  skipped: number;
}

export interface BulkDigestCluster {
  id: string;
  label: string;
  action: ClusterAction;
  count: number;
  criteria: BulkCloseCriteria;
}
export interface BulkDigest {
  ok: boolean;
  generatedAt: string;
  totalCandidates: number;
  clusters: BulkDigestCluster[];
}

export function useBulkClosePreview() {
  return useMutation<BulkClosePreview, unknown, BulkCloseCriteria>({
    mutationFn: async (criteria) =>
      (await api.post<BulkClosePreview>("/api/incidents/bulk-close/preview", { criteria })).data,
  });
}

export function useBulkCloseExecute() {
  return useMutation<
    BulkCloseResult,
    unknown,
    { confirmToken: string; caseIds: string[]; closure: BulkCloseClosure }
  >({
    mutationFn: async (body) =>
      (await api.post<BulkCloseResult>("/api/incidents/bulk-close", body)).data,
  });
}

export interface BulkWatchlistResult {
  ok: boolean;
  added: number;
  uniqueIps: number;
  skipped: number;
  errors: Array<{ ip: string; error: string; code?: string }>;
  addedIps: string[];
}

export function useBulkWatchlistExecute() {
  return useMutation<
    BulkWatchlistResult,
    unknown,
    { confirmToken: string; caseIds: string[]; watchlist: { days: number; reason: string } }
  >({
    mutationFn: async (body) =>
      (await api.post<BulkWatchlistResult>("/api/incidents/bulk-watchlist", body)).data,
  });
}

/** M5 — vacía un cluster completo (criterios, no caseIds). */
export function useBulkCloseDrain() {
  return useMutation<
    BulkDrainResult, unknown,
    { criteria: BulkCloseCriteria; closure: BulkCloseClosure; maxTotal?: number }
  >({
    mutationFn: async (body) =>
      (await api.post<BulkDrainResult>("/api/incidents/bulk-close/drain", body)).data,
  });
}

/** M3 — deshace una operación de cierre masivo (reabre + expira supresiones). */
export function useBulkCloseUndo() {
  return useMutation<BulkUndoResult, unknown, { opId: string }>({
    mutationFn: async ({ opId }) =>
      (await api.post<BulkUndoResult>(`/api/incidents/bulk-close/undo/${opId}`, {})).data,
  });
}

/** M6 — digest de candidatos de alta confianza (dry-run, siempre on). */
export function useBulkCloseDigest(enabled: boolean) {
  return useQuery<BulkDigest>({
    queryKey: ["bulk-close-digest"],
    enabled,
    queryFn: async () => (await api.get<BulkDigest>("/api/incidents/bulk-close/candidates-digest")).data,
    staleTime: 60_000,
  });
}

export interface TriageBucket {
  id: string;
  label: string;
  hint: string;
  action: ClusterAction;
  closable: boolean;
  count: number;
  criteria: BulkCloseCriteria;
}
export interface TriageResult {
  ok: boolean;
  generatedAt: string;
  total: number;
  maxAgeDays: number;
  buckets: TriageBucket[];
}

/** T1 — triage del backlog completo en disposiciones (dry-run). */
export function useBulkCloseTriage(enabled: boolean) {
  return useQuery<TriageResult>({
    queryKey: ["bulk-close-triage"],
    enabled,
    queryFn: async () => (await api.get<TriageResult>("/api/incidents/bulk-close/triage")).data,
    staleTime: 30_000,
  });
}

/** True sólo si el operador conectado ES el Shift Manager activo designado. */
export function useIsActiveShiftManager(operatorCi: string | null | undefined): boolean {
  const { data: sm } = useShiftManager();
  return !!operatorCi && !!sm?.id && sm.id === operatorCi;
}
