/**
 * useSocWorkflow.ts
 * Hooks para el flujo de trabajo SOC: cola, notificaciones, handover, auto-acciones.
 */

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";

// ── Types ──────────────────────────────────────────────────────────────────────

export interface SocRole {
  id: string;
  name: string;
  description: string;
  can_adopt: boolean;
  can_escalate_to_l2: boolean;
  can_escalate_to_l3: boolean;
  can_close_fp: boolean;
  can_close_case: boolean;
  can_assign_cases: boolean;
  can_review_kpis: boolean;
  can_post_mortem: boolean;
  can_create_handover: boolean;
  receives_auto_assign: boolean;
  escalation_score_threshold: number | null;
}

export interface SocOperator {
  id: string;
  name: string;
  email: string | null;
  role_id: string;
  role_name: string;
  is_active: boolean;
  is_shift_manager: boolean;
  shift: string;
  cases_adopted: number;
  cases_closed: number;
  fp_count: number;
  avg_mtta_min: number | null;
  avg_mttr_min: number | null;
  last_active_at: string | null;
}

export interface WorkflowQueueItem {
  id: string;
  severity: string;
  status: string;
  lifecycle_stage: string;
  assigned_role: string | null;
  score: number;
  ioc_value: string | null;
  ioc_type: string | null;
  source_log: string | null;
  mitre_tactic_name: string | null;
  mitre_technique_id: string | null;
  operator_id: string | null;
  adopted_at: string | null;
  created_at: string;
  escalation_suggested: boolean;
  escalation_reason_auto: string | null;
  shift_manager_assigned_at: string | null;
  shift_manager_ci: string | null;
  elapsed_min: number;
  sla_min: number;
  sla_pct_consumed: number;
  unacknowledged_min: number | null;
}

export interface SocNotification {
  id: string;
  operator_id: string;
  case_id: string | null;
  type: string;
  priority: "LOW" | "NORMAL" | "HIGH" | "CRITICAL";
  title: string;
  body: string | null;
  action_url: string | null;
  read_at: string | null;
  created_at: string;
}

export interface AutoAction {
  id: string;
  case_id: string;
  action_type: string;
  performed_at: string;
  target_operator: string | null;
  before_status: string | null;
  after_status: string | null;
  reason: string | null;
  details: Record<string, unknown>;
  severity: string;
  ioc_value: string | null;
}

export interface HandoverReport {
  id: string;
  outgoing_manager_ci: string;
  incoming_manager_ci: string | null;
  shift: string;
  open_cases_count: number;
  critical_open_count: number;
  pending_escalation: number;
  sla_breached_count: number;
  cases_closed_shift: number;
  cases_opened_shift: number;
  mtta_shift_min: number | null;
  mttr_shift_min: number | null;
  notes: string | null;
  pending_actions: string | null;
  critical_case_ids: string[];
  created_at: string;
  acknowledged_at: string | null;
}

export interface WorkflowHealth {
  scheduler: Array<{ name: string; running: boolean }>;
  shiftManager: SocOperator | null;
  pendingAutoClose: number;
  pendingAutoAssign: number;
  autoActionsLastHour: number;
}

// ── Query keys ─────────────────────────────────────────────────────────────────

const K = {
  roles:        ["workflow", "roles"],
  operators:    ["workflow", "operators"],
  queue:        ["workflow", "queue"],
  queueL1:      ["workflow", "queue", "l1"],
  queueL2:      ["workflow", "queue", "l2"],
  queueL3:      ["workflow", "queue", "l3"],
  notifs:       (ci: string) => ["workflow", "notifications", ci],
  autoActions:  ["workflow", "auto-actions"],
  handover:     ["workflow", "handover"],
  handoverLatest: ["workflow", "handover", "latest"],
  health:       ["workflow", "health"],
  shiftMgr:     ["workflow", "shift-manager"],
  candidates:   ["workflow", "automation", "candidates"],
};

const STALE_15 = { staleTime: 15_000 };
const STALE_30 = { staleTime: 30_000 };
const STALE_2M = { staleTime: 2 * 60_000 };
const STALE_5M = { staleTime: 5 * 60_000 };

// ── Hooks ──────────────────────────────────────────────────────────────────────

export function useWorkflowHealth() {
  return useQuery<WorkflowHealth>({
    queryKey: K.health,
    queryFn: async () => { const { data } = await api.get("/api/workflow/health"); return data; },
    ...STALE_15,
    refetchInterval: 30_000,
  });
}

export function useSocRoles() {
  return useQuery<SocRole[]>({
    queryKey: K.roles,
    queryFn: async () => { const { data } = await api.get("/api/workflow/roles"); return data; },
    ...STALE_5M,
    refetchOnWindowFocus: true,
  });
}

export function useSocOperators() {
  return useQuery<SocOperator[]>({
    queryKey: K.operators,
    queryFn: async () => { const { data } = await api.get("/api/workflow/operators"); return data; },
    // Operadores cambian 1-2 veces por shift; 2m es suficiente y
    // reduce carga sobre /api/workflow/operators (join contra KPIs).
    ...STALE_2M,
    refetchInterval: 5 * 60_000,
    refetchOnWindowFocus: false,
  });
}

export function useShiftManager() {
  return useQuery<SocOperator | null>({
    queryKey: K.shiftMgr,
    queryFn: async () => {
      const { data } = await api.get("/api/workflow/operators/shift-manager/current");
      return data?.id ? data : null;
    },
    // El shift manager dura ~8h — refetch cada 5 min sobra.
    ...STALE_5M,
    refetchInterval: 10 * 60_000,
  });
}

export function useWorkflowQueue(limit = 50) {
  return useQuery<{ items: WorkflowQueueItem[]; total: number }>({
    queryKey: [...K.queue, limit],
    queryFn: async () => { const { data } = await api.get(`/api/workflow/queue?limit=${limit}`); return data; },
    ...STALE_15,
    refetchInterval: 30_000,
  });
}

export function useWorkflowQueueL1() {
  return useQuery<WorkflowQueueItem[]>({
    queryKey: K.queueL1,
    queryFn: async () => { const { data } = await api.get("/api/workflow/queue/l1"); return data; },
    ...STALE_15,
    refetchInterval: 30_000,
  });
}

export function useWorkflowQueueL2() {
  return useQuery<WorkflowQueueItem[]>({
    queryKey: K.queueL2,
    queryFn: async () => { const { data } = await api.get("/api/workflow/queue/l2"); return data; },
    ...STALE_15,
    refetchInterval: 30_000,
  });
}

export function useWorkflowQueueL3() {
  return useQuery<WorkflowQueueItem[]>({
    queryKey: K.queueL3,
    queryFn: async () => { const { data } = await api.get("/api/workflow/queue/l3"); return data; },
    ...STALE_15,
    refetchInterval: 30_000,
  });
}

export function useSocNotifications(operatorCi: string, unreadOnly = false) {
  return useQuery<{ notifications: SocNotification[]; unreadCount: number }>({
    queryKey: [...K.notifs(operatorCi), unreadOnly],
    queryFn: async () => {
      const { data } = await api.get(
        `/api/workflow/notifications/${operatorCi}?unread=${unreadOnly}`
      );
      return data;
    },
    enabled: !!operatorCi,
    ...STALE_15,
    refetchInterval: 20_000,
  });
}

export function useMarkNotificationRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await api.patch(`/api/workflow/notifications/${id}/read`);
    },
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["workflow", "notifications"] }); },
  });
}

export function useMarkAllRead(operatorCi: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      await api.patch(`/api/workflow/notifications/${operatorCi}/read-all`);
    },
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["workflow", "notifications"] }); },
  });
}

export function useAutoActions(limit = 50) {
  return useQuery<AutoAction[]>({
    queryKey: [...K.autoActions, limit],
    queryFn: async () => { const { data } = await api.get(`/api/workflow/automation/auto-actions?limit=${limit}`); return data; },
    ...STALE_30,
    refetchInterval: 60_000,
  });
}

export function useAutomationCandidates() {
  return useQuery<{ autoCloseCandidates: WorkflowQueueItem[]; timeoutCases: WorkflowQueueItem[] }>({
    queryKey: K.candidates,
    queryFn: async () => { const { data } = await api.get("/api/workflow/automation/candidates"); return data; },
    ...STALE_15,
    refetchInterval: 30_000,
  });
}

export function useLatestHandover() {
  return useQuery<HandoverReport | null>({
    queryKey: K.handoverLatest,
    queryFn: async () => { const { data } = await api.get("/api/workflow/handover/latest"); return data; },
    ...STALE_30,
  });
}

export function useHandoverList(limit = 10) {
  return useQuery<HandoverReport[]>({
    queryKey: [...K.handover, limit],
    queryFn: async () => { const { data } = await api.get(`/api/workflow/handover?limit=${limit}`); return data; },
    ...STALE_30,
  });
}

export function useCaseTransitions(caseId: string, operatorCi: string) {
  return useQuery<{ fromStatus: string; allowed: string[]; role: string }>({
    queryKey: ["workflow", "transitions", caseId, operatorCi],
    queryFn: async () => {
      const { data } = await api.get(`/api/workflow/cases/${caseId}/transitions?operatorCi=${operatorCi}`);
      return data;
    },
    enabled: !!caseId && !!operatorCi,
    ...STALE_15,
  });
}

export function useTransitionCase() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      caseId, toStatus, operatorCi, reason,
    }: { caseId: string; toStatus: string; operatorCi: string; reason?: string }) => {
      const { data } = await api.post(`/api/workflow/cases/${caseId}/transition`, {
        toStatus, operatorCi, reason,
      });
      return data;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["incidents"] });
      void qc.invalidateQueries({ queryKey: ["workflow", "queue"] });
    },
  });
}

export function useTriggerAutoClose(operatorCi: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post("/api/workflow/automation/trigger-auto-close", {}, {
        headers: { "x-operator-ci": operatorCi },
      });
      return data;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["workflow"] });
      void qc.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
}

export function useTriggerAutoAssign(operatorCi: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post("/api/workflow/automation/trigger-auto-assign", {}, {
        headers: { "x-operator-ci": operatorCi },
      });
      return data;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["workflow"] });
      void qc.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
}

export function useRegisterOperator() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (op: {
      id: string; name: string; email?: string; roleId?: string; shift?: string;
    }) => {
      const { data } = await api.post("/api/workflow/operators/register", op);
      return data;
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: K.operators }),
  });
}

// ── Hooks de gestión administrativa ───────────────────────────────────────────

export function useUpdateOperator(operatorCi: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id, name, email, shift, notes,
    }: { id: string; name?: string; email?: string; shift?: string; notes?: string }) => {
      const { data } = await api.patch(`/api/workflow/operators/${id}`, { name, email, shift, notes }, {
        headers: { "x-operator-ci": operatorCi },
      });
      return data;
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: K.operators }),
  });
}

export function useSetOperatorStatus(operatorCi: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, isActive }: { id: string; isActive: boolean }) => {
      const { data } = await api.patch(`/api/workflow/operators/${id}/status`, { isActive }, {
        headers: { "x-operator-ci": operatorCi },
      });
      return data;
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: K.operators }),
  });
}

export function useDeleteOperator(operatorCi: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await api.delete(`/api/workflow/operators/${id}`, {
        headers: { "x-operator-ci": operatorCi },
      });
      return data;
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: K.operators }),
  });
}

export function useChangeOperatorRole(operatorCi: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, roleId }: { id: string; roleId: string }) => {
      const { data } = await api.patch(`/api/workflow/operators/${id}/role`, { roleId }, {
        headers: { "x-operator-ci": operatorCi },
      });
      return data;
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: K.operators }),
  });
}

export function useSetShiftManager(operatorCi: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { data } = await api.patch(`/api/workflow/operators/${id}/shift-manager`, {}, {
        headers: { "x-operator-ci": operatorCi },
      });
      return data;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: K.operators });
      void qc.invalidateQueries({ queryKey: K.shiftMgr });
    },
  });
}

// ── Gestión de contraseña Keycloak ────────────────────────────────────────────

export interface KcStatus {
  kcAvailable: boolean;
  kcUser: { id: string; username: string; enabled: boolean; email: string | null } | null;
  error?: string;
}

export function useKcStatus(operatorId: string | null, operatorCi: string) {
  return useQuery({
    queryKey: ["kc-status", operatorId],
    queryFn: async (): Promise<KcStatus> => {
      const { data } = await api.get<KcStatus>(
        `/api/workflow/operators/${operatorId}/kc-status`,
        { headers: { "x-operator-ci": operatorCi } },
      );
      return data;
    },
    enabled: !!operatorId,
    staleTime: 30_000,
    retry: false,
  });
}

export function useSetOperatorPassword(operatorCi: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id, password, temporary,
    }: { id: string; password: string; temporary?: boolean }) => {
      const { data } = await api.post(
        `/api/workflow/operators/${id}/set-password`,
        { password, temporary: temporary ?? false },
        { headers: { "x-operator-ci": operatorCi } },
      );
      return data as { ok: boolean; created: boolean; temporary: boolean; kcUserId: string; message: string };
    },
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({ queryKey: ["kc-status", vars.id] });
    },
  });
}

export function useCreateHandover(operatorCi: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (payload: {
      outgoingManagerCi: string;
      incomingManagerCi?: string;
      shift: string;
      notes?: string;
      pendingActions?: string;
    }) => {
      const { data } = await api.post("/api/workflow/handover", payload, {
        headers: { "x-operator-ci": operatorCi },
      });
      return data;
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: K.handover }),
  });
}
