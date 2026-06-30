/**
 * useCaseManagement.ts
 * Hook de datos para el módulo de Gestión de Casos SOC.
 * Conecta con /api/incidents/* (Trino/Iceberg backend) via TanStack Query v5.
 */

import { useEffect, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import debounce from "lodash/debounce";
import { toast } from "sonner";
import { api } from "@/api/client";
import { socket } from "@/lib/socket";
import type { SocCase, DashboardKpis, CaseStatus, Severity, CaseClassification } from "./types";
import { toNumberArray } from "./case-normalize";

/** Extrae el mensaje legible de un error API. Prioriza body.error → body.message
 *  → .message (Error) → string fallback. Soporta tanto AxiosError como Error
 *  genérico. */
export function extractApiErrorMessage(err: unknown): string {
  if (isAxiosError(err)) {
    const data = err.response?.data as { error?: string; message?: string } | undefined;
    return data?.error ?? data?.message ?? err.message ?? "Error desconocido";
  }
  if (err instanceof Error) return err.message;
  return String(err);
}

export interface CaseFilters {
  severity: Severity | "ALL";
  status:   CaseStatus | "ALL";
  search:   string;
  page:     number;
  pageSize: number;
  sort:     string;
  sortDir:  "asc" | "desc";
  dateFrom?: string;
  dateTo?:   string;
  /** CI del operador owner. "__unassigned__" → casos sin asignar. */
  assignedTo?:   string;
  /** Rol/es del operador owner. Lista separada por coma admite multi-perfil. */
  assignedRole?: string;
  /** Mostrar también casos CERRADO/FALSO_POSITIVO. Default false. */
  includeClosed?: boolean;
  /** C5 — Filtros DSL extra. Rango de score (inclusivo) y ventana de
   *  created_at. null/undefined = sin filtrar. createdAt acepta ISO 8601
   *  (las expresiones relativas como `<7d` se resuelven en el parser). */
  scoreMin?:     number | null;
  scoreMax?:     number | null;
  createdAtMin?: string;
  createdAtMax?: string;
  /** Clase eCSIRT/MISP. "ALL"/undefined = sin filtrar. */
  incidentClass?: string;
}

export interface CaseFacets {
  byOperator: Record<string, number>;
  byRole:     Record<string, number>;
  unassigned: number;
}

export interface UseCaseManagementResult {
  cases:          SocCase[];
  total:          number;
  kpis:           DashboardKpis | undefined;
  facets:         CaseFacets | undefined;
  isLoading:      boolean;
  isLoadingKpis:  boolean;
  isError:        boolean;
  errorMessage:   string | null;
  refetch:        () => void;
  adoptCase:      (caseId: string, operatorCi: string, force?: boolean) => Promise<void>;
  changeStatus:   (caseId: string, status: CaseStatus, reason?: string, operatorCi?: string, classification?: CaseClassification) => Promise<void>;
  notifySlack:    (caseId: string, reason: "escalated" | "manual") => Promise<void>;
  escalateCase:   (caseId: string, level: string, escalatedTo: string, reason: string, operatorCi: string) => Promise<void>;
}

const CASES_KEY = "incidents";
const KPIS_KEY  = "incidents-kpis";

/** Garantiza que todos los campos nuevos tienen al menos un valor por defecto. */
function normalizeCase(c: SocCase): SocCase {
  return {
    ...c,
    sourcePort:           c.sourcePort          ?? null,
    protocol:             c.protocol            ?? null,
    firewallAction:       c.firewallAction       ?? null,
    srcCountry:           c.srcCountry          ?? null,
    networkZone:          c.networkZone         ?? null,
    escalationSuggested:  c.escalationSuggested ?? false,
    escalationReasonAuto: c.escalationReasonAuto ?? null,
    // Backends antiguos (pre 029/assetsCount) responden undefined; normalizamos a 0
    // para que CaseRow no tenga que chequear existence.
    assetsCount:          Number(c.assetsCount ?? 0),
    enrichment: {
      vtMalicious:     c.enrichment?.vtMalicious     ?? null,
      vtSuspicious:    c.enrichment?.vtSuspicious    ?? null,
      abuseConfidence: c.enrichment?.abuseConfidence ?? null,
      inUrlhaus:       c.enrichment?.inUrlhaus       ?? false,
      inOpenphish:     c.enrichment?.inOpenphish     ?? false,
      vtPermalink:     c.enrichment?.vtPermalink     ?? null,
      inMisp:          c.enrichment?.inMisp          ?? false,
      shodanOrg:       c.enrichment?.shodanOrg       ?? null,
      // El API puede devolver shodanPorts como string CSV ("80,443") o JSON-encoded
      // en lugar de array. toNumberArray absorbe todas las formas.
      shodanPorts:     toNumberArray(c.enrichment?.shodanPorts),
      shodanCountry:   c.enrichment?.shodanCountry   ?? null,
      enrichedAt:      c.enrichment?.enrichedAt      ?? null,
    },
  };
}

interface CasesResponse {
  cases:    SocCase[];
  total:    number;
  page:     number;
  pageSize: number;
}

export function useCaseManagement(filters: CaseFilters): UseCaseManagementResult {
  const queryClient = useQueryClient();

  // ── Query de casos ────────────────────────────────────────────────────────
  const casesQuery = useQuery({
    queryKey: [CASES_KEY, filters],
    queryFn: async () => {
      const params = new URLSearchParams({
        severity: filters.severity,
        status:   filters.status,
        page:     String(filters.page),
        pageSize: String(filters.pageSize),
        sort:     filters.sort,
        sortDir:  filters.sortDir,
        ...(filters.search        ? { search:        filters.search        } : {}),
        ...(filters.dateFrom      ? { dateFrom:      filters.dateFrom      } : {}),
        ...(filters.dateTo        ? { dateTo:        filters.dateTo        } : {}),
        ...(filters.assignedTo    ? { assignedTo:    filters.assignedTo    } : {}),
        ...(filters.assignedRole  ? { assignedRole:  filters.assignedRole  } : {}),
        ...(filters.includeClosed ? { includeClosed: "true" }                : {}),
        ...(filters.scoreMin     != null ? { scoreMin:     String(filters.scoreMin)     } : {}),
        ...(filters.scoreMax     != null ? { scoreMax:     String(filters.scoreMax)     } : {}),
        ...(filters.createdAtMin       ? { createdAtMin: filters.createdAtMin         } : {}),
        ...(filters.createdAtMax       ? { createdAtMax: filters.createdAtMax         } : {}),
        ...(filters.incidentClass && filters.incidentClass !== "ALL"
              ? { incidentClass: filters.incidentClass } : {}),
      });
      const { data } = await api.get<CasesResponse>(`/api/incidents/open?${params}`);
      // Normalizar campos nuevos — compatibilidad con respuestas sin los campos extendidos
      if (data?.cases) {
        data.cases = data.cases.map(normalizeCase);
      }
      return data;
    },
    // Socket.IO (debounced 1.5s más abajo) es la fuente push real. El
    // polling queda como fallback para casos sin conexión WebSocket.
    // Nota 2026-04-17: subido de 30s/30-60s a 60s/60-120s porque el fetch
    // real llega por el socket; el polling agresivo sólo aumenta carga
    // sobre incident_cases_pg sin dar información adicional al operador.
    staleTime: 60_000,
    refetchInterval: (query) => {
      const hasCriticalUnacked = query.state.data?.cases.some(
        (c) => c.severity === "CRITICAL" && !c.adoptedAt && c.status === "NUEVO",
      );
      return hasCriticalUnacked ? 60_000 : 120_000;
    },
    refetchOnWindowFocus: false, // Socket.IO ya mantiene fresco el listado
  });

  // ── Facets (conteos por owner / rol / unassigned) ────────────────────────
  // Independiente del paginado: anota los selectores con conteos absolutos
  // para que el operador detecte colas atascadas a primera vista.
  const FACETS_KEY = "incidents-facets";
  const facetsQuery = useQuery({
    queryKey: [FACETS_KEY, filters.includeClosed ?? false],
    queryFn: async () => {
      const p = new URLSearchParams();
      if (filters.includeClosed) p.set("includeClosed", "true");
      const { data } = await api.get<CaseFacets>(`/api/incidents/facets?${p}`);
      return data;
    },
    staleTime:       120_000,
    refetchInterval: 120_000,
    refetchOnWindowFocus: false,
  });

  // ── Query de KPIs — PostgreSQL fast path via /api/cases/kpis ─────────────
  // Refetch adaptativo (2026-05-20): si hay CRITICAL sin adoptar, polling
  // cada 60s para reflejar contadores más rápido en el panel; si no,
  // 120s para no machacar PG. Mismo patrón que el query de cases.
  const kpisQuery = useQuery({
    queryKey: [KPIS_KEY],
    queryFn: async () => {
      // Primary: PG-backed fast endpoint (sub-ms, no Trino dependency)
      try {
        const { data } = await api.get<DashboardKpis>("/api/cases/kpis");
        return data;
      } catch {
        // Fallback to Trino-backed endpoint
        const { data } = await api.get<DashboardKpis>("/api/incidents/kpis");
        return data;
      }
    },
    staleTime: 60_000,
    refetchInterval: (query) => {
      const criticalPending = query.state.data?.criticalUnadopted ?? 0;
      return criticalPending > 0 ? 60_000 : 120_000;
    },
    refetchOnWindowFocus: false,
  });

  // ── Socket.IO ─────────────────────────────────────────────────────────────
  // Debounce 1.5s: si llegan varios eventos en ráfaga (típico al adoptar+
  // escalar+notificar un mismo caso), se hace una sola invalidación al final.
  const invalidateAll = useMemo(
    () =>
      debounce(
        () => {
          void queryClient.invalidateQueries({ queryKey: [CASES_KEY] });
          void queryClient.invalidateQueries({ queryKey: [KPIS_KEY] });
          void queryClient.invalidateQueries({ queryKey: ["incidents-facets"] });
          // Si hay un caso abierto en la vista de investigación, el socket
          // puede traer cambios (adopción ajena, transición, enrichment).
          // Invalidamos la key raíz ["case-investigation"] para que cualquier
          // caseId cacheado se re-fetchee — evita mostrar estado viejo tras
          // un refresh externo.
          void queryClient.invalidateQueries({ queryKey: ["case-investigation"] });
        },
        1500,
        { leading: false, trailing: true, maxWait: 5000 },
      ),
    [queryClient],
  );

  useEffect(() => {
    socket.connect();

    socket.on("incident:new",              invalidateAll);
    socket.on("incident:adopted",          invalidateAll);
    socket.on("incident:status_change",    invalidateAll);
    socket.on("incident:critical_unacked", invalidateAll);

    return () => {
      socket.off("incident:new",              invalidateAll);
      socket.off("incident:adopted",          invalidateAll);
      socket.off("incident:status_change",    invalidateAll);
      socket.off("incident:critical_unacked", invalidateAll);
      invalidateAll.cancel();
    };
  }, [invalidateAll]);

  // ── Mutaciones ────────────────────────────────────────────────────────────
  // Toast feedback: éxito → toast.success efímero; error → toast.error con el
  // mensaje exacto del backend (extractApiErrorMessage). El throw se mantiene
  // para que los callers que necesitan detectar 409 conflict (CaseAdoptionModal)
  // sigan recibiendo el error y puedan abrir su flow de transferencia.
  //
  // R4 (audit 2026-05-13): optimistic updates en adopt/changeStatus.
  // setQueriesData con patcher recorre TODAS las entradas [CASES_KEY, *filters]
  // — el cache se particiona por filters, así que un solo setQueryData no
  // alcanza. snapshots se guarda como Array<[key, prev]> para rollback exacto
  // si el POST falla.

  type CasesData = { cases: SocCase[]; total: number; page: number; pageSize: number };

  /** Aplica `patcher` a cada SocCase con id===caseId en todas las cachés
   *  [CASES_KEY, *]. Devuelve un array de snapshots para rollback. */
  function patchCaseAcrossCaches(
    caseId: string,
    patcher: (c: SocCase) => SocCase,
  ): Array<[readonly unknown[], CasesData | undefined]> {
    const snapshots: Array<[readonly unknown[], CasesData | undefined]> = [];
    queryClient.setQueriesData<CasesData>(
      { queryKey: [CASES_KEY] },
      (prev) => {
        if (!prev?.cases) return prev;
        const idx = prev.cases.findIndex((c) => c.id === caseId);
        if (idx < 0) return prev;
        const next = { ...prev, cases: prev.cases.slice() };
        next.cases[idx] = patcher(next.cases[idx]);
        return next;
      },
    );
    // Capturar snapshots después del set (igual basta para rollback porque
    // setQueriesData es síncrono y devuelve el estado nuevo).
    queryClient.getQueriesData<CasesData>({ queryKey: [CASES_KEY] }).forEach(([k, v]) => {
      snapshots.push([k, v]);
    });
    return snapshots;
  }

  /** Rollback: restaura cada caché a su snapshot. */
  function restoreSnapshots(snapshots: Array<[readonly unknown[], CasesData | undefined]>) {
    for (const [key, prev] of snapshots) {
      queryClient.setQueryData(key, prev);
    }
  }

  const adoptCase = async (caseId: string, operatorCi: string, force = false): Promise<void> => {
    // R4: snapshot ANTES de optimistic write (para rollback exacto en error).
    const preSnapshots = queryClient
      .getQueriesData<CasesData>({ queryKey: [CASES_KEY] })
      .map(([k, v]) => [k, v?.cases ? { ...v, cases: v.cases.slice() } : v] as [readonly unknown[], CasesData | undefined]);

    const now = new Date().toISOString();
    patchCaseAcrossCaches(caseId, (c) => ({
      ...c,
      operatorCi,
      adoptedAt:  now,
      // El backend mueve NUEVO → EN_ANALISIS automáticamente al adoptar.
      status:     c.status === "NUEVO" ? "EN_ANALISIS" : c.status,
    }));

    try {
      await api.post(`/api/incidents/${caseId}/adopt`, { operatorCi, force });
      // R-perf (2026-06-06): solo esperamos la invalidación de la lista de casos
      // (rápida, ~0.2 s). El refetch de KPIs (~3 s agregando sobre 430k filas de
      // incident_cases_pg) e investigación se hacen en segundo plano para no
      // bloquear el cierre del modal de adopción. Sin esto la vista de
      // investigación muestra operator_id=null durante staleTime (30 s).
      await queryClient.invalidateQueries({ queryKey: [CASES_KEY] });
      void queryClient.invalidateQueries({ queryKey: [KPIS_KEY] });
      void queryClient.invalidateQueries({ queryKey: ["case-investigation", caseId] });
      toast.success("Caso adoptado", { description: `Operador ${operatorCi}` });
    } catch (err) {
      restoreSnapshots(preSnapshots);
      // 409 conflict (caso ya adoptado por otro) → no spamear toast; el modal
      // muestra su propio UI de transferencia. Solo notificar errores reales.
      const isConflict = isAxiosError(err) && err.response?.status === 409;
      if (!isConflict) {
        toast.error("No se pudo adoptar el caso", { description: extractApiErrorMessage(err) });
      }
      throw err;
    }
  };

  const changeStatus = async (
    caseId:     string,
    status:     CaseStatus,
    reason?:    string,
    operatorCi?: string,
    classification?: CaseClassification,
  ): Promise<void> => {
    // R4: snapshot + optimistic update. Estados terminales también setean
    // resolvedAt para que las KPIs visibles (resolvedToday) y los filtros de
    // "abiertos" reflejen el cambio sin esperar al refetch.
    const preSnapshots = queryClient
      .getQueriesData<CasesData>({ queryKey: [CASES_KEY] })
      .map(([k, v]) => [k, v?.cases ? { ...v, cases: v.cases.slice() } : v] as [readonly unknown[], CasesData | undefined]);

    const now = new Date().toISOString();
    const isTerminal = status === "CERRADO" || status === "FALSO_POSITIVO";
    patchCaseAcrossCaches(caseId, (c) => ({
      ...c,
      status,
      resolvedAt: isTerminal && !c.resolvedAt ? now : c.resolvedAt,
      closureReason: reason ?? c.closureReason,
    }));

    try {
      // Audit 2026-05-26: el backend exige `classification` al cerrar
      // (CERRADO/FALSO_POSITIVO). Para FALSO_POSITIVO, default backend si no
      // viene; para CERRADO el caller debe enviarlo.
      await api.patch(`/api/incidents/${caseId}/status`, {
        status, reason, operatorCi,
        ...(classification ? { classification } : {}),
      });
      // R-perf (2026-06-06): KPIs/investigación en segundo plano (ver adoptCase).
      await queryClient.invalidateQueries({ queryKey: [CASES_KEY] });
      void queryClient.invalidateQueries({ queryKey: [KPIS_KEY] });
      void queryClient.invalidateQueries({ queryKey: ["case-investigation", caseId] });
      toast.success(`Estado actualizado: ${status}`);
    } catch (err) {
      restoreSnapshots(preSnapshots);
      toast.error("No se pudo cambiar el estado", { description: extractApiErrorMessage(err) });
      throw err;
    }
  };

  const notifySlack = async (caseId: string, reason: "escalated" | "manual"): Promise<void> => {
    try {
      await api.post(`/api/incidents/${caseId}/notify-slack`, { reason });
      toast.success("Slack notificado");
    } catch (err) {
      toast.error("No se pudo notificar a Slack", { description: extractApiErrorMessage(err) });
      throw err;
    }
  };

  const escalateCase = async (
    caseId:     string,
    level:      string,
    escalatedTo: string,
    reason:     string,
    operatorCi: string,
  ): Promise<void> => {
    try {
      await api.post(`/api/incidents/${caseId}/escalate`, {
        escalationLevel:  level,
        escalatedTo:      escalatedTo || undefined,
        escalationReason: reason,
        operatorCi,
      });
      // R-perf (2026-06-06): KPIs/investigación en segundo plano (ver adoptCase).
      await queryClient.invalidateQueries({ queryKey: [CASES_KEY] });
      void queryClient.invalidateQueries({ queryKey: [KPIS_KEY] });
      void queryClient.invalidateQueries({ queryKey: ["case-investigation", caseId] });
      toast.success(`Caso escalado a ${level}`);
    } catch (err) {
      toast.error("No se pudo escalar el caso", { description: extractApiErrorMessage(err) });
      throw err;
    }
  };

  return {
    cases:         casesQuery.data?.cases        ?? [],
    total:         casesQuery.data?.total        ?? 0,
    kpis:          kpisQuery.data,
    facets:        facetsQuery.data,
    isLoading:     casesQuery.isLoading,
    isLoadingKpis: kpisQuery.isLoading,
    isError:       casesQuery.isError,
    errorMessage:  casesQuery.error instanceof Error ? casesQuery.error.message : null,
    refetch:       casesQuery.refetch,
    adoptCase,
    changeStatus,
    notifySlack,
    escalateCase,
  };
}
