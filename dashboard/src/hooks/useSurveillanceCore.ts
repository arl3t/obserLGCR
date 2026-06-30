import { useCallback, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  autoPatternsFromDomain,
  surveillanceBrand24Key,
  surveillanceQueryKey,
  surveillanceRssKey,
  useDigitalSurveillanceBrand24,
  useDigitalSurveillanceRss,
  useDigitalSurveillanceSnapshot,
  useIntelFiles,
  type IntelFilesResult,
} from "@/hooks/useDigitalSurveillance";
import {
  calculateRiskScore,
} from "@/components/digital-surveillance/risk-engine/calculateRiskScore";
import {
  emailCountForDomain,
  infraRowsForSearchDomain,
  snapshotCoversDomain,
  useLeakIntelHubStore,
  type LeakIntelHubSnapshot,
} from "@/store/leak-intel-hub-store";
import { buildAllAlerts } from "@/components/digital-surveillance/risk-engine/buildAllAlerts";
import { useBrandThreats } from "@/hooks/useBrandThreats";
import { useAnalystFindings } from "@/hooks/useAnalystFindings";
import type { Alert } from "@/components/digital-surveillance/shared/AlertsBlock";
import type {
  AnalystFinding,
  RiskBand,
  RiskFactorItem,
  SurveillanceBrand24Result,
  SurveillanceBrandThreats,
  SurveillanceDomainResult,
  SurveillanceRssResult,
} from "@/types/digital-surveillance";

// Singleton vacío para `riskFactors` cuando data está undefined — preserva
// identidad referencial entre renders (ver nota en el cuerpo del hook).
const EMPTY_FACTORS: RiskFactorItem[] = Object.freeze([]) as unknown as RiskFactorItem[];

// ─────────────────────────────────────────────────────────────────────────────
// Tipo unificado expuesto al resto de la app
// ─────────────────────────────────────────────────────────────────────────────

export type SurveillanceErrors = {
  domain: Error | null;
  rss: Error | null;
  brand24: Error | null;
  intelFiles: Error | null;
};

/**
 * Resultado consolidado de Vigilancia Digital. Representa el estado completo
 * del módulo para un dominio: los 4 sub-fetches + el snapshot local de leaks
 * + los derivados (riesgo, alertas, conteos).
 *
 * Es el contrato que consume `SurveillanceProvider` y, a través de éste,
 * los tabs y componentes shared (`SituationalStrip`, `AlertsBlock`, etc.).
 */
export type SurveillanceUnifiedResult = {
  /** FQDN normalizado (lowercase, sin esquema). Vacío si no hay búsqueda. */
  domain: string;

  // ── estado agregado de las queries ──
  isLoading: boolean;
  isFetching: boolean;
  isError: boolean;
  errors: SurveillanceErrors;

  // ── datos crudos por fuente (undefined hasta que llegue la primera respuesta) ──
  data: SurveillanceDomainResult | undefined;
  rss: SurveillanceRssResult | undefined;
  brand24: SurveillanceBrand24Result | undefined;
  intelFiles: IntelFilesResult | undefined;
  snapshot: LeakIntelHubSnapshot | null;

  // ── derivados ──
  /** Cobertura del snapshot local sobre el dominio buscado. */
  hasCoverage: boolean;
  /** Correos del dominio en el dataset cargado. 0 si no aplica. */
  emailCount: number;
  /** Filas de infra (hostname / IP) del dataset que mencionan al dominio. */
  infraCount: number;

  /** Score 0-100 del backend, clampeado defensivamente. */
  riskScore: number;
  riskBand: RiskBand;
  riskFactors: RiskFactorItem[];

  /** Alertas accionables computadas en cliente sobre las 5 fuentes. */
  alerts: Alert[];

  /** Inteligencia DRP — Fase 3 §9. CT logs + typosquatting + phishing kits +
   *  leak velocity + correlaciones cross-source. */
  brandThreats: SurveillanceBrandThreats;

  /** Feed unificado del Workspace del Analista. Findings de las 5 fuentes +
   *  correlaciones cross-source. Ordenado por severity desc + detectedAt desc. */
  findings: AnalystFinding[];

  // ── acciones ──
  /** Invalida todas las queries del módulo y vuelve a fetchearlas. */
  refetchAll: () => void;
};

// ─────────────────────────────────────────────────────────────────────────────
// Hook principal — único punto de entrada de datos del módulo
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Carga TODA la inteligencia externa de un dominio en un solo hook:
 *   - `/api/surveillance/domain` → Shodan + MISP + risk score
 *   - `/api/surveillance/rss`    → menciones en feeds
 *   - `/api/surveillance/brand24`→ social listening (live o snapshot PDF)
 *   - `/api/surveillance/intel-files` → datasets disponibles en S3
 *   - Zustand `leak-intel-hub`   → snapshot del dataset ya parseado en navegador
 *
 * Se invoca UNA SOLA VEZ desde `SurveillanceProvider`. Resuelve §7.1.3 del doc
 * de referencia (hook Brand24 invocado 3 veces). React Query dedupe la red
 * pero no las suscripciones; centralizar aquí evita re-renders innecesarios.
 *
 * Cuando `domain` es vacío, todas las queries quedan `enabled: false` y el
 * resultado es un shell con `isLoading=false`, `isError=false` y arrays vacíos.
 */
export function useSurveillanceCore(domain: string): SurveillanceUnifiedResult {
  const key = (domain ?? "").trim();
  const enabled = key.length > 0;

  // 1. Sub-queries
  const domainQ = useDigitalSurveillanceSnapshot(enabled ? key : null);
  const rssQ = useDigitalSurveillanceRss(enabled ? key : null);
  const brandQ = useDigitalSurveillanceBrand24(enabled ? key : null);

  const patterns = useMemo(() => (enabled ? autoPatternsFromDomain(key) : []), [enabled, key]);
  const filesQ = useIntelFiles(enabled ? key : "", patterns, enabled);

  // 2. Snapshot local (Zustand) — sólo si cubre el dominio
  const snapshot = useLeakIntelHubStore((s) => s.snapshot);

  const { hasCoverage, emailCount, infraCount } = useMemo(() => {
    if (!snapshot || !enabled) {
      return { hasCoverage: false, emailCount: 0, infraCount: 0 };
    }
    const cov = snapshotCoversDomain(snapshot, key);
    return {
      hasCoverage: cov,
      emailCount: cov ? emailCountForDomain(snapshot, key) : 0,
      infraCount: cov ? infraRowsForSearchDomain(snapshot, key) : 0,
    };
  }, [snapshot, key, enabled]);

  // 3. CTI Cloud & Olé — snapshot cacheado para integrar al risk score (#7).
  //    NO dispara la API CTI; sólo lee el último resultado persistido en
  //    servidor (404 si no hay). Se hidrata vía useQuery con la misma
  //    queryKey que CtiDomainLeaksPanel para compartir cache.
  const ctiCachedQ = useQuery<{ count: number; topLeakNames?: string[] } | null>({
    queryKey: ["cti-cached", key.toLowerCase()],
    enabled,
    staleTime: 5 * 60_000,
    queryFn: async () => {
      const r = await fetch(`/api/intel/cti/leaks/domain/cached?domain=${encodeURIComponent(key)}`);
      if (r.status === 404) return null;
      const j = await r.json();
      if (!r.ok || !j?.ok) return null;
      return { count: j.count ?? 0, topLeakNames: j.topLeakNames ?? [] };
    },
  });

  // 4. Derivados de riesgo — pasamos por el motor versionado para integrar
  //    el builder CTI (#7). Cuando no hay data del backend, el motor opera
  //    en modo offline (backendScore=0, factors solo cliente).
  const data = domainQ.data;
  const riskResult = useMemo(() => {
    return calculateRiskScore({
      backendScore: data?.risk.score,
      backendFactors: data?.risk.factors,
      ctiHitsCount: ctiCachedQ.data?.count,
      ctiTopLeakNames: ctiCachedQ.data?.topLeakNames,
    });
  }, [data?.risk.score, data?.risk.factors, ctiCachedQ.data?.count, ctiCachedQ.data?.topLeakNames]);

  const riskScore = riskResult.score;
  const riskBand: RiskBand = data || ctiCachedQ.data ? riskResult.band : "low";
  // `riskFactors` debe ser estable — si no hay nada, retornamos un singleton
  // vacío en lugar de `[]` literal nuevo cada render, que causaría que el
  // `useMemo` del return se invalide siempre y propague identidad nueva del
  // context (raíz del React #185 loop).
  const riskFactors = (data || ctiCachedQ.data) ? riskResult.factors : EMPTY_FACTORS;

  // 4. Alertas accionables agregadas (5 builders)
  const alerts = useMemo<Alert[]>(() => {
    if (!data) return [];
    return buildAllAlerts({
      data,
      brand24: brandQ.data ?? null,
      rss: rssQ.data ?? null,
      snapshot: hasCoverage ? snapshot : null,
      emailCount,
    });
  }, [data, brandQ.data, rssQ.data, snapshot, hasCoverage, emailCount]);

  // 4b. Inteligencia DRP — Fase 3 §9 (CT, typo, phishing, velocity + correlations)
  //
  // DECISIÓN ARQUITECTÓNICA (auditoría 2026-05-08): los `brandThreats` se
  // exponen COMO FEED APARTE — NO se cablean al `riskScore` visible.
  // Razón: el score que ven los analistas viene del backend; integrar los
  // factores DRP cliente alteraría ese número y rompería trazabilidad con
  // los reportes históricos. Los threats viven en su propio canal y se
  // muestran en BrandThreatsBlock + columna Impersonation del strip +
  // SIMILAR DOMAINS del SurfaceGrid ejecutivo.
  //
  // Si en el futuro se decide integrar, el patch es: usar
  // `calculateRiskScore({ backendScore, backendFactors, threats: brandThreats.threats })`
  // en lugar de tomar `data.risk.score` directo. La función ya está lista.
  const brandThreats = useBrandThreats(key, brandQ.data);

  // 4c. Feed unificado del Workspace del Analista — agrega findings de
  //     todas las fuentes + correlaciones cross-source (Shodan∩MISP, etc.).
  //     Identidad estable mientras los datos no cambien (mismas garantías
  //     que `brandThreats`).
  const findings = useAnalystFindings({
    domain: key,
    data,
    rss: rssQ.data,
    brand24: brandQ.data,
    snapshot,
    hasCoverage,
    emailCount,
    brandThreats,
  });

  // 5. Errores normalizados — memoizados para no romper la identidad del
  //    objeto retornado entre renders cuando los errores no cambian.
  const errors = useMemo<SurveillanceErrors>(
    () => ({
      domain: errAs(domainQ.error),
      rss: errAs(rssQ.error),
      brand24: errAs(brandQ.error),
      intelFiles: errAs(filesQ.error),
    }),
    [domainQ.error, rssQ.error, brandQ.error, filesQ.error],
  );

  // 6. Refetch agregado — useCallback para identidad estable (un consumer
  //    puede ponerlo en deps de useEffect sin disparar re-fires por render).
  const queryClient = useQueryClient();
  const refetchAll = useCallback(() => {
    if (!enabled) return;
    queryClient.invalidateQueries({ queryKey: surveillanceQueryKey(key) });
    queryClient.invalidateQueries({ queryKey: surveillanceRssKey(key) });
    queryClient.invalidateQueries({ queryKey: surveillanceBrand24Key(key) });
    queryClient.invalidateQueries({ queryKey: ["surveillance-intel-files", key] });
  }, [enabled, key, queryClient]);

  // 7. Resultado consolidado — `useMemo` para que la IDENTIDAD del objeto sea
  //    estable cuando los datos no cambian. Si retornáramos un objeto literal
  //    en cada render, `SurveillanceProvider` propagaría un `value` nuevo al
  //    context cada vez, causando re-renders en cascada en TODOS los
  //    consumidores (8 tabs + strip + executive components) — y a veces loops
  //    de setState que disparan React error #185.
  const isLoading = enabled && (domainQ.isLoading || rssQ.isLoading || brandQ.isLoading);
  const isFetching = domainQ.isFetching || rssQ.isFetching || brandQ.isFetching || filesQ.isFetching;
  const stableSnapshot = hasCoverage ? snapshot : null;

  return useMemo<SurveillanceUnifiedResult>(() => ({
    domain: key,
    isLoading,
    isFetching,
    isError: domainQ.isError,
    errors,

    data,
    rss: rssQ.data,
    brand24: brandQ.data,
    intelFiles: filesQ.data,
    snapshot: stableSnapshot,

    hasCoverage,
    emailCount,
    infraCount,

    riskScore,
    riskBand,
    riskFactors,

    alerts,
    brandThreats,
    findings,

    refetchAll,
  }), [
    key,
    isLoading,
    isFetching,
    domainQ.isError,
    errors,
    data,
    rssQ.data,
    brandQ.data,
    filesQ.data,
    stableSnapshot,
    hasCoverage,
    emailCount,
    infraCount,
    riskScore,
    riskBand,
    riskFactors,
    alerts,
    brandThreats,
    findings,
    refetchAll,
  ]);
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

function errAs(e: unknown): Error | null {
  if (!e) return null;
  return e instanceof Error ? e : new Error(String(e));
}
