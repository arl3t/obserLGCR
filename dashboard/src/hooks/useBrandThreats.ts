/**
 * useBrandThreats — hook compuesto que orquesta toda la inteligencia DRP.
 *
 * Combina los 4 sub-hooks (CT logs, typosquatting, phishing kits, leak
 * velocity) y aplica el motor de correlaciones cross-source. Devuelve un
 * shape único `SurveillanceBrandThreats` que `useSurveillanceCore` expone
 * al resto de la app.
 *
 * Patrón: igual que `useSurveillanceCore` orquesta los 4 hooks principales,
 * éste orquesta los 4 hooks DRP. Se invoca UNA SOLA VEZ desde el core.
 *
 * IMPORTANTE (fix React #185, 2026-05-08): el `useMemo` retorna SINGLETON
 * estable cuando todos los queries son `undefined` y no hay velocity. Esto
 * evita que el objeto cambie identidad en cada render durante el loading
 * inicial — lo cual propagaba al context del Provider y disparaba el loop
 * de re-suscripción a las queries de TanStack.
 */

import { useMemo } from "react";
import { useCTLogs } from "@/hooks/useCTLogs";
import { useTyposquatting } from "@/hooks/useTyposquatting";
import { usePhishingKits } from "@/hooks/usePhishingKits";
import { useLeakVelocity } from "@/hooks/useLeakVelocity";
import { buildCTImpersonationThreats } from "@/components/digital-surveillance/risk-engine/builders/ctImpersonationBuilder";
import { buildTyposquattingThreats } from "@/components/digital-surveillance/risk-engine/builders/typosquattingBuilder";
import { buildPhishingKitThreats } from "@/components/digital-surveillance/risk-engine/builders/phishingKitBuilder";
import { buildLeakVelocityThreats } from "@/components/digital-surveillance/risk-engine/builders/leakVelocityBuilder";
import { detectCorrelations } from "@/components/digital-surveillance/risk-engine/correlations";
import type {
  BrandThreat,
  SurveillanceBrand24Result,
  SurveillanceBrandThreats,
  ThreatKind,
} from "@/types/digital-surveillance";

const SEVERITY_RANK: Record<BrandThreat["severity"], number> = {
  low: 0, medium: 1, high: 2, critical: 3,
};

const ZERO_BY_KIND: Record<ThreatKind, number> = Object.freeze({
  "ct-impersonation":          0,
  "typosquatting":              0,
  "leak-velocity":              0,
  "phishing-kit":               0,
  "impersonation-confidence":   0,
}) as Record<ThreatKind, number>;

const EMPTY_THREATS: BrandThreat[] = Object.freeze([]) as unknown as BrandThreat[];
const EMPTY_CORRELATIONS = Object.freeze([]) as unknown as SurveillanceBrandThreats["correlations"];

/** Singleton estable usado mientras no hay ningún query con data. */
function emptyBrandThreats(domain: string): SurveillanceBrandThreats {
  return {
    domain,
    threats: EMPTY_THREATS,
    correlations: EMPTY_CORRELATIONS,
    byKind: ZERO_BY_KIND,
    hasActiveCampaign: false,
    fetchedAt: "",
  };
}

export function useBrandThreats(
  domain: string,
  brand24: SurveillanceBrand24Result | null | undefined,
): SurveillanceBrandThreats {
  const ctQ    = useCTLogs(domain);
  const typoQ  = useTyposquatting(domain);
  const phishQ = usePhishingKits(domain);
  const velocity = useLeakVelocity(domain);

  // Extraer primitivos de brand24 para deps estables — evitar usar `brand24`
  // entero como dep porque su identidad cambia tras cada fetch aunque el
  // contenido relevante sea el mismo.
  const positiveCount = brand24?.summary?.positiveCount ?? 0;
  const negativeCount = brand24?.summary?.negativeCount ?? 0;

  return useMemo<SurveillanceBrandThreats>(() => {
    // Si TODOS los queries no tienen data y no hay velocity, retornamos el
    // singleton vacío con identidad estable hasta que algún query responda.
    const hasAnyData =
      !!ctQ.data?.certificates?.length ||
      !!typoQ.data?.candidates?.length ||
      !!phishQ.data?.matches?.length ||
      !!velocity;

    if (!hasAnyData && positiveCount === 0 && negativeCount === 0) {
      return emptyBrandThreats(domain);
    }

    const ctThreats    = buildCTImpersonationThreats(ctQ.data?.certificates);
    const typoThreats  = buildTyposquattingThreats(typoQ.data?.candidates);
    const phishThreats = buildPhishingKitThreats(phishQ.data?.matches);
    const velocityThreats = buildLeakVelocityThreats(velocity ?? undefined);

    // Feed unificado, ordenado por severity desc + detectedAt desc.
    const threats: BrandThreat[] = [
      ...ctThreats,
      ...typoThreats,
      ...phishThreats,
      ...velocityThreats,
    ].sort((a, b) => {
      const sevDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
      if (sevDiff !== 0) return sevDiff;
      return Date.parse(b.detectedAt) - Date.parse(a.detectedAt);
    });

    // Correlaciones cross-source.
    const negTotal = positiveCount + negativeCount;
    const negRatio = negTotal > 0 ? negativeCount / negTotal : 0;
    const correlations = detectCorrelations({
      domain,
      threats,
      newCredsLast24h: velocity?.newCredsLast24h ?? 0,
      newCredsLast7d:  velocity?.newCredsLast7d ?? 0,
      brand24NegRatio: negRatio,
      brand24Classified: negTotal,
    });

    // Conteo por kind para badges/KPIs.
    const byKind: Record<ThreatKind, number> = {
      "ct-impersonation":          0,
      "typosquatting":              0,
      "leak-velocity":              0,
      "phishing-kit":               0,
      "impersonation-confidence":   0,
    };
    for (const t of threats) byKind[t.kind] += 1;

    const hasActiveCampaign = correlations.some(
      (c) => c.severity === "critical" || c.severity === "high",
    );

    return {
      domain,
      threats,
      correlations,
      byKind,
      hasActiveCampaign,
      // `fetchedAt` se setea solo cuando hay data real — evita rotación de
      // identidad cuando estamos en el "shape vacío" loading state.
      fetchedAt: new Date().toISOString(),
    };
  }, [
    domain,
    ctQ.data,
    typoQ.data,
    phishQ.data,
    velocity,
    positiveCount,
    negativeCount,
  ]);
}
