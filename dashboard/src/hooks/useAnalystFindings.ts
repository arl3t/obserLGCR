/**
 * useAnalystFindings — agrega findings de todas las fuentes en un feed único.
 *
 * Consume el resultado del `useSurveillanceCore` (no se invoca en componentes
 * intermedios para no duplicar trabajo). Llama a 5 builders por-fuente +
 * el motor de correlaciones cross-source y devuelve `AnalystFinding[]`
 * ordenado por severity desc + detectedAt desc.
 *
 * Llamado UNA SOLA VEZ desde `SurveillanceProvider`. Identidad estable
 * cuando los datos no cambian (memoización con deps primitivos cuando es
 * posible).
 */

import { useMemo } from "react";
import { buildCredentialFindings } from "@/components/digital-surveillance/risk-engine/finding-builders/credentialFindingBuilder";
import { buildShodanFindings } from "@/components/digital-surveillance/risk-engine/finding-builders/shodanFindingBuilder";
import { buildMispFindings } from "@/components/digital-surveillance/risk-engine/finding-builders/mispFindingBuilder";
import { buildBrandFindings } from "@/components/digital-surveillance/risk-engine/finding-builders/brandFindingBuilder";
import { buildRssFindings } from "@/components/digital-surveillance/risk-engine/finding-builders/rssFindingBuilder";
import { detectCrossSourceCorrelations } from "@/components/digital-surveillance/risk-engine/crossSourceCorrelations";
import { useLeakVelocity } from "@/hooks/useLeakVelocity";
import type {
  AnalystFinding,
  SurveillanceBrand24Result,
  SurveillanceBrandThreats,
  SurveillanceDomainResult,
  SurveillanceRssResult,
} from "@/types/digital-surveillance";
import { ANALYST_SEVERITY_RANK } from "@/types/digital-surveillance";
import type { LeakIntelHubSnapshot } from "@/store/leak-intel-hub-store";

const EMPTY_FINDINGS: AnalystFinding[] = Object.freeze([]) as unknown as AnalystFinding[];

export type UseAnalystFindingsInput = {
  domain: string;
  data: SurveillanceDomainResult | undefined;
  rss: SurveillanceRssResult | undefined;
  brand24: SurveillanceBrand24Result | undefined;
  snapshot: LeakIntelHubSnapshot | null;
  hasCoverage: boolean;
  emailCount: number;
  brandThreats: SurveillanceBrandThreats;
};

export function useAnalystFindings(
  input: UseAnalystFindingsInput,
): AnalystFinding[] {
  // Velocity hook ya está memoizado y solo retorna primitivos derivados.
  const velocity = useLeakVelocity(input.domain);

  return useMemo(() => {
    if (!input.data) return EMPTY_FINDINGS;

    const findings: AnalystFinding[] = [];

    // Builders por fuente
    findings.push(...buildCredentialFindings({
      domain: input.domain,
      snapshot: input.snapshot,
      hasCoverage: input.hasCoverage,
      emailCount: input.emailCount,
    }));

    findings.push(...buildShodanFindings({
      domain: input.domain,
      data: input.data,
    }));

    findings.push(...buildMispFindings({
      domain: input.domain,
      data: input.data,
    }));

    findings.push(...buildBrandFindings({
      domain: input.domain,
      brand24: input.brand24,
      brandThreats: input.brandThreats,
    }));

    findings.push(...buildRssFindings({
      domain: input.domain,
      rss: input.rss,
    }));

    // Correlaciones cross-source
    findings.push(...detectCrossSourceCorrelations({
      domain: input.domain,
      data: input.data,
      rss: input.rss,
      snapshot: input.snapshot,
      hasCoverage: input.hasCoverage,
      emailCount: input.emailCount,
      brandThreats: input.brandThreats,
      newCredsLast7d: velocity?.newCredsLast7d ?? 0,
    }));

    // Orden: severity desc + detectedAt desc
    findings.sort((a, b) => {
      const sevDiff = ANALYST_SEVERITY_RANK[b.severity] - ANALYST_SEVERITY_RANK[a.severity];
      if (sevDiff !== 0) return sevDiff;
      return Date.parse(b.detectedAt) - Date.parse(a.detectedAt);
    });

    return findings;
  }, [
    input.domain,
    input.data,
    input.rss,
    input.brand24,
    input.snapshot,
    input.hasCoverage,
    input.emailCount,
    input.brandThreats,
    velocity?.newCredsLast7d,
  ]);
}
