/**
 * typosquattingBuilder — convierte resultados dnstwist en `BrandThreat[]`.
 *
 * Reglas (Fase 3 §9.1):
 *   - Candidato con MX activo → severity `high` (email spoofing-ready)
 *   - Candidato con DNS A pero sin MX → `medium` (parking / squat)
 *   - Solo registrado sin DNS → `low` (informativo, descartado del feed)
 *
 * Filtra candidatos por `TYPO_SIMILARITY_THRESHOLD` para no inundar al
 * analista con permutaciones improbables.
 */

import { TYPO_SIMILARITY_THRESHOLD } from "@/components/digital-surveillance/risk-engine/thresholds";
import type {
  BrandThreat,
  ThreatSeverity,
  TypoCandidate,
} from "@/types/digital-surveillance";

function severityForCandidate(c: TypoCandidate): ThreatSeverity | null {
  if (c.similarity < TYPO_SIMILARITY_THRESHOLD) return null;
  if (c.hasMx) return "high";
  if (c.hasA) return "medium";
  return null;  // sin DNS resolviendo, no es accionable v1
}

export function buildTyposquattingThreats(
  candidates: TypoCandidate[] | undefined,
): BrandThreat[] {
  if (!candidates?.length) return [];
  return candidates.flatMap((c) => {
    const severity = severityForCandidate(c);
    if (!severity) return [];
    const flags = [
      c.hasA && "A",
      c.hasMx && "MX",
      c.hasHttp && "HTTP",
    ].filter(Boolean).join(" · ");
    return [{
      id: `typo-${c.domain}`,
      kind: "typosquatting",
      severity,
      title: c.hasMx
        ? `Look-alike con MX activo: ${c.domain}`
        : `Dominio look-alike registrado: ${c.domain}`,
      detail: `Mutación ${c.mutation} · similaridad ${(c.similarity * 100).toFixed(0)}%${flags ? ` · ${flags}` : ""}`,
      target: c.domain,
      detectedAt: c.firstSeen ?? new Date().toISOString(),
      source: "dnstwist",
    }];
  });
}
