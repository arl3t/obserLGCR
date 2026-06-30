/**
 * ctImpersonationBuilder — convierte CT logs en `BrandThreat[]`.
 *
 * Reglas (Fase 3 §9.1):
 *   - Cert ≤24h + DNS resuelve → severity `critical` (CT_SCORE.FRESH_RESOLVING)
 *   - Cert ≤24h sin DNS → `high` (FRESH_PARKED, infra preparándose)
 *   - Cert >24h y ≤7d → `medium`
 *   - Resto → filtrados (no aporta señal)
 *
 * Función pura — testeable sin red.
 */

import {
  CT_FRESH_WINDOW_HOURS,
  CT_LOOK_ALIKE_THRESHOLD,
} from "@/components/digital-surveillance/risk-engine/thresholds";
import type {
  BrandThreat,
  CTCertificate,
  ThreatSeverity,
} from "@/types/digital-surveillance";

/** Horas transcurridas entre `loggedAt` y ahora — cap a 0 si futuro. */
function hoursAgo(loggedAt: string, now = Date.now()): number {
  const t = Date.parse(loggedAt);
  if (!Number.isFinite(t)) return Infinity;
  return Math.max(0, (now - t) / 3_600_000);
}

function severityForCert(cert: CTCertificate, hAgo: number): ThreatSeverity | null {
  if (cert.lookAlikeScore < CT_LOOK_ALIKE_THRESHOLD) return null;
  if (hAgo <= CT_FRESH_WINDOW_HOURS && cert.resolvesDns) return "critical";
  if (hAgo <= CT_FRESH_WINDOW_HOURS) return "high";
  if (hAgo <= 24 * 7) return "medium";
  return "low";
}

export function buildCTImpersonationThreats(
  certs: CTCertificate[] | undefined,
  now = Date.now(),
): BrandThreat[] {
  if (!certs?.length) return [];
  return certs.flatMap((cert) => {
    const hAgo = hoursAgo(cert.loggedAt, now);
    const severity = severityForCert(cert, hAgo);
    if (!severity || severity === "low") return [];
    const ageLabel = hAgo < 1 ? "<1h" : hAgo < 24 ? `${Math.round(hAgo)}h` : `${Math.round(hAgo / 24)}d`;
    const dnsLabel = cert.resolvesDns ? "DNS activo" : "sin DNS";
    return [{
      id: `ct-${cert.id}`,
      kind: "ct-impersonation",
      severity,
      title: `Cert look-alike emitido para ${cert.domain}`,
      detail: `Issuer ${cert.issuer} · similaridad ${(cert.lookAlikeScore * 100).toFixed(0)}% · ${ageLabel} · ${dnsLabel}`,
      target: cert.domain,
      detectedAt: cert.loggedAt,
      source: "Certificate Transparency",
    }];
  });
}
