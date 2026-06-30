/**
 * correlations.ts — motor cross-source para detectar campañas activas.
 *
 * No basta con sumar factores individuales: el valor real está en cuándo
 * múltiples señales convergen sobre el mismo dominio víctima. Estas son las
 * 3 correlaciones canónicas (Fase 3 §9.3 del doc):
 *
 *   1. ACTIVE-IMPERSONATION-CAMPAIGN
 *      CT cert nuevo (look-alike) + DNS resolviendo + leak-velocity↑ en 7d
 *      → Atacante registró infra y empezó a usarla.
 *
 *   2. SPOOFING-INFRASTRUCTURE-READY
 *      Typosquatting domain con MX + phishing-kit-match
 *      → Infra preparada para email spoofing y harvest de credenciales.
 *
 *   3. COORDINATED-REPUTATION-CREDENTIAL
 *      Brand24 spike negativo + dominio look-alike resolviendo +
 *      correos en fuga del dominio víctima
 *      → Ataque coordinado de reputación + creds.
 *
 * Función pura — no fetch, no useEffect. Recibe los inputs ya combinados
 * y devuelve `CorrelationFinding[]`.
 */

import type {
  BrandThreat,
  CorrelationFinding,
  CorrelationKind,
  ThreatSeverity,
} from "@/types/digital-surveillance";

export type CorrelationInput = {
  domain: string;
  threats: BrandThreat[];
  /** Cuentas en fuga detectadas en últimas 24h (de leak velocity). */
  newCredsLast24h: number;
  /** Cuentas en fuga en 7d. */
  newCredsLast7d: number;
  /** Ratio Brand24 negativo / total clasificado (0-1). */
  brand24NegRatio: number;
  /** Total clasificado Brand24 (validez estadística). */
  brand24Classified: number;
};

const SEVERITY_RANK: Record<ThreatSeverity, number> = {
  low: 0, medium: 1, high: 2, critical: 3,
};

function maxSeverity(...severities: ThreatSeverity[]): ThreatSeverity {
  return severities.reduce((acc, s) =>
    SEVERITY_RANK[s] > SEVERITY_RANK[acc] ? s : acc,
    "low",
  );
}

export function detectCorrelations(input: CorrelationInput): CorrelationFinding[] {
  const out: CorrelationFinding[] = [];
  const now = new Date().toISOString();

  // Particionar threats por kind para no recorrer N veces.
  const ctThreats   = input.threats.filter((t) => t.kind === "ct-impersonation");
  const typoThreats = input.threats.filter((t) => t.kind === "typosquatting");
  const phishThreats = input.threats.filter((t) => t.kind === "phishing-kit");

  // Helper: ¿hay un CT cert con DNS resolviendo (severity critical)?
  const hasCtResolving = ctThreats.some((t) => t.severity === "critical");
  // Helper: ¿hay un look-alike con MX activo (typo high)?
  const hasTypoMx      = typoThreats.some((t) => t.severity === "high");
  // Helper: ¿hay un look-alike resolviendo (typo high+medium)?
  const hasTypoResolv  = typoThreats.some((t) => t.severity === "high" || t.severity === "medium");
  // Helper: leak velocity > baseline (newCreds7d > 0).
  const hasLeakSpike   = input.newCredsLast7d > 0 || input.newCredsLast24h > 0;
  // Helper: phishing kit activo.
  const hasActivePhish = phishThreats.some((t) => t.severity === "critical");
  // Helper: Brand24 negativo significativo (≥60% con n≥20).
  const hasNegSpike =
    input.brand24Classified >= 20 && input.brand24NegRatio >= 0.6;

  // 1. ACTIVE IMPERSONATION CAMPAIGN ─────────────────────────────────────────
  if (hasCtResolving && hasLeakSpike) {
    const ev = [
      ...ctThreats.filter((t) => t.severity === "critical").map((t) => t.id),
      `velocity-${input.newCredsLast24h}`,
    ];
    const sev = maxSeverity(
      ...ctThreats.filter((t) => t.severity === "critical").map((t) => t.severity),
      "high",
    );
    out.push(buildCorrelation(
      "active-impersonation-campaign",
      sev,
      "Campaña activa de suplantación detectada",
      `Cert TLS look-alike emitido y resolviendo DNS, con incremento de credenciales en fuga ` +
      `(${input.newCredsLast7d} cuenta(s) nuevas en 7d). Posible ataque en curso.`,
      ev,
      now,
    ));
  }

  // 2. SPOOFING INFRASTRUCTURE READY ─────────────────────────────────────────
  if (hasTypoMx && hasActivePhish) {
    const ev = [
      ...typoThreats.filter((t) => t.severity === "high").map((t) => t.id),
      ...phishThreats.filter((t) => t.severity === "critical").map((t) => t.id),
    ];
    out.push(buildCorrelation(
      "spoofing-infrastructure-ready",
      "critical",
      "Infraestructura de spoofing operativa",
      `Dominio look-alike con MX activo y phishing kit reportado en feeds activos. ` +
      `Capaz de enviar correo y harvest de credenciales hoy mismo.`,
      ev,
      now,
    ));
  }

  // 3. COORDINATED REPUTATION + CREDENTIAL ATTACK ────────────────────────────
  if (hasNegSpike && hasTypoResolv && hasLeakSpike) {
    const ev = [
      ...typoThreats.filter((t) => t.severity === "high" || t.severity === "medium").map((t) => t.id),
      `brand24-neg-${Math.round(input.brand24NegRatio * 100)}`,
      `velocity-${input.newCredsLast24h}`,
    ];
    out.push(buildCorrelation(
      "coordinated-reputation-credential",
      "high",
      "Ataque coordinado de reputación + credenciales",
      `Spike de menciones negativas (${Math.round(input.brand24NegRatio * 100)}% sobre ` +
      `${input.brand24Classified}) coincide con look-alike resolviendo y ` +
      `${input.newCredsLast7d} credencial(es) nuevas en fuga.`,
      ev,
      now,
    ));
  }

  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// helper
// ─────────────────────────────────────────────────────────────────────────────

function buildCorrelation(
  kind: CorrelationKind,
  severity: ThreatSeverity,
  title: string,
  detail: string,
  evidenceIds: string[],
  detectedAt: string,
): CorrelationFinding {
  return {
    id: `corr-${kind}-${detectedAt}`,
    kind,
    severity,
    title,
    detail,
    evidenceIds,
    detectedAt,
  };
}
