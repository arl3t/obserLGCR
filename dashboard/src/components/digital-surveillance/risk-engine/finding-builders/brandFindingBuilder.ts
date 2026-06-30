/**
 * brandFindingBuilder — produce findings desde brand24 + brandThreats.
 *
 * Combina dos fuentes:
 *   - `brand24.summary` → sentiment negativo, volume spike
 *   - `brandThreats.threats` → typosquatting/CT/phishing kit (DRP)
 *   - `brandThreats.correlations` → ya vienen como findings tipo correlation
 *
 * Las correlations DRP existentes se exponen como `correlation` kind
 * directamente (sin re-procesar) en el agregador principal — este builder
 * solo emite los hallazgos de Brand24 + threats DRP individuales.
 */

import type {
  SurveillanceBrand24Result,
  SurveillanceBrandThreats,
  AnalystFinding,
  AnalystFindingSeverity,
} from "@/types/digital-surveillance";
import {
  BRAND24_MIN_CLASSIFIED,
  BRAND24_NEG_RATIO_CRITICAL,
  BRAND24_VOL_DELTA_WARN_PERCENT,
} from "@/components/digital-surveillance/risk-engine/thresholds";

export type BrandFindingInput = {
  domain: string;
  brand24: SurveillanceBrand24Result | undefined;
  brandThreats: SurveillanceBrandThreats;
};

export function buildBrandFindings(input: BrandFindingInput): AnalystFinding[] {
  const { domain, brand24, brandThreats } = input;
  const out: AnalystFinding[] = [];
  const detectedAt = new Date().toISOString();

  // ── 1. Sentiment crítico Brand24 ──────────────────────────────────────────
  if (brand24?.summary) {
    const s = brand24.summary;
    const total = s.positiveCount + s.negativeCount;
    const negRatio = total > 0 ? s.negativeCount / total : 0;

    if (total >= BRAND24_MIN_CLASSIFIED && negRatio >= BRAND24_NEG_RATIO_CRITICAL) {
      out.push({
        id: `finding-brand-neg-${domain}`,
        kind: "brand-mention-negative",
        severity: negRatio >= 0.8 ? "high" : "medium",
        title: `Sentimiento crítico en redes — ${Math.round(negRatio * 100)}% negativo`,
        sourceLabel: brand24.source === "live" ? "Brand24 (live)" : `Brand24 (${brand24.source})`,
        evidence: `${s.negativeCount.toLocaleString("es-ES")} menciones negativas sobre ${total.toLocaleString("es-ES")} clasificadas. ` +
          `Volumen total: ${s.volumeMentions.toLocaleString("es-ES")} (${s.volumeDeltaPercent > 0 ? "+" : ""}${s.volumeDeltaPercent}%).`,
        evidenceTimestamp: brand24.fetchedAt,
        why: `Spike de sentimiento negativo en ventana de medición. Si coincide con incidente de seguridad ` +
          `(fuga, downtime, vulnerabilidad pública) requiere coordinación con comunicación. Cruzar con ` +
          `coverage RSS y leak velocity para descartar campaña coordinada.`,
        refs: [
          { tab: "marca", label: "Feed completo", hint: `${total} clasificadas` },
          { tab: "noticias", label: "Cobertura RSS", hint: "comparar con menciones" },
        ],
        actions: [
          {
            id: `brand-neg-case-${domain}`,
            label: "Abrir caso reputacional",
            kind: "open-case",
            primary: true,
            payload: { factor: "brand-negative-spike", negRatio, total },
          },
        ],
        detectedAt,
      });
    } else if (Math.abs(s.volumeDeltaPercent) >= BRAND24_VOL_DELTA_WARN_PERCENT) {
      out.push({
        id: `finding-brand-volume-${domain}`,
        kind: "brand-mention-negative",
        severity: "low",
        title: `Volumen de menciones ${s.volumeDeltaPercent > 0 ? "subió" : "bajó"} ${Math.abs(s.volumeDeltaPercent)}%`,
        sourceLabel: "Brand24",
        evidence: `${s.volumeMentions.toLocaleString("es-ES")} menciones (delta ${s.volumeDeltaPercent > 0 ? "+" : ""}${s.volumeDelta}). ` +
          `Alcance: ${s.socialReach.toLocaleString("es-ES")} social.`,
        evidenceTimestamp: brand24.fetchedAt,
        why: `Cambio significativo de volumen que amerita revisión. Sin spike negativo claro pero conviene ` +
          `auditar la causa.`,
        refs: [{ tab: "marca", label: "Análisis Brand24" }],
        actions: [
          {
            id: `brand-volume-review-${domain}`,
            label: "Revisar feed",
            kind: "navigate-tab",
            payload: { tab: "marca" },
          },
        ],
        detectedAt,
      });
    }
  }

  // ── 2. Threats DRP individuales (typo/CT/phishing) — los `critical` y `high`
  //      pasan al feed; los demás quedan en TabBrand para no saturar.
  for (const t of brandThreats.threats) {
    if (t.severity !== "critical" && t.severity !== "high") continue;

    const sev: AnalystFindingSeverity = t.severity === "critical" ? "critical" : "high";
    const kindLabel = threatKindLabel(t.kind);

    out.push({
      id: `finding-brand-threat-${t.id}`,
      kind: "brand-threat",
      severity: sev,
      title: t.title,
      sourceLabel: t.source,
      evidence: `${kindLabel} · ${t.target}. ${t.detail}`,
      evidenceTimestamp: t.detectedAt,
      why: explainThreatWhy(t.kind),
      refs: [
        { tab: "marca", label: "Detalle DRP", hint: t.target },
      ],
      actions: [
        {
          id: `brand-threat-case-${t.id}`,
          label: "Abrir caso",
          kind: "open-case",
          primary: true,
          payload: { factor: t.kind, target: t.target },
        },
        {
          id: `brand-threat-watchlist-${t.id}`,
          label: "Vigilar dominio",
          kind: "add-watchlist",
          payload: { target: t.target },
        },
      ],
      detectedAt,
    });
  }

  return out;
}

function threatKindLabel(kind: string): string {
  switch (kind) {
    case "ct-impersonation":   return "Cert TLS look-alike";
    case "typosquatting":       return "Dominio look-alike registrado";
    case "phishing-kit":        return "Kit de phishing detectado";
    case "leak-velocity":       return "Spike de credenciales en fuga";
    case "impersonation-confidence": return "Suplantación visual";
    default:                    return kind;
  }
}

function explainThreatWhy(kind: string): string {
  switch (kind) {
    case "ct-impersonation":
      return "Atacante registró un certificado TLS para un dominio similar al tuyo. Si resuelve DNS, " +
        "ya tiene infraestructura para hostear phishing convincente con el candado verde.";
    case "typosquatting":
      return "Dominio look-alike registrado y resolviendo. Si tiene MX activo, puede recibir y enviar " +
        "correo simulando ser la organización — vector clásico de BEC y harvesting.";
    case "phishing-kit":
      return "Kit de phishing reportado en feeds activos (URLhaus/OpenPhish). El atacante ya tiene la " +
        "página de captura desplegada; el bloqueo en proxy/DNS corporativo es prioridad.";
    case "leak-velocity":
      return "Velocidad de aparición de credenciales por encima del baseline — indica filtración activa " +
        "en curso, no una fuga histórica.";
    default:
      return "Amenaza detectada por el motor DRP que requiere triage del SOC.";
  }
}
