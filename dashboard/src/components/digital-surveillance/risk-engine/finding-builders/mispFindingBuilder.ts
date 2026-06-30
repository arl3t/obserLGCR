/**
 * mispFindingBuilder — produce findings desde data.misp.hits.
 *
 * Estrategia: agrupar por categoría/tag para no saturar el feed con N hits
 * (un dominio puede tener 50+ atributos en MISP). Genera 1 finding por
 * categoría crítica detectada + 1 finding agregado para ruido informativo.
 */

import type { SurveillanceDomainResult } from "@/types/digital-surveillance";
import type { AnalystFinding, AnalystFindingSeverity } from "@/types/digital-surveillance";
import {
  MISP_CRITICAL_CATEGORIES,
  MISP_CRITICAL_TAG_PATTERNS,
} from "@/components/digital-surveillance/risk-engine/thresholds";

export type MispFindingInput = {
  domain: string;
  data: SurveillanceDomainResult;
};

export function buildMispFindings(input: MispFindingInput): AnalystFinding[] {
  const { domain, data } = input;
  if (!data.misp.configured || data.misp.error) return [];

  const hits = data.misp.hits ?? [];
  if (hits.length === 0) return [];

  const out: AnalystFinding[] = [];
  const detectedAt = new Date().toISOString();

  // Particionar por severidad inferida de tags + categoría.
  const critical: typeof hits = [];
  const informational: typeof hits = [];

  for (const h of hits) {
    const tagsLower = (h.tags ?? []).map((t) => t.toLowerCase());
    const matchesCriticalTag = MISP_CRITICAL_TAG_PATTERNS.some(
      (p) => tagsLower.some((t) => t.includes(p)),
    );
    const matchesCriticalCat = MISP_CRITICAL_CATEGORIES.has(h.category);
    if (matchesCriticalTag || matchesCriticalCat) {
      critical.push(h);
    } else {
      informational.push(h);
    }
  }

  // 1. Findings críticos — agrupados por kind de tag (botnet/stealer/etc)
  if (critical.length > 0) {
    // Detectar patrón dominante
    const kindCounts = new Map<string, number>();
    for (const h of critical) {
      for (const pattern of MISP_CRITICAL_TAG_PATTERNS) {
        if ((h.tags ?? []).some((t) => t.toLowerCase().includes(pattern))) {
          kindCounts.set(pattern, (kindCounts.get(pattern) ?? 0) + 1);
        }
      }
    }
    const topKind = [...kindCounts.entries()].sort((a, b) => b[1] - a[1])[0];
    const kindLabel = topKind ? topKind[0] : "amenaza";
    const sample = critical.slice(0, 3).map((h) => `${h.type}:${h.value}`).join(" · ");

    out.push({
      id: `finding-misp-critical-${domain}`,
      kind: "misp-ioc",
      severity: critical.length >= 5 ? "critical" : "high",
      title: `${critical.length} IOC(s) críticos en MISP — ${kindLabel}`,
      sourceLabel: "MISP threat intel",
      evidence: `Atributos clasificados como ${kindLabel}. Muestra: ${sample}` +
        (critical.length > 3 ? ` · +${critical.length - 3} más` : ""),
      evidenceTimestamp: critical[0]?.timestamp ?? null,
      why: `IOCs activos asociados a ${kindLabel} — bloqueo en perímetro y validación contra logs SIEM ` +
        `(últimos 90d) son acciones P2 obligatorias. Si los IOCs aparecen también en Shodan, hay infra ` +
        `comprometida activa.`,
      refs: [
        { tab: "darkweb", label: "Tabla MISP completa", hint: `${critical.length} hits` },
        { tab: "analisis", label: "Cruzar con Shodan", hint: "buscar IPs MISP en infra propia" },
      ],
      actions: [
        {
          id: `misp-critical-case-${domain}`,
          label: "Abrir caso (bloqueo IOC)",
          kind: "open-case",
          primary: true,
          payload: { factor: "misp-critical-iocs", count: critical.length, kind: kindLabel },
        },
        {
          id: `misp-critical-copy-${domain}`,
          label: `Copiar ${critical.length} IOC(s)`,
          kind: "block-ioc",
          payload: {
            iocs: critical.map((h) => h.value).join("\n"),
            count: critical.length,
          },
        },
      ],
      detectedAt,
    });
  }

  // 2. Findings informativos — uno solo agregado si hay ≥ 1
  if (informational.length > 0) {
    const severity: AnalystFindingSeverity =
      informational.length >= 20 ? "medium" : "low";
    const sample = informational.slice(0, 3).map((h) => `${h.type}`).join(", ");

    out.push({
      id: `finding-misp-info-${domain}`,
      kind: "misp-ioc",
      severity,
      title: `${informational.length} atributo(s) MISP informativos`,
      sourceLabel: "MISP threat intel",
      evidence: `Atributos sin tags de actividad activa: ${sample}` +
        (informational.length > 3 ? ` · +${informational.length - 3} más` : ""),
      evidenceTimestamp: informational[0]?.timestamp ?? null,
      why: `Cobertura defensiva — IOCs documentados en feeds para correlación con detecciones futuras. ` +
        `Triagear contra logs últimos 90 días para descartar contacto pasado.`,
      refs: [
        { tab: "darkweb", label: "Detalle MISP", hint: `${informational.length} atributos` },
      ],
      actions: [
        {
          id: `misp-info-review-${domain}`,
          label: "Revisar en MISP",
          kind: "navigate-tab",
          payload: { tab: "darkweb" },
        },
      ],
      detectedAt,
    });
  }

  return out;
}
