/**
 * phishingKitBuilder — feeds activos URLhaus / OpenPhish (Fase 3 §9.1).
 *
 * Reglas:
 *   - Match con `reportedAt ≤ 7d` → severity `critical` (campaña activa)
 *   - Match más antiguo → `high` (histórico)
 */

import type {
  BrandThreat,
  PhishingKitMatch,
} from "@/types/digital-surveillance";

const ACTIVE_WINDOW_DAYS = 7;

function isActiveMatch(match: PhishingKitMatch, now: number): boolean {
  const t = Date.parse(match.reportedAt);
  if (!Number.isFinite(t)) return false;
  const ageDays = (now - t) / (24 * 3_600_000);
  return ageDays <= ACTIVE_WINDOW_DAYS;
}

export function buildPhishingKitThreats(
  matches: PhishingKitMatch[] | undefined,
  now = Date.now(),
): BrandThreat[] {
  if (!matches?.length) return [];
  return matches.map((m, i) => {
    const active = isActiveMatch(m, now);
    return {
      id: `phish-${m.hash ?? i}`,
      kind: "phishing-kit" as const,
      severity: active ? ("critical" as const) : ("high" as const),
      title: active
        ? `Phishing kit activo: ${m.url}`
        : `Phishing kit reportado: ${m.url}`,
      detail: `Fuente ${m.source}${m.tags.length > 0 ? ` · ${m.tags.slice(0, 3).join(", ")}` : ""}${m.hash ? ` · hash ${m.hash.slice(0, 12)}…` : ""}`,
      target: m.url,
      detectedAt: m.reportedAt,
      source: m.source,
    };
  });
}
