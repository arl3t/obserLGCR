/**
 * Punto de entrada del motor de alertas accionables.
 *
 * Combina las 5 fuentes de Vigilancia Digital (Shodan / MISP / Brand24 / RSS /
 * leak-intel) en una lista única ordenable por severidad. Cada builder es
 * puro y testeable por separado (`shared/alert-builders.ts`); este módulo
 * sólo orquesta y deduplica.
 *
 * Los umbrales que cada builder usa viven en `risk-engine/thresholds.ts` —
 * cualquier cambio se hace en un único lugar (resuelve §7.1.2 del doc de
 * referencia: triplicidad de umbrales Brand24).
 *
 * Uso típico desde el módulo (vía Provider):
 *
 *   const { alerts } = useSurveillance();   // ya consumió buildAllAlerts internamente
 *
 * Uso aislado (tests, exportación PDF, ad-hoc):
 *
 *   const alerts = buildAllAlerts({ data, brand24, rss, snapshot, emailCount });
 */

import {
  buildBrandAlerts,
  buildCredencialesAlerts,
  buildDarkWebAlerts,
  buildGlobalAlerts,
  buildInfraAlerts,
  buildNoticiasAlerts,
} from "@/components/digital-surveillance/shared/alert-builders";
import type { Alert, AlertSeverity } from "@/components/digital-surveillance/shared/AlertsBlock";
import type { LeakIntelHubSnapshot } from "@/store/leak-intel-hub-store";
import type {
  SurveillanceBrand24Result,
  SurveillanceDomainResult,
  SurveillanceRssResult,
} from "@/types/digital-surveillance";

export type BuildAllAlertsInput = {
  data: SurveillanceDomainResult;
  brand24?: SurveillanceBrand24Result | null;
  rss?: SurveillanceRssResult | null;
  snapshot?: LeakIntelHubSnapshot | null;
  emailCount: number;
};

const SEVERITY_RANK: Record<AlertSeverity, number> = { high: 3, medium: 2, low: 1 };

/**
 * Construye TODAS las alertas del módulo y las devuelve ordenadas por
 * severidad descendente (high → medium → low). Dedupe por `id`.
 *
 * Si `data` aún no llegó del backend, devuelve `[]` (no lanza).
 */
export function buildAllAlerts(input: BuildAllAlertsInput): Alert[] {
  const merged = buildGlobalAlerts(input);
  return merged.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
}

/**
 * Particiona alertas por dominio de origen — útil para mostrarlas dentro de
 * cada tab sin tener que volver a llamar a los builders por separado.
 */
export function partitionAlertsByKind(alerts: Alert[]): {
  infra: Alert[];
  darkweb: Alert[];
  brand: Alert[];
  noticias: Alert[];
  creds: Alert[];
} {
  const buckets = { infra: [], darkweb: [], brand: [], noticias: [], creds: [] } as Record<
    "infra" | "darkweb" | "brand" | "noticias" | "creds",
    Alert[]
  >;
  for (const a of alerts) {
    if (a.id.startsWith("infra:"))      buckets.infra.push(a);
    else if (a.id.startsWith("ioc:"))   buckets.darkweb.push(a);
    else if (a.id.startsWith("brand:")) buckets.brand.push(a);
    else if (a.id.startsWith("noticias:")) buckets.noticias.push(a);
    else if (a.id.startsWith("creds:")) buckets.creds.push(a);
  }
  return buckets;
}

// Re-exports — desde aquí también para que los call-sites nuevos no toquen
// `shared/alert-builders.ts` directamente. Los antiguos siguen funcionando.
export {
  buildInfraAlerts,
  buildDarkWebAlerts,
  buildBrandAlerts,
  buildNoticiasAlerts,
  buildCredencialesAlerts,
};
export type { Alert, AlertSeverity };
