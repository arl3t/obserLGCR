/**
 * plugins.ts — registry de builders del motor de scoring (#10).
 *
 * Cada plugin es una función pura que recibe el `ClientRiskInput` y devuelve
 * 0+ `RiskFactorItem`. La separación permite:
 *   1. Versionar cada builder por separado → trazabilidad fina.
 *   2. Activar/desactivar plugins por sub o por config global.
 *   3. Rollout gradual de cambios — agregar un plugin v2 sin tocar v1.
 *
 * El registry vive como módulo singleton (top-level `const`). En el futuro
 * puede pasar a init dinámico si se necesita carga lazy o A/B testing.
 */

import type { BrandThreat, RiskFactorItem, ThreatKind } from "@/types/digital-surveillance";
import {
  CREDS_MASS_LEAK_THRESHOLD,
  BRAND24_NEG_RATIO_CRITICAL,
  BRAND24_VOL_DELTA_WARN_PERCENT,
  BRAND24_MIN_CLASSIFIED,
} from "@/components/digital-surveillance/risk-engine/thresholds";

export type BuilderInput = {
  emailCount?: number;
  weakPwdRate?: number;
  brand24NegRatio?: number;
  brand24Classified?: number;
  brand24VolumeDeltaPct?: number;
  ctiHitsCount?: number;
  ctiTopLeakNames?: string[];
  threats?: BrandThreat[];
};

export type BuilderPlugin = {
  /** Identificador estable — se usa también como prefijo del factor.id. */
  id: string;
  /** Semver del plugin. Cambiar cuando se altere la fórmula. */
  version: string;
  /** Descripción legible para el UI de configuración / debug. */
  label: string;
  /** Computa los factors. Puede retornar 0+ items. */
  build(input: BuilderInput): RiskFactorItem[];
};

// ── Plugins concretos ────────────────────────────────────────────────────────

const credsLeakPlugin: BuilderPlugin = {
  id: "creds-leak",
  version: "1.0.0",
  label: "Credenciales corporativas en dumps",
  build({ emailCount }) {
    if ((emailCount ?? 0) < 1) return [];
    const count = emailCount ?? 0;
    const ratio = count / CREDS_MASS_LEAK_THRESHOLD;
    const score = Math.min(25, Math.max(5, Math.round(ratio * 25)));
    return [{
      id: "client-creds-leak",
      title: "Credenciales corporativas en dumps",
      detail: `${count} cuenta(s) detectada(s) en el snapshot local.`,
      score,
    }];
  },
};

const weakPwdPlugin: BuilderPlugin = {
  id: "weak-pwd",
  version: "1.0.0",
  label: "Alta tasa de contraseñas débiles",
  build({ weakPwdRate, emailCount }) {
    if ((weakPwdRate ?? 0) < 0.5 || (emailCount ?? 0) < 10) return [];
    const pct = Math.round((weakPwdRate ?? 0) * 100);
    const score = Math.min(15, Math.round(pct / 8));
    return [{
      id: "client-weak-pwd-rate",
      title: "Alta tasa de contraseñas débiles",
      detail: `${pct}% de contraseñas muestreadas marcadas como débiles.`,
      score,
    }];
  },
};

const brand24NegPlugin: BuilderPlugin = {
  id: "brand24-neg",
  version: "1.0.0",
  label: "Spike de menciones negativas Brand24",
  build({ brand24NegRatio, brand24Classified }) {
    if (
      (brand24NegRatio ?? 0) < BRAND24_NEG_RATIO_CRITICAL ||
      (brand24Classified ?? 0) < BRAND24_MIN_CLASSIFIED
    ) return [];
    const pct = Math.round((brand24NegRatio ?? 0) * 100);
    const score = Math.min(20, Math.round((brand24NegRatio ?? 0) * 25));
    return [{
      id: "client-brand24-neg-ratio",
      title: "Spike de menciones negativas",
      detail: `${pct}% del feed Brand24 clasificado como negativo (n=${brand24Classified}).`,
      score,
    }];
  },
};

const brand24VolumePlugin: BuilderPlugin = {
  id: "brand24-volume",
  version: "1.0.0",
  label: "Anomalía de volumen Brand24",
  build({ brand24VolumeDeltaPct }) {
    if ((brand24VolumeDeltaPct ?? 0) < BRAND24_VOL_DELTA_WARN_PERCENT) return [];
    const score = Math.min(
      10,
      Math.round((brand24VolumeDeltaPct ?? 0) / BRAND24_VOL_DELTA_WARN_PERCENT) * 5,
    );
    return [{
      id: "client-brand24-volume-spike",
      title: "Anomalía de volumen Brand24",
      detail: `+${Math.round(brand24VolumeDeltaPct ?? 0)}% vs período anterior.`,
      score,
    }];
  },
};

const ctiLeaksPlugin: BuilderPlugin = {
  id: "cti-leaks",
  version: "1.1.0", // bump cuando se agregue (vs ausente en v1.0.0)
  label: "Credenciales filtradas (CTI Cloud & Olé)",
  build({ ctiHitsCount, ctiTopLeakNames }) {
    if ((ctiHitsCount ?? 0) < 1) return [];
    const hits = ctiHitsCount ?? 0;
    const score = hits >= 200 ? 30
      : hits >= 50  ? 22
      : hits >= 10  ? 15
      : 8;
    const topNames = (ctiTopLeakNames ?? []).slice(0, 3);
    return [{
      id: "client-cti-leaks",
      title: "Credenciales filtradas (CTI Cloud & Olé)",
      detail: topNames.length > 0
        ? `${hits} hit(s) · top: ${topNames.join(", ")}`
        : `${hits} credencial(es) expuesta(s) detectada(s) en CTI.`,
      score,
    }];
  },
};

// ── DRP threats — agregado por kind (1 factor por kind, capped). ────────────

const DRP_KIND_CAP: Record<ThreatKind, number> = {
  "ct-impersonation":          45,
  "typosquatting":              35,
  "leak-velocity":              40,
  "phishing-kit":               50,
  "impersonation-confidence":   50,
};
const DRP_KIND_TITLE: Record<ThreatKind, string> = {
  "ct-impersonation":          "Suplantación de marca (CT logs)",
  "typosquatting":              "Dominios look-alike registrados",
  "leak-velocity":              "Velocidad de fuga de credenciales",
  "phishing-kit":               "Phishing kit detectado",
  "impersonation-confidence":   "Suplantación visual (modelo IA)",
};
function scoreForSeverity(severity: BrandThreat["severity"]): number {
  switch (severity) {
    case "critical": return 35;
    case "high":     return 20;
    case "medium":   return 10;
    case "low":      return 3;
  }
}

const drpThreatsPlugin: BuilderPlugin = {
  id: "drp-threats",
  version: "1.0.0",
  label: "DRP threats (CT/typo/velocity/phishing)",
  build({ threats }) {
    if (!threats?.length) return [];
    const byKind = new Map<ThreatKind, BrandThreat[]>();
    for (const t of threats) {
      const arr = byKind.get(t.kind) ?? [];
      arr.push(t);
      byKind.set(t.kind, arr);
    }
    const out: RiskFactorItem[] = [];
    for (const [kind, items] of byKind) {
      const raw = items.reduce((acc, t) => acc + scoreForSeverity(t.severity), 0);
      const score = Math.min(DRP_KIND_CAP[kind], raw);
      if (score <= 0) continue;
      const top = items.sort(
        (a, b) => scoreForSeverity(b.severity) - scoreForSeverity(a.severity),
      )[0];
      out.push({
        id: `client-${kind}`,
        title: DRP_KIND_TITLE[kind],
        detail: `${items.length} hallazgo(s) · top: ${top.title}`,
        score,
      });
    }
    return out;
  },
};

// ── Registry ─────────────────────────────────────────────────────────────────

/**
 * Orden importa para la deduplicación de factor ids cuando dos plugins
 * pudieran emitir el mismo id (no debería pasar). El primero que registra
 * un id gana.
 */
export const BUILDER_REGISTRY: ReadonlyArray<BuilderPlugin> = [
  credsLeakPlugin,
  weakPwdPlugin,
  brand24NegPlugin,
  brand24VolumePlugin,
  ctiLeaksPlugin,
  drpThreatsPlugin,
];

/** Mapa { pluginId → version } — útil para persistir en snapshots de análisis. */
export function getPluginVersions(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const p of BUILDER_REGISTRY) out[p.id] = p.version;
  return out;
}
