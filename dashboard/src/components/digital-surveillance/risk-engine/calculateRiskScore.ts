/**
 * Recompute frontend del Risk Score — función pura.
 *
 * Origen de verdad sigue siendo el backend (`/api/surveillance/domain` →
 * `risk.score` ya consolidado). Esta función existe para dos casos:
 *
 *   1. **Modo offline / backend caído.** Cuando `backendScore` no está
 *      disponible, recomputamos un estimado conservador a partir de los
 *      datos que el cliente sí tiene en memoria (snapshot Leak Intel Hub,
 *      summary Brand24).
 *
 *   2. **What-if cliente.** Vistas como TabResumen o TabEjecutivo pueden
 *      añadir factores locales (sentimiento negativo, ratio de credenciales
 *      débiles) sin esperar a que el backend los integre. El resultado es
 *      determinístico y testeable.
 *
 * Convención: el score se clampa a [0, 100] y la banda se deriva de
 * `RISK_BAND` (single source of truth). Un factor con `score = 0` no se
 * incluye en el resultado — se filtra para no agregar ruido visual.
 *
 * Ver `docs/REWRITE-VIGILANCIA-PROGRESO.md §5.7` para el roadmap completo
 * (Fase 3 añade factores de impersonation/typosquatting/CT logs aquí mismo).
 */

import type {
  BrandThreat,
  RiskBand,
  RiskFactorItem,
  ThreatKind,
} from "@/types/digital-surveillance";
import { RISK_BAND } from "@/components/digital-surveillance/risk-engine/thresholds";
import {
  BUILDER_REGISTRY,
  getPluginVersions,
} from "@/components/digital-surveillance/risk-engine/plugins";

// ─────────────────────────────────────────────────────────────────────────────
// Tipos públicos
// ─────────────────────────────────────────────────────────────────────────────

export type ClientRiskInput = {
  /** Score del backend cuando está disponible. Si no, se omite. */
  backendScore?: number;
  /** Factores ya calculados por el backend (Shodan, MISP, etc.). */
  backendFactors?: RiskFactorItem[];

  // ── Inputs cliente — datos del navegador no visibles al backend ──

  /** Cuentas del dominio detectadas en el snapshot Leak Intel Hub local. */
  emailCount?: number;
  /** Ratio de contraseñas débiles del snapshot (0-1). */
  weakPwdRate?: number;
  /** Ratio de menciones negativas Brand24 (0-1). */
  brand24NegRatio?: number;
  /** Muestras clasificadas Brand24 (validación estadística). */
  brand24Classified?: number;
  /** Delta de volumen Brand24 vs período anterior (porcentaje absoluto). */
  brand24VolumeDeltaPct?: number;

  // ── CTI Cloud & Olé (#7 — builder integrado) ──
  /** Hits de credenciales filtradas detectadas vía CTI para el dominio. */
  ctiHitsCount?: number;
  /** Top N leaks por nombre (RedLine, AT&T, etc.) — usado en el detail. */
  ctiTopLeakNames?: string[];

  // ── Inputs DRP — Fase 3 §9.1 (CT, typosquatting, leak velocity, phishing kit) ──
  /** Feed unificado de amenazas en tiempo real. Cada item se mapea a un
   *  factor capped por kind para no inundar el score. */
  threats?: BrandThreat[];
};

export type ClientRiskResult = {
  /** Score 0-100, clamped. */
  score: number;
  /** Banda derivada de `RISK_BAND`. */
  band: RiskBand;
  /** Factores combinados (backend + cliente, score > 0). */
  factors: RiskFactorItem[];
  /** Indica si el resultado depende sólo de datos cliente (offline mode). */
  offline: boolean;
  /** Versión del motor de scoring — sirve para auditoría y rollout
   *  gradual (#10). Cambiar cuando se agregue/quite un builder o se ajusten
   *  thresholds que muevan el score histórico. */
  engineVersion: string;
  /** Snapshot de versiones de cada plugin activo. Persistido junto al
   *  análisis para reproducir el score offline. */
  pluginVersions: Record<string, string>;
};

/**
 * Versión semántica del motor:
 *   v1.0.0 — backend + creds + brand24 + DRP threats.
 *   v1.1.0 — agrega builder CTI Cloud & Olé (#7).
 *   v1.2.0 — refactor a plugin registry (#10). El score numérico no cambia
 *            vs v1.1.0 (mismos plugins, misma fórmula), pero el output ahora
 *            incluye `pluginVersions` por builder.
 *
 * Cambiar este string CADA vez que se modifica una fórmula que afecte el
 * score histórico — los snapshots persisten `risk_score` y `risk_band`
 * crudos, pero la `engineVersion` + `pluginVersions` permiten trazar diff
 * en informes.
 */
export const RISK_ENGINE_VERSION = "v1.2.0";

// ─────────────────────────────────────────────────────────────────────────────
// Función pura
// ─────────────────────────────────────────────────────────────────────────────

export function calculateRiskScore(input: ClientRiskInput): ClientRiskResult {
  const offline = input.backendScore === undefined;
  const backendScore = clamp01to100(input.backendScore ?? 0);
  const backendFactors = (input.backendFactors ?? []).filter((f) => f.score > 0);

  const clientFactors = computeClientFactors(input);
  const clientAdder = clientFactors.reduce((acc, f) => acc + f.score, 0);

  // El backend ya integra factores propios; los cliente se suman encima.
  // Cuando estamos offline, el "backendScore" inicial es 0 y solo aportan los
  // factores cliente.
  const rawScore = backendScore + clientAdder;
  const score = clamp01to100(rawScore);
  const band = bandFromScore(score);

  return {
    score,
    band,
    factors: dedupeById([...backendFactors, ...clientFactors]),
    offline,
    engineVersion: RISK_ENGINE_VERSION,
    pluginVersions: getPluginVersions(),
  };
}

/** Atajo: solo banda a partir del score (mismo umbral que `bandFromScore` en
 *  `lib/digital-surveillance-api.ts`). Reexportado por compat. */
export function bandFromScore(score: number): RiskBand {
  if (score >= RISK_BAND.high) return "high";
  if (score >= RISK_BAND.medium) return "medium";
  return "low";
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers internos
// ─────────────────────────────────────────────────────────────────────────────

function clamp01to100(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

function dedupeById(factors: RiskFactorItem[]): RiskFactorItem[] {
  const seen = new Set<string>();
  const out: RiskFactorItem[] = [];
  for (const f of factors) {
    if (seen.has(f.id)) continue;
    seen.add(f.id);
    out.push(f);
  }
  return out;
}

/**
 * Itera el registry de plugins y agrega factors. Cada plugin es responsable
 * de sus propios thresholds, caps y formato del detail (#10).
 */
function computeClientFactors(input: ClientRiskInput): RiskFactorItem[] {
  const out: RiskFactorItem[] = [];
  for (const plugin of BUILDER_REGISTRY) {
    try {
      out.push(...plugin.build(input));
    } catch (err) {
      // Un plugin defectuoso no debe romper el motor — log y seguimos con
      // los otros. El score histórico se preserva mejor degradando que
      // tirando el cómputo entero.
      // eslint-disable-next-line no-console
      console.warn(`[risk-engine] plugin '${plugin.id}' v${plugin.version} failed:`, err);
    }
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// DRP — Fase 3 §9.1
// ─────────────────────────────────────────────────────────────────────────────

/** Aporte máximo permitido por kind (para que múltiples threats del mismo
 *  tipo no dominen la suma). */
const KIND_CAP: Record<ThreatKind, number> = {
  "ct-impersonation":          45,
  "typosquatting":              35,
  "leak-velocity":              40,
  "phishing-kit":               50,
  "impersonation-confidence":   50,
};

/** Score por threat según severity. */
function scoreForSeverity(severity: BrandThreat["severity"]): number {
  switch (severity) {
    case "critical": return 35;
    case "high":     return 20;
    case "medium":   return 10;
    case "low":      return 3;
  }
}

/** Convierte el feed unificado de threats en factors agregados (1 factor por
 *  kind, capped). Skip kinds sin threats. */
export function threatsToFactors(threats: BrandThreat[] | undefined): RiskFactorItem[] {
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
    const score = Math.min(KIND_CAP[kind], raw);
    if (score <= 0) continue;
    const top = items.sort(
      (a, b) => scoreForSeverity(b.severity) - scoreForSeverity(a.severity),
    )[0];
    out.push({
      id: `client-${kind}`,
      title: KIND_TITLE[kind],
      detail: `${items.length} hallazgo(s) · top: ${top.title}`,
      score,
    });
  }
  return out;
}

const KIND_TITLE: Record<ThreatKind, string> = {
  "ct-impersonation":          "Suplantación de marca (CT logs)",
  "typosquatting":              "Dominios look-alike registrados",
  "leak-velocity":              "Velocidad de fuga de credenciales",
  "phishing-kit":               "Phishing kit detectado",
  "impersonation-confidence":   "Suplantación visual (modelo IA)",
};
