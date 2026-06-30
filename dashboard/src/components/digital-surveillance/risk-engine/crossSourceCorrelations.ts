/**
 * crossSourceCorrelations.ts — correlaciones que cruzan fuentes que NO viven
 * en el subsistema DRP (que ya tiene su propio motor en `correlations.ts`).
 *
 * Estas reglas miran datos de Shodan, MISP, snapshot de credenciales y RSS
 * para detectar patrones que un analista hilaría manualmente revisando
 * múltiples tabs. Output directo en formato `AnalystFinding` con
 * kind="correlation" — entran al feed unificado del Workspace del Analista.
 *
 * Reglas implementadas:
 *   1. SHODAN ∩ MISP — IP visible en infra propia coincide con IOC malicioso
 *   2. CREDENCIALES ∩ BRAND THREATS — fuga activa + dominio look-alike registrado
 *   3. RSS ∩ LEAK VELOCITY — spike de cobertura + spike de credenciales en fuga
 *
 * Función pura. Recibe los inputs ya combinados del Provider y no toca DOM
 * ni red.
 */

import type {
  AnalystFinding,
  AnalystFindingSeverity,
  SurveillanceBrandThreats,
  SurveillanceDomainResult,
  SurveillanceRssResult,
} from "@/types/digital-surveillance";
import type { LeakIntelHubSnapshot } from "@/store/leak-intel-hub-store";
import {
  MISP_CRITICAL_TAG_PATTERNS,
  RSS_COVERAGE_SPIKE,
} from "@/components/digital-surveillance/risk-engine/thresholds";

export type CrossSourceInput = {
  domain: string;
  data: SurveillanceDomainResult | undefined;
  rss: SurveillanceRssResult | undefined;
  snapshot: LeakIntelHubSnapshot | null;
  hasCoverage: boolean;
  emailCount: number;
  brandThreats: SurveillanceBrandThreats;
  /** Velocity sin endpoint backend devuelve 0/0 — la regla 3 chequea esto. */
  newCredsLast7d: number;
};

export function detectCrossSourceCorrelations(
  input: CrossSourceInput,
): AnalystFinding[] {
  const out: AnalystFinding[] = [];
  const detectedAt = new Date().toISOString();

  // ── REGLA 1: SHODAN ∩ MISP ──────────────────────────────────────────────────
  // Si una IP en infra propia (Shodan) aparece en MISP como IOC malicioso,
  // hay infra comprometida activa — máxima prioridad.
  out.push(...ruleShodanMisp(input, detectedAt));

  // ── REGLA 2: CREDENCIALES ∩ BRAND THREATS ──────────────────────────────────
  // Fuga activa de credenciales + dominio look-alike resolviendo / phishing kit
  // → posible cadena: phisher recolecta creds para futuro ATO o resale.
  out.push(...ruleCredsBrand(input, detectedAt));

  // ── REGLA 3: RSS ∩ LEAK VELOCITY ───────────────────────────────────────────
  // Spike de cobertura mediática coincide con spike de credenciales en fuga
  // → fuga ya pública, comunicación coordinada requerida.
  out.push(...ruleRssLeak(input, detectedAt));

  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Regla 1: Shodan ∩ MISP
// ─────────────────────────────────────────────────────────────────────────────

function ruleShodanMisp(input: CrossSourceInput, detectedAt: string): AnalystFinding[] {
  const { domain, data } = input;
  if (!data?.shodan.configured || !data.misp.configured) return [];

  const shodanIps = new Set(
    (data.shodan.matches ?? [])
      .map((m) => m.ip)
      .filter((ip): ip is string => Boolean(ip)),
  );
  if (shodanIps.size === 0) return [];

  const mispHits = data.misp.hits ?? [];
  const overlaps: { ip: string; tags: string[]; category: string }[] = [];

  for (const hit of mispHits) {
    if (hit.type !== "ip-src" && hit.type !== "ip-dst" && hit.type !== "domain|ip") continue;
    const value = (hit.value ?? "").trim();
    if (!shodanIps.has(value)) continue;
    overlaps.push({ ip: value, tags: hit.tags ?? [], category: hit.category });
  }

  if (overlaps.length === 0) return [];

  // Severidad: critical si tag de C2/botnet, high siempre que hay overlap.
  const hasCriticalTag = overlaps.some((o) =>
    o.tags.some((t) =>
      MISP_CRITICAL_TAG_PATTERNS.some((p) => t.toLowerCase().includes(p)),
    ),
  );
  const severity: AnalystFindingSeverity = hasCriticalTag ? "critical" : "high";
  const ipsList = overlaps.slice(0, 3).map((o) => o.ip).join(", ");

  return [{
    id: `corr-shodan-misp-${domain}`,
    kind: "correlation",
    severity,
    title: `Infra propia con IOCs maliciosos — ${overlaps.length} IP(s)`,
    sourceLabel: "Cross-source: Shodan ∩ MISP",
    evidence: `IPs visibles públicamente en Shodan que también están en MISP como IOCs: ${ipsList}` +
      (overlaps.length > 3 ? ` · +${overlaps.length - 3} más` : ""),
    evidenceTimestamp: detectedAt,
    why: hasCriticalTag
      ? `Cruce CRÍTICO. Una IP en tu superficie expuesta está marcada en threat intel como C2/botnet/RAT. ` +
        `Hay alta probabilidad de host comprometido sirviendo de pivot. Aislar y forensear como prioridad.`
      : `Una IP de tu infraestructura aparece en threat intel pero sin tags de actividad activa — ` +
        `puede ser falso positivo o IOC histórico. Validar contra logs y triagear.`,
    refs: [
      { tab: "analisis", label: "Hosts Shodan", hint: ipsList },
      { tab: "darkweb", label: "MISP atributos", hint: `${overlaps.length} hits` },
    ],
    actions: [
      {
        id: `corr-shodan-misp-case-${domain}`,
        label: severity === "critical" ? "Aislar host (P1)" : "Abrir caso",
        kind: "open-case",
        primary: true,
        payload: { factor: "shodan-misp-overlap", ips: overlaps.length, severity },
      },
      {
        id: `corr-shodan-misp-block-${domain}`,
        label: "Copiar IPs",
        kind: "block-ioc",
        payload: { iocs: overlaps.map((o) => o.ip).join("\n") },
      },
    ],
    detectedAt,
  }];
}

// ─────────────────────────────────────────────────────────────────────────────
// Regla 2: Credenciales ∩ Brand Threats
// ─────────────────────────────────────────────────────────────────────────────

function ruleCredsBrand(input: CrossSourceInput, detectedAt: string): AnalystFinding[] {
  const { domain, hasCoverage, emailCount, brandThreats } = input;
  if (!hasCoverage || emailCount === 0) return [];

  // Buscar typosquatting o CT activos (high+critical).
  const typosCt = brandThreats.threats.filter(
    (t) =>
      (t.kind === "ct-impersonation" || t.kind === "typosquatting") &&
      (t.severity === "high" || t.severity === "critical"),
  );

  if (typosCt.length === 0) return [];

  const targets = typosCt.slice(0, 3).map((t) => t.target).join(", ");
  const severity: AnalystFindingSeverity =
    typosCt.some((t) => t.severity === "critical") ? "high" : "medium";

  return [{
    id: `corr-creds-brand-${domain}`,
    kind: "correlation",
    severity,
    title: `Fuga + look-alike activos — posible cadena de phishing`,
    sourceLabel: "Cross-source: Credenciales ∩ DRP",
    evidence: `${emailCount.toLocaleString("es-ES")} cuentas de @${domain} en fuga + ` +
      `${typosCt.length} dominio(s) look-alike activos: ${targets}`,
    evidenceTimestamp: detectedAt,
    why: `Combinación clásica de pre-incidente: el atacante tiene infraestructura para hostear ` +
      `phishing convincente (look-alike) y un universo de víctimas con credenciales ya filtradas. ` +
      `Riesgo de campaña dirigida: bloquear los dominios fake en proxy/DNS antes de notificar a usuarios.`,
    refs: [
      { tab: "credenciales", label: "Cuentas filtradas", hint: `${emailCount} usuarios` },
      { tab: "marca", label: "Detalle DRP", hint: targets },
    ],
    actions: [
      {
        id: `corr-creds-brand-case-${domain}`,
        label: "Abrir caso correlacionado",
        kind: "open-case",
        primary: true,
        payload: { factor: "creds-brand-chain", emailCount, threatCount: typosCt.length },
      },
    ],
    detectedAt,
  }];
}

// ─────────────────────────────────────────────────────────────────────────────
// Regla 3: RSS ∩ Leak Velocity
// ─────────────────────────────────────────────────────────────────────────────

function ruleRssLeak(input: CrossSourceInput, detectedAt: string): AnalystFinding[] {
  const { domain, rss, hasCoverage, newCredsLast7d } = input;
  if (!rss || !hasCoverage) return [];

  const directMentions =
    (rss.items?.length ?? 0) +
    ((rss.custom ?? []).filter((i) => i.matched).length);

  // Necesitamos ambos spikes simultáneos. `newCredsLast7d` viene de
  // useLeakVelocity que hoy retorna 0 hasta que exista endpoint backend §9.7.
  // Esta regla queda dormante hasta entonces, sin emitir falsos positivos.
  if (directMentions < RSS_COVERAGE_SPIKE) return [];
  if (newCredsLast7d <= 0) return [];

  return [{
    id: `corr-rss-leak-${domain}`,
    kind: "correlation",
    severity: "high",
    title: `Cobertura mediática + fuga activa — incidente público`,
    sourceLabel: "Cross-source: RSS ∩ Leak velocity",
    evidence: `${directMentions} menciones directas en RSS coinciden con ${newCredsLast7d} ` +
      `credencial(es) nuevas en fuga (últimos 7d).`,
    evidenceTimestamp: detectedAt,
    why: `La fuga ya es pública: el patrón habitual es 'leak → discovery → reporte → cobertura'. ` +
      `Coordinación con comunicación obligatoria. Validar narrativa de las notas y preparar respuesta ` +
      `pública si aún no se hizo.`,
    refs: [
      { tab: "noticias", label: "Cobertura RSS", hint: `${directMentions} menciones` },
      { tab: "credenciales", label: "Detalle de la fuga" },
    ],
    actions: [
      {
        id: `corr-rss-leak-case-${domain}`,
        label: "Abrir caso (incidente público)",
        kind: "open-case",
        primary: true,
        payload: { factor: "rss-leak-coupled", mentions: directMentions, newCreds: newCredsLast7d },
      },
    ],
    detectedAt,
  }];
}
