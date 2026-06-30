import type { LeakIntelHubSnapshot } from "@/store/leak-intel-hub-store";
import type {
  RssNewsItem,
  SurveillanceBrand24Result,
  SurveillanceDomainResult,
  SurveillanceMispHit,
  SurveillanceRssResult,
  SurveillanceShodanMatch,
} from "@/types/digital-surveillance";
import type { Alert } from "@/components/digital-surveillance/shared/AlertsBlock";
import {
  BRAND24_HIGH_REACH,
  BRAND24_MIN_CLASSIFIED,
  BRAND24_NEG_RATIO_CRITICAL,
  BRAND24_TOP_N_HIGH_REACH_ALERTS,
  BRAND24_VOL_DELTA_WARN_PERCENT,
  CREDS_MASS_LEAK_THRESHOLD,
  CREDS_WEAK_PWD_MIN_SAMPLES,
  CREDS_WEAK_PWD_RATE,
  HIGH_RISK_PORTS,
  INFRA_TOP_N_ALERTS,
  MISP_HIGH_THREAT_LEVEL,
  MISP_SPIKE_7D_THRESHOLD,
  MISP_SPIKE_WINDOW_MS,
  MISP_TOP_N_HIGH_ALERTS,
  PORT_LABELS,
  RSS_COVERAGE_SPIKE,
  RSS_NEG_KEYWORDS,
  RSS_TOP_N_NEG_ALERTS,
} from "@/components/digital-surveillance/risk-engine/thresholds";

function compact(n: number): string {
  if (!Number.isFinite(n)) return "—";
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (Math.abs(n) >= 1_000)     return `${(n / 1_000).toFixed(1)}K`;
  return String(Math.round(n));
}

// ── Infra (Shodan) ───────────────────────────────────────────────────────────

export function buildInfraAlerts(data: SurveillanceDomainResult): Alert[] {
  const matches: SurveillanceShodanMatch[] = data.shodan.matches ?? [];
  const critical = matches
    .filter((m) => m.port != null && HIGH_RISK_PORTS.has(m.port))
    .slice(0, INFRA_TOP_N_ALERTS);

  return critical.map((m) => {
    const portLabel = PORT_LABELS[m.port as number] ?? `puerto ${m.port}`;
    const product = m.product ?? m.transport ?? "servicio";
    const ip = m.ip ?? "—";
    const host = m.hostnames[0] ?? null;
    const country = m.country ?? "?";
    return {
      id: `infra:${ip}:${m.port}`,
      severity: "high",
      title: `${portLabel} expuesto a Internet`,
      detail: `${ip}${host ? ` (${host})` : ""} · ${product} · ${country}`,
      context: m.org ? `org: ${m.org}` : undefined,
      socFinding: {
        id: `infra:${ip}:${m.port}`,
        title: `${portLabel} expuesto en ${ip}`,
        detail: `${product} · puerto ${m.port} · país ${country}`,
        score: 35,
      },
    };
  });
}

// ── Dark web (MISP) ──────────────────────────────────────────────────────────

export function buildDarkWebAlerts(data: SurveillanceDomainResult): Alert[] {
  const hits: SurveillanceMispHit[] = data.misp.hits ?? [];
  if (hits.length === 0) return [];

  const alerts: Alert[] = [];

  // Top N IOCs por threat-level alto
  const high = hits
    .filter((h) => h.threat_level === MISP_HIGH_THREAT_LEVEL)
    .sort((a, b) => {
      const ta = a.timestamp ? +new Date(a.timestamp) : 0;
      const tb = b.timestamp ? +new Date(b.timestamp) : 0;
      return tb - ta;
    })
    .slice(0, MISP_TOP_N_HIGH_ALERTS);

  for (const h of high) {
    alerts.push({
      id: `ioc:${h.uuid ?? h.id}`,
      severity: "high",
      title: `IOC threat-level alto: ${h.type}`,
      detail: `${h.value}${h.event_title ? ` · "${h.event_title}"` : ""}`,
      context: h.tags?.length ? `tags: ${h.tags.slice(0, 3).join(", ")}` : undefined,
      socFinding: {
        id: `ioc:${h.uuid ?? h.id}`,
        title: `IOC MISP — ${h.type}=${h.value}`,
        detail: `evento ${h.event_title ?? h.event_id ?? "?"} · ${h.category}`,
        score: 30,
      },
    });
  }

  // Spike: ≥N IOCs en los últimos 7 días
  const now = Date.now();
  const last7d = hits.filter((h) => {
    if (!h.timestamp) return false;
    const t = +new Date(h.timestamp);
    return Number.isFinite(t) && now - t <= MISP_SPIKE_WINDOW_MS;
  }).length;
  if (last7d >= MISP_SPIKE_7D_THRESHOLD) {
    alerts.push({
      id: "ioc:spike-7d",
      severity: "medium",
      title: `Spike de IOCs en MISP: ${last7d} en últimos 7 días`,
      detail: `total histórico ${data.misp.count ?? hits.length}`,
    });
  }

  return alerts;
}

// ── Marca (Brand24) ──────────────────────────────────────────────────────────

export function buildBrandAlerts(b24: SurveillanceBrand24Result | null | undefined): Alert[] {
  if (!b24 || !b24.summary) return [];
  const s = b24.summary;
  const total = s.positiveCount + s.negativeCount;
  const alerts: Alert[] = [];

  if (total >= BRAND24_MIN_CLASSIFIED && s.negativeCount / total >= BRAND24_NEG_RATIO_CRITICAL) {
    const pct = Math.round((s.negativeCount / total) * 100);
    alerts.push({
      id: "brand:neg-spike",
      severity: "high",
      title: "Spike de menciones negativas",
      detail: `${pct}% negativas (${s.negativeCount}/${total} clasificadas)`,
      socFinding: {
        id: "brand:neg-spike",
        title: "Crisis de reputación — sentimiento negativo dominante",
        detail: `${pct}% de menciones negativas (${s.negativeCount}/${total})`,
        score: 30,
      },
    });
  }

  if (Math.abs(s.volumeDeltaPercent) >= BRAND24_VOL_DELTA_WARN_PERCENT) {
    alerts.push({
      id: "brand:vol-anomaly",
      severity: s.volumeDeltaPercent > 0 ? "medium" : "low",
      title: `Anomalía de volumen: ${s.volumeDeltaPercent > 0 ? "+" : ""}${s.volumeDeltaPercent}%`,
      detail: `${compact(s.volumeMentions)} menciones vs período previo`,
    });
  }

  // Top N menciones de alto reach + negativas
  const topNeg = (b24.mentions ?? [])
    .filter((m) => m.sentiment === "negative" && (m.reach ?? 0) >= BRAND24_HIGH_REACH)
    .sort((a, b) => (b.reach ?? 0) - (a.reach ?? 0))
    .slice(0, BRAND24_TOP_N_HIGH_REACH_ALERTS);

  for (const m of topNeg) {
    alerts.push({
      id: `brand:high-reach:${m.id}`,
      severity: "high",
      title: "Mención de alto reach con sentimiento negativo",
      detail: `${m.author} · ${m.source} · reach ${compact(m.reach!)}`,
      context: m.snippet ? `"${m.snippet.slice(0, 120)}${m.snippet.length > 120 ? "…" : ""}"` : undefined,
      socFinding: {
        id: `brand:mention:${m.id}`,
        title: `Mención negativa de alto reach (${m.author})`,
        detail: `${m.source} · reach ${compact(m.reach!)} · "${(m.snippet ?? "").slice(0, 80)}"`,
        score: 25,
      },
    });
  }

  return alerts;
}

// ── Noticias (RSS) ───────────────────────────────────────────────────────────

export function buildNoticiasAlerts(rss: SurveillanceRssResult | null | undefined): Alert[] {
  if (!rss) return [];
  const direct = rss.items ?? [];
  const customMatched = (rss.custom ?? []).filter((i) => i.matched);
  const all = [...direct, ...customMatched];
  if (all.length === 0) return [];

  const alerts: Alert[] = [];

  // Pico de cobertura (>= RSS_COVERAGE_SPIKE)
  if (all.length >= RSS_COVERAGE_SPIKE) {
    alerts.push({
      id: "noticias:spike",
      severity: "medium",
      title: `Pico de cobertura mediática: ${all.length} menciones`,
      detail: "concentración inusual de menciones en los feeds consultados",
    });
  }

  // Top N menciones con keyword negativo (denun/fraude/hack/...)
  const negativeNews = all
    .filter((i) => RSS_NEG_KEYWORDS.test(`${i.title} ${i.snippet ?? ""}`))
    .sort((a, b) => {
      const ta = a.publishedAt ? +new Date(a.publishedAt) : 0;
      const tb = b.publishedAt ? +new Date(b.publishedAt) : 0;
      return tb - ta;
    })
    .slice(0, RSS_TOP_N_NEG_ALERTS);

  for (const n of negativeNews) {
    alerts.push({
      id: `noticias:neg:${hashId(n.url || n.title)}`,
      severity: "medium",
      title: "Noticia con tono negativo",
      detail: `${n.source} · ${n.title.slice(0, 120)}${n.title.length > 120 ? "…" : ""}`,
      context: n.snippet ? n.snippet.slice(0, 140) : undefined,
      socFinding: {
        id: `noticias:${hashId(n.url || n.title)}`,
        title: `Cobertura negativa: ${n.source}`,
        detail: n.title.slice(0, 200),
        score: 20,
      },
    });
  }

  return alerts;
}

// ── Credenciales (snapshot leak-intel) ───────────────────────────────────────

export function buildCredencialesAlerts(
  snapshot: LeakIntelHubSnapshot | null | undefined,
  emailCount: number,
): Alert[] {
  if (!snapshot) return [];
  const alerts: Alert[] = [];

  if (emailCount >= CREDS_MASS_LEAK_THRESHOLD) {
    alerts.push({
      id: "creds:mass-leak",
      severity: "high",
      title: "Fuga masiva de credenciales del dominio",
      detail: `${compact(emailCount)} correos del dominio en datasets cargados`,
      context: `fuente: ${snapshot.sourceLabel}`,
      socFinding: {
        id: "creds:mass-leak",
        title: "Fuga masiva de credenciales corporativas",
        detail: `${emailCount} correos del dominio en ${snapshot.sourceLabel}`,
        score: 35,
      },
    });
  } else if (emailCount > 0) {
    alerts.push({
      id: "creds:partial-leak",
      severity: "medium",
      title: "Credenciales del dominio en datasets",
      detail: `${emailCount} correo${emailCount === 1 ? "" : "s"} del dominio detectado${emailCount === 1 ? "" : "s"}`,
      context: `fuente: ${snapshot.sourceLabel}`,
      socFinding: {
        id: "creds:partial-leak",
        title: "Credenciales del dominio en datasets cargados",
        detail: `${emailCount} correos detectados · ${snapshot.sourceLabel}`,
        score: 20,
      },
    });
  }

  if (
    snapshot.weakPwdRate &&
    snapshot.weakPwdRate >= CREDS_WEAK_PWD_RATE &&
    (snapshot.passwordSamples ?? 0) >= CREDS_WEAK_PWD_MIN_SAMPLES
  ) {
    const pct = Math.round(snapshot.weakPwdRate * 100);
    alerts.push({
      id: "creds:weak-pwd",
      severity: "medium",
      title: `Alta proporción de contraseñas débiles: ${pct}%`,
      detail: `${snapshot.passwordSamples} contraseñas analizadas`,
    });
  }

  return alerts;
}

// ── Global aggregator ────────────────────────────────────────────────────────

export function buildGlobalAlerts(input: {
  data: SurveillanceDomainResult;
  brand24?: SurveillanceBrand24Result | null;
  rss?: SurveillanceRssResult | null;
  snapshot?: LeakIntelHubSnapshot | null;
  emailCount: number;
}): Alert[] {
  const alerts = [
    ...buildInfraAlerts(input.data),
    ...buildDarkWebAlerts(input.data),
    ...buildBrandAlerts(input.brand24),
    ...buildNoticiasAlerts(input.rss),
    ...buildCredencialesAlerts(input.snapshot, input.emailCount),
  ];
  // Dedupe by id (id ya es único por dominio)
  const seen = new Set<string>();
  return alerts.filter((a) => (seen.has(a.id) ? false : (seen.add(a.id), true)));
}

// ── helpers ──────────────────────────────────────────────────────────────────

function hashId(input: string): string {
  let h = 5381;
  for (let i = 0; i < input.length; i++) h = (h * 33) ^ input.charCodeAt(i);
  return (h >>> 0).toString(36);
}

// Re-export tipos para que el feed RSS no se acople a tipos internos
export type { Alert };
export type { RssNewsItem };
