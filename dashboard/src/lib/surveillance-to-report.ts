/**
 * surveillance-to-report.ts
 *
 * Convierte los datos en vivo de una consulta de Vigilancia Digital
 * (SurveillanceDomainResult) al formato DarkWebReportData que consume
 * DarkWebExposureReport para renderizar e imprimir el informe.
 */

import type { SurveillanceDomainResult, SurveillanceMispHit, SurveillanceRssResult } from "@/types/digital-surveillance";
import type {
  DarkWebReportData,
  ExposedHostRow,
  GlossaryEntry,
  LeakTableRow,
} from "@/types/darkweb-report";
import { PY_TZ } from "@/lib/format";

const RISKY_PORTS = new Set([4444, 3389, 445, 23, 21, 3306, 5432, 6379, 27017]);

// ── helpers ───────────────────────────────────────────────────────────────────

function apexDomain(domain: string): string {
  const parts = domain.replace(/^www\./, "").split(".");
  return parts.length >= 2 ? parts.slice(-2).join(".") : domain;
}

function mispTimestampToDate(ts: string | null | undefined): string {
  // Backend (`mispService.normalizeMispTimestamp`) ya devuelve ISO 8601 o null.
  // Mantenemos el parser tolerante por si llega de una fuente legada.
  if (!ts) return "";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 10);
}

// ── exportable mapper ─────────────────────────────────────────────────────────

export function surveillanceToReportData(
  data: SurveillanceDomainResult,
  rss?: SurveillanceRssResult | null,
): DarkWebReportData {
  const domain    = data.domain;
  const queriedAt = data.queriedAt || new Date().toISOString();

  // ── Riesgo ────────────────────────────────────────────────────────────────
  // Escala interna 0-100 → escala del informe 1-10
  const overallRiskScore = Math.max(1, Math.round((data.risk.score / 100) * 10));

  // ── Shodan → infraestructura expuesta ────────────────────────────────────
  const shodanMatches = data.shodan.matches ?? [];
  const exposedHosts: ExposedHostRow[] = shodanMatches.map((m) => ({
    hostname:                   m.hostnames?.[0] ?? m.ip ?? "—",
    externalIp:                 m.ip ?? "—",
    exposedPorts:               m.port != null ? [String(m.port)] : [],
    publicVulnerabilityReports: 0,
    hasUnusualOrRiskyPorts:     RISKY_PORTS.has(m.port ?? 0),
  }));

  // ── MISP → filas de fugas ─────────────────────────────────────────────────
  const mispHits: SurveillanceMispHit[] = data.misp.hits ?? [];
  const leakRows: LeakTableRow[] = mispHits.slice(0, 20).map((h, i) => ({
    id:               h.uuid ?? String(i),
    leakName:         h.event_title ?? `Evento MISP ${h.event_id ?? i}`,
    publishedAt:      mispTimestampToDate(h.timestamp),
    estimatedRecords: 0,
    sourceType:       "MISP",
    tags:             h.tags ?? [],
  }));

  // ── CTI Cloud & Olé hits ──────────────────────────────────────────────────
  const ctiHits = (data.cti.hits ?? []) as Record<string, unknown>[];
  const ctiCount = data.cti.count ?? ctiHits.length;

  // Menciones en foros/dark web: CTI hits + tags MISP con "forum/hacker"
  const mispForumCount = mispHits.filter((h) =>
    (h.tags ?? []).some((t) =>
      /forum|hacker|leak|darkweb|paste/i.test(t),
    ),
  ).length;
  const hackerForumCount = ctiCount + mispForumCount;

  // ── Párrafos ejecutivos desde factores de riesgo ──────────────────────────
  const paragraphs: string[] = [];

  if ((data.shodan.total ?? 0) > 0) {
    paragraphs.push(
      `Shodan detectó ${data.shodan.total} host(s) con servicios expuestos en Internet asociados a ${domain}.`,
    );
  }
  if (mispHits.length > 0) {
    paragraphs.push(
      `MISP Threat Intelligence registra ${mispHits.length} atributo(s) IOC relacionados con ${domain} en los últimos 90 días.`,
    );
  }
  if (ctiCount > 0) {
    paragraphs.push(
      `CTI Cloud & Olé identifica ${ctiCount} resultado(s) en fuentes de dark web y paste sites para ${domain}.`,
    );
  }

  const activeFactors = (data.risk.factors ?? []).filter((f) => f.score > 0);
  for (const f of activeFactors) {
    if (f.detail) paragraphs.push(f.detail);
  }

  if (paragraphs.length === 0) {
    paragraphs.push(
      `No se detectaron indicadores de compromiso significativos para ${domain} en las fuentes consultadas (Shodan, MISP, CTI Cloud & Olé).`,
    );
  }

  // ── RSS: artículos directamente relacionados con el dominio ───────────────
  const rssDirectCount = (rss?.items ?? []).length;
  const rssSecurityCount = (rss?.general ?? []).length;

  // ── Glosario base ─────────────────────────────────────────────────────────
  const glossary: GlossaryEntry[] = [
    { term: "IOC",        definition: "Indicator of Compromise — indicador de compromiso (IP, dominio, hash, URL)." },
    { term: "MISP",       definition: "Malware Information Sharing Platform — plataforma de intercambio de inteligencia sobre amenazas." },
    { term: "CTI",        definition: "Cyber Threat Intelligence — inteligencia sobre amenazas cibernéticas." },
    { term: "Shodan",     definition: "Motor de búsqueda de dispositivos e infraestructura expuesta en Internet." },
    { term: "Paste site", definition: "Servicio de publicación de texto anónimo (Pastebin, etc.) frecuentemente usado para filtrar datos." },
    { term: "Dark Web",   definition: "Parte de Internet solo accesible mediante software especializado (Tor), usada entre otros para tráfico ilícito de datos." },
  ];

  // ── Ensamblado final ──────────────────────────────────────────────────────
  return {
    meta: {
      clientName:    apexDomain(domain),
      clientDomain:  domain,
      generatedAt:   queriedAt,
      reportVersion: "1.0",
      subtitle: `Análisis de exposición externa generado automáticamente por LegacyHunt · ${new Date(queriedAt).toLocaleDateString("es-ES", { timeZone: PY_TZ, dateStyle: "long" })}`,
    },

    executive: {
      overallRiskScore,
      kpis: {
        detectedLogins:             0,
        similarDomainsDetected:     0,
        leaksResults:               mispHits.length + ctiCount,
        employeesInFreeBotnetLogs:  0,
        clientNameInHackerForums:   hackerForumCount,
        exposedInfrastructureHosts: data.shodan.total ?? 0,
      },
      paragraphs,
    },

    detectedLogins: {
      total:           0,
      description:     "Sin credenciales detectadas en las fuentes configuradas.",
      sampleUsernames: [],
    },

    similarDomains: [],

    leaksWithClientDomain: {
      riskAnalysisBullets: leakRows.length > 0
        ? [
            `${mispHits.length} atributo(s) IOC detectado(s) en MISP Threat Intelligence.`,
            ...(ctiCount > 0 ? [`${ctiCount} resultado(s) en fuentes CTI / dark web.`] : []),
          ]
        : ["Sin registros en bases de datos de fugas conocidas para este dominio."],
      latestLeaks:  leakRows,
      exampleLeaks: [],
    },

    leakedCredentials: {
      totalCredentialRecords: 0,
      uniqueEmailsEstimated:  0,
      notes: "Sin credenciales filtradas detectadas en las fuentes configuradas.",
    },

    riskyUsers:     [],
    passwordStrength: [],
    passwordReuse: {
      narrative:                    "",
      estimatedAccountsWithReuse:   0,
    },

    domainAnalysis: {
      paragraphs: [
        `El dominio ${domain} fue analizado el ${new Date(queriedAt).toLocaleDateString("es-ES", { timeZone: PY_TZ, dateStyle: "long" })}.`,
        ...(rssDirectCount > 0
          ? [`Se encontraron ${rssDirectCount} artículo(s) en RSS y noticias con mención directa al dominio.`]
          : []),
        ...(rssSecurityCount > 0
          ? [`${rssSecurityCount} artículo(s) de seguridad general recuperados de fuentes configuradas.`]
          : []),
      ],
      additionalSimilarDomains: [],
    },

    exposedInfrastructure: {
      narrative: exposedHosts.length > 0
        ? `Shodan detectó ${exposedHosts.length} host(s) con servicios expuestos para ${domain}.`
        : `Sin servicios expuestos detectados en Shodan para ${domain}.`,
      hosts: exposedHosts,
    },

    infraWazuh: {
      intro: [
        "Correlación entre infraestructura expuesta externamente y alertas del agente Wazuh interno.",
        "Los datos de Wazuh se obtienen del pipeline de LegacyHunt; la correlación completa requiere que los hosts de Shodan coincidan con agentes registrados.",
      ],
      totals: {
        serversDetectedInExternalSources:    exposedHosts.length,
        serversWithExposedOpenPorts:         exposedHosts.filter((h) => h.exposedPorts.length > 0).length,
        serversWithPublicVulnerabilityReports: 0,
        serversWithUnusualOrRiskyPorts:      exposedHosts.filter((h) => h.hasUnusualOrRiskyPorts).length,
      },
      wazuhRelatedAlerts30d: 0,
      valueProposition: "Integra los datos de Wazuh desde el módulo SOC de LegacyHunt para correlación automática.",
      correlationRows: [],
    },

    botnetLogs: {
      employeesDetected: 0,
      narrative:         `Sin registros de botnets detectados para ${domain}.`,
      sampleLines:       [],
    },

    hackerForums: {
      mentionCount: String(hackerForumCount),
      narrative: hackerForumCount > 0
        ? `Se detectaron ${hackerForumCount} referencia(s) en fuentes CTI / MISP asociadas a actividad en foros o dark web para ${domain}.`
        : `Sin menciones detectadas en foros o dark web para ${domain}.`,
    },

    glossary,
  };
}
