/**
 * credentialFindingBuilder — produce findings desde el snapshot Leak Intel Hub.
 *
 * Genera 1 finding por servicio crítico expuesto + 1 finding agregado
 * por exposición masiva (≥ CREDS_MASS_LEAK_THRESHOLD usuarios) + 1 por
 * stealer logs detectados con malware. Los findings individuales por usuario
 * NO se generan acá (saturarían el feed) — viven en TabCredenciales.
 */

import type { LeakIntelHubSnapshot } from "@/store/leak-intel-hub-store";
import type {
  AnalystFinding,
  AnalystFindingAction,
} from "@/types/digital-surveillance";
import { CREDS_MASS_LEAK_THRESHOLD } from "@/components/digital-surveillance/risk-engine/thresholds";

export type CredentialFindingInput = {
  domain: string;
  snapshot: LeakIntelHubSnapshot | null;
  hasCoverage: boolean;
  emailCount: number;
};

/** Servicios que disparan finding `critical` siempre que tengan hits. */
const CRITICAL_SERVICES = new Set([
  "Microsoft / O365",
  "Webmail Corporativo",
  "Google Workspace",
  "VPN",
]);

export function buildCredentialFindings(
  input: CredentialFindingInput,
): AnalystFinding[] {
  const { domain, snapshot, hasCoverage, emailCount } = input;
  if (!snapshot || !hasCoverage) return [];

  const out: AnalystFinding[] = [];
  const detectedAt = new Date().toISOString();

  // 1. Servicios críticos con credenciales filtradas — uno por servicio
  for (const svc of snapshot.criticalServices ?? []) {
    const isCritical = CRITICAL_SERVICES.has(svc.service);
    if (svc.hits === 0) continue;

    const severity = isCritical
      ? svc.hits >= 50 ? "critical" : "high"
      : svc.hits >= 100 ? "high" : "medium";

    const actions: AnalystFindingAction[] = [
      {
        id: `creds-svc-rotate-${svc.service}`,
        label: "Forzar rotación masiva",
        kind: "rotate-creds",
        primary: true,
        payload: { service: svc.service, hits: svc.hits },
      },
      {
        id: `creds-svc-case-${svc.service}`,
        label: "Abrir caso",
        kind: "open-case",
        payload: { factor: "credential-leak", service: svc.service, score: 80 },
      },
    ];

    out.push({
      id: `finding-creds-svc-${slugify(svc.service)}`,
      kind: "credential-leak",
      severity,
      title: `Credenciales filtradas — ${svc.service}`,
      sourceLabel: snapshot.sourceLabel,
      evidence: `${svc.hits.toLocaleString("es-ES")} registro(s) con credenciales para ${svc.service} de @${domain}`,
      evidenceTimestamp: snapshot.updatedAt,
      why: isCritical
        ? `Servicio en CIS Top 25 (acceso corporativo crítico). La exposición de credenciales habilita ATO inmediato sin pivot adicional.`
        : `Servicio con ${svc.hits.toLocaleString("es-ES")} credenciales activas — riesgo de credential stuffing y reuso en otros sistemas.`,
      refs: [
        { tab: "credenciales", label: "Detalle credenciales", hint: svc.service },
      ],
      actions,
      detectedAt,
    });
  }

  // 2. Fuga masiva — agregado cuando emailCount >= threshold
  if (emailCount >= CREDS_MASS_LEAK_THRESHOLD) {
    const score = snapshot.overallRiskScore ?? 80;
    out.push({
      id: `finding-creds-mass-${domain}`,
      kind: "credential-leak",
      severity: emailCount >= 500 ? "critical" : "high",
      title: `Fuga masiva detectada — ${emailCount.toLocaleString("es-ES")} cuentas`,
      sourceLabel: snapshot.sourceLabel,
      evidence: `${emailCount.toLocaleString("es-ES")} cuenta(s) corporativa(s) de @${domain} en el dump. Risk score local: ${score}/100.`,
      evidenceTimestamp: snapshot.updatedAt,
      why: `Volumen ≥ ${CREDS_MASS_LEAK_THRESHOLD} usuarios afectados — supera el umbral SOC para incidente coordinado. ` +
        `Reset masivo + revocación de tokens activos requerido en próximos 7 días.`,
      refs: [
        { tab: "credenciales", label: "Análisis completo", hint: `${emailCount} usuarios` },
        { tab: "ejecutivo", label: "Plan ejecutivo", hint: "P2 acciones priorizadas" },
      ],
      actions: [
        {
          id: `creds-mass-case-${domain}`,
          label: "Abrir caso ejecutivo",
          kind: "open-case",
          primary: true,
          payload: { factor: "mass-credential-leak", emailCount, score },
        },
        {
          id: `creds-mass-watchlist-${domain}`,
          label: "Agregar a Watchlist",
          kind: "add-watchlist",
        },
      ],
      detectedAt,
    });
  }

  // 3. Stealer logs con malware identificado — un finding por familia
  const malware = snapshot.malwareFamilyList ?? [];
  if (malware.length > 0 && (snapshot.stealerRows ?? 0) > 0) {
    const topFamilies = malware.slice(0, 3).map((m) => `${m.label} (${m.count})`).join(", ");
    out.push({
      id: `finding-creds-stealer-${domain}`,
      kind: "credential-leak",
      severity: "high",
      title: `Stealer logs activos en distribución`,
      sourceLabel: snapshot.sourceLabel,
      evidence: `${(snapshot.stealerRows ?? 0).toLocaleString("es-ES")} registros con stealer logs. Familias: ${topFamilies}.`,
      evidenceTimestamp: snapshot.updatedAt,
      why: `Stealer logs implican que el dispositivo del usuario fue comprometido. ` +
        `Las credenciales están frescas (no del passwd-spray común) y suelen incluir cookies de sesión + auth tokens — ` +
        `el reset de pwd no alcanza, hay que invalidar sesiones activas.`,
      refs: [
        { tab: "credenciales", label: "Familias detectadas", hint: topFamilies },
        { tab: "darkweb", label: "MISP IOCs", hint: "buscar familias en MISP" },
      ],
      actions: [
        {
          id: `creds-stealer-case-${domain}`,
          label: "Abrir caso (stealer)",
          kind: "open-case",
          primary: true,
          payload: { factor: "stealer-malware", families: malware.length },
        },
      ],
      detectedAt,
    });
  }

  return out;
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}
