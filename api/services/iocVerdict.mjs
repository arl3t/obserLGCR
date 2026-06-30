/**
 * iocVerdict.mjs — Veredicto agregado de un IOC a partir del enriquecimiento.
 *
 * Función PURA (sin red, sin DB) para que sea testeable y reutilizable tanto
 * por el live fan-out (enrichmentService) como por jobs batch. Consume el
 * `summary` + `status` que produce enrichIoc y devuelve un score 0-100, un
 * nivel cualitativo y las razones legibles que lo justifican.
 *
 * Diseño de scoring (aditivo, capeado a 100):
 *  - Señales de MALICIA (VT, AbuseIPDB, MISP, URLhaus, ThreatFox, OpenPhish,
 *    Spamhaus, OTX, GreyNoise=malicious) suman al score.
 *  - Señales de EXPOSICIÓN (CVEs de Shodan) suman menos: indican riesgo de
 *    superficie, no que el IOC sea malicioso per se.
 *  - Señales BENIGNAS (GreyNoise RIOT/benign, AbuseIPDB whitelisted) capean el
 *    score hacia abajo y se listan aparte para que el analista entienda el
 *    "por qué no es lo que parece".
 */

export const VERDICT_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "BENIGN"];

function levelFromScore(score, strongBenign) {
  // Las señales de malicia con score alto siempre ganan: un IOC con abuso
  // confirmado no es "benigno" aunque GreyNoise lo marque RIOT (conflicto →
  // que decida el score). Solo cuando el score se mantiene bajo el benigno
  // fuerte fija el veredicto.
  if (score >= 75) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 25) return "MEDIUM";
  if (strongBenign) return "BENIGN";
  if (score >= 10) return "LOW";
  return "INFO";
}

/**
 * @param {object} args
 * @param {object} args.summary  — summary de enrichIoc
 * @param {object} [args.sources] — sources detalladas (para razones más ricas)
 * @returns {{ score:number, level:string, reasons:string[], benign:string[] }}
 */
export function computeIocVerdict({ summary = {}, sources = {} } = {}) {
  let score = 0;
  const reasons = [];
  const benign = [];

  const vtMal = Number(summary.vtMalicious ?? 0) || 0;
  const vtSus = Number(summary.vtSuspicious ?? 0) || 0;
  if (vtMal > 0) {
    score += Math.min(40, 12 + vtMal * 5);
    reasons.push(`VirusTotal: ${vtMal} motor(es) lo marcan malicioso`);
  } else if (vtSus > 0) {
    score += Math.min(15, vtSus * 3);
    reasons.push(`VirusTotal: ${vtSus} motor(es) sospechoso(s)`);
  }

  const abuse = Number(summary.abuseConfidence ?? 0) || 0;
  if (abuse >= 25) {
    score += Math.round(abuse * 0.4);
    reasons.push(`AbuseIPDB: ${abuse}% de confianza de abuso`);
  }

  if (summary.inMisp) {
    score += 25;
    const lvl = summary.mispThreatLevel;
    reasons.push(`Presente en MISP${lvl ? ` (threat level ${lvl})` : ""}`);
  }

  if (summary.inUrlhaus) {
    score += 30;
    reasons.push("Listado en URLhaus (host/URL de malware activo)");
  }

  if (summary.inThreatfox) {
    score += 30;
    const m = summary.threatfoxMalware;
    reasons.push(`Listado en ThreatFox${m ? ` — ${m}` : ""}`);
  }

  if (summary.inOpenphish) {
    score += 30;
    reasons.push("Listado en OpenPhish (phishing activo)");
  }

  if (summary.spamhausListed) {
    score += 20;
    const l = summary.spamhausLabel;
    reasons.push(`Listado en Spamhaus${l ? ` — ${l}` : ""}`);
  }

  const otxPulses = Number(summary.otxPulseCount ?? 0) || 0;
  if (otxPulses > 0) {
    score += Math.min(20, otxPulses * 3);
    reasons.push(`AlienVault OTX: ${otxPulses} pulse(s) lo referencian`);
  }

  // Exposición (no maliciosidad): CVEs expuestas vía Shodan.
  const vulns = Array.isArray(summary.shodanVulns) ? summary.shodanVulns.length : 0;
  if (vulns > 0) {
    score += Math.min(15, vulns * 3);
    reasons.push(`Shodan: ${vulns} CVE(s) expuesta(s) en el host`);
  }
  // CVEs en CISA KEV (explotación activa) — exposición de riesgo mucho mayor.
  const kev = Number(summary.shodanKevCount ?? 0) || 0;
  if (kev > 0) {
    score += Math.min(20, kev * 8);
    reasons.push(`${kev} CVE(s) en CISA KEV — explotación activa conocida`);
  }

  // GreyNoise: contexto fuerte de triage.
  const gn = summary.greynoise ?? sources.greynoise ?? null;
  const gnClass = gn?.classification ?? null;
  if (gnClass === "malicious") {
    score += 20;
    reasons.push("GreyNoise: clasificado como scanner malicioso");
  }
  const gnBenign = Boolean(gn?.riot) || gnClass === "benign";
  if (gnBenign) {
    benign.push("GreyNoise: tráfico de servicio/escáner benigno conocido (RIOT)");
  }

  if (sources.abuseipdb?.isWhitelisted) {
    benign.push("AbuseIPDB: IP en allowlist (whitelisted)");
  }

  // Señales benignas fuertes capean el score: un IOC en RIOT no debería
  // quedar como HIGH solo por exposición de superficie.
  if (gnBenign) score = Math.min(score, 15);

  score = Math.max(0, Math.min(100, Math.round(score)));
  const level = levelFromScore(score, gnBenign);

  return { score, level, reasons, benign };
}
