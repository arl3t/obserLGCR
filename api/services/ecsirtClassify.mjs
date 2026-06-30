/**
 * ecsirtClassify.mjs — Clasificación de incidentes según la taxonomía
 * eCSIRT.net / ENISA Reference Incident Classification (la taxonomía `ecsirt` de
 * MISP, estándar de facto en CSIRTs). Deriva la CLASE del incidente desde la
 * táctica MITRE + tipo de IOC + fuente + enriquecimiento, de forma determinista.
 *
 * Se usa para clasificar TODO caso (incluidos los aún sin triage manual), en vez
 * de depender de la categoría NIST que sólo se setea a mano al cerrar.
 *
 * Interoperable con MISP: las claves mapean 1:1 a los predicados de la taxonomía
 * `ecsirt` (ver MAP_TO_MISP) para taggear eventos exportados.
 */

export const ECSIRT_CLASSES = {
  ABUSIVE_CONTENT:   { label: "Contenido abusivo",            short: "Abuso",        misp: "ecsirt:abusive-content" },
  MALICIOUS_CODE:    { label: "Código malicioso",             short: "Malware",      misp: "ecsirt:malicious-code" },
  INFO_GATHERING:    { label: "Recolección de información",   short: "Recon",        misp: "ecsirt:information-gathering" },
  INTRUSION_ATTEMPT: { label: "Intento de intrusión",         short: "Intento",      misp: "ecsirt:intrusion-attempts" },
  INTRUSION:         { label: "Intrusión",                    short: "Intrusión",    misp: "ecsirt:intrusions" },
  AVAILABILITY:      { label: "Disponibilidad (DoS)",         short: "DoS",          misp: "ecsirt:availability" },
  INFO_CONTENT_SEC:  { label: "Seguridad de contenido",       short: "Datos/Exfil",  misp: "ecsirt:information-content-security" },
  FRAUD:             { label: "Fraude / Phishing",            short: "Fraude",       misp: "ecsirt:fraud" },
  VULNERABLE:        { label: "Sistema vulnerable",           short: "Vulnerable",   misp: "ecsirt:vulnerable" },
  OTHER:             { label: "Sin clasificar",               short: "Otro",         misp: "ecsirt:other" },
};

// Táctica MITRE ATT&CK → clase eCSIRT.
const TACTIC_MAP = {
  TA0043: "INFO_GATHERING",     // Reconnaissance
  TA0007: "INFO_GATHERING",     // Discovery
  TA0001: "INTRUSION_ATTEMPT",  // Initial Access
  TA0006: "INTRUSION_ATTEMPT",  // Credential Access
  TA0002: "MALICIOUS_CODE",     // Execution
  TA0003: "MALICIOUS_CODE",     // Persistence
  TA0005: "MALICIOUS_CODE",     // Defense Evasion
  TA0011: "MALICIOUS_CODE",     // Command and Control
  TA0004: "INTRUSION",          // Privilege Escalation
  TA0008: "INTRUSION",          // Lateral Movement
  TA0009: "INFO_CONTENT_SEC",   // Collection
  TA0010: "INFO_CONTENT_SEC",   // Exfiltration
  TA0040: "AVAILABILITY",       // Impact (DoS/sabotaje; ransomware lo captura el gate de malware)
};

// eCSIRT → categoría NIST SP 800-61 del modal de cierre. Valores ALINEADOS con
// NIST_CATEGORIES del frontend (InvestigationModals): UNAUTHORIZED_ACCESS,
// DENIAL_OF_SERVICE, MALICIOUS_CODE, IMPROPER_USAGE, SCANS_PROBES, INVESTIGATION,
// OTHER. Sirve para prellenar la categoría al cerrar el caso.
export const ECSIRT_TO_NIST = {
  MALICIOUS_CODE:    "MALICIOUS_CODE",
  INTRUSION:         "UNAUTHORIZED_ACCESS",
  INTRUSION_ATTEMPT: "UNAUTHORIZED_ACCESS",
  AVAILABILITY:      "DENIAL_OF_SERVICE",
  INFO_CONTENT_SEC:  "UNAUTHORIZED_ACCESS",
  INFO_GATHERING:    "SCANS_PROBES",
  FRAUD:             "IMPROPER_USAGE",
  ABUSIVE_CONTENT:   "IMPROPER_USAGE",
  VULNERABLE:        "INVESTIGATION",
  OTHER:             "OTHER",
};

const s = (v) => String(v ?? "").trim().toLowerCase();

/**
 * @param {{ mitreTacticId?, iocType?, sourceLog?, enrichment?, detectionType? }} input
 * @returns {{ class, subclass, label, short, misp, source }}
 */
export function classifyEcsirt(input = {}) {
  const { mitreTacticId, iocType, sourceLog, enrichment, detectionType } = input;
  const enr = enrichment || {};
  const src = s(sourceLog);
  const it  = s(iocType);
  const mk = (cls, subclass = null, source = "heuristic") => ({
    class: cls, subclass,
    label: ECSIRT_CLASSES[cls].label, short: ECSIRT_CLASSES[cls].short,
    misp: ECSIRT_CLASSES[cls].misp, nist: ECSIRT_TO_NIST[cls] ?? "OTHER", source,
  });

  // 1. Señales DURAS de enrichment (máxima confianza).
  if (enr.inThreatfox || enr.threatfoxMalware)
    return mk("MALICIOUS_CODE", enr.threatfoxMalware || "malware", "intel");
  if (enr.inUrlhaus || enr.inOpenphish || src.includes("pmg") || src.includes("phish"))
    return mk("FRAUD", "phishing", "intel");
  if (enr.spamhausListed)
    return mk("ABUSIVE_CONTENT", "spam", "intel");

  // 2. Táctica MITRE (señal principal).
  const t = TACTIC_MAP[String(mitreTacticId ?? "").toUpperCase()];
  if (t) return mk(t, null, "mitre");

  // 3. Heurística por tipo de IOC / detección.
  if (it === "url" || it === "domain") return mk("FRAUD", null, "ioc-type");
  if (["hash", "md5", "sha1", "sha256"].includes(it)) return mk("MALICIOUS_CODE", null, "ioc-type");
  if (s(detectionType).includes("scan")) return mk("INFO_GATHERING", null, "detection");

  return mk("OTHER", null, "default");
}
