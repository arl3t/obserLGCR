/**
 * bulkCloseCriteria.mjs
 *
 * Parser/validador PURO de los criterios del Asistente de cierre masivo. Sin DB
 * ni efectos → testeable en node:test. La ruta lo usa para normalizar el body
 * del preview/execute antes de armar el SQL.
 */

export const VALID_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"];
export const BLOCKED_SEVERITIES = ["CRITICAL", "HIGH"];
// Estados que un cierre masivo puede tocar (nunca terminales).
export const SELECTABLE_STATUSES = ["NUEVO", "EN_ANALISIS", "CONFIRMADO", "MONITOREADO", "ESCALADO"];
export const VALID_IOC_TYPES = ["ip", "domain", "fqdn", "url", "hash", "email"];
export const VALID_NET_CLASSES = ["internal", "public"];
export const VALID_FIREWALL_ACTIONS = ["blocked", "allowed", "none"];
export const VALID_TECH_CLASSES = ["recon", "threat", "other"];
export const MAX_LIMIT = 200;

const DEFAULT_SEVERITIES = ["LOW", "MEDIUM", "NEGLIGIBLE"];
const DEFAULT_STATUSES = ["NUEVO", "EN_ANALISIS"];

function uniqUpper(arr, allowed) {
  if (!Array.isArray(arr)) return null;
  const set = new Set();
  for (const v of arr) {
    const s = String(v ?? "").trim().toUpperCase();
    if (s && allowed.includes(s)) set.add(s);
  }
  return [...set];
}

function clampInt(v, def, min, max) {
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, n));
}

/**
 * Normaliza/valida criterios. Devuelve { ok, errors, criteria } donde
 * `criteria.effectiveSeverities` ya aplica el gate de CRITICAL/HIGH.
 *
 * @param {object} input body.criteria
 * @returns {{ ok: boolean, errors: string[], criteria: object }}
 */
export function parseBulkCloseCriteria(input = {}) {
  const errors = [];
  const c = input ?? {};

  const mitreTacticId = c.mitreTacticId != null && String(c.mitreTacticId).trim() !== ""
    ? String(c.mitreTacticId).trim().toUpperCase()
    : null;
  if (mitreTacticId && !/^TA\d{4}$/.test(mitreTacticId)) {
    errors.push("mitreTacticId debe tener formato TAxxxx (ej. TA0043)");
  }

  // Filtro por técnica MITRE (T1046 ruido vs T1071/T1566 amenaza) — el
  // discriminador más fino dentro de una misma táctica.
  const mitreTechniqueId = c.mitreTechniqueId != null && String(c.mitreTechniqueId).trim() !== ""
    ? String(c.mitreTechniqueId).trim().toUpperCase()
    : null;
  if (mitreTechniqueId && !/^T\d{4}(\.\d{3})?$/.test(mitreTechniqueId)) {
    errors.push("mitreTechniqueId debe tener formato Txxxx (ej. T1046)");
  }

  // netClass: internal (RFC1918) | public. Sólo aplica a IPs.
  let netClass = c.netClass != null ? String(c.netClass).trim().toLowerCase() : "";
  if (netClass === "any" || netClass === "") netClass = null;
  if (netClass && !VALID_NET_CLASSES.includes(netClass)) {
    errors.push(`netClass inválido: ${netClass} (internal|public)`);
    netClass = null;
  }

  // firewallAction: blocked (ya mitigado) | allowed | none.
  let firewallAction = c.firewallAction != null ? String(c.firewallAction).trim().toLowerCase() : "";
  if (firewallAction === "any" || firewallAction === "") firewallAction = null;
  if (firewallAction && !VALID_FIREWALL_ACTIONS.includes(firewallAction)) {
    errors.push(`firewallAction inválido: ${firewallAction} (blocked|allowed|none)`);
    firewallAction = null;
  }

  // techClass: recon (ruido) | threat (amenaza) | other — clasificación de la
  // técnica MITRE, usada por el triage para reproducir exactamente cada bucket.
  let techClass = c.techClass != null ? String(c.techClass).trim().toLowerCase() : "";
  if (techClass === "any" || techClass === "") techClass = null;
  if (techClass && !VALID_TECH_CLASSES.includes(techClass)) {
    errors.push(`techClass inválido: ${techClass} (recon|threat|other)`);
    techClass = null;
  }

  const severityIn = uniqUpper(c.severityIn, VALID_SEVERITIES) ?? [...DEFAULT_SEVERITIES];
  const statusIn = uniqUpper(c.statusIn, SELECTABLE_STATUSES) ?? [...DEFAULT_STATUSES];
  if (severityIn.length === 0) errors.push("severityIn no puede quedar vacío");
  if (statusIn.length === 0) errors.push("statusIn no puede quedar vacío");

  const includeHighSeverity = c.includeHighSeverity === true;
  // Gate de severidad alta: si NO se habilitó, se quitan CRITICAL/HIGH del filtro
  // efectivo (quedan "bloqueados", se reportan aparte en el preview).
  const effectiveSeverities = includeHighSeverity
    ? severityIn
    : severityIn.filter((s) => !BLOCKED_SEVERITIES.includes(s));
  if (effectiveSeverities.length === 0) {
    errors.push("Sin severidades seleccionables (marcá 'Incluir CRITICAL/HIGH' o agregá LOW/MEDIUM/NEGLIGIBLE)");
  }

  let iocType = c.iocType != null ? String(c.iocType).trim().toLowerCase() : "";
  if (iocType === "any" || iocType === "") iocType = null;
  if (iocType && !VALID_IOC_TYPES.includes(iocType)) {
    errors.push(`iocType inválido: ${iocType}`);
    iocType = null;
  }

  const iocPattern = c.iocPattern != null ? String(c.iocPattern).trim() : "";
  const sourceLog = c.sourceLog != null ? String(c.sourceLog).trim() : "";
  const matchTrustedOrigins = c.matchTrustedOrigins === true;
  const maxAgeDays = clampInt(c.maxAgeDays, 30, 1, 365);
  const limit = clampInt(c.limit, MAX_LIMIT, 1, MAX_LIMIT);

  return {
    ok: errors.length === 0,
    errors,
    criteria: {
      mitreTacticId,
      mitreTechniqueId,
      netClass,
      firewallAction,
      techClass,
      severityIn,
      effectiveSeverities,
      blockedSeverities: includeHighSeverity ? [] : severityIn.filter((s) => BLOCKED_SEVERITIES.includes(s)),
      statusIn,
      iocType,
      iocPattern,
      sourceLog,
      matchTrustedOrigins,
      maxAgeDays,
      includeHighSeverity,
      limit,
    },
  };
}
