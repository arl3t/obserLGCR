/**
 * bulkCloseConfidence.mjs
 *
 * Scoring de confianza + clustering semántico para el Asistente de cierre masivo.
 * PURO (sin DB ni red) → testeable en node:test. La ruta lo usa sobre las filas
 * del preview para (1) puntuar cada caso, (2) agruparlos en clusters accionables
 * y (3) derivar la recomendación de acción.
 *
 * Por qué NO depende de enrichment: en el lake real (2026-06-17) el 98,6% de los
 * casos abiertos no tienen `iocVerdict` poblado. La confianza se deriva de señales
 * ESTRUCTURALES siempre presentes: firewall_action (¿ya bloqueado?), técnica MITRE
 * (recon vs amenaza), netclass (interno este-oeste vs público) y banda de score.
 * El veredicto de intel, si existe, sólo refuerza o veta.
 */
import { isRfc1918 } from "./netClass.mjs";

// Técnicas de AMENAZA real: nunca aptas para cierre automático (veto duro).
// C2, phishing/initial access, explotación, cuentas válidas, scripting, ransomware,
// volcado de credenciales, explotación de servicio remoto.
export const THREAT_TECHNIQUES = new Set([
  "T1071", "T1566", "T1190", "T1078", "T1059", "T1486", "T1003", "T1210",
]);

// Técnicas de RECON/ruido: candidatas a cierre cuando ya están mitigadas.
// Network service discovery, remote system discovery, active scanning, gather info.
export const RECON_TECHNIQUES = new Set([
  "T1046", "T1018", "T1595", "T1590", "T1592", "T1135",
]);

// Tácticas de descubrimiento (cuando no hay technique_id fiable).
const RECON_TACTICS = new Set(["TA0007", "TA0043"]); // Discovery, Reconnaissance
// Veredictos de intel que vetan el cierre automático.
const MALICIOUS_VERDICT_LEVELS = new Set(["CRITICAL", "HIGH", "MALICIOUS"]);

const LOW_BAND_SEVERITIES = new Set(["MEDIUM", "LOW", "NEGLIGIBLE"]);

function norm(v) { return String(v ?? "").trim().toUpperCase(); }

/** netclass de una fila: 'internal' (RFC1918) | 'public' | 'other' (no IP). */
export function netClassOf(row) {
  if (norm(row?.ioc_type) !== "IP") return "other";
  const ip = String(row?.ioc_value ?? "").trim();
  if (!ip) return "other";
  return isRfc1918(ip) ? "internal" : "public";
}

/**
 * Clase de técnica de la fila combinando technique_id Y tactic_id (en este lake
 * el tactic_id a veces trae el technique_id por un bug de etiquetado, así que se
 * miran ambos). 'threat' gana sobre 'recon'.
 */
export function techClassOf(row) {
  const codes = [norm(row?.mitre_technique_id), norm(row?.mitre_tactic_id)].filter(Boolean);
  if (codes.some((c) => THREAT_TECHNIQUES.has(c))) return "threat";
  if (codes.some((c) => RECON_TECHNIQUES.has(c) || RECON_TACTICS.has(c))) return "recon";
  if (codes.length === 0) return "recon"; // sin técnica reconocida = ruido por defecto
  return "other";
}

/** Clase de acción del firewall: 'blocked' | 'allowed' | 'none'. */
export function fwClassOf(row) {
  const fw = norm(row?.firewall_action);
  if (fw === "BLOCK" || fw === "DENY" || fw === "DROP" || fw === "BLOCKED" || fw === "DROPPED") return "blocked";
  if (fw) return "allowed";
  return "none";
}

function verdictLevel(row) {
  // Acepta varias formas: row.verdict_level, o enrichment_data.iocVerdict.level/verdict.
  const lvl = row?.verdict_level
    ?? row?.enrichment_data?.iocVerdict?.level
    ?? row?.enrichment_data?.iocVerdict?.verdict;
  return norm(lvl) || null;
}

/**
 * Puntúa la confianza de cierre automático de UN caso. Devuelve confianza 0..1,
 * las señales que sumaron, el veto (si lo hay) y las clases para clustering.
 */
export function scoreCaseConfidence(row = {}) {
  const netclass = netClassOf(row);
  const techClass = techClassOf(row);
  const fwClass = fwClassOf(row);
  const sev = norm(row.severity);
  const vlvl = verdictLevel(row);

  // ── Vetos duros: confianza 0, no apto para lote ──
  let veto = null;
  if (techClass === "threat") veto = "threat_technique";
  else if (sev === "CRITICAL") veto = "critical_severity";
  else if (vlvl && MALICIOUS_VERDICT_LEVELS.has(vlvl)) veto = "malicious_verdict";

  if (veto) {
    return { confidence: 0, signals: [], veto, netclass, techClass, fwClass };
  }

  const signals = [];
  let conf = 0;
  if (fwClass === "blocked") { conf += 0.4; signals.push("already_blocked"); }
  if (techClass === "recon") { conf += 0.3; signals.push("recon_noise"); }
  if (netclass === "internal") { conf += 0.2; signals.push("internal_east_west"); }
  const scoreNum = Number.parseInt(row.score, 10);
  if (LOW_BAND_SEVERITIES.has(sev) || (Number.isFinite(scoreNum) && scoreNum < 50)) {
    conf += 0.1; signals.push("low_score_band");
  }
  if (vlvl === "BENIGN") { conf += 0.3; signals.push("verdict_benign"); }

  return { confidence: Math.min(1, Math.round(conf * 100) / 100), signals, veto: null, netclass, techClass, fwClass };
}

// ── Triage del backlog (T1/T2) ──────────────────────────────────────────────
// Enruta cada caso a una disposición. El veto manda: amenaza/CRITICAL → analista.
export const TRIAGE_BUCKETS = {
  auto_close_suppress: {
    order: 1, label: "Auto-cerrar + supresión", action: "close_and_suppress",
    hint: "interno · ya bloqueado · recon → confianza alta",
    closable: true,
    criteria: { techClass: "recon", netClass: "internal", firewallAction: "blocked", iocType: "ip", severityIn: ["MEDIUM", "HIGH"], includeHighSeverity: true },
  },
  close_watchlist: {
    order: 2, label: "Cerrar + watchlist", action: "close_and_watchlist",
    hint: "público · ya bloqueado · recon → bloquear en lgcrBL y cerrar",
    closable: true,
    criteria: { techClass: "recon", netClass: "public", firewallAction: "blocked", iocType: "ip", severityIn: ["MEDIUM", "HIGH"], includeHighSeverity: true },
  },
  review: {
    order: 3, label: "Revisar (recon sin bloqueo / señal débil)", action: "review",
    hint: "recon que el firewall no bloqueó → muestreo antes de cerrar",
    closable: true,
    criteria: { techClass: "recon", firewallAction: "none", severityIn: ["LOW", "MEDIUM", "NEGLIGIBLE"] },
  },
  escalate_analyst: {
    order: 4, label: "Escalar a analista (vetado)", action: "manual_review",
    hint: "técnica de amenaza / CRITICAL → NO apto para lote",
    closable: false,
    criteria: { techClass: "threat" },
  },
};

/** Disposición de triage de un caso (clases ya calculadas). */
export function triageDisposition({ netclass, techClass, blocked, severity } = {}) {
  if (techClass === "threat" || norm(severity) === "CRITICAL") return "escalate_analyst";
  if (techClass === "recon" && netclass === "internal" && blocked) return "auto_close_suppress";
  if (techClass === "recon" && netclass === "public" && blocked) return "close_watchlist";
  return "review";
}

/** Disposición a partir de una fila cruda (usa los mismos clasificadores). */
export function triageRow(row = {}) {
  return triageDisposition({
    netclass: netClassOf(row), techClass: techClassOf(row),
    blocked: fwClassOf(row) === "blocked", severity: row.severity,
  });
}

/**
 * M4 — Plan de supresión cluster-aware. El ruido recon interno no necesita 60d
 * (cegaría detección este-oeste legítima); las IPs públicas que se bloquean en
 * lgcrBL NO deben suprimirse (el feed ya las cubre y deben seguir alertando si
 * reaparecen por otra vía). Devuelve si crear supresión y con qué TTL.
 *
 * @param {object} row  fila del caso
 * @param {object} opts { suppressionDays:number, smart?:boolean }
 * @returns {{ create:boolean, days:number, skipReason:string|null }}
 */
export const RECON_INTERNAL_SUPPRESSION_CAP_DAYS = 14;
export function suppressionPlan(row = {}, { suppressionDays = 30, smart = true } = {}) {
  const days = Math.max(1, Math.min(365, Number.parseInt(suppressionDays, 10) || 30));
  if (!smart) return { create: true, days, skipReason: null };
  const netclass = netClassOf(row);
  const techClass = techClassOf(row);
  // IP pública → no suprimir (se gobierna por el feed saliente / watchlist).
  if (netclass === "public") return { create: false, days, skipReason: "public_use_watchlist" };
  // Recon interno → TTL corto y acotado.
  if (techClass === "recon" && netclass === "internal") {
    return { create: true, days: Math.min(days, RECON_INTERNAL_SUPPRESSION_CAP_DAYS), skipReason: null };
  }
  return { create: true, days, skipReason: null };
}

const CLUSTER_LABELS = {
  "internal|blocked|recon": "Discovery interno ya bloqueado (este-oeste)",
  "public|blocked|recon": "Discovery público ya bloqueado",
  "internal|none|recon": "Discovery interno (sin acción de firewall)",
  "public|none|recon": "Discovery público (sin acción de firewall)",
};

/** Acción recomendada para un cluster según su perfil + confianza media. */
export function clusterAction(netclass, techClass, avgConfidence) {
  if (techClass === "threat") return "manual_review";
  if (avgConfidence < 0.7) return "review";
  if (techClass === "recon" && netclass === "internal") return "close_and_suppress";
  if (techClass === "recon" && netclass === "public") return "close_and_watchlist";
  return "review";
}

/**
 * Agrupa filas en clusters semánticos por (netclass · firewall · técnica) —
 * NO por ioc_value (en este lake la cardinalidad caso/IP es ~1.1, el merge de
 * duplicados aporta poco). Devuelve clusters ordenados por tamaño.
 */
export function clusterCases(rows = []) {
  const map = new Map();
  for (const r of rows) {
    const s = scoreCaseConfidence(r);
    const key = `${s.netclass}|${s.fwClass}|${s.techClass}`;
    let cl = map.get(key);
    if (!cl) {
      cl = { key, netclass: s.netclass, fwClass: s.fwClass, techClass: s.techClass,
        count: 0, confSum: 0, vetoed: 0, caseIds: [], sampleIds: [] };
      map.set(key, cl);
    }
    cl.count++;
    cl.confSum += s.confidence;
    if (s.veto) cl.vetoed++;
    cl.caseIds.push(String(r.id));
    if (cl.sampleIds.length < 5) cl.sampleIds.push(String(r.id));
  }
  const clusters = [...map.values()].map((cl) => {
    const avgConfidence = cl.count ? Math.round((cl.confSum / cl.count) * 100) / 100 : 0;
    const action = clusterAction(cl.netclass, cl.techClass, avgConfidence);
    const label = CLUSTER_LABELS[cl.key]
      ?? `${cl.techClass === "threat" ? "Amenaza" : cl.techClass === "recon" ? "Recon/ruido" : "Otros"} · ${cl.netclass} · fw:${cl.fwClass}`;
    const { confSum, ...rest } = cl;
    return { ...rest, avgConfidence, action, label };
  });
  clusters.sort((a, b) => b.count - a.count);
  return clusters;
}

/**
 * Recomendación de acción para el preview a partir de los clusters: elige el
 * cluster accionable más grande. Mantiene la forma {action,closeStatus,
 * classification,rationale} que ya consume la UI, + adjunta los clusters.
 */
export function recommendFromClusters(rows = []) {
  const clusters = clusterCases(rows);
  const n = rows.length;
  if (n === 0) {
    return { action: "close", closeStatus: "FALSO_POSITIVO", classification: "FALSE_POSITIVE",
      rationale: "Sin coincidencias con estos criterios.", clusters };
  }
  const actionable = clusters.filter((c) => c.action === "close_and_suppress" || c.action === "close_and_watchlist");
  const top = actionable[0];
  if (!top) {
    const threat = clusters.find((c) => c.action === "manual_review");
    const rationale = threat
      ? `Hay ${threat.count} caso(s) con técnicas de amenaza real (no aptos para lote). Revisá manualmente; no se recomienda cierre automático.`
      : "Sin cluster de alta confianza. Revisá la muestra y cerrá como FALSO_POSITIVO si corresponde.";
    return { action: "close", closeStatus: "FALSO_POSITIVO", classification: "FALSE_POSITIVE", rationale, clusters };
  }
  const pct = Math.round((top.count / n) * 100);
  if (top.action === "close_and_suppress") {
    return { action: "close", closeStatus: "FALSO_POSITIVO", classification: "FALSE_POSITIVE",
      rationale: `~${pct}% son ${top.label} (confianza ${top.avgConfidence}). Recomendado: cerrar como FALSO_POSITIVO + supresión.`,
      clusters };
  }
  return { action: "close_and_watchlist", closeStatus: "CERRADO", classification: "TRUE_POSITIVE",
    rationale: `~${pct}% son ${top.label} (confianza ${top.avgConfidence}). Recomendado: bloquear las IPs en lgcrBL y cerrar.`,
    clusters };
}
