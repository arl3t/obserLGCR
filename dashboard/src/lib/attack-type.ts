/**
 * attack-type.ts — Inferencia del "tipo de ataque" para un caso SOC.
 *
 * Deriva una etiqueta legible y un color a partir de la combinación de
 * mitre_tactic_id, incident_category, ioc_type, source_log y firewall_action.
 * Se prioriza la señal más específica (sourceLog leak_intel, MITRE explícito,
 * categoría NIST, IOC + firewall, IOC solo).
 *
 * Devuelve `null` si no hay señal suficiente para clasificar — la UI debe
 * pedir al operador que complete la clasificación.
 */

import type { SocCase } from "@/components/case-management/types";

export interface AttackType {
  /** Etiqueta corta para el badge */
  label:    string;
  /** Frase descriptiva para tooltip / detalle */
  detail:   string;
  /** Color de acento (Tailwind hex) */
  color:    string;
  /** ATT&CK tactic ID derivado, si aplica */
  tacticId: string | null;
  /** Confianza heurística: "high" si vino de MITRE/categoría explícita; "low" si es solo por IOC */
  confidence: "high" | "low";
}

const TACTIC_LABEL: Record<string, { label: string; color: string }> = {
  TA0043: { label: "Reconocimiento",                color: "#06b6d4" },
  TA0042: { label: "Desarrollo de recursos",         color: "#64748b" },
  TA0001: { label: "Acceso inicial / Phishing",      color: "#f59e0b" },
  TA0002: { label: "Ejecución de código",            color: "#ef4444" },
  TA0003: { label: "Persistencia",                   color: "#dc2626" },
  TA0004: { label: "Escalada de privilegios",        color: "#dc2626" },
  TA0005: { label: "Evasión de defensas",            color: "#a855f7" },
  TA0006: { label: "Acceso a credenciales",          color: "#f97316" },
  TA0007: { label: "Descubrimiento / escaneo",       color: "#06b6d4" },
  TA0008: { label: "Movimiento lateral",             color: "#dc2626" },
  TA0009: { label: "Recolección de datos",           color: "#a855f7" },
  TA0011: { label: "Comando y control (C2)",         color: "#dc2626" },
  TA0010: { label: "Exfiltración de datos",          color: "#dc2626" },
  TA0040: { label: "Impacto / Denegación",           color: "#dc2626" },
};

const NIST_LABEL: Record<string, { label: string; color: string }> = {
  UNAUTHORIZED_ACCESS: { label: "Acceso no autorizado",       color: "#ef4444" },
  DENIAL_OF_SERVICE:   { label: "Denegación de servicio",     color: "#dc2626" },
  MALICIOUS_CODE:      { label: "Código malicioso",           color: "#dc2626" },
  IMPROPER_USAGE:      { label: "Uso indebido",               color: "#f59e0b" },
  SCANS_PROBES:        { label: "Reconocimiento / escaneo",   color: "#06b6d4" },
  INVESTIGATION:       { label: "Investigación abierta",      color: "#94a3b8" },
  OTHER:               { label: "Otro",                       color: "#94a3b8" },
};

/**
 * Infiere el tipo de ataque para un caso. Devuelve null si no hay señal.
 */
export function inferAttackType(c: Pick<SocCase,
  "mitre" | "incidentCategory" | "iocType" | "source" | "firewallAction"
>): AttackType | null {
  const tacticId = c.mitre?.tacticId ?? null;
  const ioc      = (c.iocType ?? "").toLowerCase();
  const src      = (c.source  ?? "").toLowerCase();
  const fw       = (c.firewallAction ?? "").toUpperCase();

  // 1. Señal de mayor especificidad: detección de credenciales fugadas
  if (src === "leak_intel" || (ioc === "domain" && tacticId === "TA0006")) {
    return {
      label:      "Credenciales fugadas",
      detail:     "Detección desde Vigilancia Digital — credenciales del dominio expuestas en dump/leak.",
      color:      "#f97316",
      tacticId:   tacticId ?? "TA0006",
      confidence: "high",
    };
  }

  // 2. Señal MITRE explícita (alta confianza)
  if (tacticId && TACTIC_LABEL[tacticId]) {
    const t = TACTIC_LABEL[tacticId];
    return {
      label:      t.label,
      detail:     `Clasificado por MITRE ATT&CK: ${tacticId} (${c.mitre?.tacticName ?? t.label}).`,
      color:      t.color,
      tacticId,
      confidence: "high",
    };
  }

  // 3. Categoría NIST SP 800-61
  if (c.incidentCategory && NIST_LABEL[c.incidentCategory]) {
    const n = NIST_LABEL[c.incidentCategory];
    return {
      label:      n.label,
      detail:     `Categoría NIST: ${c.incidentCategory}.`,
      color:      n.color,
      tacticId:   null,
      confidence: "high",
    };
  }

  // 4. Heurística por IOC (baja confianza — sugerencia)
  if (ioc === "url")    return { label: "Web attack",         detail: "URL marcada como sospechosa — posible phishing/SQLi/XSS.", color: "#f59e0b", tacticId: "TA0001", confidence: "low" };
  if (ioc === "hash")   return { label: "Malware",            detail: "Hash detectado — archivo malicioso.",                       color: "#dc2626", tacticId: "TA0002", confidence: "low" };
  if (ioc === "email")  return { label: "Phishing / spam",    detail: "Email marcado como malicioso.",                              color: "#f59e0b", tacticId: "TA0001", confidence: "low" };
  if (ioc === "domain") return { label: "Dominio sospechoso", detail: "Dominio marcado por threat intel.",                          color: "#f59e0b", tacticId: null,     confidence: "low" };

  if (ioc === "ip") {
    if (fw === "BLOCK" || fw === "DROP" || fw === "DENY") {
      return { label: "Conexión bloqueada (firewall)", detail: "IP cuya conexión fue bloqueada por el perímetro.", color: "#22c55e", tacticId: null, confidence: "low" };
    }
    return { label: "Actividad de IP sospechosa", detail: "IP marcada por correlación interna o threat intel.", color: "#f59e0b", tacticId: null, confidence: "low" };
  }

  // 5. Sin señal
  return null;
}
