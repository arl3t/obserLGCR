/**
 * services/dedupKey.mjs — Fuente única de la fórmula de `dedup_key`.
 *
 * Antes de este archivo había 3 copias desfasadas:
 *   - routes/incidents.mjs (usaba `source_log`)
 *   - controllers/forcedAckController.mjs (usaba `source_category`)
 *   - data/airflow/dags/incident_cases_sync_daily.py (usaba `source_category`)
 *
 * Una copia usaba source_log y otras source_category → hashes distintos para
 * el mismo caso → falsos negativos de deduplicación. Este módulo centraliza
 * la fórmula y aplica normalización consistente de IOC.
 *
 * FÓRMULA CANÓNICA (mantiene la del DAG y forcedAckController para no
 * invalidar dedup_keys existentes en PG):
 *
 *   sev ∈ {CRITICAL, HIGH} → SHA256("<ioc_norm>|<mitre_tactic_id>")
 *   sev ∈ {MEDIUM, LOW, …} → SHA256("<ioc_norm>|<source_category>")
 *
 * `source_category` se deriva de `source_log` cuando el caller solo tiene ese
 * último (ver `sourceCategoryOf`). Garantiza que Node y Python produzcan el
 * mismo hash sin importar qué campo esté disponible.
 *
 * NORMALIZACIÓN del `ioc_value`:
 *   - Siempre `.trim()`.
 *   - `.toLowerCase()` SOLO para tipos donde el case es irrelevante:
 *     domain, url, email, sha1, sha256, md5, hash. IPs e hostnames mantienen
 *     su forma original (case-sensitive en algunos entornos).
 *
 * La contraparte Python vive en `data/airflow/plugins/dedup_key_canon.py`
 * y debe mantenerse byte-a-byte alineada con este archivo.
 */

import { createHash } from "node:crypto";

const HASH_SENSITIVE_TYPES = new Set([
  "domain", "url", "email",
  "hash", "md5", "sha1", "sha256",
]);

/**
 * Rango numérico de severidad. Espejo de `SEVERITY_RANK` en el DAG Python
 * (`data/airflow/dags/incident_cases_sync_daily.py`). Se usa para decidir si una
 * recurrencia "escala" respecto de una supresión vigente: MEDIUM/LOW/NEGLIGIBLE
 * comparten el bucket de `dedup_key` (`ioc|source_category`), así que un LOW
 * auto-cerrado no debe suprimir un MEDIUM posterior del mismo IOC.
 */
export const SEVERITY_RANK = Object.freeze({
  NEGLIGIBLE: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5,
});

/** Devuelve el rango numérico de una severidad (0 si desconocida). */
export function severityRank(sev) {
  return SEVERITY_RANK[String(sev ?? "").toUpperCase()] ?? 0;
}

/**
 * Mapea `source_log` (ej. "wazuh_alerts", "opnsense_filterlog") a la
 * `source_category` de alto nivel que se usa en el hash (ej. "siem",
 * "firewall"). La tabla es pequeña y estable — se sincroniza con la versión
 * Python. Cualquier log no listado cae en "other".
 */
export function sourceCategoryOf(sourceLogOrCategory) {
  const s = String(sourceLogOrCategory ?? "").trim().toLowerCase();
  if (!s) return "";
  // Ya es una categoría — respetar.
  if (["siem", "firewall", "ids", "ips", "email", "edr", "dns", "proxy", "auth", "other"].includes(s)) return s;
  // Mapping log → category.
  if (s.startsWith("wazuh"))        return "siem";
  if (s.includes("filterlog"))      return "firewall";
  if (s.startsWith("fortigate") || s.startsWith("fg")) return "firewall";
  if (s.startsWith("opnsense"))     return "firewall";
  if (s.startsWith("suricata"))     return "ids";
  if (s.startsWith("snort"))        return "ids";
  if (s.startsWith("pmg") || s.includes("postfix") || s.includes("email")) return "email";
  if (s.startsWith("bind") || s.includes("dns"))   return "dns";
  if (s.includes("squid") || s.includes("proxy")) return "proxy";
  return "other";
}

/**
 * Normaliza un `ioc_value` antes del hash. Acepta cualquier input y lo
 * convierte a string; `trim` siempre; `toLowerCase` solo para tipos
 * case-insensitive. Si `iocType` es null/undefined trata el valor como
 * opaco y solo aplica trim.
 */
export function normalizeIoc(iocValue, iocType) {
  const trimmed = String(iocValue ?? "").trim();
  const t = String(iocType ?? "").toLowerCase().trim();
  return HASH_SENSITIVE_TYPES.has(t) ? trimmed.toLowerCase() : trimmed;
}

/**
 * Calcula el dedup_key canónico.
 *
 * @param {object} p
 * @param {string} p.iocValue
 * @param {string} [p.iocType]         — "ip" | "domain" | "url" | "email" | "hash" | ...
 * @param {string} p.severity          — CRITICAL | HIGH | MEDIUM | LOW | NEGLIGIBLE
 * @param {string} [p.mitreTacticId]   — ID MITRE (TA####) — solo importa para CRITICAL/HIGH
 * @param {string} [p.sourceLog]       — log de origen ("wazuh_alerts", "opnsense_filterlog", …)
 * @param {string} [p.sourceCategory]  — opcional; si se pasa explícito se respeta, si no se deriva de sourceLog
 * @returns {string} SHA-256 hex de 64 caracteres.
 */
export function dedupKey({ iocValue, iocType, severity, mitreTacticId, sourceLog, sourceCategory }) {
  const sev   = String(severity ?? "MEDIUM").toUpperCase();
  const ioc   = normalizeIoc(iocValue, iocType);
  const mitre = String(mitreTacticId ?? "").trim();
  const cat   = (sourceCategory != null && String(sourceCategory).trim())
    ? String(sourceCategory).trim().toLowerCase()
    : sourceCategoryOf(sourceLog);
  const raw = (sev === "CRITICAL" || sev === "HIGH")
    ? `${ioc}|${mitre}`
    : `${ioc}|${cat}`;
  return createHash("sha256").update(raw, "utf8").digest("hex");
}
