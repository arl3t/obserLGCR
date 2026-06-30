/**
 * cveDetection.mjs — B1 audit Casos 2026-05-21
 *
 * Patrones de detección de explotación que se aplican sobre texto de eventos
 * crudos (Wazuh full_log, Suricata payload_printable, OPNsense raw_log,
 * FortiGate message). Cada match identifica una técnica (con CVE cuando aplica)
 * para que el panel del analista lo vea sin abrir el JSON crudo.
 *
 * Origen: las regex vivían client-side en
 * `legacyhunt-dashboard/src/components/hunting/IocDeepAnalysisPanel.tsx` y solo
 * se aplicaban en la página de Hunting. Esta migración las mueve a backend
 * para reutilizarlas en `/api/cases/:id/cves` y dejar la fuente única.
 *
 * Diseño:
 *   - `ATTACK_PATTERNS` es una lista frozen — agregar uno requiere editar
 *     este archivo y el test.
 *   - `detectCvesInText(text)` retorna matches deduplicados por `name+cve`.
 *   - `detectCvesInEvent(rawEvent)` aplica sobre la unión de campos string
 *     conocidos (message, full_log, payload_printable, http.url, etc.).
 *   - `tone` informa la prioridad visual: crit > high > warn.
 *   - Cada match incluye `detail`: el substring matcheado, max 200 chars.
 */

const _PATTERNS = [
  { re: /vendor\/phpunit\/phpunit\/src\/Util\/PHP\/eval-stdin\.php/i,
    match: { name: "PHPUnit RCE",                cve: "CVE-2017-9841", mitre: "T1190", tone: "crit" } },
  { re: /\$\{jndi:(ldap|rmi|dns):/i,
    match: { name: "Log4Shell",                  cve: "CVE-2021-44228", mitre: "T1190", tone: "crit" } },
  { re: /\(\)\s*\{\s*:;?\s*\}\s*;/,
    match: { name: "Shellshock",                 cve: "CVE-2014-6271", mitre: "T1190", tone: "crit" } },
  { re: /\/remote\/fgt_lang|\/remote\/login/i,
    match: { name: "Fortinet FortiGate probe",   cve: "CVE-2022-40684", mitre: "T1190", tone: "crit" } },
  { re: /\/owa\/auth\/x\.js|autodiscover\.xml/i,
    match: { name: "Exchange (ProxyLogon) probe", cve: "CVE-2021-26855", mitre: "T1190", tone: "crit" } },
  { re: /\/wp-content\/plugins\/.*\.php\?.*=cmd/i,
    match: { name: "WordPress plugin RCE",       mitre: "T1190", tone: "crit" } },
  { re: /\/wp-login\.php|\/xmlrpc\.php/i,
    match: { name: "WordPress brute-force",      mitre: "T1110.001", tone: "high" } },
  { re: /\.\.\/\.\.\/\.\.\/etc\/passwd|%2e%2e%2fetc%2fpasswd/i,
    match: { name: "Path traversal",             mitre: "T1083", tone: "high" } },
  { re: /union\s+select|'\s+or\s+'1'\s*=\s*'1|sleep\(\d+\)/i,
    match: { name: "SQL injection",              mitre: "T1190", tone: "high" } },
  { re: /\.env(\s|\?|$)|\/\.git\/config/i,
    match: { name: "Secret files probe",         mitre: "T1083", tone: "high" } },
  { re: /cgi-bin\/\.\.\/|cgi-bin\/.*\.cgi\?.*%00/i,
    match: { name: "CGI injection",              mitre: "T1190", tone: "high" } },
  { re: /ssh_[a-z_]+_auth.*user\s*=\s*(root|admin|test)/i,
    match: { name: "SSH brute root/admin",       mitre: "T1110.001", tone: "high" } },
  { re: /<script|javascript:|onerror\s*=|onload\s*=/i,
    match: { name: "XSS probe",                  mitre: "T1059.007", tone: "warn" } },
  { re: /\/actuator(\/|$)|\/api\/v2\/swagger\.json/i,
    match: { name: "Spring Boot actuator probe", mitre: "T1592", tone: "warn" } },
  { re: /\/api\/v1\/.*\/exec|\/console\/api\//i,
    match: { name: "API exec endpoint probe",    mitre: "T1190", tone: "warn" } },
];

export const ATTACK_PATTERNS = Object.freeze(_PATTERNS.map(Object.freeze));

/**
 * Regex genérico para extraer cualquier CVE-YYYY-NNNN(N+) presente en texto
 * libre. Útil cuando el sensor reporta el CVE directamente (Wazuh
 * vulnerability-detector, Suricata signature metadata, FortiGate ips_log).
 */
const CVE_RE = /\bCVE-(\d{4})-(\d{4,7})\b/g;

/**
 * Detecta patrones de explotación en un fragmento de texto.
 *
 * @param {string|null|undefined} text
 * @returns {Array<{ name, cve?, mitre?, tone, detail }>}
 */
export function detectCvesInText(text) {
  if (!text || typeof text !== "string") return [];
  const out  = [];
  const seen = new Set();

  // 1) Patrones conocidos (Log4Shell, ProxyLogon, etc.)
  for (const p of ATTACK_PATTERNS) {
    const m = text.match(p.re);
    if (!m) continue;
    const key = p.match.name + (p.match.cve ?? "");
    if (seen.has(key)) continue;
    seen.add(key);
    // Tracking adicional por CVE: si después un literal CVE-X aparece en el
    // texto y ya lo cubrió un pattern, no duplicar.
    if (p.match.cve) seen.add(p.match.cve);
    out.push({
      ...p.match,
      detail: String(m[0]).slice(0, 200),
      source: "pattern",
    });
  }

  // 2) Cualquier CVE-YYYY-NNNN mencionado literalmente (Wazuh vuln-detector,
  //    Suricata reference, FortiGate attack metadata, etc.).
  for (const m of text.matchAll(CVE_RE)) {
    const cve = m[0];
    if (seen.has(cve)) continue;
    seen.add(cve);
    out.push({
      name:   `CVE referenciado en evento`,
      cve,
      tone:   "warn",   // sin contexto adicional; el caller puede subir tono si tiene CVSS
      detail: text.slice(Math.max(0, m.index - 60), Math.min(text.length, m.index + cve.length + 60)),
      source: "cve_literal",
    });
  }

  return out;
}

/**
 * Aplica `detectCvesInText` sobre los campos string conocidos de un evento
 * crudo (Wazuh JSON, Suricata eve.json, FortiGate KV, OPNsense filterlog).
 * Acepta tanto el objeto parseado (`event.parsed`) como el string crudo
 * (`event.event_json`).
 *
 * @param {{ event_json?: string, parsed?: object } | object | null} rawEvent
 * @returns {Array}
 */
export function detectCvesInEvent(rawEvent) {
  if (!rawEvent) return [];

  // Reunir todos los strings interesantes en un "haystack" único.
  const parts = [];

  // Caso 1: objeto plano
  const obj = rawEvent?.parsed ?? rawEvent;

  // Campos típicos por sensor — orden de prioridad para que el `detail` del
  // primer hit refleje la fuente más útil.
  const candidates = [
    obj?.message, obj?.full_log,
    obj?.payload_printable,
    obj?.http?.url, obj?.http?.user_agent,
    obj?.dns?.rrname,
    obj?.tls?.sni,
    obj?.alert?.signature, obj?.alert?.category,
    obj?.attack, obj?.attackname,
    obj?.data?.vulnerability?.cve,
    obj?.rule?.description,
    obj?.subject,
    rawEvent?.event_json,
  ];
  for (const c of candidates) {
    if (typeof c === "string" && c) parts.push(c);
  }

  if (!parts.length) return [];

  // Aplicar detección sobre el merge. El orden importa: detectCvesInText
  // dedupa por key, así que campos prioritarios deben ir primero.
  return detectCvesInText(parts.join("\n"));
}

/**
 * Helper para clasificar severidad operacional de un set de matches.
 * @param {Array} matches
 * @returns {'crit'|'high'|'warn'|null}
 */
export function maxCveTone(matches) {
  if (!matches?.length) return null;
  const tones = new Set(matches.map((m) => m.tone));
  if (tones.has("crit")) return "crit";
  if (tones.has("high")) return "high";
  if (tones.has("warn")) return "warn";
  return null;
}
