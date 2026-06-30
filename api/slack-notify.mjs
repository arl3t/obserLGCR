/**
 * slack-notify.mjs — Envío de notificaciones a Slack vía Incoming Webhooks.
 *
 * Variables de entorno:
 *   SLACK_WEBHOOK_URL    URL del Incoming Webhook (obligatoria para enviar)
 *   SLACK_CHANNEL        Canal destino, p.ej. #soc-alerts (opcional)
 *   SLACK_USERNAME       Nombre del bot (default: LegacyHunt SOC)
 *   SLACK_ICON_EMOJI     Emoji del icono (default: :shield:)
 *   SLACK_NOTIFY_ENABLED true/false (default: true si SLACK_WEBHOOK_URL está definida)
 *   DASHBOARD_URL        URL base del dashboard para links en alertas
 *                        (default: http://localhost:5173)
 *
 * Criterios de activación (configurables en .env):
 *   SSH brute force      SLACK_NOTIFY_MIN_SSH_ATTEMPTS ≥ 100
 *   Wazuh crítico        SLACK_NOTIFY_MIN_WAZUH_LEVEL  ≥ 12
 *   IOC alto riesgo      SLACK_NOTIFY_MIN_IOC_SCORE    ≥ 80
 *
 * Clasificación de severidad:
 *   SSH:  CRITICAL ≥ 500 intentos o usuario privilegiado
 *         HIGH     ≥ 100 intentos
 *         MEDIUM   ≥ 50 intentos
 *   IOC:  CRITICAL score ≥ 90
 *         HIGH     score ≥ 80
 *   Wazuh: CRITICAL nivel ≥ 15
 *          HIGH    nivel ≥ 12
 *          MEDIUM  nivel ≥ 8
 *
 * Deduplicación:
 *   Alertas de sensor (SSH, Wazuh, IOC, auditd): suprimidas 60 min — evita spam de ciclos.
 *   Alertas de adopción de incidentes (bulk): suprimidas 15 min — se repiten hasta adopción.
 */

import { formatCaseNumber } from "./services/caseNumber.mjs";
import { getResolvedConfigSync, getResolvedConfigBool } from "./services/appConfigService.mjs";

// Config resuelta por-llamada (DB cifrada → .env → default) vía appConfigService:
// editable desde Ajustes sin reiniciar (applyMode "live"). Antes eran consts a
// nivel de módulo evaluadas una vez al import.
const webhookUrl   = () => (getResolvedConfigSync("SLACK_WEBHOOK_URL") ?? "").trim();
const slackChannel = () => (getResolvedConfigSync("SLACK_CHANNEL") ?? "").trim();
const slackUser    = () => (getResolvedConfigSync("SLACK_USERNAME") ?? "LegacyHunt SOC").trim();
const slackIcon    = () => (getResolvedConfigSync("SLACK_ICON_EMOJI") ?? ":shield:").trim();
const dashUrl      = () => (getResolvedConfigSync("DASHBOARD_URL") ?? "http://localhost:5173").trim().replace(/\/+$/, "");

/** ¿Slack activo? Webhook definido y SLACK_NOTIFY_ENABLED != false. */
export function isSlackEnabled() {
  return webhookUrl().length > 0 && getResolvedConfigBool("SLACK_NOTIFY_ENABLED", true);
}

// ── Deduplicación ─────────────────────────────────────────────────────────────

/** Caché en memoria: key → timestamp de expiración. */
const _dedupeCache = new Map();
/** TTL estándar para alertas de sensor (SSH, Wazuh, IOC, auditd): 60 minutos. */
const DEDUPE_TTL_MS = 60 * 60 * 1_000;
/** TTL para alertas de adopción de incidentes: 15 minutos — repite hasta que el operador actúe. */
const DEDUPE_ADOPTION_TTL_MS = 15 * 60 * 1_000;

/**
 * Devuelve true si la clave ya fue emitida en el último TTL (suprime la alerta).
 * Registra la clave y purga entradas expiradas si el mapa supera 1000 entries.
 * @param {string} key  - Clave de deduplicación
 * @param {number} [ttlMs] - TTL en ms; usa DEDUPE_TTL_MS si se omite
 */
function isDuplicate(key, ttlMs = DEDUPE_TTL_MS) {
  const now = Date.now();
  const expiry = _dedupeCache.get(key);
  if (expiry && now < expiry) return true;
  _dedupeCache.set(key, now + ttlMs);
  if (_dedupeCache.size > 1_000) {
    for (const [k, v] of _dedupeCache) {
      if (v < now) _dedupeCache.delete(k);
    }
  }
  return false;
}

// ── Clasificación de severidad ────────────────────────────────────────────────

/**
 * Cuentas de sistema que representan mayor riesgo si son atacadas.
 * Un intento de fuerza bruta contra root/admin baja el umbral de notificación.
 */
const PRIVILEGED_USERS = new Set([
  "root", "admin", "administrator", "postgres", "oracle",
  "ubuntu", "ec2-user", "pi", "vagrant", "deploy", "git",
]);

/**
 * Clasifica la severidad de un ataque SSH.
 * @returns {{ level: "CRITICAL"|"HIGH"|"MEDIUM", emoji: string, label: string }}
 */
function sshSeverity(attempts, invalid_user) {
  const user = String(invalid_user ?? "").toLowerCase().trim();
  const isPrivileged = PRIVILEGED_USERS.has(user) || user === "root";
  if (attempts >= 500 || (isPrivileged && attempts >= 50)) {
    return { level: "CRITICAL", emoji: "🔴", label: "CRÍTICO" };
  }
  if (attempts >= 100) {
    return { level: "HIGH", emoji: "🟠", label: "ALTO" };
  }
  return { level: "MEDIUM", emoji: "🟡", label: "MEDIO" };
}

/**
 * Riesgo del nombre de usuario SSH.
 * @returns {{ label: string, detail: string }}
 */
function usernameRisk(user) {
  const u = String(user ?? "").toLowerCase().trim();
  if (u === "root" || u === "admin" || u === "administrator") {
    return { label: "Cuenta privilegiada crítica", detail: "Escalación directa si tiene éxito" };
  }
  if (PRIVILEGED_USERS.has(u)) {
    return { label: "Cuenta de sistema conocida", detail: "Acceso a servicios internos si compromete" };
  }
  return { label: "Usuario desconocido", detail: "Enumeración de credenciales" };
}

/**
 * Clasifica la severidad de un IOC según su score.
 * @returns {{ level: string, emoji: string, label: string }}
 */
function iocSeverity(score) {
  if (score >= 90) return { level: "CRITICAL", emoji: "🔴", label: "CRÍTICO" };
  if (score >= 80) return { level: "HIGH",     emoji: "🟠", label: "ALTO" };
  if (score >= 60) return { level: "MEDIUM",   emoji: "🟡", label: "MEDIO" };
  return                  { level: "LOW",      emoji: "⚪", label: "BAJO"  };
}

/**
 * Clasifica la severidad de una alerta Wazuh según su nivel.
 * @returns {{ level: string, emoji: string, label: string }}
 */
function wazuhSeverity(level) {
  if (level >= 15) return { level: "CRITICAL", emoji: "🔴", label: "CRÍTICO" };
  if (level >= 12) return { level: "HIGH",     emoji: "🟠", label: "ALTO"   };
  if (level >= 8)  return { level: "MEDIUM",   emoji: "🟡", label: "MEDIO"  };
  return                  { level: "LOW",      emoji: "⚪", label: "BAJO"   };
}

// ── Helpers de formato ────────────────────────────────────────────────────────

function fmtNumber(n) {
  return Number(n).toLocaleString("es-ES");
}

function nowUtc() {
  return new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

/**
 * Calcula la duración entre dos timestamps ISO o strings de fecha.
 * @returns {string} Ej: "2h 15m" o "—" si no aplica
 */
function calcDuration(first_seen, last_seen) {
  try {
    const a = new Date(first_seen);
    const b = last_seen ? new Date(last_seen) : new Date();
    const ms = b - a;
    if (isNaN(ms) || ms < 0) return "—";
    const h = Math.floor(ms / 3_600_000);
    const m = Math.floor((ms % 3_600_000) / 60_000);
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m`;
    return "<1m";
  } catch {
    return "—";
  }
}

// ── Enviador base ─────────────────────────────────────────────────────────────

/**
 * Envía un mensaje a Slack.
 * @param {{ text: string, blocks?: unknown[], attachments?: unknown[] }} payload
 * @returns {Promise<{ ok: boolean, status?: number, body?: string, error?: string }>}
 */
export async function sendSlackAlert(payload) {
  if (!isSlackEnabled()) {
    return { ok: false, error: "Slack no configurado (SLACK_WEBHOOK_URL no definida o SLACK_NOTIFY_ENABLED=false)" };
  }

  const channel = slackChannel();
  const body = {
    username: slackUser(),
    icon_emoji: slackIcon(),
    ...(channel ? { channel } : {}),
    text: payload.text,
    ...(payload.blocks ? { blocks: payload.blocks } : {}),
    ...(payload.attachments ? { attachments: payload.attachments } : {}),
  };

  try {
    const res = await fetch(webhookUrl(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(8_000),
    });
    const text = await res.text();
    return { ok: res.ok, status: res.status, body: text };
  } catch (err) {
    return { ok: false, error: String(err?.message ?? err) };
  }
}

// ── Constructores de bloques Block Kit ────────────────────────────────────────

/**
 * Alerta para brute force SSH con usuarios inválidos.
 *
 * Criterio de activación: attempts >= SLACK_NOTIFY_MIN_SSH_ATTEMPTS (default 100)
 * Deduplicación: clave `ssh:<srcip>:<invalid_user>` — silenciado 60 min tras primera alerta.
 *
 * @param {{ srcip: string, invalid_user: string, attempts: number, agent: string,
 *           first_seen?: string, last_seen?: string, dedupe?: boolean }} opts
 */
export function buildSshBruteforceBlock(opts) {
  const { srcip, invalid_user, attempts, agent, first_seen, last_seen, dedupe = true } = opts;

  if (dedupe && isDuplicate(`ssh:${srcip}:${invalid_user}`)) {
    return null; // suprimido por deduplicación
  }

  const sev     = sshSeverity(attempts, invalid_user);
  const uRisk   = usernameRisk(invalid_user);
  const duration = calcDuration(first_seen, last_seen);

  // Acción recomendada según severidad
  const action = sev.level === "CRITICAL"
    ? "Bloquear IP inmediatamente en firewall perimetral. Revisar si hay sesiones activas."
    : sev.level === "HIGH"
    ? "Verificar si el IP figura en listas de bloqueo. Considerar regla temporal en pf/ufw."
    : "Monitorizar; escalar si los intentos continúan.";

  return {
    text: `${sev.emoji} [${sev.label}] SSH Brute Force: \`${srcip}\` → \`${invalid_user}\` (${fmtNumber(attempts)} intentos)`,
    blocks: [
      {
        type: "header",
        text: {
          type: "plain_text",
          text: `${sev.emoji} SSH Brute Force — Severidad ${sev.label}`,
          emoji: true,
        },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*IP atacante:*\n\`${srcip}\`` },
          { type: "mrkdwn", text: `*Usuario objetivo:*\n\`${invalid_user}\`` },
          { type: "mrkdwn", text: `*Intentos:*\n${fmtNumber(attempts)}` },
          { type: "mrkdwn", text: `*Duración ataque:*\n${duration}` },
          { type: "mrkdwn", text: `*Agente Wazuh:*\n${agent}` },
          { type: "mrkdwn", text: `*Riesgo usuario:*\n${uRisk.label}` },
        ],
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Primer intento:*\n${first_seen ?? "—"}` },
          { type: "mrkdwn", text: `*Último intento:*\n${last_seen ?? "—"}` },
        ],
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Riesgo:* ${uRisk.detail}\n*Acción recomendada:* ${action}`,
        },
      },
      { type: "divider" },
      {
        type: "actions",
        elements: [
          {
            type: "button",
            text: { type: "plain_text", text: "Ver en Dashboard", emoji: true },
            url: `${dashUrl()}/wazuh-intelligence`,
            style: "danger",
          },
        ],
      },
      {
        type: "context",
        elements: [
          { type: "mrkdwn", text: `_LegacyHunt SOC · ${nowUtc()} · Reglas Wazuh 5710–5758_` },
        ],
      },
    ],
  };
}

/**
 * Alerta para alertas Wazuh críticas (nivel ≥ 12).
 *
 * Criterio de activación: level >= SLACK_NOTIFY_MIN_WAZUH_LEVEL (default 12) y ≥ 10 hits en 2h.
 * Deduplicación: clave `wazuh:<rule_id>:<agent>` — silenciado 60 min.
 *
 * @param {{ rule_id: string, description: string, agent: string, srcip?: string,
 *           level: number, count: number, mitre?: string, dedupe?: boolean }} opts
 */
export function buildCriticalWazuhBlock(opts) {
  const { rule_id, description, agent, srcip, level, count, mitre, dedupe = true } = opts;

  if (dedupe && isDuplicate(`wazuh:${rule_id}:${agent}`)) {
    return null;
  }

  const sev = wazuhSeverity(level);

  return {
    text: `${sev.emoji} [${sev.label}] Wazuh L${level}: ${description} (${fmtNumber(count)} hits en 2h)`,
    blocks: [
      {
        type: "header",
        text: {
          type: "plain_text",
          text: `${sev.emoji} Wazuh — Alerta ${sev.label} (Nivel ${level})`,
          emoji: true,
        },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Regla:*\n\`${rule_id}\`` },
          { type: "mrkdwn", text: `*Nivel:*\n${level} — ${sev.label}` },
          { type: "mrkdwn", text: `*Agente:*\n${agent}` },
          { type: "mrkdwn", text: `*IP origen:*\n\`${srcip ?? "—"}\`` },
          { type: "mrkdwn", text: `*Hits (2h):*\n${fmtNumber(count)}` },
          { type: "mrkdwn", text: `*MITRE ATT&CK:*\n${mitre ?? "—"}` },
        ],
      },
      {
        type: "section",
        text: { type: "mrkdwn", text: `*Descripción:*\n${description}` },
      },
      { type: "divider" },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `_LegacyHunt SOC · ${nowUtc()} · <${dashUrl()}/wazuh-intelligence|Ver en Dashboard>_`,
          },
        ],
      },
    ],
  };
}

/**
 * Alerta para IOC con score VT/Shodan/AbuseIPDB alto.
 *
 * Criterio de activación: score >= SLACK_NOTIFY_MIN_IOC_SCORE (default 80).
 * Deduplicación: clave `ioc:<ip>` — silenciado 60 min.
 *
 * @param {{ ip: string, score: number, vt_positives?: number, shodan_ports?: string,
 *           abuse_confidence?: number, dedupe?: boolean }} opts
 */
export function buildHighScoreIocBlock(opts) {
  const { ip, score, vt_positives, shodan_ports, abuse_confidence, dedupe = true } = opts;

  if (dedupe && isDuplicate(`ioc:${ip}`)) {
    return null;
  }

  const sev = iocSeverity(score);

  // Resumen de inteligencia disponible
  const intelParts = [];
  if (vt_positives != null) intelParts.push(`VT: ${vt_positives} motores`);
  if (abuse_confidence != null) intelParts.push(`AbuseIPDB: ${abuse_confidence}%`);
  if (shodan_ports) intelParts.push(`Shodan: ${shodan_ports}`);
  const intelSummary = intelParts.length ? intelParts.join(" · ") : "Sin datos de inteligencia adicional";

  return {
    text: `${sev.emoji} [${sev.label}] IOC detectado: \`${ip}\` (score ${score})`,
    blocks: [
      {
        type: "header",
        text: {
          type: "plain_text",
          text: `${sev.emoji} IOC ${sev.label} — Score de Enriquecimiento`,
          emoji: true,
        },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*IP:*\n\`${ip}\`` },
          { type: "mrkdwn", text: `*Score:*\n*${score} / 100*` },
          { type: "mrkdwn", text: `*Severidad:*\n${sev.label}` },
          { type: "mrkdwn", text: `*VT detecciones:*\n${vt_positives ?? "—"}` },
          { type: "mrkdwn", text: `*Shodan puertos:*\n${shodan_ports ?? "—"}` },
          { type: "mrkdwn", text: `*AbuseIPDB:*\n${abuse_confidence != null ? `${abuse_confidence}%` : "—"}` },
        ],
      },
      {
        type: "section",
        text: { type: "mrkdwn", text: `*Inteligencia:* ${intelSummary}` },
      },
      { type: "divider" },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `_LegacyHunt SOC · ${nowUtc()} · <${dashUrl()}/enriched-score|Ver /enriched-score>_`,
          },
        ],
      },
    ],
  };
}

/**
 * Alerta de fallo de DAG Airflow (para on_failure_callback).
 * No usa deduplicación ya que los fallos de DAG deben notificarse siempre.
 * @param {{ dag_id: string, task_id: string, run_id: string, error: string }} opts
 */
export function buildDagFailureBlock(opts) {
  const { dag_id, task_id, run_id, error } = opts;
  return {
    text: `⚠️ DAG fallido: ${dag_id} / ${task_id}`,
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: "⚠️ Airflow — Fallo en DAG", emoji: true },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*DAG:*\n\`${dag_id}\`` },
          { type: "mrkdwn", text: `*Tarea:*\n\`${task_id}\`` },
          { type: "mrkdwn", text: `*Run ID:*\n${run_id}` },
          { type: "mrkdwn", text: `*Hora:*\n${nowUtc()}` },
        ],
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Error:*\n\`\`\`${String(error).slice(0, 400)}\`\`\``,
        },
      },
      { type: "divider" },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `_Revisar en Airflow UI → http://localhost:8082 · ${nowUtc()}_`,
          },
        ],
      },
    ],
  };
}

/**
 * Alerta de auditd — ejecución de proceso privilegiado o sospechoso.
 *
 * Criterio de activación: euid=0 (root) o reglas Wazuh 80700–80799.
 * Deduplicación: clave `auditd:<agent>:<exe>` — silenciado 60 min.
 *
 * @param {{ agent: string, command: string, exe: string, uid: string, euid: string,
 *           rule_id: string, mitre?: string, dedupe?: boolean }} opts
 */
export function buildAuditdPrivilegeBlock(opts) {
  const { agent, command, exe, uid, euid, rule_id, mitre, dedupe = true } = opts;

  if (dedupe && isDuplicate(`auditd:${agent}:${exe}`)) {
    return null;
  }

  const isRootExec = String(euid ?? uid ?? "").trim() === "0";
  const emoji = isRootExec ? "🔴" : "🟠";
  const severityLabel = isRootExec ? "CRÍTICO — Ejecución como root" : "ALTO — Proceso sospechoso";

  return {
    text: `${emoji} auditd: \`${command}\` en ${agent} (euid=${euid}, regla ${rule_id})`,
    blocks: [
      {
        type: "header",
        text: {
          type: "plain_text",
          text: `${emoji} auditd — ${severityLabel}`,
          emoji: true,
        },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Agente:*\n${agent}` },
          { type: "mrkdwn", text: `*Comando:*\n\`${command}\`` },
          { type: "mrkdwn", text: `*Ejecutable:*\n\`${exe}\`` },
          { type: "mrkdwn", text: `*UID / EUID:*\n${uid} / ${euid}` },
          { type: "mrkdwn", text: `*Regla Wazuh:*\n\`${rule_id}\`` },
          { type: "mrkdwn", text: `*MITRE ATT&CK:*\n${mitre ?? "—"}` },
        ],
      },
      { type: "divider" },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `_LegacyHunt SOC · ${nowUtc()} · <${dashUrl()}/wazuh-intelligence|Ver /wazuh-intelligence>_`,
          },
        ],
      },
    ],
  };
}

/**
 * Notificación masiva de incidentes abiertos — solicita adopción de casos.
 *
 * Envía un único mensaje con la lista completa de CRITICAL/HIGH/MEDIUM abiertos.
 * Deduplicación: clave `incidents:bulk:<date>` — silenciado 30 min.
 *
 * @param {{
 *   incidents: Array<{
 *     incident_key: string, ioc_value: string, ioc_type?: string,
 *     severity: string, score: number, mitre_tactic_name?: string,
 *     source_log?: string, vt_malicious?: number, abuse_confidence?: number,
 *     classified_at?: string
 *   }>,
 *   triggeredBy?: string,
 *   dedupe?: boolean
 * }} opts
 */
export function buildIncidentBulkAdoptionBlock(opts) {
  const { incidents = [], triggeredBy = "sistema", dedupe = true } = opts;
  if (!incidents.length) return null;

  // Slot de 15 min: la clave rota cada cuarto de hora → repite hasta que el operador adopte.
  const slot = Math.floor(Date.now() / DEDUPE_ADOPTION_TTL_MS);
  const dedupeKey = `incidents:bulk:${slot}`;
  if (dedupe && isDuplicate(dedupeKey, DEDUPE_ADOPTION_TTL_MS)) return null;

  const SEV_EMOJI  = { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "⚪" };
  const SEV_LABEL  = { CRITICAL: "CRÍTICO", HIGH: "ALTO", MEDIUM: "MEDIO", LOW: "BAJO" };

  const critical = incidents.filter((i) => i.severity === "CRITICAL");
  const high     = incidents.filter((i) => i.severity === "HIGH");
  const medium   = incidents.filter((i) => i.severity === "MEDIUM");

  /* Resumen de totales */
  const summaryParts = [];
  if (critical.length) summaryParts.push(`🔴 ${critical.length} CRÍTICO${critical.length > 1 ? "S" : ""}`);
  if (high.length)     summaryParts.push(`🟠 ${high.length} ALTO${high.length > 1 ? "S" : ""}`);
  if (medium.length)   summaryParts.push(`🟡 ${medium.length} MEDIO${medium.length > 1 ? "S" : ""}`);
  const summaryText = summaryParts.join("  ·  ");

  /* Lista de incidentes — max 20 para evitar límite de bloques Slack */
  const topIncidents = [...critical, ...high, ...medium].slice(0, 20);
  const incidentLines = topIncidents.map((inc) => {
    const sev  = SEV_EMOJI[inc.severity] ?? "⚪";
    const ioc  = String(inc.ioc_value ?? "—").slice(0, 30);
    const mitre = inc.mitre_tactic_name ? ` · ${inc.mitre_tactic_name}` : "";
    const vt   = inc.vt_malicious > 0 ? ` · VT:${inc.vt_malicious}` : "";
    const abuse = inc.abuse_confidence > 0 ? ` · Abuse:${inc.abuse_confidence}%` : "";
    return `${sev} \`${ioc}\`  — *${inc.score}pts*${mitre}${vt}${abuse}`;
  }).join("\n");

  const overflow = incidents.length > 20 ? `\n_… y ${incidents.length - 20} más_` : "";

  return {
    text: `🚨 [ADOPCIÓN REQUERIDA] ${incidents.length} incidente${incidents.length > 1 ? "s" : ""} abierto${incidents.length > 1 ? "s" : ""} — ${summaryText}`,
    blocks: [
      {
        type: "header",
        text: {
          type: "plain_text",
          text: `🚨 INCIDENTES ABIERTOS — Adopción requerida`,
          emoji: true,
        },
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*${incidents.length} caso${incidents.length > 1 ? "s" : ""} requieren atención inmediata.*\n${summaryText}\n\nActivado por: *${triggeredBy}*`,
        },
      },
      { type: "divider" },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Detalle de incidentes:*\n${incidentLines}${overflow}`,
        },
      },
      { type: "divider" },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Reglas de adopción:*\n• 🔴 CRITICAL / 🟠 HIGH → cierre obligatorio con ID de operador\n• 🟡 MEDIUM → documentación requerida\n• SLA CRITICAL: 15 min  ·  HIGH: 30 min  ·  MEDIUM: 60 min`,
        },
      },
      {
        type: "actions",
        elements: [
          {
            type: "button",
            text: { type: "plain_text", text: "📋 Gestión de Incidentes →", emoji: true },
            url: `${dashUrl()}/incident-management`,
            style: "danger",
          },
          {
            type: "button",
            text: { type: "plain_text", text: "🔍 Clasificación →", emoji: true },
            url: `${dashUrl()}/incident-classification`,
          },
        ],
      },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `_LegacyHunt SOC · ${nowUtc()} · ${incidents.length} incidente${incidents.length > 1 ? "s" : ""} pendientes de adopción_`,
          },
        ],
      },
    ],
  };
}


/**
 * Bloque de Slack para notificaciones de adopción desde la Gestión de Casos SOC.
 *
 * Reemplaza buildHighScoreIocBlock para los endpoints /incidents/:id/notify-slack:
 * incluye regla, agente, IP, MITRE, score breakdown completo (con MISP 0-20),
 * playbook y código de adopción de 15 minutos.
 *
 * @param {{
 *   caseId:    string,
 *   severity:  string,
 *   rule:      string,
 *   agent:     string,
 *   srcIp:     string,
 *   iocType?:  string,
 *   mitre?:    string | null,
 *   eventExtract?: string | null,
 *   score:     number,
 *   scoreBreakdown?: {
 *     mitre?:    number | null,
 *     evidence?: number | null,
 *     wazuh?:    number | null,
 *     misp?:     number | null,
 *     context?:  number | null,
 *     level?:    number | null,
 *   },
 *   code:      string,
 *   expiresAt: number,
 *   reason?:   string,
 *   dedupe?:   boolean,
 * }} opts
 */
export function buildSocCaseAdoptionBlock(opts) {
  const {
    caseId, severity, rule, agent, srcIp, iocType,
    mitre, eventExtract, score, scoreBreakdown = {},
    reason, dedupe = true,
  } = opts;

  if (dedupe && isDuplicate(`soccase:${caseId}:${severity}`, DEDUPE_ADOPTION_TTL_MS)) {
    return null;
  }

  const sevEmoji = severity === "CRITICAL" ? "🔴" : severity === "HIGH" ? "🟠" : "🟡";
  const dashboardLink = `${dashUrl()}/gestion`;

  const SLA_MAP = { CRITICAL: "15 min", HIGH: "30 min", MEDIUM: "60 min", LOW: "4h" };
  const sla = SLA_MAP[severity] ?? "60 min";

  const PLAYBOOK_MAP = {
    CRITICAL: "Bloquear IP inmediatamente · Aislar sistema afectado",
    HIGH:     "Investigar logs de autenticación · Considerar bloqueo",
    MEDIUM:   "Monitorizar 4h · Correlacionar con otros eventos",
    LOW:      "Registrar y revisar en próximo turno",
  };
  const playbookAction = PLAYBOOK_MAP[severity] ?? "Registrar y revisar en próximo turno";

  // ── Score bars ────────────────────────────────────────────────────────────────
  const bar = (pts, max) => {
    if (pts == null || isNaN(pts)) return "░".repeat(10);
    const filled = Math.min(10, Math.max(0, Math.round((Number(pts) / max) * 10)));
    return "█".repeat(filled) + "░".repeat(10 - filled);
  };
  const fmt = (v) => (v != null && !isNaN(v)) ? String(Math.round(Number(v))) : "null";

  const sm  = scoreBreakdown.mitre    ?? null;
  const se  = scoreBreakdown.evidence ?? null;
  const sw  = scoreBreakdown.wazuh    ?? null;
  const smp = scoreBreakdown.misp     ?? null;
  const sc  = scoreBreakdown.context  ?? null;
  const lvl = scoreBreakdown.level    ?? null;

  const scoreText =
    `*Score de riesgo: ${score}/100 — ${severity}*\n` +
    `\`MITRE    [${bar(sm, 40)}] ${fmt(sm)}/40\`\n` +
    `\`Evidencia[${bar(se, 35)}] ${fmt(se)}/35\`\n` +
    `\`Wazuh    [${bar(sw, 25)}] ${fmt(sw)}/25${lvl != null ? ` (level ${lvl})` : ""}\`\n` +
    `\`MISP     [${bar(smp, 20)}] ${fmt(smp)}/20\`\n` +
    `\`Contexto [${bar(sc, 10)}] ${fmt(sc)}/10\``;

  return {
    text: `${sevEmoji} [ADOPCIÓN REQUERIDA] Incidente ${severity} — \`${srcIp}\` — SLA: ${sla}`,
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: `${sevEmoji} ADOPCIÓN REQUERIDA — ${severity}`, emoji: true },
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `Un incidente *${severity}* requiere adopción inmediata por un operador SOC.\n` +
                `⏰ *SLA:* ${sla}`,
        },
      },
      { type: "divider" },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Regla:*\n${rule}` },
          { type: "mrkdwn", text: `*Agente/Host:*\n${agent}` },
          { type: "mrkdwn", text: `*IP origen:*\n\`${srcIp || "—"}\`` },
          { type: "mrkdwn", text: `*MITRE ATT&CK:*\n${mitre || "—"}` },
        ],
      },
      ...(eventExtract ? [{
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Extracto del evento:*\n${String(eventExtract).slice(0, 300)}`,
        },
      }] : []),
      { type: "divider" },
      {
        type: "section",
        text: { type: "mrkdwn", text: scoreText },
      },
      { type: "divider" },
      {
        type: "section",
        text: { type: "mrkdwn", text: `*Playbook ${severity}:*\n${playbookAction}` },
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `Abrí el caso en el dashboard y adoptalo desde la cola de *Gestión*.`,
        },
        accessory: {
          type: "button",
          text: { type: "plain_text", text: "Adoptar en Dashboard →", emoji: true },
          url: dashboardLink,
          style: "danger",
        },
      },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `_${formatCaseNumber(opts.caseNumber) ? `Caso *${formatCaseNumber(opts.caseNumber)}* · ` : ""}ID: \`${caseId}\`${reason ? ` · motivo: ${reason}` : ""} · LegacyHunt SOC · ${nowUtc()}_`,
          },
        ],
      },
    ],
  };
}

// Compat: algunos callers importaban `slackEnabled` como valor. Ahora es dinámico
// (la config es editable en runtime), así que se expone como función isSlackEnabled().
