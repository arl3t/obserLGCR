/**
 * autoClassifyController.mjs
 *
 * Dos flujos de clasificación automática:
 *
 * 1. autoClassifyFp  — POST /api/incidents/auto-classify
 *    Detecta FP CONFIRMED (known-safe, score<10 + intel limpia) y los persiste
 *    en incident_classifications con status=FALSO_POSITIVO + resolved_at.
 *
 * 2. autoProcessAll — POST /api/incidents/auto-process
 *    Para TODOS los IOCs MEDIUM / LOW / NEGLIGIBLE pendientes:
 *    · Abre el caso (classified_at = now)
 *    · Auto-documenta (closure_notes generadas de intel disponible)
 *    · Cierra inmediatamente (resolved_at = now, adopted_by = auto-sistema)
 *
 *    Política por severidad:
 *      NEGLIGIBLE (<10)  → FP confirmado de alta confianza (IP_KNOWN_SAFE o CLEAN_INTEL_LOW_SCORE) → FALSO_POSITIVO
 *                           resto → MONITOREADO (sin cierre automático)
 *      LOW (10-29)       → FP confirmado → FALSO_POSITIVO
 *                           FP probable  → EN_ANALISIS (revisión manual)
 *                           resto        → MONITOREADO (sin cierre automático)
 *      MEDIUM (30-54)    → FP confirmado → FALSO_POSITIVO
 *                           FP probable / intel limpia → MONITOREADO (requiere revisión analista)
 *
 *    Estados escritos (v2): FALSO_POSITIVO | CERRADO | MONITOREADO
 *    Estados legacy 'RESUELTO' en datos históricos se tratan como CERRADO.
 */

import { createHash, randomUUID } from "node:crypto";
import { trinoExec } from "../services/trinoWriter.mjs";
import { resolveNamedTrinoQuery } from "../trino/registry.mjs";
import { config } from "../config.mjs";
import { inferDetectionType, inferRuleFamily } from "../config/case-taxonomy.mjs";
import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { bootstrapCaseTasks } from "../services/casePlaybookService.mjs";
import { dedupKey, severityRank } from "../services/dedupKey.mjs";
import { upsertSuppression } from "../services/caseSuppression.mjs";
import { isSourceEnabled } from "../services/sourceLogCatalog.mjs";
import { classifyEcsirt } from "../services/ecsirtClassify.mjs";
import { screenIocMalice } from "../services/enrichmentService.mjs";
import { isRfc1918 } from "../services/netClass.mjs";

const TRINO_URL  = config.TRINO_URL;
const TRINO_USER = config.TRINO_USER || "legacyhunt-api";
const TABLE      = "minio_iceberg.hunting.incident_classifications";
const SESSION    = { catalog: "minio_iceberg", schema: "hunting" };

/* ── IPs known-safe ────────────────────────────────────────────────────────── */

const KNOWN_SAFE = new Set([
  "8.8.8.8", "8.8.4.4",
  "1.1.1.1", "1.0.0.1",
  "9.9.9.9", "149.112.112.112",
  "208.67.222.222", "208.67.220.220",
  "4.2.2.1", "4.2.2.2",
]);

/* ── Helpers SQL ───────────────────────────────────────────────────────────── */

function sq(s) {
  return `'${String(s ?? "").replace(/'/g, "''")}'`;
}
function tsz(iso) {
  const d = iso ? new Date(iso.replace(" UTC", "Z")) : new Date();
  return `TIMESTAMP '${d.toISOString().replace("T", " ").replace("Z", " UTC")}'`;
}
function incidentKey(iocValue, dt) {
  return createHash("sha256")
    .update(`${iocValue}|${dt}`)
    .digest("hex")
    .slice(0, 32);
}

/* ── Trino query helper ────────────────────────────────────────────────────── */

async function runNamedQuery(id, params) {
  const resolved = resolveNamedTrinoQuery(id, params, config);
  if (!resolved.ok) return { ok: false, error: resolved.error, rows: [] };
  if (!TRINO_URL)   return { ok: false, error: "TRINO_URL no configurada", rows: [] };

  const headers = {
    "X-Trino-User":    TRINO_USER,
    "X-Trino-Source":  "legacyhunt-auto-classify",
    "X-Trino-Catalog": "minio_iceberg",
    "X-Trino-Schema":  "hunting",
  };

  try {
    let res  = await fetch(`${TRINO_URL}/v1/statement`, {
      method: "POST",
      headers: { ...headers, "Content-Type": "text/plain" },
      body:   resolved.sql,
      signal: AbortSignal.timeout(30_000),
    });
    let data = await res.json();
    if (data.error) return { ok: false, error: data.error.message, rows: [] };

    let columns = [];
    const rows  = [];

    while (data.nextUri) {
      const nextUrl = data.nextUri.startsWith("http")
        ? data.nextUri
        : `${TRINO_URL}${data.nextUri}`;
      await new Promise((r) => setTimeout(r, 200));
      res  = await fetch(nextUrl, { headers, signal: AbortSignal.timeout(30_000) });
      data = await res.json();
      if (data.error) return { ok: false, error: data.error.message, rows };
      if (data.columns) columns = data.columns.map((c) => c.name);
      if (data.data) {
        for (const row of data.data) {
          const obj = {};
          columns.forEach((col, i) => { obj[col] = row[i]; });
          rows.push(obj);
        }
      }
    }
    if (data.columns && !columns.length) columns = data.columns.map((c) => c.name);
    if (data.data) {
      for (const row of data.data) {
        const obj = {};
        columns.forEach((col, i) => { obj[col] = row[i]; });
        rows.push(obj);
      }
    }
    return { ok: true, rows };
  } catch (err) {
    return { ok: false, error: String(err?.message ?? err), rows: [] };
  }
}

/* ── Clasificador FP ───────────────────────────────────────────────────────── */

function classifyFp(ioc) {
  const vt    = ioc.vt_malicious    != null ? Number(ioc.vt_malicious)    : null;
  const abuse = ioc.abuse_confidence != null ? Number(ioc.abuse_confidence) : null;
  const ports = String(ioc.shodan_ports ?? "");
  const hasC2Port = ports.includes("4444") || ports.includes("3389") ||
                    /,445,|^445,|,445$/.test(ports);

  if (KNOWN_SAFE.has(ioc.ioc_value)) {
    return { fp_confidence: "CONFIRMED", fp_reason: "IP_KNOWN_SAFE" };
  }
  if (
    (vt === null || vt === 0) &&
    (abuse === null || abuse < 10) &&
    !ioc.in_urlhaus && !ioc.in_openphish && !hasC2Port &&
    Number(ioc.score ?? 99) < 10
  ) {
    return { fp_confidence: "CONFIRMED", fp_reason: "CLEAN_INTEL_LOW_SCORE" };
  }
  if (
    ioc.severity === "LOW" &&
    (vt === null || vt === 0) &&
    (abuse === null || abuse < 20) &&
    !ioc.in_urlhaus && !ioc.in_openphish && !hasC2Port
  ) {
    return { fp_confidence: "PROBABLE", fp_reason: "LOW_CLEAN_INTEL" };
  }
  if (
    ioc.severity === "MEDIUM" &&
    (vt === null || vt === 0) &&
    (abuse === null || abuse < 25) &&
    !ioc.in_urlhaus && !ioc.in_openphish
  ) {
    return { fp_confidence: "POSSIBLE", fp_reason: "MEDIUM_CLEAN_INTEL" };
  }
  return { fp_confidence: "INSUFFICIENT", fp_reason: null };
}

/* ── Auto-documentación ────────────────────────────────────────────────────── */

function buildClosureNotes(ioc, fpResult, status) {
  const parts = [
    `[AUTO-SISTEMA] Caso procesado automáticamente — ${new Date().toISOString().replace("T"," ").slice(0,19)} UTC`,
    `Severidad: ${ioc.severity} | Score: ${ioc.score} (MITRE:${ioc.score_mitre} + Evidencia:${ioc.score_evidence} + Wazuh:${ioc.score_wazuh})`,
  ];

  // Inteligencia de amenazas
  const intel = [];
  if (ioc.vt_malicious != null)    intel.push(`VirusTotal: ${ioc.vt_malicious} detecciones maliciosas`);
  if (ioc.vt_suspicious != null && ioc.vt_suspicious > 0) intel.push(`VT sospechosos: ${ioc.vt_suspicious}`);
  if (ioc.abuse_confidence != null) intel.push(`AbuseIPDB: ${ioc.abuse_confidence}% confianza`);
  if (ioc.in_urlhaus)    intel.push("URLhaus: presente en feed activo");
  if (ioc.in_openphish)  intel.push("OpenPhish: presente en feed activo");
  if (ioc.shodan_ports)  intel.push(`Shodan puertos: ${ioc.shodan_ports}`);
  if (ioc.shodan_vulns && ioc.shodan_vulns !== "null")
    intel.push(`Shodan CVEs: ${ioc.shodan_vulns}`);
  if (ioc.mitre_tactic_name)
    intel.push(`MITRE ATT&CK: ${ioc.mitre_tactic_name}${ioc.mitre_technique_id ? ` (${ioc.mitre_technique_id})` : ""}`);
  if (intel.length) parts.push("Intel: " + intel.join(" | "));
  else              parts.push("Intel: sin detecciones en fuentes externas");

  // Criterio de cierre
  const fpLabel = fpResult.fp_reason?.replace(/_/g, " ") ?? "AUTO";
  if (status === "FALSO_POSITIVO") {
    parts.push(`Conclusión: FALSO POSITIVO confirmado — criterio: ${fpLabel}`);
    parts.push("Acción: caso cerrado automáticamente, sin riesgo operacional");
  } else if (status === "CERRADO") {
    if (ioc.severity === "NEGLIGIBLE") {
      parts.push("Conclusión: NEGLIGIBLE — sin inteligencia de amenaza activa, ruido de red");
      parts.push("Acción: caso registrado para KPI y cerrado; sin acción operacional requerida");
    } else if (fpResult.fp_confidence === "CONFIRMED") {
      // LOW FP confirmado: registrado como CERRADO para visibilidad en KPI
      parts.push(`Conclusión: FALSO POSITIVO confirmado (LOW) — criterio: ${fpLabel}`);
      parts.push("Acción: caso creado y cerrado para registro KPI; confirmado sin riesgo operacional");
    } else {
      parts.push(`Conclusión: RIESGO BAJO aceptable — criterio: ${fpLabel}`);
      parts.push("Acción: caso documentado y cerrado, actividad dentro de parámetros normales");
    }
  } else {
    // MONITOREADO / EN_ANALISIS — requiere aprobación o gestión de operador
    const pendingNote = fpResult.fp_confidence !== "INSUFFICIENT"
      ? ` (FP ${fpResult.fp_confidence}: ${fpLabel} — pendiente confirmación operador)`
      : "";
    const riskLabel = ioc.severity === "LOW" || ioc.severity === "NEGLIGIBLE" ? "RIESGO BAJO" : "RIESGO MEDIO";
    parts.push(`Conclusión: ${riskLabel}${pendingNote} — requiere validación de operador antes de cerrar`);
    if (status === "EN_ANALISIS") {
      parts.push("Acción: caso en EN_ANALISIS, sin cierre automático");
    } else {
      parts.push("Acción: caso en MONITOREADO, cierre bloqueado hasta aprobación de operador SOC");
    }
  }

  return parts.join("\n");
}

/* ── Persistencia con columnas v2 ──────────────────────────────────────────── */

async function persistCase(ioc, { status, recommendedAction, closureNotes, fpReason, isAuto }) {
  const today         = new Date().toISOString().slice(0, 10);
  const dt            = String(ioc.dt ?? today).slice(0, 10);
  const key           = incidentKey(ioc.ioc_value, dt);
  const now           = new Date().toISOString();
  // P1 dedup-churn (2026-06-04): el espejo a PG dejaba `dedup_key` (y `ioc_value`)
  // en NULL — 30.642 casos auto-clasificados sin clave de dedup → invisibles a la
  // supresión y a los lookups de recurrencia. Fuente única: services/dedupKey.mjs.
  const dk            = dedupKey({
    iocValue:      ioc.ioc_value,
    iocType:       ioc.ioc_type ?? "ip",
    severity:      ioc.severity,
    mitreTacticId: ioc.mitre_tactic_id,
    sourceLog:     ioc.source_log,
  });
  // ── Toggle de detección (2026-06-08): fuente deshabilitada ⇒ no alimenta casos.
  // Gate espejo del filtro del DAG (_load_disabled_source_logs). Fail-open: una
  // fuente desconocida (no en el catálogo) se considera habilitada. Devolvemos un
  // resultado no-op explícito para que el caller no lo cuente como creado ni error.
  if (!isSourceEnabled(ioc.source_log)) {
    logger.info("autoclassify.source_disabled_skip", { key, sourceLog: ioc.source_log, severity: ioc.severity });
    return { ok: true, skipped: "source_disabled", caseId: null };
  }
  // ── P3 dedup-churn: no materializar recurrencias suprimidas ──────────────────
  // Si el dedup_key tiene una supresión vigente (lo cerró un auto-close reciente),
  // NO creamos un caso operacional en PG — esa recreación es el churn de ~90k
  // LOW/semana. Sí registramos la detección en Iceberg como CERRADO por
  // recurrencia para (a) no reaparecer como `pending` cada corrida y (b) dejar
  // traza analítica honesta. Fail-open: si el lookup falla, seguimos el flujo
  // normal. Espejo del check del DAG (incident_cases_sync_daily.py:665) y de
  // routes/incidents.mjs:1492 en el path automático.
  let skipPgMirror = false;
  // ── Gate churn webfilter-URL (2026-06-25) ────────────────────────────────────
  // El IOC `url` de fortigate_webfilter es 99,95% churn: 23.062 casos en 7 días →
  // 1 HIGH, 2 adoptados por un humano, el resto abre LOW y se auto-cierra. No aporta
  // señal que el IOC `ip` (host literal, 2º bloque del extractor 41) no capture ya
  // CON geo+intel — ese sí abre el caso HIGH real (p.ej. INC-11901, beacon WECON).
  // Para LOW/MEDIUM NO creamos caso operacional en PG (queda la traza en Iceberg +
  // el enriched_ioc como contexto de correlación); un url de categoría maliciosa
  // (Malware/Phishing/C2 → piso de severidad ALTA en el extractor) SÍ abre. Mata el
  // grueso del ruido que sepulta la señal de fortigate-IP (46/81 HIGH) y wazuh.
  const isWebfilterUrl = (ioc.ioc_type === "url")
    && /^fortigate_webfilter/.test(String(ioc.source_log ?? ""));
  if (isWebfilterUrl && !["HIGH", "CRITICAL"].includes(String(ioc.severity ?? "").toUpperCase())) {
    skipPgMirror = true;
    logger.info("autoclassify.webfilter_url_churn_skip_pg", { key, severity: ioc.severity });
  }
  if (dk) {
    try {
      const [supRow] = await pgQuery(
        `SELECT severity FROM legacyhunt_soc.case_suppressions
         WHERE dedup_key = $1 AND suppressed_until > NOW()
         ORDER BY suppressed_until DESC
         LIMIT 1`,
        [dk],
      );
      // ── ALTA-3 dedup-churn (audit 2026-06-05): supresión severity-aware ──────
      // El dedup_key de MEDIUM/LOW/NEGLIGIBLE comparte bucket (ioc|source_category),
      // así que un LOW auto-cerrado generaba una supresión que tapaba un MEDIUM
      // posterior del mismo IOC → escalada de severidad invisible hasta 30 días.
      // Solo suprimimos si la severidad actual NO supera la suprimida; si escala,
      // dejamos materializar el caso (posible escalación real).
      const suppress = supRow
        && severityRank(ioc.severity) <= severityRank(supRow.severity);
      if (supRow && !suppress) {
        logger.info("autoclassify.suppression_overridden_severity_escalation", {
          key, dedupKey: dk, suppressedSeverity: supRow.severity, currentSeverity: ioc.severity,
        });
      }
      if (suppress) {
        skipPgMirror = true;
        const wasTerminal = status === "FALSO_POSITIVO" || status === "CERRADO";
        if (!wasTerminal) {
          // Caso que habría quedado ABIERTO (MONITOREADO/EN_ANALISIS) → lo
          // registramos cerrado por recurrencia en lugar de abrir backlog.
          status            = "CERRADO";
          recommendedAction = `AUTO_SUPPRESSED_RECURRENCE:${recommendedAction}`;
          closureNotes      = `[AUTO-SUPRIMIDO] Recurrencia de un IOC con supresión vigente (dedup_key ${dk.slice(0, 12)}…) — no se materializa caso operacional para evitar churn.\n${closureNotes}`;
        }
        logger.debug("autoclassify.suppressed_recurrence_skip_pg", { key, dedupKey: dk, severity: ioc.severity });

        // ── P2 dedup-churn: contar la recurrencia en el caso existente ─────────
        // Antes, las recurrencias creaban filas con occurrence_count=1 (merge
        // nunca disparaba: 421k/421k en 1). La supresión las gateaba pero perdía
        // la señal. Acá las contamos sobre el caso canónico (el más reciente con
        // ese dedup_key) → soft-merge: el dedup KPI refleja dedup real y queda
        // traza de cuántas veces recurrió el IOC. Best-effort.
        try {
          // ALTA-4: NO tocar updated_at — el caso canónico suele estar CERRADO y
          // bumpear updated_at lo recontaba como "resuelto hoy" en v_soc_kpis.
          // last_seen es la señal de recurrencia. Si no hay caso canónico con ese
          // dedup_key (subselect → NULL) el UPDATE afecta 0 filas y la recurrencia
          // se perdería en silencio: lo registramos para no inflar el dedup KPI.
          const bumped = await pgQuery(
            `UPDATE incident_cases_pg
             SET occurrence_count = COALESCE(occurrence_count, 1) + 1,
                 last_seen        = now()
             WHERE id = (
               SELECT id FROM incident_cases_pg
               WHERE dedup_key = $1
               ORDER BY created_at DESC
               LIMIT 1
             )
             RETURNING id`,
            [dk],
          );
          if (!bumped.length) {
            logger.warn("autoclassify.occurrence_bump_no_canonical", { key, dedupKey: dk, severity: ioc.severity });
          }
        } catch (occErr) {
          logger.warn("autoclassify.occurrence_bump_failed", { key, dedupKey: dk, err: occErr.message });
        }
      }
    } catch (supErr) {
      logger.warn("autoclassify.suppression_lookup_failed", { key, err: supErr.message });
    }
  }

  // ── P2 churn born-CERRADO (audit 2026-06-18) ─────────────────────────────────
  // Medición: 238/241 casos cerrados/día son occurrence_count=1 (PRIMER toque) y
  // el 97,3% de incident_cases_pg son lápidas. El primer toque de un IOC de ruido
  // benigno EXTERNO se clasifica terminal (CERRADO/FALSO_POSITIVO) y hoy escribe
  // una fila PG born-CERRADO cuyo ÚNICO objeto es que el trigger trg_suppress_on_close
  // siembre la supresión que gateará la 2ª aparición. Esa fila ensucia el backlog y
  // hace que el KPI "casos creados" mida churn en vez de detección.
  //
  // Fix: sembramos la supresión DIRECTAMENTE (misma lógica que el trigger mig 079:
  // reason + suppression_days(reason,severity) + ON CONFLICT GREATEST) y NO espejamos
  // la fila. La traza analítica honesta ya quedó en Iceberg (writeResult, abajo).
  // Resultado: incident_cases_pg sólo recibe casos reales/accionables.
  //
  // EXCLUSIÓN DELIBERADA — IPs internas RFC1918: la mig 079 quiere que sus
  // recurrencias AUTO_CLOSED reaparezcan (movimiento lateral este-oeste). NO las
  // tocamos: siguen el path normal (fila + trigger, que ya respeta el skip RFC1918).
  // Gated/reversible por SKIP_BORN_CLOSED_PG_MIRROR (default ON). Fail-safe: si el
  // seed falla, NO suprimimos el mirror → cae al INSERT normal y el trigger siembra
  // la supresión (mejor una lápida que perder la supresión y reabrir churn).
  const isTerminalStatus = status === "FALSO_POSITIVO" || status === "CERRADO";
  const skipBornClosed   = (process.env.SKIP_BORN_CLOSED_PG_MIRROR ?? "true") === "true";
  if (!skipPgMirror
      && isTerminalStatus
      && skipBornClosed
      && dk
      && !isRfc1918(String(ioc.ioc_value ?? ""))) {
    try {
      const supReason = status === "FALSO_POSITIVO" ? "FALSO_POSITIVO" : "AUTO_CLOSED";
      await pgQuery(
        `INSERT INTO legacyhunt_soc.case_suppressions
            (dedup_key, reason, severity, suppressed_until, suppressed_by, original_ioc, created_at, updated_at)
         VALUES (
            $1, $2, upper($3),
            NOW() + (legacyhunt_soc.suppression_days($2, $3) || ' days')::interval,
            'autoclassify-born-closed', NULLIF($4, ''), now(), now()
         )
         ON CONFLICT (dedup_key) DO UPDATE SET
            reason           = EXCLUDED.reason,
            severity         = COALESCE(EXCLUDED.severity, case_suppressions.severity),
            suppressed_until = CASE
              WHEN case_suppressions.reason = EXCLUDED.reason
                THEN GREATEST(case_suppressions.suppressed_until, EXCLUDED.suppressed_until)
              ELSE EXCLUDED.suppressed_until
            END,
            original_ioc     = COALESCE(EXCLUDED.original_ioc, case_suppressions.original_ioc),
            updated_at       = NOW()`,
        [dk, supReason, String(ioc.severity ?? "LOW"), ioc.ioc_value ?? ""],
      );
      skipPgMirror = true;
      logger.info("autoclassify.born_closed_skip_pg_seed_suppression", {
        key, dedupKey: dk, reason: supReason, severity: ioc.severity,
      });
    } catch (seedErr) {
      logger.warn("autoclassify.born_closed_seed_failed", { key, dedupKey: dk, err: seedErr.message });
    }
  }

  const detectionType = inferDetectionType(ioc.source_log, ioc.mitre_tactic_name);
  const ruleFamily    = inferRuleFamily(detectionType, ioc.mitre_tactic_name, null);
  const deleteSql = `
DELETE FROM ${TABLE}
WHERE incident_key = ${sq(key)}
`.trim();

  const sql = `
INSERT INTO ${TABLE} (
  incident_key, ioc_value, ioc_type, source_log,
  score, score_mitre, score_evidence, score_wazuh, severity,
  mitre_technique_id, mitre_tactic_id, mitre_tactic_name,
  vt_malicious, vt_suspicious, vt_permalink,
  shodan_ports, shodan_vulns, abuse_confidence,
  in_urlhaus, in_openphish,
  recommended_action, classified_at, dt,
  adopted_by, adopted_at,
  status, resolved_at, closure_notes,
  detection_type, rule_family
) VALUES (
  ${sq(key)},
  ${sq(ioc.ioc_value)},
  ${sq(ioc.ioc_type ?? "ip")},
  ${sq(ioc.source_log ?? "v_incident_score")},
  ${Number(ioc.score ?? 0)},
  ${Number(ioc.score_mitre ?? 0)},
  ${Number(ioc.score_evidence ?? 0)},
  ${Number(ioc.score_wazuh ?? 0)},
  ${sq(ioc.severity)},
  ${ioc.mitre_technique_id ? sq(ioc.mitre_technique_id) : "NULL"},
  ${ioc.mitre_tactic_id    ? sq(ioc.mitre_tactic_id)    : "NULL"},
  ${ioc.mitre_tactic_name  ? sq(ioc.mitre_tactic_name)  : "NULL"},
  ${ioc.vt_malicious    != null ? Number(ioc.vt_malicious)    : "NULL"},
  ${ioc.vt_suspicious   != null ? Number(ioc.vt_suspicious)   : "NULL"},
  NULL,
  ${ioc.shodan_ports ? sq(JSON.stringify(ioc.shodan_ports)) : "NULL"},
  ${ioc.shodan_vulns ? sq(JSON.stringify(ioc.shodan_vulns)) : "NULL"},
  ${ioc.abuse_confidence != null ? Number(ioc.abuse_confidence) : "NULL"},
  ${ioc.in_urlhaus  ? "true" : "false"},
  ${ioc.in_openphish ? "true" : "false"},
  ${sq(recommendedAction)},
  ${tsz(now)},
  DATE '${dt}',
  'auto-sistema',
  ${tsz(now)},
  ${sq(status)},
  ${tsz(now)},
  ${sq(closureNotes)},
  ${sq(detectionType)},
  ${sq(ruleFamily)}
)`.trim();

  const del = await trinoExec(deleteSql, SESSION);
  if (!del.ok && !/not found|does not exist/i.test(del.error ?? "")) {
    return del;
  }
  const writeResult = await trinoExec(sql, SESSION);

  // ── Espejo en incident_cases_pg (fuente operacional del dashboard) ───────────
  // Los casos LOW/NEGLIGIBLE clasificados automáticamente nunca llegan al DAG
  // (que filtra por severity IN ('CRITICAL','HIGH','MEDIUM')), por lo que se
  // persisten directamente aquí para que autoCloseLowNegligible() los encuentre
  // y aparezcan en la vista SOC.
  // P3: si la recurrencia está suprimida (skipPgMirror), NO se crea fila en PG —
  // el registro terminal ya quedó en Iceberg y no debe ensuciar el backlog SOC.
  if (writeResult.ok && !skipPgMirror) {
    try {
      const isAutoClose = status === "FALSO_POSITIVO" || status === "CERRADO";
      // 2026-05-27: detected_at ahora se popula desde mv_first_alert_per_ioc
      // (DAG cross-source, refresh 30 min). pendingAutoProcess hace LEFT JOIN
      // y devuelve first_alert_ts — si está null el IOC no tuvo alerta en la
      // ventana 2d de la materializada (caso raro: scoring offline o IOC
      // recién aparecido fuera del refresh). En ese caso, detected_at queda
      // NULL y migración 048 lo filtra del MTTD — comportamiento honesto.
      const detectedAtIso = (() => {
        const raw = ioc.first_alert_ts;
        if (!raw) return null;
        // Trino emite timestamps como "yyyy-MM-dd HH:mm:ss.SSS UTC". PG los
        // parsea, pero el TZ "UTC" trailing rompe el parse en algunos drivers;
        // normalizamos a ISO 8601.
        if (typeof raw === "string") {
          const trimmed = raw.replace(/\sUTC$/i, "Z").replace(" ", "T");
          return trimmed;
        }
        return null;
      })();
      // Fix 2026-06-07: el INSERT omitía source_log/ioc_type/mitre_* aunque el
      // scoring snapshot (ioc.*) los trae y se escriben a Iceberg. Resultado:
      // ~34k casos creados por este path quedaban "sin sensor identificado" en
      // PG (source_log='' ). Los agregamos al INSERT y los backfilleamos in-place
      // vía ON CONFLICT (COALESCE+NULLIF) para los casos pre-fix que se re-clasifican.
      // Score breakdown desde el snapshot de scoring (mismos componentes que se
      // escriben a Iceberg incident_classifications). Sin esto el endpoint
      // scoring-detail reconstruye el breakdown desde enrichment_data y queda en
      // ceros → la UI no muestra "Score breakdown" para los casos de este path.
      const enrichmentJson = JSON.stringify({
        score_mitre:    Number(ioc.score_mitre    ?? 0),
        score_evidence: Number(ioc.score_evidence ?? 0),
        score_wazuh:    Number(ioc.score_wazuh    ?? 0),
        score_misp:     Number(ioc.score_misp     ?? 0),
        score_context:  Number(ioc.score_context  ?? 0),
      });
      // Clasificación eCSIRT/MISP persistida (mig 088): clave derivada de la misma
      // classifyEcsirt() que usa la lectura, desde la identidad del snapshot de
      // scoring (MITRE + tipo de IOC + fuente). Sin señales de intel en este path
      // (enrichmentJson sólo trae el breakdown de score) → cae a MITRE/heurística,
      // consistente con el chip de la cola para casos de este mirror.
      const incidentClass = classifyEcsirt({
        mitreTacticId: ioc.mitre_tactic_id,
        iocType:       ioc.ioc_type,
        sourceLog:     ioc.source_log,
      }).class;
      const cols = [
        "id", "severity", "status", "score", "recommended_action",
        "dedup_key", "ioc_value",
        "source_log", "ioc_type", "mitre_tactic_id", "mitre_tactic_name",
        "incident_class",
        "enrichment_data",
        "anchor_dt", "created_at", "updated_at",
      ];
      const vals = ["$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13::jsonb", "CURRENT_DATE", "now()", "now()"];
      const params = [
        key, ioc.severity, status, Number(ioc.score ?? 0), recommendedAction,
        dk, ioc.ioc_value ?? null,
        ioc.source_log ?? null, ioc.ioc_type ?? null,
        ioc.mitre_tactic_id ?? null, ioc.mitre_tactic_name ?? null,
        incidentClass,
        enrichmentJson,
      ];
      if (detectedAtIso) {
        cols.push("detected_at");
        params.push(detectedAtIso);
        vals.push(`$${params.length}`);
      }
      if (isAutoClose) {
        cols.push("auto_closed_at", "auto_closed_reason", "resolved_at");
        params.push(closureNotes);
        vals.push("now()", `$${params.length}`, "now()");
      }
      // Guard 2026-05-27: estados terminales (CERRADO / FALSO_POSITIVO) no se
      // sobreescriben en reclasificaciones. Antes el ON CONFLICT incondicional
      // reabría LOW ya cerrados por autoCloseLowNegligible cuando fp_confidence
      // pasaba a PROBABLE en un tick posterior, dejándolos huérfanos en
      // EN_ANALISIS con auto_closed_at != NULL (v_auto_close_candidates los
      // excluye y nunca se recuperan).
      // ALTA-5 (audit 2026-06-05): ESCALADO sumado al guard. La auto-escalación
      // SLA del scheduler corre fuera de los advisory locks de autoClassify; una
      // reclasificación concurrente podía pisar el ESCALADO → caso revertido a
      // EN_ANALISIS/MONITOREADO con la metadata de escalación colgando.
      const PROTECTED = "('CERRADO','FALSO_POSITIVO','ESCALADO')";
      const updateClauses = [
        `status = CASE WHEN incident_cases_pg.status IN ${PROTECTED} `
          + "THEN incident_cases_pg.status ELSE EXCLUDED.status END",
        `recommended_action = CASE WHEN incident_cases_pg.status IN ${PROTECTED} `
          + "THEN incident_cases_pg.recommended_action ELSE EXCLUDED.recommended_action END",
        `updated_at = CASE WHEN incident_cases_pg.status IN ${PROTECTED} `
          + "THEN incident_cases_pg.updated_at ELSE now() END",
        // P1: backfill in-place de dedup_key/ioc_value en re-clasificaciones de
        // casos pre-fix (sin pisar valores ya presentes).
        "dedup_key = COALESCE(incident_cases_pg.dedup_key, EXCLUDED.dedup_key)",
        "ioc_value = COALESCE(incident_cases_pg.ioc_value, EXCLUDED.ioc_value)",
        // Backfill in-place de identidad del sensor/IOC para casos pre-fix
        // (tratamos '' como ausente). No pisa valores ya presentes.
        "source_log = COALESCE(NULLIF(incident_cases_pg.source_log, ''), EXCLUDED.source_log)",
        "ioc_type = COALESCE(NULLIF(incident_cases_pg.ioc_type, ''), EXCLUDED.ioc_type)",
        "mitre_tactic_id = COALESCE(NULLIF(incident_cases_pg.mitre_tactic_id, ''), EXCLUDED.mitre_tactic_id)",
        "mitre_tactic_name = COALESCE(NULLIF(incident_cases_pg.mitre_tactic_name, ''), EXCLUDED.mitre_tactic_name)",
        // Clase eCSIRT (mig 088): backfill in-place para casos pre-fix; no pisa
        // un valor ya presente (la identidad de la que deriva es estable).
        "incident_class = COALESCE(incident_cases_pg.incident_class, EXCLUDED.incident_class)",
        // Merge: refresca los score_* del snapshot y preserva claves ya presentes
        // (p.ej. iocEnrichment/iocVerdict de un enrich-now previo).
        "enrichment_data = COALESCE(incident_cases_pg.enrichment_data, '{}'::jsonb) || EXCLUDED.enrichment_data",
      ];
      if (detectedAtIso) {
        updateClauses.push("detected_at = COALESCE(incident_cases_pg.detected_at, EXCLUDED.detected_at)");
      }
      if (isAutoClose) {
        // El guard no se aplica acá: si el caller pide isAutoClose, refresca
        // auto_closed_at solo si todavía no estaba seteado (idempotente).
        // Audit 2026-05-27: resolved_at idem — 1263 AUTO_FP quedaban con
        // resolved_at NULL pre-fix (MTTR fantasma).
        updateClauses.push(
          "auto_closed_at = COALESCE(incident_cases_pg.auto_closed_at, now())",
          "auto_closed_reason = COALESCE(incident_cases_pg.auto_closed_reason, EXCLUDED.auto_closed_reason)",
          "resolved_at = COALESCE(incident_cases_pg.resolved_at, now())",
        );
      }
      // P1: ahora que poblamos dedup_key, un INSERT de caso ABIERTO puede chocar
      // con el índice único parcial `idx_cases_dedup_key_open_unique` (mig 034)
      // si ya existe otro caso abierto con el mismo dedup_key. Ese conflicto NO
      // lo captura `ON CONFLICT (id)` (es otra constraint) → 23505. Es un dedup
      // hit benigno (ya hay un caso abierto vivo para ese IOC): se omite en
      // silencio en lugar de propagar como error de mirror.
      let dedupCollision = false;
      try {
        await pgQuery(
          `INSERT INTO incident_cases_pg (${cols.join(", ")})
           VALUES (${vals.join(", ")})
           ON CONFLICT (id) DO UPDATE SET ${updateClauses.join(", ")}`,
          params,
        );
      } catch (insErr) {
        if (insErr?.code === "23505") {
          dedupCollision = true;
          logger.debug("autoclassify.dedup_open_collision", { key, dedupKey: dk, severity: ioc.severity });
        } else {
          throw insErr;
        }
      }

      // ── Bootstrap case_tasks (audit 2026-05-27 P3) ─────────────────────────
      // Sólo para casos que quedan ABIERTOS — los terminales (CERRADO/FALSO_POSITIVO
      // auto-clasificados) no necesitan playbook, ya están resueltos.
      // `bootstrapCaseTasks` es idempotente: si el caso ya tiene tasks (por un
      // pass anterior del backfill o re-clasificación), retorna skipped sin tocar.
      if (dedupCollision) {
        // Caso abierto duplicado bloqueado por el índice único — no hay fila
        // nueva que enriquecer ni suprimir; el caso vivo ya tiene su playbook.
      } else if (!isAutoClose) {
        try {
          await bootstrapCaseTasks(
            key,
            {
              severity:           ioc.severity,
              score:              Number(ioc.score ?? 0),
              source_log:         ioc.source_log,
              ioc_value:          ioc.ioc_value,
              ioc_type:           ioc.ioc_type ?? "ip",
              mitre_tactic_id:    ioc.mitre_tactic_id ?? null,
              mitre_tactic_name:  ioc.mitre_tactic_name ?? null,
              operator_id:        null, // auto-classified — asignación llega después
            },
            // enrichment_data: lo que tengamos del scoring snapshot. Limitado
            // — el playbook genera contexto best-effort con lo disponible.
            {
              virustotal: { malicious: ioc.vt_malicious ?? 0, suspicious: ioc.vt_suspicious ?? 0 },
              shodan:     { ports: ioc.shodan_ports ?? [], vulns: ioc.shodan_vulns ?? [] },
              abuseipdb:  { confidence: ioc.abuse_confidence ?? 0 },
            },
            "auto-classify",
            pgQuery,
            { randomUUIDFn: randomUUID },
          );
        } catch (tasksErr) {
          // Best-effort: si el bootstrap falla, el caso sigue navegable pero
          // sin tasks. El backfill periódico lo recoge en el próximo pass.
          logger.warn("autoclassify.tasks_bootstrap_failed", { key, err: tasksErr.message });
        }
      } else {
        // ── P0 dedup-churn: suprimir-al-cerrar ──────────────────────────────
        // Cierre terminal (FALSO_POSITIVO / CERRADO) → alimenta case_suppressions
        // para que el DAG y la API no recreen el mismo dedup_key apenas se cierra.
        // FALSO_POSITIVO confirmado mantiene su motivo (ventana 14/30/60d);
        // CERRADO auto-clasificado usa AUTO_CLOSED (30d fijos).
        const suppressReason = status === "FALSO_POSITIVO" ? "FALSO_POSITIVO" : "AUTO_CLOSED";
        await upsertSuppression(pgQuery, {
          dedupKey: dk,
          reason:   suppressReason,
          severity: ioc.severity,
          caseId:   key,          // hex de 32 chars → upsertSuppression lo trata como no-UUID (NULL)
          iocValue: ioc.ioc_value,
        });
      }
    } catch (pgErr) {
      // No bloquear el flujo si PG falla; el caso ya está en Iceberg
      logger.warn("autoclassify.pg_mirror_failed", { key, err: pgErr.message });
    }
  }

  // Señal Socket.IO para que el dashboard refresque la cola al aparecer un
  // CRITICAL/HIGH nuevo. (El popup de adopción por código fue eliminado — ya no
  // se genera ni envía código; este evento solo dispara el refetch del listado.)
  if (writeResult.ok && ["CRITICAL", "HIGH"].includes(ioc.severity) && status !== "FALSO_POSITIVO") {
    try {
      const { getIo } = await import("../services/socketService.mjs");
      getIo().emit("new-critical-incident", {
        incidentId: key,
        severity: ioc.severity,
        timestamp: new Date().toISOString(),
      });
      logger.info("autoclassify.new_critical_incident_emitted", { key, severity: ioc.severity });
    } catch (socketErr) {
      logger.error("autoclassify.socket_emit_failed", { key, err: socketErr.message });
      // No re-lanzar: el caso ya se guardó, el socket falla silenciosamente
    }
  }

  return writeResult;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/* Handler 1: autoClassifyFp — solo FP confirmados                            */
/* ═══════════════════════════════════════════════════════════════════════════ */

export async function autoClassifyFp(req, res) {
  const days   = Math.min(30, Math.max(1, Number(req.body?.days  ?? 7)));
  const dryRun = req.body?.dryRun === true;

  const queryResult = await runNamedQuery("lh.incidents.fp_candidates", { days });
  if (!queryResult.ok) {
    res.status(502).json({ ok: false, error: `Trino query falló: ${queryResult.error}` });
    return;
  }

  const candidates  = queryResult.rows;
  const confirmed   = candidates.filter((r) => r.fp_confidence === "CONFIRMED");
  const probable    = candidates.filter((r) => r.fp_confidence === "PROBABLE");
  const possible    = candidates.filter((r) => r.fp_confidence === "POSSIBLE");
  const insufficient = candidates.filter((r) => r.fp_confidence === "INSUFFICIENT");

  const persisted = [];
  const errors    = [];
  const today     = new Date().toISOString().slice(0, 10);

  if (!dryRun) {
    for (const ioc of confirmed) {
      const fpResult    = { fp_confidence: "CONFIRMED", fp_reason: ioc.fp_reason ?? "AUTO" };
      const closureNotes = buildClosureNotes(ioc, fpResult, "FALSO_POSITIVO");
      const result = await persistCase(ioc, {
        status:            "FALSO_POSITIVO",
        recommendedAction: `FALSO_POSITIVO_AUTO:${fpResult.fp_reason}`,
        closureNotes,
        fpReason:          fpResult.fp_reason,
        isAuto:            false,
      });
      if (result.skipped === "source_disabled") {
        // Fuente deshabilitada: no se materializa caso (ni creado ni error).
      } else if (result.ok || /already exists|duplicate|constraint/i.test(result.error ?? "")) {
        persisted.push(ioc.ioc_value);
      } else {
        errors.push({ ioc_value: ioc.ioc_value, error: result.error });
      }
    }
  }

  const toSummary = (arr) => arr.map((r) => ({
    ioc_value: r.ioc_value, severity: r.severity, score: r.score,
    fp_confidence: r.fp_confidence, fp_reason: r.fp_reason,
    vt_malicious: r.vt_malicious, abuse_confidence: r.abuse_confidence,
    in_urlhaus: r.in_urlhaus, in_openphish: r.in_openphish,
    shodan_ports: r.shodan_ports, mitre_tactic_name: r.mitre_tactic_name, dt: r.dt,
  }));

  res.json({
    ok: true, dryRun, days,
    stats: {
      total: candidates.length, confirmed: confirmed.length,
      probable: probable.length, possible: possible.length,
      insufficient: insufficient.length, persisted: persisted.length, errors: errors.length,
    },
    confirmed: toSummary(confirmed), probable: toSummary(probable),
    possible: toSummary(possible), insufficient: toSummary(insufficient),
    persisted, errors,
  });
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/* Handler 2: autoProcessLowMedium — apertura + documentación + cierre        */
/* ═══════════════════════════════════════════════════════════════════════════ */

export async function processLowMediumBatch({ days = 7, dryRun = false, allowAutoClose = true } = {}) {
  const boundedDays = Math.min(30, Math.max(1, Number(days ?? 7)));

  // 1. Obtener IOCs MEDIUM/LOW/NEGLIGIBLE no clasificados aún
  const queryResult = await runNamedQuery("lh.incidents.pending_auto_process", { days: boundedDays });
  if (!queryResult.ok) {
    return { ok: false, error: `Trino query falló: ${queryResult.error}` };
  }

  const pending = queryResult.rows;
  if (pending.length === 0) {
    return {
      ok: true,
      dryRun,
      days: boundedDays,
      stats: { total: 0, processed: 0, errors: 0, by_status: {}, by_severity: {} },
      results: [],
      persisted: [],
      errors: [],
    };
  }

  // 2. Clasificar cada IOC
  const results = [];
  const persisted = [];
  const errors = [];

  for (const ioc of pending) {
    const fpResult = classifyFp(ioc);
    let status, recommendedAction;

    if (ioc.severity === "NEGLIGIBLE") {
      // NEGLIGIBLE: solo cerrar automáticamente cuando hay FP confirmado de alta confianza.
      if (
        fpResult.fp_confidence === "CONFIRMED" &&
        (fpResult.fp_reason === "IP_KNOWN_SAFE" || fpResult.fp_reason === "CLEAN_INTEL_LOW_SCORE")
      ) {
        status = "FALSO_POSITIVO";
        recommendedAction = `FALSO_POSITIVO_AUTO:${fpResult.fp_reason}`;
      } else {
        status = "MONITOREADO";
        recommendedAction = "AUTO_NEGLIGIBLE_MONITORED:REQUIRES_REVIEW";
      }
    } else if (ioc.severity === "MEDIUM") {
      status = "MONITOREADO";
      recommendedAction = fpResult.fp_confidence !== "INSUFFICIENT"
        ? `MEDIUM_PENDING_OPERATOR:${fpResult.fp_reason ?? fpResult.fp_confidence}`
        : "AUTO_MEDIUM_MONITORED:REQUIRES_REVIEW";
    } else if (fpResult.fp_confidence === "CONFIRMED") {
      // LOW confirmado: clasificar como FP y cerrar automáticamente.
      status = "FALSO_POSITIVO";
      recommendedAction = `FALSO_POSITIVO_AUTO:${fpResult.fp_reason}`;
    } else if (fpResult.fp_confidence === "PROBABLE") {
      // LOW probable: no cerrar; enviar a análisis.
      status = "EN_ANALISIS";
      recommendedAction = `LOW_PROBABLE_FP_REVIEW:${fpResult.fp_reason}`;
    } else {
      // LOW sin señales de FP: monitorear, sin cierre automático.
      status = "MONITOREADO";
      recommendedAction = "AUTO_LOW_MONITORED:REQUIRES_REVIEW";
    }

    let finalStatus = status;
    let finalRecommendedAction = recommendedAction;

    // Switch operativo: desactiva cierres automáticos incluso para FP confirmados.
    if (!allowAutoClose && (finalStatus === "FALSO_POSITIVO" || finalStatus === "CERRADO")) {
      finalStatus = "EN_ANALISIS";
      finalRecommendedAction = `NO_AUTO_CLOSE:${recommendedAction}`;
    }

    // ── P1-bulk triage benigno (2026-06-16, gated TRIAGE_BENIGN_AUTOCLOSE) ─────
    // Si un candidato que ABRIRÍA backlog (no-terminal) es una IP pública que la
    // criba keyless (GreyNoise RIOT/benign + feeds) marca benigna conocida y SIN
    // señal de amenaza → auto-cierre como FP de ruido. VT/Shodan no se tocan (P2).
    // Best-effort: cualquier falla deja el status original. Default OFF hasta
    // validar volumen/rate-limit de GreyNoise.
    if (process.env.TRIAGE_BENIGN_AUTOCLOSE === "true"
        && allowAutoClose
        && (finalStatus === "MONITOREADO" || finalStatus === "EN_ANALISIS")
        && (ioc.ioc_type ?? "ip") === "ip"
        && !isRfc1918(String(ioc.ioc_value ?? ""))) {
      try {
        const screen = await screenIocMalice(String(ioc.ioc_value ?? "").trim(), "ip");
        if (screen.benign && !screen.malicious) {
          finalStatus = "FALSO_POSITIVO";
          finalRecommendedAction = `TRIAGE_BENIGN_NOISE:${screen.benignReasons[0] ?? "GreyNoise RIOT/benign"}`;
          logger.info("autoclassify.triage_benign_autoclose", {
            iocValue: ioc.ioc_value, reasons: screen.benignReasons,
          });
        }
      } catch (screenErr) {
        logger.debug("autoclassify.triage_screen_failed", { iocValue: ioc.ioc_value, err: screenErr?.message });
      }
    }

    const closureNotes = buildClosureNotes(ioc, fpResult, finalStatus);
    results.push({
      ioc_value: ioc.ioc_value,
      severity: ioc.severity,
      score: ioc.score,
      status: finalStatus,
      recommendedAction: finalRecommendedAction,
      fp_confidence: fpResult.fp_confidence,
      fp_reason: fpResult.fp_reason,
      vt_malicious: ioc.vt_malicious,
      abuse_confidence: ioc.abuse_confidence,
      in_urlhaus: ioc.in_urlhaus,
      in_openphish: ioc.in_openphish,
      shodan_ports: ioc.shodan_ports,
      mitre_tactic_name: ioc.mitre_tactic_name,
      closureNotes,
      dt: ioc.dt,
    });

    if (!dryRun) {
      const result = await persistCase(ioc, {
        status: finalStatus,
        recommendedAction: finalRecommendedAction,
        closureNotes,
        isAuto: true,
      });
      if (result.skipped === "source_disabled") {
        // Fuente deshabilitada: no se materializa caso (ni creado ni error).
      } else if (result.ok || /already exists|duplicate|constraint/i.test(result.error ?? "")) {
        persisted.push(ioc.ioc_value);
      } else {
        errors.push({ ioc_value: ioc.ioc_value, error: result.error });
      }
    }
  }

  const byStatus = results.reduce((acc, r) => {
    acc[r.status] = (acc[r.status] ?? 0) + 1;
    return acc;
  }, {});
  const bySeverity = results.reduce((acc, r) => {
    acc[r.severity] = (acc[r.severity] ?? 0) + 1;
    return acc;
  }, {});

  return {
    ok: true,
    dryRun,
    allowAutoClose,
    days: boundedDays,
    stats: {
      total: pending.length,
      processed: dryRun ? 0 : persisted.length,
      errors: errors.length,
      by_status: byStatus,
      by_severity: bySeverity,
    },
    results,
    persisted,
    errors,
  };
}

export async function autoProcessLowMedium(req, res) {
  const result = await processLowMediumBatch({
    days: req.body?.days ?? 7,
    dryRun: req.body?.dryRun === true,
    allowAutoClose: req.body?.allowAutoClose !== false,
  });
  if (!result.ok) {
    res.status(502).json(result);
    return;
  }
  res.json(result);
}
