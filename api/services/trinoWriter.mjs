/**
 * trinoWriter.mjs
 * Cliente Trino mínimo para operaciones de escritura (INSERT / DDL) desde servicios internos.
 * Misma lógica de polling que runTrinoQueryOnce en server.mjs, pero autocontenida
 * para que los controladores puedan importarla sin dependencias circulares.
 *
 * No lanza excepciones: devuelve { ok, error? } para que el llamador decida.
 * Timeout por defecto: 20 s (suficiente para un INSERT simple en Iceberg).
 */

import { config } from "../config.mjs";
import { logger } from "../logger.mjs";

const TRINO_URL  = config.TRINO_URL;
const TRINO_USER = config.TRINO_USER || "legacyhunt-api";
const TIMEOUT_MS = 20_000;

/**
 * Ejecuta una sentencia SQL en Trino y sondea hasta FINISHED/FAILED.
 *
 * @param {string} sql
 * @param {{ catalog?: string, schema?: string }} [session]
 * @returns {Promise<{ ok: boolean, error?: string }>}
 */
export async function trinoExec(sql, session = {}) {
  if (!TRINO_URL) return { ok: false, error: "TRINO_URL no configurada" };

  const headers = {
    "X-Trino-User":   TRINO_USER,
    "X-Trino-Source": "legacyhunt-api-writer",
    ...(session.catalog ? { "X-Trino-Catalog": session.catalog } : {}),
    ...(session.schema  ? { "X-Trino-Schema":  session.schema  } : {}),
  };

  const ac    = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);

  try {
    let res  = await fetch(`${TRINO_URL}/v1/statement`, {
      method:  "POST",
      headers: { ...headers, "Content-Type": "text/plain" },
      body:    sql,
      signal:  ac.signal,
    });
    let data = await res.json();

    if (data.error) return { ok: false, error: data.error.message };

    // Seguir nextUri hasta que no haya más (FINISHED) o falle
    while (data.nextUri) {
      const url = data.nextUri.startsWith("http")
        ? data.nextUri
        : `${TRINO_URL}${data.nextUri}`;
      res  = await fetch(url, { headers, signal: ac.signal });
      data = await res.json();
      if (data.error) return { ok: false, error: data.error.message };
      if (data.stats?.state === "FAILED") {
        return { ok: false, error: data.error?.message ?? "Trino FAILED" };
      }
    }
    return { ok: true };
  } catch (err) {
    if (err?.name === "AbortError") {
      return { ok: false, error: `Trino timeout (${TIMEOUT_MS}ms)` };
    }
    return { ok: false, error: err?.message ?? String(err) };
  } finally {
    clearTimeout(timer);
  }
}

// ── Migración de esquema ───────────────────────────────────────────────────────

const SESSION = { catalog: "minio_iceberg", schema: "hunting" };

let _migrated       = false;
let _migratedV2     = false;
let _migratedV3     = false;
let _migratedV4     = false;
let _migratedCasesV2 = false;

async function runAlterations(alterations, label, MAX = 6, DELAY_MS = 5_000) {
  for (let attempt = 1; attempt <= MAX; attempt++) {
    let allOk = true;
    for (const sql of alterations) {
      const r = await trinoExec(sql, SESSION);
      if (!r.ok) {
        if (/already exists|duplicate column/i.test(r.error ?? "")) continue;
        allOk = false;
        logger.warn("migration.alteration_failed", { label, attempt, max: MAX, err: r.error });
      }
    }
    if (allOk) {
      logger.info("migration.completed", { label });
      return true;
    }
    if (attempt < MAX) await new Promise((r) => setTimeout(r, DELAY_MS));
  }
  logger.error("migration.exhausted_retries", { label, attempts: MAX });
  return false;
}

/**
 * v1: columnas de adopción (adopted_by, adopted_at).
 */
export async function migrateIncidentClassifications() {
  if (_migrated) return;
  const table = "minio_iceberg.hunting.incident_classifications";
  const ok = await runAlterations([
    `ALTER TABLE ${table} ADD COLUMN adopted_by  VARCHAR`,
    `ALTER TABLE ${table} ADD COLUMN adopted_at  TIMESTAMP(6) WITH TIME ZONE`,
  ], "incident_classifications v1");
  if (ok) _migrated = true;
}

/**
 * v2: columnas de resolución para estadísticas MTTI/MTTR.
 *   status        — RESUELTO | FALSO_POSITIVO | MONITOREADO
 *   resolved_at   — timestamp de cierre (para MTTI y MTTR)
 *   closure_notes — documentación auto-generada del caso
 */
export async function migrateIncidentResolutionColumns() {
  if (_migratedV2) return;
  const table = "minio_iceberg.hunting.incident_classifications";
  const ok = await runAlterations([
    `ALTER TABLE ${table} ADD COLUMN status        VARCHAR`,
    `ALTER TABLE ${table} ADD COLUMN resolved_at   TIMESTAMP(6) WITH TIME ZONE`,
    `ALTER TABLE ${table} ADD COLUMN closure_notes VARCHAR`,
  ], "incident_classifications v2 (resolution)");
  if (ok) _migratedV2 = true;
}

/**
 * v3: taxonomía de origen para recalibración de reglas sin mezclar fuentes.
 *   detection_type — filterlog | suricata | wazuh_rule | ioc_sql | force_ack | vpn | fortigate | manual
 *   rule_family    — familia de regla / categoría (sshd, port_scanner, traffic_block, …)
 */
export async function migrateIncidentTaxonomyColumns() {
  if (_migratedV3) return;
  const table = "minio_iceberg.hunting.incident_classifications";
  const ok = await runAlterations([
    `ALTER TABLE ${table} ADD COLUMN detection_type VARCHAR`,
    `ALTER TABLE ${table} ADD COLUMN rule_family    VARCHAR`,
  ], "incident_classifications v3 (taxonomy)");
  if (ok) _migratedV3 = true;
}

/**
 * v4: confidence_level para alinear con enriched_ioc v2 y v_incident_score_v2.
 *   Requerido por managedIncidents (segunda UNION: v1.confidence_level).
 */
export async function migrateIncidentClassificationsV4() {
  if (_migratedV4) return;
  const table = "minio_iceberg.hunting.incident_classifications";
  const ok = await runAlterations([
    `ALTER TABLE ${table} ADD COLUMN confidence_level VARCHAR`,
  ], "incident_classifications v4 (confidence_level)");
  if (ok) _migratedV4 = true;
}

/**
 * v5 (incident_cases): columnas operacionales faltantes en incident_cases.
 *   adopted_at        — timestamp real de adopción del caso (distinto de last_seen)
 *   escalation_level  — TIER1 | TIER2 | IR | EXECUTIVE | EXTERNAL
 *   escalated_to      — nombre/equipo receptor de la escalación
 *   escalated_at      — timestamp de la escalación formal
 *   escalation_reason — motivo documentado de la escalación
 *   recommended_action — acción recomendada separada de las notas de operador
 */
export async function migrateIncidentCasesV2() {
  if (_migratedCasesV2) return;
  const table = "minio_iceberg.hunting.incident_cases";
  const ok = await runAlterations([
    `ALTER TABLE ${table} ADD COLUMN adopted_at         TIMESTAMP(6) WITH TIME ZONE`,
    `ALTER TABLE ${table} ADD COLUMN escalation_level   VARCHAR`,
    `ALTER TABLE ${table} ADD COLUMN escalated_to       VARCHAR`,
    `ALTER TABLE ${table} ADD COLUMN escalated_at       TIMESTAMP(6) WITH TIME ZONE`,
    `ALTER TABLE ${table} ADD COLUMN escalation_reason  VARCHAR`,
    `ALTER TABLE ${table} ADD COLUMN recommended_action VARCHAR`,
  ], "incident_cases v5 (adopted_at + escalation + recommended_action)");
  if (ok) _migratedCasesV2 = true;
}
