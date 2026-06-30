/**
 * routes/outliers.mjs — Detección de Anomalías (Outlier Detection)
 *
 * Monta en: /api/outliers (con requireAuth() al nivel del mount en server.mjs).
 *
 * Endpoints:
 *   GET  /                      Lista filtrable (window, entity_type, severity, log_family)
 *   GET  /dashboard             Resumen 24h + top entities + breakdown por log_family
 *   GET  /for-case/:id          Outliers asociados a los IOCs de un caso (via case_iocs)
 *   POST /:id/acknowledge       Ack individual (UUID)
 *   POST /acknowledge-entity    Ack bulk por (entity_type, entity_value, hours)
 *
 * Las lecturas pasan por el registry con prefijo `lh.outliers.*` — sin SQL
 * dinámico de lectura acá. Los dos POST usan UPDATE Iceberg (DML) directo.
 *
 * Diseño: docs/OUTLIER-DETECTION.md
 */

import { Router } from "express";
import { resolveNamedTrinoQuery } from "../trino/registry.mjs";
import { pgQuery } from "../db/postgres.mjs";
import { config } from "../config.mjs";
import { logger } from "../logger.mjs";
import { resolveJwtOperatorCi } from "../services/operatorResolver.mjs";
import { trinoExec } from "../services/trinoWriter.mjs";
import { emitOutlierAcknowledged } from "./../services/socketService.mjs";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const SESSION = { catalog: "minio_iceberg", schema: "hunting" };

/**
 * Factory del router. Recibe dos deps desde server.mjs:
 *   @param runQuery      ref a runTrinoQueryWithInitRetries (ejecuta SQL + reintenta init)
 *   @param _getIo        socket.io handle (reservado para el commit de acknowledge)
 */
export default function outliersRouter(runQuery, _getIo) {
  const router = Router();

  /** Resuelve una named query y la ejecuta. Devuelve rows o throw. */
  async function runNamed(queryId, params) {
    const resolved = resolveNamedTrinoQuery(queryId, params, config);
    if (!resolved.ok) {
      const err = new Error(resolved.error ?? "named query resolution failed");
      err.status  = resolved.status ?? 500;
      err.details = resolved.details;
      throw err;
    }
    return runQuery(resolved.sql, SESSION);
  }

  // ── GET /api/outliers ──────────────────────────────────────────────────────
  // Lista filtrada. Todos los filtros son opcionales; `window` default 24h,
  // `limit` default 100.
  router.get("/", async (req, res) => {
    const hours      = parseWindow(req.query.window, 24);
    const limit      = Math.min(500, Math.max(1, Number(req.query.limit) || 100));
    const entity_type = req.query.entity_type ?? undefined;
    const severity    = req.query.severity ?? undefined;
    const log_family  = req.query.log_family ?? undefined;
    try {
      const rows = await runNamed("lh.outliers.last_window", {
        hours, limit, entity_type, severity, log_family,
      });
      res.json({ ok: true, rows, params: { hours, limit, entity_type, severity, log_family } });
    } catch (err) {
      logger.error("outliers/list_failed", { err: err?.message, status: err?.status });
      res.status(err.status ?? 500).json({ ok: false, error: err.message });
    }
  });

  // ── GET /api/outliers/dashboard ────────────────────────────────────────────
  // Agrega summary_24h + top_entities(24h) + by_log_family(7d). Se hace en
  // paralelo para cortar latencia. Si cualquier sub-query falla se devuelve
  // parcial con el campo `errors` marcando cuáles fallaron — el dashboard
  // puede renderear los paneles OK y ocultar el roto.
  router.get("/dashboard", async (_req, res) => {
    const [summary, top, byFamily] = await Promise.allSettled([
      runNamed("lh.outliers.summary_24h", {}),
      runNamed("lh.outliers.top_entities", { days: 1, limit: 10 }),
      runNamed("lh.outliers.by_log_family", { days: 7 }),
    ]);

    const errors = [];
    const payload = {
      ok: true,
      summary:       pickOrError(summary,  "summary_24h",  errors)?.[0] ?? null,
      top_entities:  pickOrError(top,      "top_entities", errors) ?? [],
      by_log_family: pickOrError(byFamily, "by_log_family", errors) ?? [],
    };
    if (errors.length) {
      payload.errors = errors;
      payload.ok = false;
    }
    res.json(payload);
  });

  // ── GET /api/outliers/for-case/:id ─────────────────────────────────────────
  // Lee los IOCs del caso desde case_iocs (PG) y busca outliers cuyo
  // entity_value o related_ioc_id matchee alguno de esos IOCs. Alimenta el
  // tab "Outliers relacionados" de CaseInvestigationView.
  router.get("/for-case/:id", async (req, res) => {
    const caseId = String(req.params.id ?? "").trim();
    if (!caseId) return res.status(400).json({ ok: false, error: "caseId requerido" });

    let iocs;
    try {
      iocs = await pgQuery(
        `SELECT DISTINCT ioc_value
           FROM case_iocs
          WHERE case_id = $1
            AND ioc_value IS NOT NULL
          LIMIT 50`,
        [caseId],
      );
    } catch (err) {
      return res.status(500).json({ ok: false, error: err.message });
    }
    if (!iocs.length) {
      return res.json({ ok: true, rows: [], note: "caso sin IOCs registrados" });
    }

    // Ejecutamos una query por IOC (N pequeño, cap 50) en paralelo. Si el
    // volumen crece, se puede reemplazar por un solo SQL con IN(...) nuevo.
    const results = await Promise.allSettled(
      iocs.map((r) => runNamed("lh.outliers.for_ioc", { ioc_value: r.ioc_value })),
    );
    const rows = results.flatMap((r) => (r.status === "fulfilled" ? r.value : []));
    // Dedupe por outlier_id
    const seen = new Set();
    const deduped = rows.filter((o) => {
      if (seen.has(o.outlier_id)) return false;
      seen.add(o.outlier_id);
      return true;
    });
    res.json({ ok: true, rows: deduped, ioc_count: iocs.length });
  });

  // ── POST /api/outliers/acknowledge-entity ──────────────────────────────────
  // Ack bulk: marca como reconocidas todas las detecciones sin-ack de una misma
  // (entity_type, entity_value) dentro de una ventana (default 24h). Resuelve
  // el problema "una IP anómala persistente genera 4 rows/día × N anomaly_types
  // y el operador tiene que ackear una por una".
  //
  // El UPDATE se acota por `detection_time >= now - hours` para que el operador
  // no ack-ee sin querer detecciones antiguas que nunca vio.
  router.post("/acknowledge-entity", async (req, res) => {
    const entity_type  = String(req.body?.entity_type ?? "").trim();
    const entity_value = String(req.body?.entity_value ?? "").trim();
    const hours        = Math.min(168, Math.max(1, Number(req.body?.hours) || 24));
    const notes = typeof req.body?.notes === "string"
      ? req.body.notes.slice(0, 500)
      : null;

    if (!entity_type || !entity_value) {
      return res.status(400).json({
        ok: false,
        error: "entity_type y entity_value son requeridos",
      });
    }
    // Defensa: el schema del registry sólo acepta ciertos entity_type;
    // replicamos acá para no delegar validación en el propio UPDATE.
    const VALID_ENTITY_TYPES = [
      "ip", "host", "port", "hour", "user", "country",
      "sensor", "source_log", "business_tag",
    ];
    if (!VALID_ENTITY_TYPES.includes(entity_type)) {
      return res.status(400).json({
        ok: false,
        error: `entity_type inválido: ${entity_type}`,
      });
    }
    // entity_value: chars seguros para inline SQL. IPs (v4/v6), hostnames,
    // puertos, códigos país, sensores — todos encajan en este set. Si un
    // detector futuro emite entity_value con espacios/especiales, relajamos.
    if (!/^[0-9a-zA-Z.:/_\-]{1,200}$/.test(entity_value)) {
      return res.status(400).json({
        ok: false,
        error: "entity_value contiene caracteres inválidos o es muy largo",
      });
    }

    const operatorCi = await resolveJwtOperatorCi(req);
    if (!operatorCi) {
      return res.status(403).json({
        ok: false,
        error: "Operador no resuelto desde JWT. Linkeá tu cuenta Keycloak a soc_operators para reconocer outliers.",
      });
    }

    const esc = (v) => `'${String(v ?? "").replace(/'/g, "''")}'`;
    const sql = `
UPDATE minio_iceberg.hunting.outliers
   SET acknowledged_at = current_timestamp,
       acknowledged_by = ${esc(operatorCi)},
       notes           = ${notes == null ? "notes" : esc(notes)}
 WHERE entity_type  = ${esc(entity_type)}
   AND entity_value = ${esc(entity_value)}
   AND detection_time >= current_timestamp - INTERVAL '${hours}' HOUR
   AND acknowledged_at IS NULL`;
    const result = await trinoExec(sql, SESSION);
    if (!result.ok) {
      logger.warn("outliers/ack_entity_update_failed", {
        entity_type, entity_value, hours, err: result.error,
      });
      return res.status(502).json({
        ok: false,
        error: result.error ?? "Iceberg UPDATE falló",
      });
    }

    // Iceberg no reporta filas afectadas — hacemos un conteo post-UPDATE
    // de las filas de esta entidad que quedan ack-eadas por este operador
    // en la misma ventana, como proxy de "cuántas ack-eó este llamado".
    let acknowledged = null;
    let sampleRow = null;
    try {
      const rows = await runQuery(
        `SELECT COUNT(*) AS n,
                arbitrary(severity) AS severity,
                MAX(CAST(acknowledged_at AS varchar)) AS last_ack_at
           FROM minio_iceberg.hunting.outliers
          WHERE entity_type  = ${esc(entity_type)}
            AND entity_value = ${esc(entity_value)}
            AND detection_time >= current_timestamp - INTERVAL '${hours}' HOUR
            AND acknowledged_by = ${esc(operatorCi)}`,
        SESSION,
      );
      const r = rows[0] ?? null;
      if (r) {
        acknowledged = Number(r.n) || 0;
        sampleRow = {
          entity_type,
          entity_value,
          severity: r.severity ?? null,
          acknowledged_at: r.last_ack_at ?? null,
          acknowledged_by: operatorCi,
        };
      }
    } catch (err) {
      logger.warn("outliers/ack_entity_readback_failed", {
        entity_type, entity_value, err: err?.message,
      });
    }

    if (sampleRow) {
      // Reutilizamos el mismo evento que ack single — el frontend ya invalida
      // la query cache en el listener.
      emitOutlierAcknowledged({
        outlier_id: null,
        entity_type: sampleRow.entity_type,
        entity_value: sampleRow.entity_value,
        severity: sampleRow.severity,
        acknowledged_by: sampleRow.acknowledged_by,
        acknowledged_at: sampleRow.acknowledged_at,
        bulk: true,
        count: acknowledged,
      });
    }

    res.json({
      ok: true,
      entity_type,
      entity_value,
      hours,
      acknowledged,
    });
  });

  // ── POST /api/outliers/:id/acknowledge ─────────────────────────────────────
  // Marca un outlier como revisado por el operador autenticado. La identidad
  // sale EXCLUSIVAMENTE del JWT (no hay fallback a body) — un acknowledge debe
  // ser inequívoco para la auditoría.
  //
  // Implementación: Iceberg UPDATE (formato v2 soporta DML). Es una write
  // costosa — Iceberg re-escribe el data file que contiene la row — pero los
  // acks son eventos operativos esporádicos (~decenas por día), así que no
  // necesitamos lote/compactación especial.
  router.post("/:id/acknowledge", async (req, res) => {
    const outlierId = String(req.params.id ?? "").trim();
    if (!UUID_RE.test(outlierId)) {
      return res.status(400).json({ ok: false, error: "outlier_id no es un UUID válido" });
    }
    const notes = typeof req.body?.notes === "string"
      ? req.body.notes.slice(0, 500)
      : null;

    const operatorCi = await resolveJwtOperatorCi(req);
    if (!operatorCi) {
      return res.status(403).json({
        ok: false,
        error: "Operador no resuelto desde JWT. Linkeá tu cuenta Keycloak a soc_operators para reconocer outliers.",
      });
    }

    const esc = (v) => `'${String(v ?? "").replace(/'/g, "''")}'`;
    // SET acknowledged_at/_by/notes con WHERE por outlier_id + guard anti-double-ack
    const sql = `
UPDATE minio_iceberg.hunting.outliers
   SET acknowledged_at = current_timestamp,
       acknowledged_by = ${esc(operatorCi)},
       notes           = ${notes == null ? "notes" : esc(notes)}
 WHERE outlier_id = ${esc(outlierId)}
   AND acknowledged_at IS NULL`;
    const result = await trinoExec(sql, SESSION);
    if (!result.ok) {
      logger.warn("outliers/ack_update_failed", { outlierId, err: result.error });
      return res.status(502).json({ ok: false, error: result.error ?? "Iceberg UPDATE falló" });
    }

    // Iceberg no reporta "filas afectadas" de forma confiable — leemos el row
    // después del UPDATE para confirmar y emitir socket con datos frescos.
    let ackedRow = null;
    try {
      const rows = await runQuery(
        `SELECT outlier_id, entity_type, entity_value, severity,
                CAST(acknowledged_at AS varchar) AS acknowledged_at,
                acknowledged_by
           FROM minio_iceberg.hunting.outliers
          WHERE outlier_id = ${esc(outlierId)}
          LIMIT 1`,
        SESSION,
      );
      ackedRow = rows[0] ?? null;
    } catch (err) {
      logger.warn("outliers/ack_readback_failed", { outlierId, err: err?.message });
    }

    if (!ackedRow) {
      return res.status(404).json({
        ok: false,
        error: "outlier no encontrado tras el UPDATE (¿id equivocado o ya ack antes?)",
      });
    }

    emitOutlierAcknowledged({
      outlier_id:      ackedRow.outlier_id,
      entity_type:     ackedRow.entity_type,
      entity_value:    ackedRow.entity_value,
      severity:        ackedRow.severity,
      acknowledged_by: ackedRow.acknowledged_by,
      acknowledged_at: ackedRow.acknowledged_at,
    });

    res.json({ ok: true, outlier: ackedRow });
  });

  return router;
}

// ── Helpers locales ──────────────────────────────────────────────────────────

/**
 * Parsea un string de ventana tipo "24h" / "7d" / "1h" a horas. Default si
 * el input es inválido. Cap 168h (7d) por el schema del registry.
 */
function parseWindow(raw, defaultHours) {
  if (raw == null) return defaultHours;
  const s = String(raw).trim().toLowerCase();
  const m = s.match(/^(\d+)\s*(h|d|hr|hour|hours|day|days)?$/);
  if (!m) return defaultHours;
  const n = Number(m[1]);
  const unit = m[2] ?? "h";
  const hours = unit.startsWith("d") ? n * 24 : n;
  return Math.min(168, Math.max(1, hours));
}

/**
 * Extrae `value` de un Promise.allSettled result o loggea el error en el
 * array compartido.
 */
function pickOrError(settled, name, errors) {
  if (settled.status === "fulfilled") return settled.value;
  errors.push({ name, error: settled.reason?.message ?? "unknown" });
  return null;
}
