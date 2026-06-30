/**
 * routes/hunt.mjs — Endpoints del feature "Hunt Pivots".
 *
 * Monta en: /api/hunt (requireAuth() en el mount de server.mjs).
 *
 * Endpoints v1 (Sprint 1):
 *   POST /preview                Devuelve evidencia agregada + suggestedCase
 *                                para abrir un caso desde un pivote (IP,
 *                                agent, CVE, sender, outlier).
 *
 * No persiste nada. La apertura efectiva del caso se hace en el endpoint
 * existente POST /api/incidents/open-from-flow consumiendo el `suggestedCase`
 * devuelto acá.
 *
 * Diseño: docs/HUNT-PIVOTS.md
 *
 * Ejemplo:
 *   curl -X POST http://localhost:8787/api/hunt/preview \\
 *     -H "Authorization: Bearer <jwt>" \\
 *     -H "Content-Type: application/json" \\
 *     -d '{"pivot":"src_ip","value":"185.220.101.5"}'
 */

import { Router } from "express";
import { logger } from "../logger.mjs";
import { pgQuery } from "../db/postgres.mjs";
import { trinoExec } from "../services/trinoWriter.mjs";
import { resolveJwtOperatorCi } from "../services/operatorResolver.mjs";
import {
  PIVOT_TYPES,
  aggregateEvidence,
  suggestSeverity,
  suggestScore,
  suggestSourceLog,
  lookupExistingCase,
  lookupExistingCasesBatch,
} from "../services/huntPivots.mjs";

// Acepta UUID con guiones y el formato 32-hex sin guiones (casos importados de
// Trino). Solo-hex → seguro para concatenar; antes daba 400 en esos casos.
const UUID_RE = /^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
const ICEBERG_SESSION = { catalog: "minio_iceberg", schema: "hunting" };

function sqlStr(v) {
  return `'${String(v ?? "").replace(/'/g, "''")}'`;
}

export default function huntRouter(runQuery) {
  const router = Router();

  router.post("/preview", async (req, res) => {
    const { pivot, value } = req.body ?? {};

    if (!PIVOT_TYPES.includes(pivot)) {
      return res.status(400).json({
        ok: false,
        error: `pivot inválido: '${pivot}'. Aceptados: ${PIVOT_TYPES.join(", ")}`,
      });
    }
    if (!value || typeof value !== "string") {
      return res.status(400).json({ ok: false, error: "value requerido (string)" });
    }

    try {
      const evidence = await aggregateEvidence(runQuery, { pivot, value });

      // El IOC del caso a abrir suele ser el `value` recibido, EXCEPTO para
      // outlier (donde el IOC es el entity_value del row, no el outlier_id).
      const iocValue = evidence.iocValue || value;

      // Si la evidencia agregada está vacía (0 eventos en 24h), abrir un
      // caso desde acá sería un caso sin contexto. Marcamos isEmpty para
      // que la UI muestre un mensaje claro + deshabilite "Investigar ahora".
      // El operador igual puede ampliar manualmente (futuro: ventana 7d) o
      // abrir desde otra fuente. Decisión documentada en docs/HUNT-PIVOTS.md.
      const isEmpty = (evidence.totalEvents24h ?? 0) === 0;
      evidence.isEmpty = isEmpty;

      const suggestedCase = isEmpty ? null : {
        iocValue,
        iocType:        evidence.defaultIocType,
        sourceLog:      suggestSourceLog(evidence),
        severity:       suggestSeverity(evidence),
        score:          suggestScore(evidence),
        mitreTacticId:  evidence.mitreTactics?.[0] ?? null,
        rawContext:     evidence.representativeEvent
          ? {
              hint:      "Evento representativo agregado por /api/hunt/preview",
              pivot,
              value,
              ts:        evidence.representativeEvent.ts,
              ruleId:    evidence.representativeEvent.ruleId,
              ruleDesc:  evidence.representativeEvent.ruleDesc,
              severity:  evidence.representativeEvent.lvl,
            }
          : { hint: "Sin evento representativo", pivot, value },
        // Meta para auditoría: el flow que abrió el caso.
        huntPivot: { pivot, value },
      };

      const existingCase = await lookupExistingCase(iocValue);

      return res.json({
        ok: true,
        evidence,
        suggestedCase,
        existingCase,
      });
    } catch (err) {
      const status = Number(err?.status) || 500;
      if (status >= 500) {
        logger.error("hunt/preview_failed", { err: err?.message, pivot, value });
      }
      return res.status(status).json({ ok: false, error: err.message });
    }
  });

  // ── GET /api/hunt/adoption ─────────────────────────────────────────────────
  // Métrica de adopción del feature Hunt Pivots. Cuenta inserts de
  // incident_case_audit con action='hunt_pivot_opened' en últimos N días
  // (default 7), agrupados por pivote. Lo consume el widget de /leader.
  router.get("/adoption", async (req, res) => {
    const days = Math.max(1, Math.min(90, Number(req.query.days) || 7));
    try {
      const rows = await pgQuery(
        `SELECT
           COALESCE(detail->>'pivot', '?') AS pivot,
           COUNT(*) AS n
         FROM legacyhunt_soc.incident_case_audit
         WHERE action = 'hunt_pivot_opened'
           AND created_at >= now() - ($1 || ' days')::interval
         GROUP BY 1
         ORDER BY n DESC`,
        [String(days)],
      );
      const byPivot = {};
      let total = 0;
      for (const r of rows) {
        const n = Number(r.n ?? 0);
        byPivot[r.pivot] = n;
        total += n;
      }
      return res.json({ ok: true, days, total, byPivot });
    } catch (err) {
      logger.error("hunt/adoption_failed", { err: err.message });
      return res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── POST /api/hunt/case-status ─────────────────────────────────────────────
  // Lookup batch para el flag "caso abierto" en cada fila de los rankings
  // /hunt. Recibe { values: string[] } y devuelve { byValue: { <ioc>: case } }.
  // Usado por HuntPage tras cargar las 20 filas del tab activo.
  //
  // Tope defensivo: 200 IOCs por request (el frontend nunca pasa de 20).
  router.post("/case-status", async (req, res) => {
    const values = Array.isArray(req.body?.values) ? req.body.values : null;
    if (!values) {
      return res.status(400).json({ ok: false, error: "values requerido (array de strings)" });
    }
    if (values.length > 200) {
      return res.status(400).json({ ok: false, error: "máximo 200 values por request" });
    }
    try {
      const byValue = await lookupExistingCasesBatch(values);
      return res.json({ ok: true, byValue });
    } catch (err) {
      logger.error("hunt/case-status_failed", { err: err.message });
      return res.status(500).json({ ok: false, error: err.message });
    }
  });

  // ── POST /api/hunt/case-opened ─────────────────────────────────────────────
  // Llamado por el frontend tras recibir 201 de /api/incidents/open-from-flow
  // cuando el caso provino del flujo Hunt Pivots.
  //
  // Tareas:
  //   1. Inserta fila en legacyhunt_soc.incident_case_audit con
  //      action='hunt_pivot_opened' para tracking de adopción.
  //   2. Si el pivote es de un outlier (recibe entity_type+entity_value),
  //      busca el outlier_id más reciente para esa entidad y UPDATEa
  //      `related_case_id` en minio_iceberg.hunting.outliers (D4 del plan).
  //
  // Errores de Trino/PG NO escalan a HTTP 500 — perder el tracking no debe
  // tumbar la UI; el caso ya está creado correctamente.
  router.post("/case-opened", async (req, res) => {
    const { caseId, pivot, value, outlierEntityType, outlierEntityValue, evidence } = req.body ?? {};

    if (!caseId || !UUID_RE.test(caseId)) {
      return res.status(400).json({ ok: false, error: "caseId UUID requerido" });
    }
    if (!pivot || !PIVOT_TYPES.includes(pivot)) {
      return res.status(400).json({ ok: false, error: "pivot inválido" });
    }
    if (!value || typeof value !== "string") {
      return res.status(400).json({ ok: false, error: "value requerido" });
    }

    const operatorCi = await resolveJwtOperatorCi(req).catch(() => null);

    // 1. Audit row — best-effort.
    let audited = false;
    try {
      await pgQuery(
        `INSERT INTO legacyhunt_soc.incident_case_audit (case_id, action, detail)
         VALUES ($1, 'hunt_pivot_opened', $2::jsonb)`,
        [caseId, JSON.stringify({ pivot, value, operatorCi, source: "hunt-pivots-ui" })],
      );
      audited = true;
    } catch (err) {
      logger.warn("hunt/case-opened audit failed", { err: err.message, caseId });
    }

    // 1b. Snapshot del preview — si el frontend lo manda, lo guardamos en
    // enrichment_data.huntPivotSnapshot. Le da a la vista de investigación
    // contexto agregado (5,959 alertas, top reglas, severity breakdown) sin
    // re-correr la query de 20s. Best-effort: si falla, no rompe nada — el
    // operador igual puede usar el tab "Eventos" para ver datos live.
    let snapshotPersisted = false;
    if (evidence && typeof evidence === "object") {
      const snapshot = {
        capturedAt: new Date().toISOString(),
        pivot,
        value,
        totalEvents24h:    evidence.totalEvents24h ?? 0,
        bySource:          evidence.bySource ?? {},
        severityBreakdown: evidence.severityBreakdown ?? {},
        topRules:          Array.isArray(evidence.topRules) ? evidence.topRules.slice(0, 10) : [],
        mitreTactics:      Array.isArray(evidence.mitreTactics) ? evidence.mitreTactics : [],
        lastSeen:          evidence.lastSeen ?? null,
        representativeEvent: evidence.representativeEvent ?? null,
        defaultSourceLog:  evidence.defaultSourceLog ?? null,
      };
      try {
        await pgQuery(
          `UPDATE incident_cases_pg
              SET enrichment_data = COALESCE(enrichment_data, '{}'::jsonb)
                                  || jsonb_build_object('huntPivotSnapshot', $2::jsonb)
            WHERE id = $1`,
          [caseId, JSON.stringify(snapshot)],
        );
        snapshotPersisted = true;
      } catch (err) {
        logger.warn("hunt/case-opened snapshot persist failed", { err: err.message, caseId });
      }
    }

    // 2. Outlier linking — solo si vino la entidad asociada.
    let outlierLinked = false;
    if (outlierEntityType && outlierEntityValue) {
      try {
        const rows = await trinoExec(
          `SELECT outlier_id
             FROM minio_iceberg.hunting.outliers
            WHERE entity_type  = ${sqlStr(outlierEntityType)}
              AND entity_value = ${sqlStr(outlierEntityValue)}
            ORDER BY detection_time DESC
            LIMIT 1`,
          ICEBERG_SESSION,
        );
        const oid = Array.isArray(rows) && rows[0]?.outlier_id;
        if (oid) {
          await trinoExec(
            `UPDATE minio_iceberg.hunting.outliers
                SET related_case_id = ${sqlStr(caseId)}
              WHERE outlier_id = ${sqlStr(oid)}`,
            ICEBERG_SESSION,
          );
          outlierLinked = true;
        }
      } catch (err) {
        logger.warn("hunt/case-opened outlier link failed", { err: err.message, caseId });
      }
    }

    return res.json({ ok: true, audited, outlierLinked, snapshotPersisted });
  });

  return router;
}
