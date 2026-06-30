/**
 * Opcional: crea minio_iceberg.hunting.v_incident_score_v2 ejecutando el SQL del repo
 * (misma fuente que scripts/bootstrap-trino-scoring-v2-views.sh → 21_v2_view_incident_score.sql).
 * Requiere tablas Iceberg previas (bootstrap-trino-threat-hunt-iceberg / bootstrap-trino-minio).
 */
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * @param {(q: string, session: object) => Promise<void>} runTrinoQueryWithInitRetries
 * @param {{ catalog: string, schema: string }} session
 * @param {{ info: Function, warn: Function }} logger
 * @returns {Promise<boolean>} true si se ejecutó SQL (aunque Trino pueda fallar después)
 */
export async function tryApplyScoringV2ViewFromFile(runTrinoQueryWithInitRetries, session, logger) {
  if (process.env.TRINO_AUTO_APPLY_SCORING_V2_VIEW !== "1") {
    return false;
  }
  const p =
    (process.env.SCORING_V2_VIEW_SQL_PATH && String(process.env.SCORING_V2_VIEW_SQL_PATH).trim()) ||
    join(process.cwd(), "sql/threat-hunt/21_v2_view_incident_score.sql");
  if (!existsSync(p)) {
    logger.warn("scoring_v2_view_sql_file_missing", {
      path: p,
      hint: "Monte ./scripts/sql/threat-hunt en el contenedor (p. ej. /app/sql/threat-hunt) o ejecute ./scripts/bootstrap-trino-scoring-v2-views.sh en el host.",
    });
    return false;
  }
  const raw = await readFile(p, "utf8");
  const sql = raw.trim();
  if (!sql) {
    logger.warn("scoring_v2_view_sql_empty", { path: p });
    return false;
  }
  logger.info("scoring_v2_view_applying_sql", { path: p });
  await runTrinoQueryWithInitRetries(sql, session);
  return true;
}
