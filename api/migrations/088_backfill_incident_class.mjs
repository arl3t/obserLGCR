/**
 * 088_backfill_incident_class.mjs — backfill de incident_cases_pg.incident_class.
 *
 * Recorre todos los casos y materializa la clave eCSIRT con la MISMA función
 * classifyEcsirt() que usa la lectura (services/ecsirtClassify) → el valor
 * persistido coincide exactamente con el chip de la cola al momento del backfill.
 *
 * Idempotente: re-ejecutable sin efectos colaterales (recalcula y reescribe).
 * Por defecto solo toca filas con incident_class NULL; con --all reescribe todas.
 *
 * Uso (dentro del contenedor, migrations/ está montado en /app/migrations):
 *   docker compose exec legacyhunt-api node /app/migrations/088_backfill_incident_class.mjs
 *   docker compose exec legacyhunt-api node /app/migrations/088_backfill_incident_class.mjs --all
 */
import { pgQuery, getPgPool } from "../db/postgres.mjs";
import { classifyEcsirt } from "../services/ecsirtClassify.mjs";

const ALL = process.argv.includes("--all");
const BATCH = 2000;

// Extrae el enrichment relevante para classifyEcsirt igual que mapCaseRow:
// enrichment_data.iocEnrichment ?? enrichment_data.
function pickEnrichment(ed) {
  if (!ed) return null;
  const obj = typeof ed === "string"
    ? (() => { try { return JSON.parse(ed); } catch { return null; } })()
    : ed;
  return obj?.iocEnrichment ?? obj ?? null;
}

async function main() {
  const where = ALL ? "" : "WHERE incident_class IS NULL";
  const total = Number(
    (await pgQuery(`SELECT COUNT(*)::int AS n FROM incident_cases_pg ${where}`))[0]?.n ?? 0,
  );
  console.log(`[088] backfill incident_class — ${total} casos (${ALL ? "TODOS" : "solo NULL"})`);

  let processed = 0;
  let updated = 0;
  let lastId = "";
  // Keyset pagination por id (estable, sin OFFSET creciente).
  for (;;) {
    const rows = await pgQuery(
      `SELECT id, mitre_tactic_id, ioc_type, source_log, enrichment_data
         FROM incident_cases_pg
        WHERE id > $1 ${ALL ? "" : "AND incident_class IS NULL"}
        ORDER BY id
        LIMIT $2`,
      [lastId, BATCH],
    );
    if (rows.length === 0) break;
    lastId = rows[rows.length - 1].id;

    // Agrupamos por clase computada y aplicamos un UPDATE ... = ANY(ids) por clase
    // (menos round-trips que un UPDATE por fila).
    const byClass = new Map();
    for (const r of rows) {
      const cls = classifyEcsirt({
        mitreTacticId: r.mitre_tactic_id,
        iocType:       r.ioc_type,
        sourceLog:     r.source_log,
        enrichment:    pickEnrichment(r.enrichment_data),
      }).class;
      if (!byClass.has(cls)) byClass.set(cls, []);
      byClass.get(cls).push(r.id);
    }
    for (const [cls, ids] of byClass) {
      await pgQuery(
        `UPDATE incident_cases_pg SET incident_class = $1 WHERE id = ANY($2::varchar[])`,
        [cls, ids],
      );
      updated += ids.length;  // UPDATE sin RETURNING → rows=[]; contamos los ids enviados.
    }

    processed += rows.length;
    if (processed % 20000 < BATCH) console.log(`[088]   …${processed}/${total}`);
  }

  console.log(`[088] OK — ${processed} recorridos, ${updated} actualizados.`);
  await getPgPool().end();
}

main().catch((err) => {
  console.error("[088] ERROR:", err);
  process.exit(1);
});
