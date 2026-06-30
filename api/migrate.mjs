/**
 * Runner de migraciones simple para obserLGCR.
 *
 * Aplica todos los archivos `NNN_*.sql` (no `.down.sql`) del directorio
 * `migrations/` en orden numérico, dentro de una tabla de control idempotente
 * `schema_migrations`. Pensado para el fork demo (solo Postgres): el esquema
 * resultante es idéntico al de la plataforma original sin el data-lake.
 *
 * Uso:  PG_HOST=... PG_PASSWORD=... node migrate.mjs
 */
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { getPgPool } from "./db/postgres.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const MIG_DIR = join(__dirname, "migrations");

async function main() {
  const pool = getPgPool();

  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      filename   TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  const applied = new Set(
    (await pool.query("SELECT filename FROM schema_migrations")).rows.map((r) => r.filename),
  );

  const files = readdirSync(MIG_DIR)
    .filter((f) => f.endsWith(".sql") && !f.endsWith(".down.sql"))
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));

  let ok = 0;
  let skipped = 0;
  for (const file of files) {
    if (applied.has(file)) {
      skipped++;
      continue;
    }
    const sql = readFileSync(join(MIG_DIR, file), "utf8");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(sql);
      await client.query("INSERT INTO schema_migrations (filename) VALUES ($1)", [file]);
      await client.query("COMMIT");
      ok++;
      console.log(`  ✔ ${file}`);
    } catch (err) {
      await client.query("ROLLBACK");
      console.error(`  x ${file} — FALLO: ${err.message}`);
      // Continúa: en el fork demo algunas migraciones asumen objetos del
      // data-lake. Las que fallen quedan sin registrar y pueden reintentarse.
    } finally {
      client.release();
    }
  }

  console.log(`\nMigraciones: ${ok} aplicadas, ${skipped} ya estaban, de ${files.length} totales.`);
  await pool.end();
}

main().catch((err) => {
  console.error("migrate.mjs error fatal:", err);
  process.exit(1);
});
