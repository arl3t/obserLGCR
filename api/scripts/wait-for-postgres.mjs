/**
 * Espera a que PostgreSQL acepte conexiones antes de migrate/server.
 * Evita arranques en VPS donde Timescale tarda o el healthcheck pasa antes de estar listo.
 */
import { getPgPool } from "../db/postgres.mjs";

const MAX_ATTEMPTS = parseInt(process.env.PG_WAIT_ATTEMPTS ?? "60", 10);
const DELAY_MS = parseInt(process.env.PG_WAIT_DELAY_MS ?? "2000", 10);

async function probe() {
  const pool = getPgPool();
  try {
    await pool.query("SELECT 1");
    await pool.end();
    return true;
  } catch (err) {
    try { await pool.end(); } catch { /* noop */ }
    throw err;
  }
}

async function main() {
  const host = process.env.PG_HOST ?? "localhost";
  const port = process.env.PG_PORT ?? "5432";
  console.log(`Esperando PostgreSQL en ${host}:${port} (máx ${MAX_ATTEMPTS} intentos)…`);

  for (let i = 1; i <= MAX_ATTEMPTS; i++) {
    try {
      await probe();
      console.log(`PostgreSQL listo (intento ${i}/${MAX_ATTEMPTS}).`);
      return;
    } catch (err) {
      const msg = err?.message ?? String(err);
      console.warn(`  [${i}/${MAX_ATTEMPTS}] ${msg}`);
      if (i === MAX_ATTEMPTS) {
        console.error("PostgreSQL no respondió a tiempo. Revise: docker compose ps && docker logs obserlgcr-postgres");
        process.exit(1);
      }
      await new Promise((r) => setTimeout(r, DELAY_MS));
    }
  }
}

main();
