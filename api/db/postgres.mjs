import pg from "pg";

const { Pool } = pg;

let _pool = null;

export function getPgPool() {
  if (!_pool) {
    _pool = new Pool({
      host:     process.env.PG_HOST     ?? "localhost",
      port:     parseInt(process.env.PG_PORT ?? "5432"),
      database: process.env.PG_DATABASE ?? "legacyhunt",
      user:     process.env.PG_USER     ?? "legacyhunt",
      password: process.env.PG_PASSWORD,
      max:      10,
      idleTimeoutMillis:       30000,
      connectionTimeoutMillis: 5000,
    });

    _pool.on("error", (err) => {
      console.error("[PostgreSQL] Pool error:", err.message);
    });
  }
  return _pool;
}

/** Ejecuta una query con el pool y devuelve las filas */
export async function pgQuery(sql, params = []) {
  const pool = getPgPool();
  const { rows } = await pool.query(sql, params);
  return rows;
}

/**
 * Ejecuta `fn(client)` con un cliente dedicado del pool. La conexión se
 * mantiene hasta el final de `fn`, lo cual es imprescindible para operaciones
 * session-scoped como `pg_try_advisory_lock` / `pg_advisory_unlock`.
 *
 * El cliente expone `client.query(sql, params)` compatible con `pgQuery`.
 * Se libera al pool en `finally` incluso si `fn` lanza.
 */
export async function withPgClient(fn) {
  const pool   = getPgPool();
  const client = await pool.connect();
  try {
    return await fn(client);
  } finally {
    client.release();
  }
}
