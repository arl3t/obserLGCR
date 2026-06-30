/**
 * trinoReader.mjs
 * Cliente Trino mínimo para lecturas (SELECT) desde servicios internos.
 * Complementa trinoWriter.mjs (que solo expone trinoExec sin rows).
 *
 * Patrón replicado de autoClassifyController.runNamedQuery: POST /v1/statement,
 * polling nextUri, dedupe columnas/data, devuelve rows con keys = column names
 * (snake_case tal como Trino los emite).
 */

import { config } from "../config.mjs";

const TRINO_URL  = config.TRINO_URL;
const TRINO_USER = config.TRINO_USER || "legacyhunt-api";

/**
 * Ejecuta una sentencia SQL en Trino y devuelve los rows resultantes.
 *
 * @param {string} sql
 * @param {{ catalog?: string, schema?: string, timeoutMs?: number }} [opts]
 * @returns {Promise<{ ok: boolean, rows: Record<string, unknown>[], error?: string }>}
 */
export async function runTrinoQuery(sql, opts = {}) {
  if (!TRINO_URL) return { ok: false, error: "TRINO_URL no configurada", rows: [] };

  const headers = {
    "X-Trino-User":   TRINO_USER,
    "X-Trino-Source": "legacyhunt-api-reader",
    ...(opts.catalog ? { "X-Trino-Catalog": opts.catalog } : {}),
    ...(opts.schema  ? { "X-Trino-Schema":  opts.schema  } : {}),
  };
  const timeoutMs = opts.timeoutMs ?? 60_000;

  try {
    let res = await fetch(`${TRINO_URL}/v1/statement`, {
      method: "POST",
      headers: { ...headers, "Content-Type": "text/plain" },
      body: sql,
      signal: AbortSignal.timeout(timeoutMs),
    });
    let data = await res.json();
    if (data.error) return { ok: false, error: data.error.message, rows: [] };

    let columns = [];
    const rows = [];

    if (data.columns) columns = data.columns.map((c) => c.name);
    if (data.data) {
      for (const row of data.data) {
        const obj = {};
        columns.forEach((col, i) => { obj[col] = row[i]; });
        rows.push(obj);
      }
    }

    while (data.nextUri) {
      const nextUrl = data.nextUri.startsWith("http")
        ? data.nextUri
        : `${TRINO_URL}${data.nextUri}`;
      await new Promise((r) => setTimeout(r, 200));
      res  = await fetch(nextUrl, { headers, signal: AbortSignal.timeout(timeoutMs) });
      data = await res.json();
      if (data.error) return { ok: false, error: data.error.message, rows };
      if (data.columns && !columns.length) columns = data.columns.map((c) => c.name);
      if (data.data) {
        for (const row of data.data) {
          const obj = {};
          columns.forEach((col, i) => { obj[col] = row[i]; });
          rows.push(obj);
        }
      }
    }
    return { ok: true, rows };
  } catch (err) {
    return { ok: false, error: String(err?.message ?? err), rows: [] };
  }
}
