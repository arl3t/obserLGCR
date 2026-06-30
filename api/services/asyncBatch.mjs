/**
 * services/asyncBatch.mjs — utilidades de concurrencia acotada.
 *
 * Para paralelizar loops de operaciones independientes sin saturar el pool de
 * PG (max 10) ni perder la semántica de backpressure. NO usar para escrituras
 * inline a Iceberg/Trino sobre la MISMA tabla: commits concurrentes disparan
 * CommitFailedException (esas deben seguir seriales).
 */

/**
 * Mapea `fn` sobre `items` en chunks de `size`, corriendo cada chunk en paralelo
 * (Promise.allSettled, aislando errores por ítem). Devuelve los resultados en
 * orden. Una promesa rechazada se materializa como `{ __error: <reason> }`.
 *
 * Si se pasa `stopWhen(result)` y devuelve true para algún resultado de un chunk,
 * no se procesan más chunks (preserva backpressure tipo QUEUE_FULL, con un
 * sobre-procesamiento acotado al tamaño del chunk en curso).
 *
 * @template T, R
 * @param {T[]} items
 * @param {number} size            concurrencia (chunk). <=0 → 1.
 * @param {(item: T, index: number) => Promise<R>} fn
 * @param {{ stopWhen?: (result: R) => boolean }} [opts]
 * @returns {Promise<Array<R | { __error: unknown }>>}
 */
export async function mapChunked(items, size, fn, opts = {}) {
  const { stopWhen } = opts;
  const chunk = Math.max(1, Math.floor(size) || 1);
  const out = [];
  for (let i = 0; i < items.length; i += chunk) {
    const slice = items.slice(i, i + chunk);
    const settled = await Promise.allSettled(slice.map((it, j) => fn(it, i + j)));
    let stop = false;
    for (const s of settled) {
      const val = s.status === "fulfilled" ? s.value : { __error: s.reason };
      out.push(val);
      if (stopWhen && s.status === "fulfilled" && stopWhen(val)) stop = true;
    }
    if (stop) break;
  }
  return out;
}
