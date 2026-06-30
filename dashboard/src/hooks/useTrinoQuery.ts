import { useQuery, type UseQueryOptions } from "@tanstack/react-query";
import { executeTrinoQuery } from "@/api/trino";
import { executeTrinoRun, executeTrinoRunBatch, type BatchQuerySpec } from "@/api/trino-run";
import { normalizeRows, type TrinoQueryResponse } from "@/api/types";

export function useTrinoSql(
  queryKey: unknown[],
  sql: string,
  options?: Omit<
    UseQueryOptions<Record<string, unknown>[]>,
    "queryKey" | "queryFn"
  >,
) {
  return useQuery({
    queryKey: [...queryKey, sql],
    queryFn: async () => {
      const res: TrinoQueryResponse = await executeTrinoQuery(sql);
      if (res.error) throw new Error(res.error);
      return normalizeRows(res);
    },
    ...options,
  });
}

/* ─── Batch hook ─────────────────────────────────────────────────────────── */

/**
 * Especificación de una consulta dentro de un batch.
 * `key` es el nombre que usa el componente para extraer el resultado del mapa
 * devuelto por `useTrinoNamedBatch`. Debe ser único dentro del batch.
 */
export interface BatchSpec extends BatchQuerySpec {
  /** Alias local para acceder al resultado: `results.key`. */
  key: string;
}

/**
 * Resultado tipado por clave para `useTrinoNamedBatch`.
 * Para cada `key` del `BatchSpec` expone `data`, `error` y `cached`.
 */
export type BatchResults<K extends string> = {
  [key in K]: {
    data: Record<string, unknown>[] | undefined;
    error: string | undefined;
    cached: boolean;
  };
};

/**
 * Lanza **una sola** petición POST /api/trino/batch con todas las consultas y
 * devuelve:
 *  - `results`:  mapa `key → { data, error, cached }` — nunca undefined
 *  - `isLoading`, `isFetching`, `isError`, `refetch` del useQuery subyacente
 *
 * Usar cuando un componente necesita ≥ 3 consultas al mismo tiempo.
 * El hook es estable siempre que el array `specs` sea estático (definir fuera
 * del render o con useMemo) — `specs` no entra en el closure de queryFn.
 *
 * @example
 * const SPECS = [
 *   { key: "blocks24", id: "lh.syslog.blocks_last_24h" },
 *   { key: "topIps",   id: "lh.syslog.top_blocked_ips", params: { limit: 8, hours: 24 } },
 * ] as const satisfies BatchSpec[];
 *
 * const { results, isLoading } = useTrinoNamedBatch(["home", "perim"], SPECS, STALE_2M);
 * const b24 = Number(results.blocks24.data?.[0]?.c ?? 0);
 */
export function useTrinoNamedBatch<K extends string>(
  queryKey: unknown[],
  specs: readonly BatchSpec[],
  options?: Omit<UseQueryOptions<BatchResults<K>>, "queryKey" | "queryFn">,
) {
  // La clave incluye el array de specs serializado para invalidar si cambia.
  const specsKey = JSON.stringify(specs.map((s) => ({ key: s.key, id: s.id, params: s.params ?? {} })));

  const query = useQuery<BatchResults<K>>({
    queryKey: [...queryKey, "batch", specsKey],
    queryFn: async () => {
      const batchSpecs: BatchQuerySpec[] = specs.map(({ id, params }) => ({ id, params }));
      const rawResults = await executeTrinoRunBatch(batchSpecs);

      // Construye el mapa key → resultado.
      const map = {} as BatchResults<K>;
      specs.forEach((spec, i) => {
        const r = rawResults[i];
        (map as Record<string, unknown>)[spec.key] = {
          data: r?.error ? undefined : (r?.rows ?? []),
          error: r?.error,
          cached: r?.cached ?? false,
        };
      });
      return map;
    },
    ...options,
  });

  // Garantiza que `results` nunca sea undefined: si aún no hay datos,
  // devuelve entradas vacías para todas las claves.
  const emptyResults = Object.fromEntries(
    specs.map((s) => [s.key, { data: undefined, error: undefined, cached: false }]),
  ) as BatchResults<K>;

  return {
    ...query,
    results: query.data ?? emptyResults,
  };
}

/** Consulta nombrada en legacyhunt-api (`lh.*`); el SQL no sale del backend. */
export function useTrinoNamed(
  queryKey: unknown[],
  id: string,
  params?: Record<string, unknown>,
  options?: Omit<
    UseQueryOptions<Record<string, unknown>[]>,
    "queryKey" | "queryFn"
  >,
) {
  const p = params ?? {};
  const paramsKey = JSON.stringify(p);
  return useQuery({
    queryKey: [...queryKey, "named", id, paramsKey],
    queryFn: async () => {
      const res: TrinoQueryResponse = await executeTrinoRun(id, p);
      if (res.error) throw new Error(res.error);
      return normalizeRows(res);
    },
    ...options,
  });
}
