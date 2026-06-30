import { isAxiosError } from "axios";
import { api } from "@/api/client";
import { executeTrinoQuery } from "@/api/trino";
import type { TrinoQueryResponse } from "@/api/types";
import { buildSqlForNamedQuery } from "@/lib/trino-named-fallback";

/* ─── Batch API ──────────────────────────────────────────────────────────── */

export interface BatchQuerySpec {
  id: string;
  params?: Record<string, unknown>;
}

export interface BatchQueryResult {
  id: string;
  rows: Record<string, unknown>[];
  cached: boolean;
  error?: string;
}

export interface BatchRunOptions {
  noCache?: boolean;
}

/**
 * Envía múltiples consultas nombradas en un solo POST /api/trino/batch.
 * El API las ejecuta en paralelo (Promise.all) sobre la misma caché LRU.
 * Usar en componentes que disparan ≥ 3 consultas al mismo tiempo para reducir
 * el número de round-trips HTTP y la presión sobre el rate-limiter.
 */
export async function executeTrinoRunBatch(
  queries: BatchQuerySpec[],
  options?: BatchRunOptions,
): Promise<BatchQueryResult[]> {
  const { data } = await api.post<{ results: Array<{id: string; rows?: Record<string,unknown>[]; cached?: boolean; error?: string}> }>(
    "/api/trino/batch",
    { queries, nocache: options?.noCache === true },
  );
  // El endpoint /batch devuelve rows ya normalizadas (mismo formato que /run).
  return data.results.map((r) => ({
    id: r.id,
    rows: r.rows ?? [],
    cached: r.cached ?? false,
    error: r.error,
  }));
}

export async function executeTrinoRun(
  id: string,
  params?: Record<string, unknown>,
  options?: { timeoutMs?: number },
): Promise<TrinoQueryResponse> {
  const trimmed = id.trim();
  const p = params ?? {};
  const tryClientSqlFallback = (): Promise<TrinoQueryResponse> | null => {
    const sql = buildSqlForNamedQuery(trimmed, p);
    return sql ? executeTrinoQuery(sql) : null;
  };

  try {
    const axiosConfig = options?.timeoutMs ? { timeout: options.timeoutMs } : undefined;
    const { data } = await api.post<TrinoQueryResponse>(
      "/api/trino/run",
      { id: trimmed, params: p },
      axiosConfig,
    );
    return data;
  } catch (e) {
    if (isAxiosError(e)) {
      const status = e.response?.status;
      const rawBody = e.response?.data;
      const errStr =
        typeof rawBody === "object" && rawBody != null && "error" in rawBody
          ? String((rawBody as { error?: string }).error ?? "")
          : "";

      const useFallback =
        status === 404 ||
        (status === 400 && /unknown query id/i.test(errStr));

      if (useFallback) {
        const fb = tryClientSqlFallback();
        if (fb) return fb;
      }

      if (typeof rawBody === "object" && rawBody != null && "error" in rawBody) {
        const msg = (rawBody as { error?: string }).error;
        if (msg) throw new Error(msg);
      }
      if (status === 503) {
        throw new Error(
          "El API respondió 503 (Trino no configurado). En el .env de la raíz del repo defina TRINO_URL=http://127.0.0.1:8080, reinicie legacyhunt-api y asegúrese de que Trino esté en marcha (docker compose --profile lakehouse).",
        );
      }
      if (status === 404) {
        throw new Error(
          "POST /api/trino/run → 404. Reconstruya legacyhunt-api (`docker compose build legacyhunt-api && … up -d`) y compruebe `curl -X POST http://127.0.0.1:8787/api/trino/run -H 'Content-Type: application/json' -d '{\"id\":\"lh.syslog.any_row\",\"params\":{}}'`. Si el API es reciente, revise el proxy Vite /api → :8787 y que nada más use el puerto 8787.",
        );
      }
    }
    throw e;
  }
}
