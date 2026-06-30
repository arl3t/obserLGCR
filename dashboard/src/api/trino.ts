import { isAxiosError } from "axios";
import { api } from "@/api/client";
import type { TrinoQueryResponse } from "@/api/types";

/** Respuesta genérica del proxy: ajusta al contrato de tu backend. */
export async function executeTrinoQuery(
  query: string,
): Promise<TrinoQueryResponse> {
  try {
    /* X-Api-Key lo añade el interceptor de `api` si VITE_TRINO_PROXY_API_KEY está definido. */
    const { data } = await api.post<TrinoQueryResponse>("/api/trino/query", {
      query: query.trim(),
    });
    return data;
  } catch (e) {
    if (isAxiosError(e)) {
      const body = e.response?.data as { error?: string } | undefined;
      const status = e.response?.status;
      if (status === 401 && /api key/i.test(body?.error ?? "")) {
        const hasKey = Boolean((import.meta.env.VITE_TRINO_PROXY_API_KEY ?? "").trim());
        throw new Error(
          `${body?.error ?? "Invalid or missing API key"}. ` +
            (hasKey
              ? "El front ya envía X-Api-Key (interceptor Axios). Compruebe que coincida exactamente con TRINO_PROXY_API_KEY en legacyhunt-api, sin espacios ni comillas, y reinicie Vite y el API."
              : "Defina VITE_TRINO_PROXY_API_KEY en legacyhunt-dashboard/.env igual que TRINO_PROXY_API_KEY del API (el Bearer del login no sirve). Reinicie npm run dev tras guardar .env.") +
            " Si despliega legacyhunt-api con lh.incidents.live_top_v2, POST /api/trino/run evita el fallback SQL.",
        );
      }
      if (body?.error) throw new Error(body.error);
      if (status === 503) {
        throw new Error(
          "El API respondió 503 (Trino no configurado). En el .env de la raíz del repo defina TRINO_URL=http://127.0.0.1:8080, reinicie legacyhunt-api y asegúrese de que Trino esté en marcha (docker compose --profile lakehouse).",
        );
      }
    }
    throw e;
  }
}
