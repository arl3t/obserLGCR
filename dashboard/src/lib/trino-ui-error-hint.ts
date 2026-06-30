/**
 * Añade una pista cuando el mensaje del API/axios es poco accionable en el overview.
 * Evita duplicar si axios ya sustituyó el error (client.ts → "Sin conexión con legacyhunt-api…").
 */
export function hintForTrinoOrApiError(message: string | undefined): string {
  if (!message) return "";
  const raw = message.trim();
  const m = raw.toLowerCase();

  if (
    raw.includes("Sin conexión con legacyhunt-api") ||
    raw.includes("Sin conexión con el API")
  ) {
    return raw;
  }

  if (
    m.includes("fetch failed") ||
    m.includes("failed to fetch") ||
    m.includes("network error") ||
    m === "load failed"
  ) {
    return `No hay respuesta HTTP desde legacyhunt-api (navegador: «${raw}»). Pruebe: curl -sS http://127.0.0.1:8787/api/health/live (debe devolver JSON). Si falla la conexión, levante legacyhunt-api (p. ej. docker compose --profile core --profile lakehouse up -d legacyhunt-api). Con npm run dev, Vite proxea /api → 8787; deje VITE_API_BASE_URL vacío salvo que sirva el front sin proxy.`;
  }
  if (/table .* does not exist/i.test(raw) && /wazuh/i.test(raw)) {
    return `${raw} — Ejecute en la raíz del repo: ./scripts/bootstrap-trino-wazuh-view.sh (o vuelva a correr ./scripts/bootstrap-trino-minio.sh, que la invoca al final).`;
  }
  if (/unknown query id|\/api\/trino\/run/i.test(raw) && /404|trino\/run/i.test(raw)) {
    return `${raw} — Actualice la imagen legacyhunt-api y reinicie el contenedor; compruebe GET http://127.0.0.1:8787/api/trino/run (debe responder 405 Method Not Allowed, no 404).`;
  }
  return raw;
}
