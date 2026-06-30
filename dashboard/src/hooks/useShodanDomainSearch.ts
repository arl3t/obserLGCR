import { useQuery } from "@tanstack/react-query";
import { getLegacyHuntApiBase } from "@/lib/api-origin";
import type {
  ShodanDomainSearchResponse,
  ShodanErrorResponse,
} from "@/types/shodan";

function parseApiJson(
  raw: string,
  status: number,
): ShodanDomainSearchResponse | ShodanErrorResponse {
  const t = raw.trimStart();
  if (t.startsWith("<!") || t.startsWith("<html") || t.startsWith("<HTML")) {
    throw new Error(
      "Respuesta HTML en lugar de JSON: el front no alcanzó legacyhunt-api. En dev, Vite proxea /api → :8787; levante el contenedor (docker compose --profile lakehouse). En build estática defina VITE_API_BASE_URL o proxee /api en nginx.",
    );
  }
  try {
    return JSON.parse(raw) as ShodanDomainSearchResponse | ShodanErrorResponse;
  } catch {
    throw new Error(
      `Respuesta no JSON (HTTP ${status}). Revise URL del API y proxy /api → :8787.`,
    );
  }
}

async function fetchShodanDomain(
  domain: string,
): Promise<ShodanDomainSearchResponse> {
  const b = getLegacyHuntApiBase();
  const path = `/api/shodan/domain-search?domain=${encodeURIComponent(domain)}`;
  const href = b ? `${b}${path}` : path;
  const r = await fetch(href);
  const raw = await r.text();
  const data = parseApiJson(raw, r.status);
  if (!r.ok || !data.ok) {
    const err = data as ShodanErrorResponse;
    throw new Error(err.error ?? `HTTP ${r.status}`);
  }
  return data as ShodanDomainSearchResponse;
}

export function useShodanDomainSearch(domain: string | null) {
  const d = domain?.trim() ?? "";
  return useQuery({
    queryKey: ["shodan-domain", d],
    queryFn: () => fetchShodanDomain(d),
    enabled: d.length >= 3,
    staleTime: 5 * 60_000,
    retry: 1,
  });
}
