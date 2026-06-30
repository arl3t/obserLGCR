import type {
  RiskBand,
  SurveillanceBrand24Result,
  SurveillanceDomainResult,
  SurveillanceRssResult,
} from "@/types/digital-surveillance";
import { authFetch } from "@/lib/auth-fetch";

export function normalizeSurveillanceDomain(raw: string): string {
  return raw.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0] ?? "";
}

export function riskLabelEs(band: RiskBand): string {
  return band === "high" ? "Alto" : band === "medium" ? "Medio" : "Bajo";
}

/**
 * Llama a GET /api/surveillance/domain?domain=X.
 * Lanza un error si la respuesta no es ok para que React Query lo gestione.
 */
export async function fetchSurveillanceDomain(domain: string): Promise<SurveillanceDomainResult> {
  const key = normalizeSurveillanceDomain(domain);
  if (!key) throw new Error("Dominio vacío");

  const res = await authFetch(`/api/surveillance/domain?domain=${encodeURIComponent(key)}`);
  const json = await res.json().catch(() => ({}));

  if (!res.ok || json.ok === false) {
    throw new Error(json.error ?? `HTTP ${res.status}`);
  }
  return json as SurveillanceDomainResult;
}

export async function fetchSurveillanceRss(domain: string): Promise<SurveillanceRssResult> {
  const key = normalizeSurveillanceDomain(domain);
  if (!key) throw new Error("Dominio vacío");

  const res  = await authFetch(`/api/surveillance/rss?domain=${encodeURIComponent(key)}`);
  const json = await res.json().catch(() => ({}));

  if (!res.ok || json.ok === false) {
    throw new Error(json.error ?? `HTTP ${res.status}`);
  }
  return json as SurveillanceRssResult;
}

/**
 * Llama a GET /api/surveillance/brand24?domain=X. Cuando el dominio no tiene
 * proyecto Brand24 configurado ni snapshots, el backend devuelve un payload
 * vacío con `projectId: null` (no es error: la UI debe mostrar estado vacío).
 */
export async function fetchSurveillanceBrand24(domain: string): Promise<SurveillanceBrand24Result> {
  const key = normalizeSurveillanceDomain(domain);
  if (!key) throw new Error("Dominio vacío");

  const res  = await authFetch(`/api/surveillance/brand24?domain=${encodeURIComponent(key)}`);
  const json = await res.json().catch(() => ({}));

  if (!res.ok || json.ok === false) {
    throw new Error(json.error ?? `HTTP ${res.status}`);
  }
  return json as SurveillanceBrand24Result;
}
