/**
 * useEnrichment — mutación para POST /api/surveillance/enrich.
 *
 * Llamado desde el drawer OSINT. No usa useQuery porque la consulta es
 * on-demand del analista (con un click) — useMutation calza mejor que
 * cachear queryKey por (type, value).
 */

import { useMutation } from "@tanstack/react-query";
import { authFetch } from "@/lib/auth-fetch";

export type EnrichType = "ip" | "domain" | "hash";

export type EnrichSourceResult = {
  source: string;
  ok: boolean;
  error?: string;
  summary?: Record<string, unknown>;
};

export type EnrichResponse = {
  ok: boolean;
  type: EnrichType;
  value: string;
  results: EnrichSourceResult[];
  fetchedAt: string;
};

export function useEnrichment() {
  return useMutation<EnrichResponse, Error, { type: EnrichType; value: string }>({
    mutationFn: async ({ type, value }) => {
      const r = await authFetch("/api/surveillance/enrich", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type, value }),
      });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        throw new Error(j?.error ?? `HTTP ${r.status}`);
      }
      return r.json();
    },
  });
}

/** Heurística rápida para inferir el tipo de un valor pasado por el analista. */
export function detectIocType(raw: string): EnrichType | null {
  const v = raw.trim();
  if (/^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/.test(v)) return "ip";
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return "hash";
  if (/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(v)) return "domain";
  return null;
}
