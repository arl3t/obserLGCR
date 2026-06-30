import { useQuery } from "@tanstack/react-query";
import {
  fetchSurveillanceBrand24,
  fetchSurveillanceDomain,
  fetchSurveillanceRss,
} from "@/lib/digital-surveillance-api";
import type {
  SurveillanceBrand24Result,
  SurveillanceDomainResult,
  SurveillanceRssResult,
} from "@/types/digital-surveillance";
import { authFetch } from "@/lib/auth-fetch";

// ── Intel Files types ─────────────────────────────────────────────────────────

export interface IntelFileEntry {
  key: string;
  filename: string;
  orgSlug: string;
  type: "CSV" | "PDF" | "JSON" | "ZIP" | string;
  ext: string;
  size: number;
  lastModified: string;
  downloadUrl: string;
}

export interface IntelFilesResult {
  ok: boolean;
  domain: string;
  patterns: string[];
  total: number;
  truncated: boolean;
  files: IntelFileEntry[];
}

/**
 * Genera patrones glob desde un dominio.
 *
 * Ejemplos:
 *   "legacy-roots.net" → ["legacy-roots*", "legacy-roots.net"]
 *   "itti.com.py"      → ["itti.com*", "itti.com.py"]   (sin "itti*" — muy abierto)
 *   "fdc.com.py"       → ["fdc.com*", "fdc.com.py"]
 *
 * El primer-label glob (`acme*`) solo se incluye si tiene ≥ 5 caracteres,
 * porque labels cortos como "fdc" o "abc" matchean filenames totalmente
 * ajenos en el bucket de inteligencia (ej. `fdc_compras_2024.csv`).
 *
 * Esta función debe mantenerse alineada con la copia equivalente en
 * `legacyhunt-api/server.mjs:autoPatternsFromDomain`.
 */
export const APEX_GLOB_MIN_LEN = 5;

export function autoPatternsFromDomain(domain: string): string[] {
  const parts = domain.split(".");
  const patterns: string[] = [];
  // primer label + wildcard, solo si es lo bastante específico
  if (parts.length > 0 && parts[0].length >= APEX_GLOB_MIN_LEN) {
    patterns.push(`${parts[0]}*`);
  }
  // dominio sin último label + wildcard (si ≥ 3 partes)
  if (parts.length >= 3) patterns.push(`${parts.slice(0, -1).join(".")}*`);
  // dominio completo exacto
  patterns.push(domain);
  return [...new Set(patterns)];
}

export type { SurveillanceDomainResult, SurveillanceRssResult };

export const surveillanceQueryKey = (domain: string) =>
  ["surveillance-domain", domain] as const;

export const surveillanceRssKey = (domain: string) =>
  ["surveillance-rss", domain] as const;

export const surveillanceBrand24Key = (domain: string) =>
  ["surveillance-brand24", domain] as const;

/**
 * Consulta /api/surveillance/domain?domain=X y retorna datos reales de
 * Shodan + MISP. Solo se activa cuando `domain` no es vacío.
 *
 * Nota: CTI Cloud & Olé se desconectó de este endpoint (modo manual) y se
 * invoca vía `POST /api/intel/cti/leaks/domain`. La sección `cti` del
 * response se mantiene como `{ configured: false }` por compatibilidad.
 */
export function useDigitalSurveillanceSnapshot(domain: string | null) {
  const key = domain?.trim() ?? "";
  return useQuery<SurveillanceDomainResult>({
    queryKey: surveillanceQueryKey(key || "__empty__"),
    queryFn: () => fetchSurveillanceDomain(key),
    enabled: key.length > 0,
    staleTime: 2 * 60 * 1000, // 2 min
    retry: 1,
  });
}

/** Formatea bytes en forma legible: 1234 → "1.2 KB" */
export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Busca archivos (CSV/PDF/JSON/ZIP) en las Fuentes de inteligencia (S3/MinIO)
 * que coincidan con los patrones del dominio consultado.
 * `patterns` es un array de globs, ej: ["itti*", "itti.com.py"]
 * `enabled` controla cuándo se dispara la query (por defecto al montar).
 */
export function useIntelFiles(domain: string, patterns: string[], enabled = true) {
  const key = domain.trim();
  const patStr = patterns.join(",");
  return useQuery<IntelFilesResult>({
    queryKey: ["surveillance-intel-files", key, patStr],
    queryFn: async () => {
      const params = new URLSearchParams({ domain: key, patterns: patStr });
      const res = await authFetch(`/api/surveillance/intel-files?${params.toString()}`);
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error ?? `HTTP ${res.status}`);
      }
      return res.json();
    },
    enabled: enabled && key.length > 0 && patterns.length > 0,
    staleTime: 5 * 60 * 1000, // 5 min
    retry: 1,
  });
}

/**
 * Consulta /api/surveillance/rss?domain=X.
 * Se activa solo cuando `domain` no es vacío. Cache 30 min en servidor.
 */
export function useDigitalSurveillanceRss(domain: string | null) {
  const key = domain?.trim() ?? "";
  return useQuery<SurveillanceRssResult>({
    queryKey: surveillanceRssKey(key || "__empty__"),
    queryFn: () => fetchSurveillanceRss(key),
    enabled: key.length > 0,
    staleTime: 30 * 60 * 1000, // 30 min (el servidor cachea también)
    retry: 1,
  });
}

/**
 * Consulta /api/surveillance/brand24?domain=X. El backend cachea 30 min y
 * cae a snapshots PDF cuando no hay proyecto live. Si el dominio no tiene
 * proyecto Brand24, `data.projectId` será `null` y `data.summary` también.
 */
export function useDigitalSurveillanceBrand24(domain: string | null) {
  const key = domain?.trim() ?? "";
  return useQuery<SurveillanceBrand24Result>({
    queryKey: surveillanceBrand24Key(key || "__empty__"),
    queryFn:  () => fetchSurveillanceBrand24(key),
    enabled:  key.length > 0,
    staleTime: 30 * 60 * 1000,
    retry: 1,
  });
}
