/**
 * feature-flags.ts — flags de funcionalidad del dashboard (VITE_* en build).
 */
function flag(v: unknown): boolean {
  return String(v ?? "").trim().toLowerCase() === "true";
}

/** Reservado para flags futuros. */
export const PLACEHOLDER_FLAGS = flag(import.meta.env.VITE_PLACEHOLDER);
