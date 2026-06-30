/**
 * operator-ci.ts — Single source of truth para el CI del operador SOC.
 *
 * Centraliza clave de storage, carga, guardado y validación para evitar
 * la dispersión de sessionStorage/localStorage en múltiples componentes.
 */

export const OPERATOR_CI_KEY   = "lh_operator_ci";
export const OPERATOR_NAME_KEY = "lh_operator_name";

const MIN_CI_LEN = 5;

/** Lee el CI del operador desde localStorage. Devuelve "" si no existe. */
export function loadOperatorCi(): string {
  try { return localStorage.getItem(OPERATOR_CI_KEY) ?? ""; }
  catch { return ""; }
}

/** Persiste el CI en localStorage (trimmed). No-op si localStorage no está disponible. */
export function saveOperatorCi(ci: string): void {
  try { localStorage.setItem(OPERATOR_CI_KEY, ci.trim()); }
  catch { /* ignore */ }
}

/** Lee el nombre del operador desde localStorage. */
export function loadOperatorName(): string {
  try { return localStorage.getItem(OPERATOR_NAME_KEY) ?? ""; }
  catch { return ""; }
}

/**
 * Valida el CI del operador.
 * @returns Mensaje de error si inválido, null si válido.
 */
export function validateCi(ci: string): string | null {
  if (ci.trim().length < MIN_CI_LEN)
    return `El CI debe tener al menos ${MIN_CI_LEN} caracteres.`;
  return null;
}
