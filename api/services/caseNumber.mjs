/**
 * caseNumber — formateo/parseo del número de caso corto y legible.
 *
 * El caso tiene dos identificadores:
 *   - `id` (UUID/hex): PK técnica, usada en joins, FKs, lakehouse y APIs internas.
 *   - `case_number` (BIGINT secuencial): identificador corto para humanos, asignado
 *     solo a casos no-LOW o adoptados (ver migración 091_case_number.sql).
 *
 * Formato de display: `INC-000123` (prefijo + 6 dígitos con padding; crece a 7+
 * dígitos sin romper nada cuando se supere el millón).
 */

const PREFIX = "INC";
const PAD = 6;

/**
 * Formatea un número de caso a su código legible. Devuelve null si no hay número
 * (caso LOW sin adoptar → todavía no tiene código).
 * @param {number|string|null|undefined} n
 * @returns {string|null} p.ej. "INC-000123"
 */
export function formatCaseNumber(n) {
  if (n == null || n === "") return null;
  const num = Number(n);
  if (!Number.isFinite(num) || num <= 0) return null;
  return `${PREFIX}-${String(Math.trunc(num)).padStart(PAD, "0")}`;
}

/**
 * Extrae el número entero de una cadena de búsqueda: acepta "INC-000123",
 * "inc123", "#123" o "123". Devuelve null si no hay dígitos.
 * @param {string|number|null|undefined} s
 * @returns {number|null}
 */
export function parseCaseNumber(s) {
  if (s == null) return null;
  const digits = String(s).replace(/[^0-9]/g, "");
  if (!digits) return null;
  const n = parseInt(digits, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}
