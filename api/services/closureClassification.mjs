/**
 * services/closureClassification.mjs
 *
 * Audit 2026-05-26 (P2-9). Antes de este módulo había 3 lugares duplicando
 * la validación de `classification`:
 *   - workflowEngine.transitionCase  (validación + throw en el flujo backend)
 *   - routes/incidents.mjs PATCH /status (VALID_CLASS local)
 *   - frontend types.ts (CaseClassification literal)
 *
 * Acá vive la fuente única, y los dos call-sites del backend la consumen.
 * Las funciones son **puras**: sin pgQuery, sin io, sin side effects — se
 * pueden testear en node:test sin stubs.
 */

// Valores válidos para `classification` en incident_cases_pg.
//
// Manuales (el operador los elige en la UI):
//   TRUE_POSITIVE   — incidente real, contenido
//   FALSE_POSITIVE  — actividad legítima
//   DUPLICATE       — ya tratado en otro caso (ver dedup_key)
//   NO_ACTIONABLE   — sin acción requerida
//
// Sistema (no aparecen en UI, los aplica el backend en flujos auto-* o por
// backfill histórico):
//   AUTO_TP / AUTO_FP / AUTO_DUPLICATE  — auto-close + intel
//   AUTO_NO_ACTIONABLE                  — severity-too-low (backfill 061)
//   LEGACY_UNCLASSIFIED                 — cerrados pre-classification (backfill 061)
//
// `FALSO_POSITIVO` (es) está aceptado por compat con cuerpos antiguos del
// PATCH /status — pgUpsertCase lo normaliza a FALSE_POSITIVE al escribir.
export const VALID_CLASSIFICATIONS = new Set([
  "TRUE_POSITIVE",
  "FALSE_POSITIVE",
  "FALSO_POSITIVO",
  "DUPLICATE",
  "NO_ACTIONABLE",
  "AUTO_TP",
  "AUTO_FP",
  "AUTO_DUPLICATE",
  "AUTO_NO_ACTIONABLE",
  "LEGACY_UNCLASSIFIED",
]);

// Valores que un humano puede elegir desde la UI. Se devuelven en el
// payload del 400 para que el frontend pueda renderizarlos sin hardcodearlos.
export const MANUAL_CLOSURE_CHOICES = [
  "TRUE_POSITIVE",
  "FALSE_POSITIVE",
  "DUPLICATE",
  "NO_ACTIONABLE",
];

// Statuses que disparan el requirement de classification.
const CLOSURE_STATUSES = new Set(["CERRADO", "FALSO_POSITIVO"]);

/**
 * Normaliza el alias ES → EN para almacenamiento canónico. No toca AUTO_*
 * ni LEGACY_*. Idempotente.
 */
export function normalizeClassification(value) {
  if (value == null) return value;
  const s = String(value).toUpperCase();
  return s === "FALSO_POSITIVO" ? "FALSE_POSITIVE" : s;
}

/**
 * Decide la classification a escribir para una transición de estado.
 * Pura: nunca toca DB, nunca lanza efectos.
 *
 * Reglas:
 *   - Si toStatus no es de cierre (CERRADO/FALSO_POSITIVO) → null (no escribir).
 *   - Si roleId === "SYSTEM" → respeta `classification` si viene (con
 *     normalización), si no → null (auto-close legacy puede no pasarla).
 *   - Si toStatus === "FALSO_POSITIVO" y no llega classification → default
 *     FALSE_POSITIVE.
 *   - Si llega `currentClassification` y no llega nueva → reusa la actual
 *     (preserva el outcome ya seteado en transiciones encadenadas).
 *   - Si no hay manera de derivarla → 400 "required".
 *   - Si llega y no está en VALID_CLASSIFICATIONS → 400 "invalid".
 *
 * @returns {{ok: true, value: string | null} | {ok: false, code: "required" | "invalid", message: string, hint?: object}}
 */
export function decideClosureClassification({ toStatus, classification, currentClassification, roleId }) {
  // No-closure: nunca requiere classification.
  if (!CLOSURE_STATUSES.has(toStatus)) {
    return { ok: true, value: null };
  }

  const incoming = classification != null ? normalizeClassification(classification) : null;
  const current  = currentClassification != null ? normalizeClassification(currentClassification) : null;

  // SYSTEM (auto-close, backfill jobs): tolerante — si no viene, dejá lo que
  // hay; si viene, validá igual.
  if (roleId === "SYSTEM") {
    if (incoming == null) return { ok: true, value: null };
    if (!VALID_CLASSIFICATIONS.has(incoming)) {
      return {
        ok: false, code: "invalid",
        message: `Classification '${incoming}' inválida (SYSTEM).`,
        hint: { allowed: [...VALID_CLASSIFICATIONS] },
      };
    }
    return { ok: true, value: incoming };
  }

  // Humano cerrando: derivar el valor final.
  let finalClass = incoming;
  if (finalClass == null && toStatus === "FALSO_POSITIVO") finalClass = "FALSE_POSITIVE";
  if (finalClass == null) finalClass = current;
  if (finalClass == null) {
    return {
      ok: false, code: "required",
      message: "Classification requerida al cerrar",
      hint: { allowed: MANUAL_CLOSURE_CHOICES, hintText: "Body { status, classification, reason }" },
    };
  }
  if (!VALID_CLASSIFICATIONS.has(finalClass)) {
    return {
      ok: false, code: "invalid",
      message: `Classification '${finalClass}' inválida`,
      hint: { allowed: MANUAL_CLOSURE_CHOICES },
    };
  }
  return { ok: true, value: finalClass };
}

/**
 * Helper: ¿el valor implica false_positive=true? Usado por el UPDATE de
 * incident_cases_pg para mantener el flag legacy `is_false_positive` en
 * sync con la classification.
 */
export function isFalsePositiveClassification(value) {
  if (value == null) return false;
  const v = normalizeClassification(value);
  return v === "FALSE_POSITIVE" || v === "AUTO_FP";
}
