/**
 * services/transitionRbac.mjs — RBAC granular por transición de estado de caso.
 *
 * Aislado del controlador para permitir pruebas unitarias sin levantar
 * el resto del router (Trino, Postgres, Slack, etc).
 *
 * Auditado 2026-05-13 (R10/R13): el mapa target→capability vive aquí;
 * `routes/incidents.mjs` compone fetch de soc_operators×soc_roles con
 * `decideTransitionRbac` para resolver el permiso.
 */

/**
 * target_status → capability(ies) requerida(s).
 *   string  → exige exactamente ese cap
 *   array   → "any-of" (cualquiera concedido alcanza)
 * Si el target no está en el mapa, no exige cap extra (asume can_adopt,
 * ya chequeado al adoptar el caso).
 */
export const TRANSITION_CAP = {
  CONFIRMADO:     "can_close_case",
  FALSO_POSITIVO: "can_close_fp",
  CERRADO:        "can_close_case",
  ESCALADO:       ["can_escalate_to_l2", "can_escalate_to_l3"],
};

/**
 * Decisión RBAC pura.
 *
 * @param {null|undefined|{role_id?, is_active?, can_close_fp?, can_close_case?, can_escalate_to_l2?, can_escalate_to_l3?}} role
 *        Row de soc_operators LEFT JOIN soc_roles. `null`/`undefined` →
 *        operador legacy/no encontrado → permitir (fallback conservador).
 * @param {string} targetStatus  Estado de destino a transicionar.
 *
 * @returns {{ok: true} | {ok: false, status: number, body: object}}
 */
export function decideTransitionRbac(role, targetStatus) {
  const required = TRANSITION_CAP[targetStatus];
  if (!required) return { ok: true };
  if (!role)     return { ok: true };
  if (!role.is_active) {
    return { ok: false, status: 403, body: { error: "Operador inactivo." } };
  }
  const caps = Array.isArray(required) ? required : [required];
  const granted = caps.some((c) => role[c] === true);
  if (!granted) {
    return {
      ok: false,
      status: 403,
      body: {
        error: `Rol ${role.role_id} no tiene permiso para transicionar a ${targetStatus}.`,
        required_capability: caps.length === 1 ? caps[0] : caps,
        role: role.role_id,
        targetStatus,
      },
    };
  }
  return { ok: true };
}
