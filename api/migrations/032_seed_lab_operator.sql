-- =============================================================================
-- 032 — Seed del operador lab (OIDC_ENABLED=false)
--
-- En modo lab el middleware de auth puebla req.user con sub="lab-user".
-- resolveOperatorContextPg resuelve por soc_operators.kc_user_id, así que
-- sembramos una fila con ese mismo valor para que el chat y el resto del
-- flujo SOC funcionen sin Keycloak.
--
-- Rol ADMIN: lab necesita todos los caps (can_review_kpis para intents
-- sensibles del chat, can_adopt/can_close_case para la Gestión de incidentes).
-- En producción (OIDC on) esta fila no afecta — el sub real del JWT no
-- coincide con "lab-user".
--
-- Idempotente: ON CONFLICT DO UPDATE mantiene los campos consistentes si la
-- migración se re-ejecuta.
-- =============================================================================

INSERT INTO soc_operators (id, name, email, role_id, is_active, kc_user_id)
VALUES ('lab-user', 'Lab User (OIDC off)', NULL, 'ADMIN', true, 'lab-user')
ON CONFLICT (id) DO UPDATE SET
  name       = EXCLUDED.name,
  role_id    = EXCLUDED.role_id,
  is_active  = EXCLUDED.is_active,
  kc_user_id = EXCLUDED.kc_user_id;
