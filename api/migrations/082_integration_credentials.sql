-- 082_integration_credentials.sql
-- Ajustes 2026-06-07: gestión de API keys de fuentes de inteligencia desde la UI.
-- Las keys vivían sólo en .env (process.env) y exigían reiniciar el contenedor
-- para cambiarlas. Esta tabla las hace editables en runtime desde Ajustes (ADMIN).
--
-- Seguridad:
--   · value_enc guarda el secreto CIFRADO (AES-256-GCM, services/apiKeysService.mjs)
--     con master key SETTINGS_ENC_KEY del .env. NUNCA en texto plano.
--   · El endpoint GET sólo devuelve máscara (últimos 4) — jamás el valor completo.
--   · Sólo claves del catálogo threat-intel (apiKeysService CATALOG); no secretos
--     de infra (AWS/Trino/OIDC/VAPID).
--   · El servicio resuelve DB → fallback .env. Borrar una fila revierte al .env.
--
-- NO auto-aplicada (ver memoria pg_migrations_manual). Aplicar manualmente.

CREATE TABLE IF NOT EXISTS legacyhunt_soc.integration_credentials (
  key_name    VARCHAR(64)  PRIMARY KEY,         -- nombre canónico de env (p.ej. VT_API_KEY)
  value_enc   TEXT         NOT NULL,            -- AES-256-GCM: base64(iv).base64(tag).base64(ct)
  updated_by  VARCHAR(128),                     -- operador (ci/sub) que lo seteó
  updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE legacyhunt_soc.integration_credentials IS
  'API keys de fuentes de inteligencia, cifradas (AES-256-GCM). Editable desde Ajustes (ADMIN). Resuelve DB→env en apiKeysService.';
