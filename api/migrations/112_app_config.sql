-- 112_app_config.sql
-- Ajustes 2026-06-28: hacer EDITABLE desde la UI (ADMIN) toda la configuración
-- que hoy vive sólo en el .env (process.env), sin reiniciar el contenedor para
-- las variables que la API resuelve en runtime (applyMode "live": lgcrBL, Slack,
-- SMTP, etc.). Complementa a integration_credentials (que sigue cubriendo las
-- API keys threat-intel del catálogo de apiKeysService).
--
-- Seguridad:
--   · value_enc guarda SIEMPRE el valor CIFRADO (AES-256-GCM, services/secretCrypto.mjs)
--     con master key SETTINGS_ENC_KEY del .env — una sola ruta de I/O, incluso para
--     valores no-secretos. is_secret controla SOLO el enmascarado de la respuesta.
--   · El endpoint GET nunca devuelve secretos en claro (sólo máscara últimos 4);
--     los no-secretos sí se devuelven en claro para edición cómoda.
--   · section/applyMode NO viven en DB: están en el catálogo declarativo en código
--     (services/appConfigCatalog.mjs), fuente de verdad versionada.
--   · El servicio resuelve DB → fallback .env → default. Borrar una fila revierte al .env.
--   · SETTINGS_ENC_KEY se EXCLUYE del catálogo (es el bootstrap del cifrado).
--
-- NO auto-aplicada (ver memoria pg_migrations_manual). Aplicar manualmente.

CREATE TABLE IF NOT EXISTS legacyhunt_soc.app_config (
  key_name    VARCHAR(96)  PRIMARY KEY,        -- nombre canónico de env (p.ej. LGCRBL_GIT_TOKEN)
  value_enc   TEXT         NOT NULL,           -- AES-256-GCM: base64(iv).base64(tag).base64(ct)
  is_secret   BOOLEAN      NOT NULL DEFAULT true,  -- sólo afecta el masking de la respuesta
  updated_by  VARCHAR(128),                    -- operador (ci/sub) que lo seteó
  updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE legacyhunt_soc.app_config IS
  'Config del .env editable desde Ajustes (ADMIN), cifrada (AES-256-GCM). Resuelve DB→env en appConfigService. section/applyMode en el catálogo de código.';
