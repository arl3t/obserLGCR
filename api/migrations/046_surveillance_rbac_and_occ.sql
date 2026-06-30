-- =============================================================================
-- 046 — RBAC para watchlist + OCC para anotaciones (#9).
--
-- 1. surveillance_watchlist_subs.visibility (private|shared|global)
--    - private: solo el owner_ci puede ver/editar
--    - shared:  cualquier hunter+ puede ver/editar
--    - global:  cualquier autenticado puede ver; solo manager+ edita
--
-- 2. surveillance_finding_annotations.version (Optimistic Concurrency Control)
--    Cada update bumpea +1. El cliente envía expectedVersion en upsert; si
--    no coincide → 412 Precondition Failed para evitar pisar ediciones de
--    otros analistas multi-operador.
--
-- Idempotente.
-- =============================================================================

-- ── 1. RBAC visibility en watchlist subs ────────────────────────────────────
ALTER TABLE surveillance_watchlist_subs
  ADD COLUMN IF NOT EXISTS visibility VARCHAR(8)
  NOT NULL DEFAULT 'shared'
  CHECK (visibility IN ('private', 'shared', 'global'));

COMMENT ON COLUMN surveillance_watchlist_subs.visibility IS
  'Política de acceso: private (solo owner_ci), shared (hunter+), '
  'global (todos ven, solo manager+ edita). Default shared.';

-- ── 2. Version para OCC en anotaciones ──────────────────────────────────────
ALTER TABLE surveillance_finding_annotations
  ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;

COMMENT ON COLUMN surveillance_finding_annotations.version IS
  'Optimistic concurrency token. Cada UPDATE bumpea +1; el cliente envía '
  'expectedVersion en upsert y la API devuelve 412 si no matchea (evita '
  'que dos analistas pisen ediciones concurrentes).';
