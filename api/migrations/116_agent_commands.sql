-- 116_agent_commands.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Feature "Collector — acciones remotas" (PROTOTIPO, Opción A: cola por polling).
-- La consola encola una acción para un host (inventory_hosts) y el agente la
-- reclama en su check-in vía GET /api/inventory/commands (Bearer agent-jwt),
-- la ejecuta SOLO si está en el allowlist y reporta el resultado vía
-- POST /api/inventory/commands/:id/result.
--
-- Modelo SALIENTE intacto: el agente NO abre puertos; sólo pregunta por trabajo.
-- Allowlist CERRADO (sin shell/RCE arbitrario), reforzado por CHECK + servicio + agente.
-- Destructivas (reboot/shutdown) requieren confirm en la ruta + flag en el agente.
--
-- Gating: el canal completo está detrás de COLLECTOR_COMMANDS_ENABLED=1 (server).
--
-- NO auto-aplicada. Aplicar manualmente:
--   docker exec -i postgres psql -U huntdb -d huntdb < migrations/116_agent_commands.sql
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS agent_commands (
  id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  host_id          UUID         NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
  action           TEXT         NOT NULL,
  params           JSONB        NOT NULL DEFAULT '{}',
  status           TEXT         NOT NULL DEFAULT 'pending',
  requested_by     TEXT,                                   -- operador OIDC (sub/email)
  requested_reason TEXT,                                   -- obligatorio para destructivas
  result           JSONB,                                  -- { output, error, ... } del agente
  exit_code        INTEGER,
  created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
  delivered_at     TIMESTAMPTZ,                            -- cuándo lo reclamó el agente
  completed_at     TIMESTAMPTZ,                            -- cuándo reportó resultado
  expires_at       TIMESTAMPTZ  NOT NULL DEFAULT (now() + interval '1 hour'),
  -- Allowlist CERRADO de acciones (espejo del dispatcher del agente).
  CONSTRAINT agent_commands_action_chk CHECK (
    action IN ('collect_now', 'ping', 'fetch_logs', 'reboot', 'shutdown')
  ),
  CONSTRAINT agent_commands_status_chk CHECK (
    status IN ('pending', 'delivered', 'done', 'error', 'expired', 'canceled')
  )
);

-- Poll del agente: pendientes por host (índice parcial para el caso caliente).
CREATE INDEX IF NOT EXISTS idx_agent_cmds_host_pending
  ON agent_commands (host_id, created_at)
  WHERE status = 'pending';

-- Listado del dashboard: historial reciente por host.
CREATE INDEX IF NOT EXISTS idx_agent_cmds_host_recent
  ON agent_commands (host_id, created_at DESC);
