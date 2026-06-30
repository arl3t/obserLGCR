-- 113_case_playbooks.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Playbooks generados por el analista LLM a partir del contexto del caso.
--
-- Objetivo (junio 2026):
--   · Persistir cada playbook generado para un caso → base de conocimiento.
--   · Antes de generar uno NUEVO, consultar por context_key; si ya existe uno
--     reutilizable, se reenvía el existente (sin re-llamar al LLM).
--   · Cada playbook se publica además como artículo kb_articles (categoría
--     "Playbooks") para que quede buscable en el portal y la KB interna.
--
-- También:
--   · ticket_messages.playbook_html — adjunto playbook (HTML) en un mensaje, en
--     paralelo a report_html. El cliente lo abre en el modal del portal.
--   · tickets.soc_last_read_at — marca de lectura del SOC para resaltar/titilar
--     en el dashboard del analista los mensajes nuevos del cliente sin leer.
--
-- NO auto-aplicada (ver memoria pg_migrations_manual). Aplicar manualmente:
--   docker exec -i postgres psql -U huntdb -d huntdb < migrations/113_case_playbooks.sql
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS case_playbooks (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         UUID,                              -- caso que originó el playbook (sin FK: incident_cases_pg puede vivir en Iceberg)
  kb_article_id   UUID REFERENCES kb_articles(id) ON DELETE SET NULL,  -- copia publicada en la KB
  context_key     TEXT NOT NULL,                     -- clave de matching: tactic|source|sev_bucket
  title           TEXT NOT NULL,
  body_md         TEXT NOT NULL,                     -- fuente markdown
  body_html       TEXT NOT NULL,                     -- render seguro escape-first (lo que se adjunta/lee)
  mitre_tactic_id VARCHAR(16),
  source_log      VARCHAR(64),
  severity_text   VARCHAR(16),
  severity_score  INT,
  generated_by    VARCHAR(8) NOT NULL DEFAULT 'rule' CHECK (generated_by IN ('llm','rule')),
  model           TEXT,                              -- modelo LLM usado (NULL si rule-based)
  created_by      VARCHAR(64),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_case_playbooks_context ON case_playbooks(context_key, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_case_playbooks_case    ON case_playbooks(case_id);

-- Adjunto playbook en un mensaje del hilo (espejo de report_html).
ALTER TABLE ticket_messages ADD COLUMN IF NOT EXISTS playbook_html TEXT;

-- Lectura del SOC (para "no leídos" del analista). NULL = nunca leído.
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS soc_last_read_at TIMESTAMPTZ;
