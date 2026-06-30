-- 109_kb_articles.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Base de Conocimiento (autoservicio) del portal de soporte — funcionalidad #20.
-- Artículos/FAQ que el cliente lee para resolver dudas comunes SIN abrir ticket.
-- Curados por el SOC; el cliente sólo ve los PUBLICADOS. org_id NULL = global
-- (compartido por todos los clientes); preparado para artículos por-cliente a futuro.
-- Ver docs/PROPUESTA-TICKETING-PUBLICO.md §7 (#20).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS kb_articles (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      UUID REFERENCES organizations(id) ON DELETE CASCADE,  -- NULL = global
  slug        VARCHAR(160) NOT NULL UNIQUE,
  title       TEXT NOT NULL,
  category    VARCHAR(80) NOT NULL DEFAULT 'General',
  excerpt     TEXT,                 -- resumen corto para listados/búsqueda
  body_md     TEXT NOT NULL,        -- fuente markdown (la edita el operador)
  body_html   TEXT NOT NULL,        -- render seguro escape-first (lo que ve el cliente)
  tags        JSONB NOT NULL DEFAULT '[]'::jsonb,
  status      VARCHAR(12) NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','PUBLISHED')),
  view_count  INT NOT NULL DEFAULT 0,
  helpful_yes INT NOT NULL DEFAULT 0,
  helpful_no  INT NOT NULL DEFAULT 0,
  created_by  VARCHAR(64),
  updated_by  VARCHAR(64),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  published_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_kb_articles_status ON kb_articles(status);
CREATE INDEX IF NOT EXISTS idx_kb_articles_category ON kb_articles(category);
CREATE INDEX IF NOT EXISTS idx_kb_articles_org ON kb_articles(org_id);
-- Búsqueda simple por texto (título/resumen/cuerpo) — trigram para ILIKE rápido.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_kb_articles_title_trgm ON kb_articles USING gin (title gin_trgm_ops);
