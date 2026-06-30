-- 075_cve_cache_epss.sql — I1 audit 2026-06-05
--
-- Agrega EPSS (Exploit Prediction Scoring System, FIRST.org) al cache de CVEs.
-- EPSS estima la probabilidad de que un CVE sea explotado en los próximos 30
-- días — más accionable que CVSS para priorización (un CVSS 9.8 con EPSS 0.1%
-- es menos urgente que un CVSS 7.5 con EPSS 90%).
--
-- Idempotente: `services/nvdEnrichment.mjs::ensureCveCacheTable` aplica los
-- mismos ALTER al boot, esta migración cubre el deploy formal (las migrations
-- NO se auto-aplican — ver memoria pg_migrations_manual).
--
-- EPSS se recalcula a diario; el servicio refresca filas con epss_fetched_at
-- nulo o > 24h vía un request batch a https://api.first.org/data/v1/epss.

ALTER TABLE legacyhunt_soc.cve_cache ADD COLUMN IF NOT EXISTS epss_score      NUMERIC(8,6);
ALTER TABLE legacyhunt_soc.cve_cache ADD COLUMN IF NOT EXISTS epss_percentile NUMERIC(8,6);
ALTER TABLE legacyhunt_soc.cve_cache ADD COLUMN IF NOT EXISTS epss_fetched_at TIMESTAMPTZ;
