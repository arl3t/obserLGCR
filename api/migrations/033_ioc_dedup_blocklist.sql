-- =============================================================================
-- 033 — Blocklist de IOCs genéricos para la detección de duplicados
--
-- Problema: `GET /api/incidents/duplicates` agrupa casos abiertos por
-- `ioc_value` y devuelve todos los que aparezcan >1 vez. IPs genéricas como
-- 8.8.8.8, 127.0.0.1 o rangos RFC1918 terminan generando "grupos de
-- duplicados" de 50+ casos sin relación real entre sí, lo que infla la tabla
-- del DuplicatePanel y empuja a merges que en la práctica fusionarían casos
-- legítimamente independientes.
--
-- Esta tabla permite al operador / Leader mantener en caliente una lista
-- (sin redeploys) de patrones a excluir del agrupamiento por duplicados.
-- Dos formatos soportados:
--   · kind='exact'  → igualdad estricta sobre ioc_value.
--   · kind='prefix' → match por LIKE '<pattern>%'  (útil para RFC1918: 10.%, 172.1_.%, 192.168.%).
--
-- El endpoint /duplicates hace anti-JOIN con esta tabla. Las supresiones
-- (case_suppressions) siguen existiendo para bloquear APERTURA; esta tabla
-- sólo afecta la detección de duplicados DESPUÉS de que los casos ya están
-- abiertos.
--
-- Idempotente: CREATE … IF NOT EXISTS + ON CONFLICT DO NOTHING en seed.
-- =============================================================================

CREATE TABLE IF NOT EXISTS ioc_dedup_blocklist (
  pattern     VARCHAR(256) PRIMARY KEY,
  kind        VARCHAR(8)   NOT NULL CHECK (kind IN ('exact', 'prefix')),
  reason      TEXT,
  added_by    VARCHAR(64),
  added_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE  ioc_dedup_blocklist IS 'Patrones de ioc_value excluidos del agrupamiento en /api/incidents/duplicates.';
COMMENT ON COLUMN ioc_dedup_blocklist.kind IS 'exact = igualdad estricta; prefix = LIKE <pattern>%';

-- Seed con genéricos bien conocidos. `added_by=system` permite al operador
-- distinguir los seeds de los agregados manualmente.
INSERT INTO ioc_dedup_blocklist (pattern, kind, reason, added_by) VALUES
  -- DNS públicos / broadcasters
  ('8.8.8.8',   'exact',  'Google Public DNS',            'system'),
  ('8.8.4.4',   'exact',  'Google Public DNS',            'system'),
  ('1.1.1.1',   'exact',  'Cloudflare Public DNS',        'system'),
  ('1.0.0.1',   'exact',  'Cloudflare Public DNS',        'system'),
  ('9.9.9.9',   'exact',  'Quad9 Public DNS',             'system'),
  ('149.112.112.112', 'exact', 'Quad9 Public DNS',        'system'),
  -- loopback y comodines
  ('0.0.0.0',   'exact',  'Unspecified',                  'system'),
  ('127.0.0.1', 'exact',  'IPv4 loopback',                'system'),
  ('::1',       'exact',  'IPv6 loopback',                'system'),
  ('255.255.255.255', 'exact', 'IPv4 broadcast',          'system'),
  ('localhost', 'exact',  'DNS loopback',                 'system'),
  -- RFC1918 — rangos privados, casi nunca representan un atacante externo
  ('10.',       'prefix', 'RFC1918 10.0.0.0/8',           'system'),
  ('192.168.',  'prefix', 'RFC1918 192.168.0.0/16',       'system'),
  ('127.',      'prefix', 'Loopback 127.0.0.0/8',         'system'),
  ('172.16.',   'prefix', 'RFC1918 172.16.0.0/12',        'system'),
  ('172.17.',   'prefix', 'RFC1918 172.17.0.0/12',        'system'),
  ('172.18.',   'prefix', 'RFC1918 172.18.0.0/12',        'system'),
  ('172.19.',   'prefix', 'RFC1918 172.19.0.0/12',        'system'),
  ('172.2',     'prefix', 'RFC1918 172.20-29.x.x',        'system'),
  ('172.30.',   'prefix', 'RFC1918 172.30.0.0/12',        'system'),
  ('172.31.',   'prefix', 'RFC1918 172.31.0.0/12',        'system'),
  -- Link-local IPv4
  ('169.254.',  'prefix', 'Link-local 169.254.0.0/16',    'system')
ON CONFLICT (pattern) DO NOTHING;
