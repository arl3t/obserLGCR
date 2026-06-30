-- 119_platform_users.sql
-- Usuarios del dashboard obserLGCR (login email + password en PostgreSQL).

CREATE TABLE IF NOT EXISTS platform_users (
  id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT         NOT NULL UNIQUE,
  pass_hash     TEXT         NOT NULL,
  display_name  TEXT,
  role          TEXT         NOT NULL DEFAULT 'analyst'
                CHECK (role IN ('analyst', 'hunter', 'manager', 'admin')),
  enabled       BOOLEAN      NOT NULL DEFAULT true,
  last_login_at TIMESTAMPTZ,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_platform_users_email ON platform_users (lower(email));

-- Credenciales de laboratorio (cambiar en producción):
--   admin@obserlgcr.local     / changeme-admin
--   operator@obserlgcr.local  / changeme-operator
INSERT INTO platform_users (email, pass_hash, display_name, role)
VALUES
  (
    'admin@obserlgcr.local',
    'CM4p55tEmNwyY28CoN0gbA==.CzXebVQwV23hfJPm3epb89JZPNLgOVhhwToCs89/8oEQIQX/tbPaGfDX8L3BaGrJ5KhYI/UdyCtIvHY6zm2CJw==',
    'Administrador NOC',
    'admin'
  ),
  (
    'operator@obserlgcr.local',
    '3X1pODQrkIdtGi7d9Bbc/g==.yvgKsXwrLTTsjiYTPSY9r2n/QW7qOjDYGa+vT1RKSykyjjkrsak2pIm7V/oVX/1lLGrKyiKM4JSf0Z82WCNmvQ==',
    'Operador NOC',
    'analyst'
  )
ON CONFLICT (email) DO NOTHING;
