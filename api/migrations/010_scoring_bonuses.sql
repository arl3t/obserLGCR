-- =============================================================================
-- 010_scoring_bonuses.sql
-- Mejoras al motor de scoring:
--   · asset_registry       — criticidad de activos por sensorKey
--   · geo_risk_config      — multiplicador de riesgo por país (override de operador)
--   · scoring_bonus_log    — log auditable de bonos aplicados por caso
-- =============================================================================

-- ── Asset Registry ────────────────────────────────────────────────────────────
-- Cada fila representa un activo conocido. El campo sensor_key debe coincidir
-- con SocCase.sensorKey (IP del agente Wazuh, nombre de dispositivo Fortigate/OPNsense).
-- La criticidad (tier1/tier2/tier3) se usa en el scoring de IPs RFC1918.

CREATE TABLE IF NOT EXISTS asset_registry (
  id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Clave de búsqueda: IP, hostname normalizado, nombre de dispositivo
  sensor_key    TEXT         NOT NULL UNIQUE,
  hostname      TEXT,
  ip_address    INET,
  asset_type    TEXT         NOT NULL DEFAULT 'workstation',
    -- server | workstation | network-device | iot | critical-infra | cloud-instance
  criticality   TEXT         NOT NULL DEFAULT 'tier3'
    CHECK (criticality IN ('tier1', 'tier2', 'tier3')),
    -- tier1: DC, infra crítica (AD, firewall, backup) → 20 pts
    -- tier2: servidores de aplicación, DB                → 13 pts
    -- tier3: estaciones de trabajo, devices               →  6 pts
  business_unit TEXT,
  owner         TEXT,
  location      TEXT,        -- rack, VLAN, zona, datacenter
  os_platform   TEXT,        -- Windows, Linux, FortiOS, etc.
  tags          JSONB        NOT NULL DEFAULT '[]',
    -- p.ej. ["prod","exposed","pci-scope"]
  description   TEXT,
  is_active     BOOLEAN      NOT NULL DEFAULT true,
  created_by    TEXT         NOT NULL DEFAULT 'system',
  updated_by    TEXT,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asset_registry_ip
  ON asset_registry(ip_address);

CREATE INDEX IF NOT EXISTS idx_asset_registry_criticality
  ON asset_registry(criticality) WHERE is_active = true;

-- Activos de ejemplo — reemplazar con inventario real
INSERT INTO asset_registry
  (sensor_key, hostname, asset_type, criticality, business_unit, description)
VALUES
  ('dc01.local',     'DC01',  'server',         'tier1', 'IT-Infra',  'Controlador de Dominio Primario'),
  ('backup01.local', 'BKP01', 'server',         'tier1', 'IT-Infra',  'Servidor de backup crítico'),
  ('fw-opnsense',    'OPNsense', 'network-device', 'tier1', 'Network', 'Firewall perimetral OPNsense'),
  ('fw-fortigate',   'Fortigate', 'network-device','tier1', 'Network', 'UTM Fortigate perimetral')
ON CONFLICT (sensor_key) DO NOTHING;

-- ── Geo-Risk Config ───────────────────────────────────────────────────────────
-- Permite a los operadores sobreescribir o agregar países al multiplicador de riesgo.
-- El servicio usa primero esta tabla; si no hay override, usa la lista hardcoded.

CREATE TABLE IF NOT EXISTS geo_risk_config (
  id             SERIAL       PRIMARY KEY,
  country_code   CHAR(2)      NOT NULL UNIQUE,  -- ISO 3166-1 alpha-2
  country_name   TEXT         NOT NULL,
  risk_tier      TEXT         NOT NULL DEFAULT 'elevated'
    CHECK (risk_tier IN ('high', 'elevated', 'standard', 'low')),
    -- high:     ×1.25 (OFAC sanctioned, known APT origin)
    -- elevated: ×1.10 (high cybercrime rate, threat intel feeds)
    -- standard: ×1.00 (base)
    -- low:      ×0.95 (trusted / low threat intel activity)
  reason         TEXT,        -- justificación (fuente: CISA, OFAC, threat intel)
  added_by       TEXT         NOT NULL DEFAULT 'system',
  updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Países de alto riesgo por defecto (OFAC + principales fuentes APT)
INSERT INTO geo_risk_config (country_code, country_name, risk_tier, reason) VALUES
  ('KP', 'Corea del Norte',  'high',     'OFAC sancionado; Lazarus Group, APT38'),
  ('IR', 'Irán',             'high',     'OFAC sancionado; APT33, APT34, APT35'),
  ('RU', 'Rusia',            'high',     'APT28, APT29, Sandworm; CISA advisories'),
  ('CN', 'China',            'high',     'APT10, APT41, Volt Typhoon; CISA advisories'),
  ('SY', 'Siria',            'high',     'OFAC sancionado; SilverTerrier activity'),
  ('CU', 'Cuba',             'high',     'OFAC sancionado'),
  ('BY', 'Bielorrusia',      'high',     'APT activity aligned con RU; CISA advisories'),
  ('NG', 'Nigeria',          'elevated', 'Alta actividad BEC y phishing (FBI IC3)'),
  ('RO', 'Rumanía',          'elevated', 'Alta actividad ransomware y carding'),
  ('BR', 'Brasil',           'elevated', 'Trojanizadores bancarios, RATs regionales'),
  ('PK', 'Pakistán',         'elevated', 'APT36, phishing gubernamental'),
  ('VN', 'Vietnam',          'elevated', 'APT32 (OceanLotus); phishing industrial'),
  ('UA', 'Ucrania',          'elevated', 'Malware development, bullet-proof hosting'),
  ('IN', 'India',            'elevated', 'Call-center fraud, tech support scams'),
  ('ID', 'Indonesia',        'elevated', 'Skimming, defacement, DDoS for hire')
ON CONFLICT (country_code) DO NOTHING;

-- ── Scoring Bonus Log ─────────────────────────────────────────────────────────
-- Registro auditable de bonos adicionales aplicados a cada caso.
-- Permite trazabilidad completa de por qué un caso tuvo cierto score.

CREATE TABLE IF NOT EXISTS scoring_bonus_log (
  id            BIGSERIAL    PRIMARY KEY,
  case_id       TEXT         NOT NULL,  -- incident_cases.case_id
  bonus_type    TEXT         NOT NULL,
    -- kill_chain_depth | temporal_fresh | fp_penalty | geo_risk |
    -- asset_criticality | correlation_group | intra_a_bonus
  bonus_value   NUMERIC(6,2) NOT NULL,  -- pts añadidos (puede ser negativo: penalización)
  multiplier    NUMERIC(5,3),           -- si fue multiplicador en vez de suma
  detail        JSONB        NOT NULL DEFAULT '{}',
    -- datos que justifican el bono: {tactics: [], country: "RU", tier: "tier1", etc.}
  calculated_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sblog_case_id
  ON scoring_bonus_log(case_id);

CREATE INDEX IF NOT EXISTS idx_sblog_type
  ON scoring_bonus_log(bonus_type, calculated_at DESC);
