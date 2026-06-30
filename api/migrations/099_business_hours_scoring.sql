-- 099_business_hours_scoring.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Factor de FRANJA HORARIA en el scoring de apertura de casos.
--
-- Contexto: una detección FUERA del horario laboral tradicional de Paraguay es
-- más sospechosa (nadie debería estar operando los activos a las 3 AM del
-- domingo). No vuelve maliciosa la detección — AMPLIFICA la sospecha de algo ya
-- puntuado, igual que geo_mult / novelty_mult. Por eso es un MULTIPLICADOR
-- (≥ 1.0, "solo amplifica", nunca penaliza el horario laboral).
--
-- Horario laboral tradicional PY:  L–V 05:00–18:00,  Sáb 05:00–14:00.
-- Todo lo demás = fuera de horario (con sub-tramo "noche profunda" 22:00–05:00 y
-- domingos/feriados con el multiplicador más alto).
--
-- IMPORTANTE — zona horaria: usar SIEMPRE la zona IANA `America/Asuncion`, NUNCA
-- un offset fijo. Paraguay ABOLIÓ el horario de verano en 2024 y quedó fijo en
-- UTC-3 todo el año; la base tz codifica tanto el histórico (cambios DST) como la
-- regla actual. Los timestamps del lake/PG están en UTC → convertir a hora local
-- antes de extraer hora/día de la semana.
--
-- Estas tablas son la FUENTE de:
--   1. El path Node real-time  (services/scoringBonus.mjs::calcOffHoursMultiplier)
--   2. El calendario del Centro de Mando (GET /api/calendar/py-holidays)
-- El path SQL (v_incident_score_v4) replica el MISMO horario inline porque Trino
-- no puede consultar PG — mantener en sync (igual que soc_thresholds ↔ vista v4).
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Config de horario laboral + multiplicadores (singleton id=1) ─────────────
CREATE TABLE IF NOT EXISTS business_hours_config (
  id                smallint     PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  timezone          text         NOT NULL DEFAULT 'America/Asuncion',
  -- Horario laboral (hora local, 0–23). Fin EXCLUSIVO.
  weekday_start     smallint     NOT NULL DEFAULT 5  CHECK (weekday_start  BETWEEN 0 AND 23),
  weekday_end       smallint     NOT NULL DEFAULT 18 CHECK (weekday_end    BETWEEN 1 AND 24),
  saturday_start    smallint     NOT NULL DEFAULT 5  CHECK (saturday_start BETWEEN 0 AND 23),
  saturday_end      smallint     NOT NULL DEFAULT 14 CHECK (saturday_end   BETWEEN 1 AND 24),
  -- Ventana "noche profunda" (cruza medianoche): [deep_night_start, 24) ∪ [0, deep_night_end)
  deep_night_start  smallint     NOT NULL DEFAULT 22 CHECK (deep_night_start BETWEEN 0 AND 23),
  deep_night_end    smallint     NOT NULL DEFAULT 5  CHECK (deep_night_end   BETWEEN 0 AND 23),
  -- Multiplicadores (≥ 1.0 — solo amplifican).
  mult_business     numeric(4,2) NOT NULL DEFAULT 1.00 CHECK (mult_business >= 1.0),
  mult_soft         numeric(4,2) NOT NULL DEFAULT 1.08 CHECK (mult_soft     >= 1.0),
  mult_deep         numeric(4,2) NOT NULL DEFAULT 1.15 CHECK (mult_deep      >= 1.0),
  -- Tope del multiplicador COMBINADO (geo × novelty × offhours) para que un
  -- borderline no explote (ej. 60 → 108). Aplicado en Node; documentado para SQL.
  combined_mult_cap numeric(4,2) NOT NULL DEFAULT 1.60 CHECK (combined_mult_cap >= 1.0),
  enabled           boolean      NOT NULL DEFAULT true,
  updated_at        timestamptz  NOT NULL DEFAULT now()
);

INSERT INTO business_hours_config (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;

-- ── Feriados nacionales de Paraguay ──────────────────────────────────────────
-- Un feriado se trata como off-hours profundo (como domingo): mult_deep.
-- Semana Santa (Jueves/Viernes Santo) es móvil → se siembra por año concreto.
CREATE TABLE IF NOT EXISTS py_holidays (
  holiday_date date        PRIMARY KEY,
  name         text        NOT NULL,
  is_movable   boolean     NOT NULL DEFAULT false,
  created_at   timestamptz NOT NULL DEFAULT now()
);

-- 2026 (Semana Santa: Pascua 05-abr → Jueves Santo 02-abr, Viernes Santo 03-abr)
INSERT INTO py_holidays (holiday_date, name, is_movable) VALUES
  (DATE '2026-01-01', 'Año Nuevo',                          false),
  (DATE '2026-03-01', 'Día de los Héroes',                  false),
  (DATE '2026-04-02', 'Jueves Santo',                       true),
  (DATE '2026-04-03', 'Viernes Santo',                      true),
  (DATE '2026-05-01', 'Día del Trabajador',                 false),
  (DATE '2026-05-14', 'Día de la Independencia Nacional',   false),
  (DATE '2026-05-15', 'Día de la Independencia / Día de la Madre', false),
  (DATE '2026-06-12', 'Paz del Chaco',                      false),
  (DATE '2026-08-15', 'Fundación de Asunción',              false),
  (DATE '2026-09-29', 'Victoria de Boquerón',               false),
  (DATE '2026-12-08', 'Día de la Virgen de Caacupé',        false),
  (DATE '2026-12-25', 'Navidad',                            false)
ON CONFLICT (holiday_date) DO NOTHING;

-- 2027 (Semana Santa: Pascua 28-mar → Jueves Santo 25-mar, Viernes Santo 26-mar)
INSERT INTO py_holidays (holiday_date, name, is_movable) VALUES
  (DATE '2027-01-01', 'Año Nuevo',                          false),
  (DATE '2027-03-01', 'Día de los Héroes',                  false),
  (DATE '2027-03-25', 'Jueves Santo',                       true),
  (DATE '2027-03-26', 'Viernes Santo',                      true),
  (DATE '2027-05-01', 'Día del Trabajador',                 false),
  (DATE '2027-05-14', 'Día de la Independencia Nacional',   false),
  (DATE '2027-05-15', 'Día de la Independencia / Día de la Madre', false),
  (DATE '2027-06-12', 'Paz del Chaco',                      false),
  (DATE '2027-08-15', 'Fundación de Asunción',              false),
  (DATE '2027-09-29', 'Victoria de Boquerón',               false),
  (DATE '2027-12-08', 'Día de la Virgen de Caacupé',        false),
  (DATE '2027-12-25', 'Navidad',                            false)
ON CONFLICT (holiday_date) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_py_holidays_date ON py_holidays (holiday_date);
