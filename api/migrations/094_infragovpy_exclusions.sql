-- =============================================================================
-- 094 — Exclusiones (allowlist) del feed outbound lgcrBL (ex-InfraGOVPY)
--
-- Lista de IPs/rangos que NUNCA deben publicarse en el feed saliente aunque el
-- scoring las marque como maliciosas: infra propia, egress NAT corporativo, IPs
-- de partners/CERT, scanners contratados o falsos positivos crónicos.
--
-- A diferencia de manualRemove (que solo pone expires_at=NOW() y el sync de
-- 10 min vuelve a insertar la IP si sigue puntuando alto), una exclusión es
-- persistente y se respeta en: (1) el sync auto desde incident_cases,
-- (2) la lectura/export/submit (defensa en profundidad) y (3) la inclusión
-- manual / force-include (las rechaza).
--
-- Formatos: kind='exact' (IPv4 estricta) y kind='cidr' (rango IPv4, p.ej.
-- 200.1.2.0/24 — match vía services/netClass.ipv4InCidr). expires_at NULL =
-- permanente. Espejo del diseño de ioc_dedup_blocklist (mig 033).
--
-- NOTA: el servicio infragovpyWatchlistService.ensureExclusionsTable() crea esta
-- tabla de forma idempotente al arrancar la API; esta migración existe para
-- repetibilidad y para entornos donde se apliquen las migraciones a mano.
--
-- Idempotente: CREATE … IF NOT EXISTS.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS legacyhunt_soc;

CREATE TABLE IF NOT EXISTS legacyhunt_soc.infragovpy_exclusions (
    id          BIGSERIAL    PRIMARY KEY,
    pattern     VARCHAR(64)  NOT NULL,
    kind        VARCHAR(8)   NOT NULL DEFAULT 'exact' CHECK (kind IN ('exact','cidr')),
    reason      TEXT,
    added_by    VARCHAR(64),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    CONSTRAINT uq_infragovpy_excl_pattern UNIQUE (pattern)
);

CREATE INDEX IF NOT EXISTS idx_infragovpy_excl_expires
    ON legacyhunt_soc.infragovpy_exclusions (expires_at);
