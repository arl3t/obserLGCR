/**
 * infragovpyWatchlistService.mjs
 *
 * Mantenedor de la lista outbound InfraGOVPY con ventana deslizante de 7 días.
 *
 *   · ensureTable()          → DDL idempotente (tabla + índices + migración manual)
 *   · syncFromIncidentCases()→ scan 24h sobre incident_cases_pg, UPSERT
 *   · getActive(...)         → filas con expires_at > NOW()
 *   · getKpis()              → contadores agregados
 *   · manualInclude(...)     → agrega un IP a pedido (origin='manual')
 *   · manualRemove(ip)       → expira inmediatamente (set expires_at=now())
 *
 * Los re-reportes (UPSERT sobre una IP existente) reinician expires_at a
 * now()+7d e incrementan report_count — penalización implícita.
 */

import { pgQuery } from "../db/postgres.mjs";
import { logger } from "../logger.mjs";
import { isReservedIp, ipv4InCidr } from "./netClass.mjs";

const WATCHLIST_DAYS       = 7;   // TTL base — casos NUEVO/EN_ANALISIS/MONITOREADO/CERRADO
const TTL_CONFIRMED_DAYS   = 14;  // CONFIRMADO → análisis L2 validó el ataque
const TTL_ESCALATED_DAYS   = 21;  // ESCALADO → incidente real, SOC tomó acción
const SCAN_HOURS_DEFAULT   = 24;  // severity HIGH o score≥60 — ventana corta
const SCAN_HOURS_CRITICAL  = 72;  // CRITICAL — ventana extendida
const SCAN_HOURS_VALIDATED = 72;  // CONFIRMADO/ESCALADO sin importar severity
const MIN_SCORE            = 60;

// IPs reservadas / no enrutables (RFC1918 + loopback + link-local + 0.0.0.0/8 +
// CGNAT + loopback/link-local IPv6) — excluidas del feed outbound. Antes era un
// regex local; ahora la fuente única es netClass.isReservedIp (añade CGNAT 100.64/10).

// ── DDL idempotente ──────────────────────────────────────────────────────────
export async function ensureWatchlistTable() {
  await pgQuery(`CREATE SCHEMA IF NOT EXISTS legacyhunt_soc`);
  await pgQuery(`
    CREATE TABLE IF NOT EXISTS legacyhunt_soc.infragovpy_watchlist (
      ip                       VARCHAR(64)  PRIMARY KEY,
      first_seen               TIMESTAMPTZ  NOT NULL DEFAULT now(),
      last_seen                TIMESTAMPTZ  NOT NULL DEFAULT now(),
      expires_at               TIMESTAMPTZ  NOT NULL,
      report_count             INTEGER      NOT NULL DEFAULT 1 CHECK (report_count >= 1),
      first_score              INTEGER      NOT NULL DEFAULT 0,
      last_score               INTEGER      NOT NULL DEFAULT 0,
      max_score                INTEGER      NOT NULL DEFAULT 0,
      last_severity            VARCHAR(16),
      last_status              VARCHAR(16),
      last_source_log          VARCHAR(128),
      last_mitre_tactic_id     VARCHAR(32),
      last_mitre_tactic_name   VARCHAR(128),
      last_mitre_technique_id  VARCHAR(32),
      last_case_id             VARCHAR(64),
      origin                   VARCHAR(16)  NOT NULL DEFAULT 'auto'
                               CHECK (origin IN ('auto', 'manual')),
      added_by                 VARCHAR(64),
      reason                   TEXT,
      updated_at               TIMESTAMPTZ  NOT NULL DEFAULT now()
    )
  `);
  // M4 (audit 2026-06-15): columnas que el sync inserta pero que sólo existían vía
  // migraciones manuales (031: last_status; 058: last_mitre_technique_id). Como las
  // migraciones PG NO se auto-aplican, un deploy fresco fallaba el sync con "column
  // does not exist" y el feed quedaba vacío en silencio. ADD COLUMN idempotente acá.
  await pgQuery(`ALTER TABLE legacyhunt_soc.infragovpy_watchlist ADD COLUMN IF NOT EXISTS last_status VARCHAR(16)`);
  await pgQuery(`ALTER TABLE legacyhunt_soc.infragovpy_watchlist ADD COLUMN IF NOT EXISTS last_mitre_technique_id VARCHAR(32)`);
  await pgQuery(`CREATE INDEX IF NOT EXISTS idx_infragovpy_wl_expires_at ON legacyhunt_soc.infragovpy_watchlist (expires_at)`);
  await pgQuery(`CREATE INDEX IF NOT EXISTS idx_infragovpy_wl_last_seen  ON legacyhunt_soc.infragovpy_watchlist (last_seen DESC)`);
  await pgQuery(`CREATE INDEX IF NOT EXISTS idx_infragovpy_wl_origin     ON legacyhunt_soc.infragovpy_watchlist (origin)`);

  // Migración one-shot desde infragovpy_manual_include si existe
  try {
    await pgQuery(`
      INSERT INTO legacyhunt_soc.infragovpy_watchlist (
        ip, first_seen, last_seen, expires_at,
        report_count, first_score, last_score, max_score,
        last_severity, origin, added_by, reason
      )
      SELECT ioc_value, added_at, added_at, expires_at,
             1, 100, 100, 100,
             'MANUAL', 'manual', added_by, reason
        FROM legacyhunt_soc.infragovpy_manual_include
       WHERE expires_at > NOW()
      ON CONFLICT (ip) DO NOTHING
    `);
  } catch (err) {
    // Tabla vieja puede no existir en despliegues nuevos → ignorar
    if (!/does not exist/i.test(err?.message ?? "")) {
      logger.warn("infragovpy_watchlist: manual-include migration warning", { error: err?.message });
    }
  }
}

// ── Exclusiones (allowlist del feed lgcrBL) ──────────────────────────────────
//
// Lista de IPs/rangos que NUNCA deben publicarse en el feed outbound, aunque
// el scoring las marque como maliciosas: infra propia, egress NAT corporativo,
// IPs de partners/CERT, scanners contratados o falsos positivos crónicos. A
// diferencia de manualRemove (que solo expira la fila y el sync de 10 min la
// re-agrega), una exclusión es persistente y se respeta en: (1) el sync auto,
// (2) la lectura/export (defensa en profundidad) y (3) la inclusión manual.
//
// Dos formatos: kind='exact' (IP estricta) y kind='cidr' (rango IPv4, p.ej.
// 200.1.2.0/24). Patrón con "/" ⇒ cidr; sin "/" ⇒ exact. expires_at NULL =
// permanente. Espejo del diseño de ioc_dedup_blocklist (mig 033).

export async function ensureExclusionsTable() {
  await pgQuery(`CREATE SCHEMA IF NOT EXISTS legacyhunt_soc`);
  await pgQuery(`
    CREATE TABLE IF NOT EXISTS legacyhunt_soc.infragovpy_exclusions (
      id          BIGSERIAL    PRIMARY KEY,
      pattern     VARCHAR(64)  NOT NULL,
      kind        VARCHAR(8)   NOT NULL DEFAULT 'exact' CHECK (kind IN ('exact','cidr')),
      reason      TEXT,
      added_by    VARCHAR(64),
      created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
      expires_at  TIMESTAMPTZ,
      CONSTRAINT uq_infragovpy_excl_pattern UNIQUE (pattern)
    )
  `);
  await pgQuery(`CREATE INDEX IF NOT EXISTS idx_infragovpy_excl_expires ON legacyhunt_soc.infragovpy_exclusions (expires_at)`);
}

/** Lista exclusiones. Por defecto solo las vigentes (permanentes o no expiradas). */
export async function listExclusions({ includeExpired = false } = {}) {
  const where = includeExpired ? "" : "WHERE expires_at IS NULL OR expires_at > NOW()";
  return pgQuery(`
    SELECT id, pattern, kind, reason, added_by, created_at, expires_at,
           (expires_at IS NULL) AS permanent
      FROM legacyhunt_soc.infragovpy_exclusions
      ${where}
     ORDER BY created_at DESC
  `);
}

/**
 * Agrega (o actualiza) una exclusión. El `kind` se deriva del patrón salvo que
 * se pase explícito: con "/" → cidr, si no → exact. `days` NULL/0 = permanente.
 * Valida que el patrón sea una IPv4 (exact) o un CIDR IPv4 (cidr).
 * @returns {Promise<object>} la fila insertada/actualizada.
 */
export async function addExclusion({ pattern, kind, reason, addedBy, days } = {}) {
  const p = String(pattern ?? "").trim();
  if (!p) throw new Error("pattern requerido");
  const resolvedKind = kind || (p.includes("/") ? "cidr" : "exact");
  if (resolvedKind !== "exact" && resolvedKind !== "cidr") {
    throw new Error("kind inválido (exact|cidr)");
  }
  // Validación: exact debe ser IPv4 estricta; cidr debe parsear como rango v4.
  if (resolvedKind === "cidr") {
    if (!ipv4InCidr(p.split("/")[0], p)) throw new Error("CIDR IPv4 inválido");
  } else if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(p) && !p.includes(":")) {
    throw new Error("IP inválida (exact espera IPv4; usa kind=cidr para rangos)");
  }
  const d = days == null || Number(days) <= 0 ? null : Math.min(3650, Number(days));
  const rows = await pgQuery(
    `INSERT INTO legacyhunt_soc.infragovpy_exclusions (pattern, kind, reason, added_by, expires_at)
     VALUES ($1, $2, $3, $4, ${d == null ? "NULL" : "NOW() + ($5 || ' days')::INTERVAL"})
     ON CONFLICT (pattern) DO UPDATE SET
       kind       = EXCLUDED.kind,
       reason     = EXCLUDED.reason,
       added_by   = EXCLUDED.added_by,
       expires_at = EXCLUDED.expires_at
     RETURNING id, pattern, kind, reason, added_by, created_at, expires_at`,
    d == null ? [p, resolvedKind, reason ?? null, addedBy ?? null]
              : [p, resolvedKind, reason ?? null, addedBy ?? null, String(d)],
  );
  return rows[0];
}

/** Borra una exclusión por id o por patrón. @returns {boolean} */
export async function removeExclusion(idOrPattern) {
  if (idOrPattern == null || idOrPattern === "") throw new Error("id|pattern requerido");
  const byId = /^\d+$/.test(String(idOrPattern));
  const rows = await pgQuery(
    `DELETE FROM legacyhunt_soc.infragovpy_exclusions
      WHERE ${byId ? "id = $1::bigint" : "pattern = $1"} RETURNING id`,
    [String(idOrPattern)],
  );
  return rows.length > 0;
}

/** Carga las exclusiones vigentes en memoria para filtrado rápido en el sync. */
export async function loadActiveExclusions() {
  const rows = await listExclusions();
  const exact = new Set();
  const cidrs = [];
  for (const r of rows) {
    if (r.kind === "cidr") cidrs.push(r.pattern);
    else exact.add(String(r.pattern).trim());
  }
  return { exact, cidrs };
}

/** ¿La IP cae en alguna exclusión vigente del set precargado? */
export function matchesExclusion(ip, excl) {
  if (!ip || !excl) return false;
  // B2 (audit 2026-06-15): normalizar UNA vez para que exact y cidr matcheen
  // sobre la misma IP trimmeada (antes el path cidr recibía el ip sin trim).
  const norm = String(ip).trim();
  if (excl.exact.has(norm)) return true;
  return excl.cidrs.some((c) => ipv4InCidr(norm, c));
}

/** Conveniencia: ¿la IP está excluida? (carga la lista y evalúa). */
export async function isExcluded(ip) {
  const excl = await loadActiveExclusions();
  return matchesExclusion(ip, excl);
}

// ── Sync desde incident_cases_pg (scheduler cada 10 min) ─────────────────────
/**
 * Lee candidatos (IPs públicas) en tres universos disjuntos que se unen:
 *   1. CRITICAL en últimas 72 h — ventana extendida para no perder críticos
 *      cuya adopción toma días.
 *   2. CONFIRMADO/ESCALADO en últimas 72 h sin importar severity — señal L2/L3
 *      de que un analista humano validó que la IP es maliciosa.
 *   3. HIGH o score≥60 en últimas 24 h — comportamiento histórico.
 * Excluye FALSO_POSITIVO explícitamente (contamina el feed outbound).
 *
 * Retorna {inserted, updated, skipped, elapsedMs}.
 */
export async function syncFromIncidentCases() {
  const t0 = Date.now();

  // Candidatos: una fila por IP con el caso "más reciente y de mayor severity".
  // El DISTINCT ON elige prioridad: ESCALADO/CONFIRMADO > CRITICAL > HIGH > otros,
  // luego score, luego last_seen — asegura que la entrada a upsertar lleve el
  // estado más validado por humanos.
  const candidates = await pgQuery(`
    WITH base AS (
      SELECT
        ioc_value,
        status,
        severity,
        score,
        source_log,
        mitre_tactic_id,
        mitre_tactic_name,
        mitre_technique_id,
        id,
        last_seen,
        anchor_dt
      FROM incident_cases_pg
      WHERE ioc_type = 'ip'
        AND ioc_value IS NOT NULL
        AND ioc_value <> ''
        AND status NOT IN ('FALSO_POSITIVO')
        AND (
              -- Universo 1: CRITICAL en 72 h
              (severity = 'CRITICAL'
                AND anchor_dt >= current_date - INTERVAL '${SCAN_HOURS_CRITICAL} hours')
           OR -- Universo 2: CONFIRMADO/ESCALADO en 72 h (cualquier severity)
              (status IN ('CONFIRMADO','ESCALADO')
                AND anchor_dt >= current_date - INTERVAL '${SCAN_HOURS_VALIDATED} hours')
           OR -- Universo 3: HIGH o score alto en 24 h (legacy)
              ((severity = 'HIGH' OR score >= ${MIN_SCORE})
                AND anchor_dt >= current_date - INTERVAL '${SCAN_HOURS_DEFAULT} hours')
            )
    )
    SELECT DISTINCT ON (ioc_value)
           ioc_value                AS ip,
           status                   AS cur_status,
           score                    AS cur_score,
           severity                 AS cur_severity,
           source_log               AS cur_source_log,
           mitre_tactic_id          AS cur_mitre_tactic_id,
           mitre_tactic_name        AS cur_mitre_tactic_name,
           mitre_technique_id       AS cur_mitre_technique_id,
           id                       AS cur_case_id,
           last_seen
      FROM base
     ORDER BY ioc_value,
              -- prioridad: validación humana > severity CRITICAL > score > last_seen
              CASE status
                WHEN 'ESCALADO'    THEN 1
                WHEN 'CONFIRMADO'  THEN 2
                WHEN 'MONITOREADO' THEN 3
                WHEN 'EN_ANALISIS' THEN 4
                WHEN 'NUEVO'       THEN 5
                WHEN 'CERRADO'     THEN 6
                ELSE 9
              END ASC,
              CASE severity
                WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4
              END ASC,
              score DESC,
              last_seen DESC NULLS LAST
  `);

  // Filtro RFC1918 en Node (regex compleja — más simple que en SQL) + exclusiones
  // (allowlist): una IP/rango excluido NUNCA entra al feed aunque puntúe alto.
  const excl = await loadActiveExclusions();
  const filtered = candidates.filter(
    (r) => r.ip && !isReservedIp(r.ip) && !matchesExclusion(r.ip, excl),
  );
  if (filtered.length === 0) {
    return { inserted: 0, updated: 0, skipped: candidates.length - filtered.length, elapsedMs: Date.now() - t0 };
  }

  // UPSERT por lotes. TTL dinámico según status y report_count ponderado
  // (+2 para CONFIRMADO/ESCALADO, +1 resto) se resuelven en SQL con CASE.
  const CHUNK = 500;
  let inserted = 0, updated = 0;

  for (let i = 0; i < filtered.length; i += CHUNK) {
    const chunk = filtered.slice(i, i + CHUNK);
    const valuesSql = [];
    const params    = [];
    let idx = 1;
    for (const r of chunk) {
      const scoreNum = Math.max(0, Math.min(200, Number(r.cur_score ?? 0)));
      valuesSql.push(
        `($${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++})`,
      );
      params.push(
        r.ip,
        scoreNum,
        String(r.cur_severity ?? "").toUpperCase() || null,
        String(r.cur_status ?? "").toUpperCase() || null,
        r.cur_source_log ?? null,
        r.cur_mitre_tactic_id ?? null,
        r.cur_mitre_tactic_name ?? null,
        r.cur_mitre_technique_id ?? null,   // B1: antes no se persistía
        r.cur_case_id ?? null,
      );
    }
    const sql = `
      WITH incoming (ip, cur_score, cur_sev, cur_status, cur_src, cur_mt_id, cur_mt_name, cur_mt_tech, cur_case_id)
      AS (VALUES ${valuesSql.join(", ")}),
      upserted AS (
        INSERT INTO legacyhunt_soc.infragovpy_watchlist AS w (
          ip, first_seen, last_seen, expires_at,
          report_count, first_score, last_score, max_score,
          last_severity, last_status, last_source_log,
          last_mitre_tactic_id, last_mitre_tactic_name, last_mitre_technique_id, last_case_id,
          origin, updated_at
        )
        SELECT
          i.ip, NOW(), NOW(),
          NOW() + (
            CASE i.cur_status
              WHEN 'ESCALADO'   THEN ${TTL_ESCALATED_DAYS}
              WHEN 'CONFIRMADO' THEN ${TTL_CONFIRMED_DAYS}
              ELSE ${WATCHLIST_DAYS}
            END || ' days'
          )::INTERVAL,
          1, i.cur_score::int, i.cur_score::int, i.cur_score::int,
          i.cur_sev, i.cur_status, i.cur_src,
          i.cur_mt_id, i.cur_mt_name, i.cur_mt_tech, i.cur_case_id,
          'auto', NOW()
        FROM incoming i
        ON CONFLICT (ip) DO UPDATE SET
          last_seen              = NOW(),
          expires_at             = GREATEST(
                                     w.expires_at,
                                     NOW() + (
                                       CASE EXCLUDED.last_status
                                         WHEN 'ESCALADO'   THEN ${TTL_ESCALATED_DAYS}
                                         WHEN 'CONFIRMADO' THEN ${TTL_CONFIRMED_DAYS}
                                         ELSE ${WATCHLIST_DAYS}
                                       END || ' days'
                                     )::INTERVAL
                                   ),
          report_count           = w.report_count + CASE
                                     WHEN EXCLUDED.last_status IN ('CONFIRMADO','ESCALADO') THEN 2
                                     ELSE 1
                                   END,
          last_score             = EXCLUDED.last_score,
          max_score              = GREATEST(w.max_score, EXCLUDED.last_score),
          last_severity          = EXCLUDED.last_severity,
          last_status            = EXCLUDED.last_status,
          last_source_log        = EXCLUDED.last_source_log,
          last_mitre_tactic_id   = EXCLUDED.last_mitre_tactic_id,
          last_mitre_tactic_name = EXCLUDED.last_mitre_tactic_name,
          last_mitre_technique_id = EXCLUDED.last_mitre_technique_id,
          last_case_id           = EXCLUDED.last_case_id,
          updated_at             = NOW()
        -- Identificamos inserts vs updates vía xmax (0 = insert, !=0 = update)
        RETURNING (xmax = 0) AS inserted
      )
      SELECT
        SUM(CASE WHEN inserted THEN 1 ELSE 0 END)::int AS ins,
        SUM(CASE WHEN inserted THEN 0 ELSE 1 END)::int AS upd
      FROM upserted`;
    const rows = await pgQuery(sql, params);
    inserted += Number(rows[0]?.ins ?? 0);
    updated  += Number(rows[0]?.upd ?? 0);
  }

  return {
    inserted,
    updated,
    skipped: candidates.length - filtered.length,
    elapsedMs: Date.now() - t0,
  };
}

// ── Lectura: lista activa + KPIs ─────────────────────────────────────────────
/**
 * Devuelve filas activas (expires_at > now()) con columnas para UI y CSV.
 * @param {{ severity?: string, origin?: string, limit?: number }} opts
 */
export async function getActive({ severity, origin, limit = 1000 } = {}) {
  const filters = ["expires_at > NOW()"];
  const params  = [];
  // M1 (audit 2026-06-15): tope de antigüedad ABSOLUTO para evitar IPs stale
  // publicadas indefinidamente. Una IP que reincide cada <TTL renueva expires_at
  // sin límite (GREATEST en el upsert); acá cortamos las entradas AUTO cuyo
  // first_seen supera LGCRBL_MAX_AGE_DAYS (default 90, 0=desactivado), salvo que
  // estén validadas por humano (CONFIRMADO/ESCALADO) o sean inclusión manual.
  const maxAgeDays = Math.max(0, Number(process.env.LGCRBL_MAX_AGE_DAYS ?? 90) || 0);
  if (maxAgeDays > 0) {
    filters.push(
      `(first_seen >= NOW() - INTERVAL '${maxAgeDays} days'` +
      ` OR origin = 'manual' OR last_status IN ('CONFIRMADO','ESCALADO'))`,
    );
  }
  if (severity && severity !== "ALL") {
    params.push(String(severity).toUpperCase());
    filters.push(`last_severity = $${params.length}`);
  }
  if (origin && origin !== "ALL") {
    params.push(origin);
    filters.push(`origin = $${params.length}`);
  }
  params.push(Math.min(5000, Math.max(1, Number(limit) || 1000)));
  const sql = `
    SELECT
      ip, first_seen, last_seen, expires_at,
      report_count, first_score, last_score, max_score,
      last_severity, last_status, last_source_log,
      last_mitre_tactic_id, last_mitre_tactic_name, last_mitre_technique_id,
      last_case_id, origin, added_by, reason,
      EXTRACT(EPOCH FROM (expires_at - NOW()))::bigint AS seconds_to_expire,
      EXTRACT(EPOCH FROM (NOW() - first_seen))::bigint AS seconds_since_first
    FROM legacyhunt_soc.infragovpy_watchlist
    WHERE ${filters.join(" AND ")}
    ORDER BY
      -- Prioridad: status validado por humano > severity > score
      CASE last_status
        WHEN 'ESCALADO'   THEN 1
        WHEN 'CONFIRMADO' THEN 2
        ELSE 9
      END ASC,
      CASE last_severity
        WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5 END ASC,
      max_score DESC,
      last_seen DESC
    LIMIT $${params.length}`;
  const rows = await pgQuery(sql, params);
  // Defensa en profundidad: aunque el sync ya no inserta IPs excluidas, una IP
  // agregada manualmente y excluida después podría seguir activa en la tabla.
  // La filtramos también en lectura para que jamás aparezca en UI/CSV/feed.
  const excl = await loadActiveExclusions();
  // M2 (audit 2026-06-15): segunda barrera de reservadas en lectura (además de
  // exclusiones) — si una IP interna entró por datos sucios, jamás sale al CSV/feed.
  return rows.filter((r) => !isReservedIp(r.ip) && !matchesExclusion(r.ip, excl));
}

export async function getKpis() {
  const [rows] = await pgQuery(`
    SELECT
      COUNT(*) FILTER (WHERE expires_at > NOW())                                     AS active_total,
      COUNT(*) FILTER (WHERE expires_at > NOW() AND last_severity = 'CRITICAL')      AS active_critical,
      COUNT(*) FILTER (WHERE expires_at > NOW() AND last_severity = 'HIGH')          AS active_high,
      COUNT(*) FILTER (WHERE expires_at > NOW() AND last_severity = 'MEDIUM')        AS active_medium,
      COUNT(*) FILTER (WHERE expires_at > NOW() AND first_seen >= NOW() - INTERVAL '24 hours') AS new_24h,
      COUNT(*) FILTER (WHERE expires_at > NOW() AND report_count >= 2)               AS penalized,
      COUNT(*) FILTER (WHERE expires_at > NOW() AND origin = 'manual')               AS active_manual,
      COALESCE(AVG(NULLIF(max_score, 0))::int, 0)                                    AS avg_max_score,
      COALESCE(MAX(max_score), 0)                                                    AS max_max_score,
      COALESCE(AVG(EXTRACT(DAY FROM (NOW() - first_seen)))::numeric(10,1), 0)         AS avg_days_in_list
    FROM legacyhunt_soc.infragovpy_watchlist
    WHERE expires_at > NOW() OR expires_at >= NOW() - INTERVAL '1 day'
  `);
  return rows ?? { active_total: 0, active_critical: 0, active_high: 0, active_medium: 0,
                   new_24h: 0, penalized: 0, active_manual: 0,
                   avg_max_score: 0, max_max_score: 0, avg_days_in_list: 0 };
}

// ── Último push (commit) al repo GitLab del feed lgcrBL ──────────────────────
// Lo empuja el DAG `infragovpy_daily_push` (07:00 PY) + el botón "Publicar" del
// panel. Consulta el commit más reciente de la rama en GitLab. Cacheado 5 min en
// memoria (no martillar la instancia). Degrada con `ok:false` si falta token o
// GitLab falla → el consumidor (endpoint / tarjeta de fuentes) no rompe.
let _lastPushCache = { at: 0, data: null };
export async function getLgcrblLastPush() {
  const now = Date.now();
  if (_lastPushCache.data && now - _lastPushCache.at < 5 * 60_000) {
    return _lastPushCache.data;
  }
  const token  = (process.env.LGCRBL_GIT_TOKEN  ?? "").trim();
  const base   = (process.env.LGCRBL_GIT_BASE   ?? "https://codigo.legacy-roots.com").trim().replace(/\/+$/, "");
  const repo   = (process.env.LGCRBL_GIT_REPO   ?? "legacy/lgcrbl").trim();
  const branch = (process.env.LGCRBL_GIT_BRANCH ?? "main").trim();
  if (!token) {
    return { ok: false, last_push_at: null, reason: "LGCRBL_GIT_TOKEN no configurado" };
  }
  try {
    const projectId = encodeURIComponent(repo);
    const c = await fetch(
      `${base}/api/v4/projects/${projectId}/repository/commits/${encodeURIComponent(branch)}`,
      {
        headers: { "PRIVATE-TOKEN": token, Accept: "application/json", "User-Agent": "legacyhunt-api" },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!c.ok) {
      logger.warn("lgcrbl/last-push gitlab non-ok", { status: c.status });
      return { ok: false, last_push_at: null, git_status: c.status };
    }
    const cj = await c.json();
    const data = {
      ok: true,
      last_push_at: cj?.committed_date ?? cj?.created_at ?? null,
      commit_sha:   cj?.short_id ?? cj?.id ?? null,
      commit_title: cj?.title ?? null,
      html_url:     cj?.id ? `${base}/${repo}/-/commit/${cj.id}` : null,
      branch,
    };
    _lastPushCache = { at: now, data };
    return data;
  } catch (err) {
    logger.warn("lgcrbl/last-push failed", { error: err?.message });
    return { ok: false, last_push_at: null, error: err?.message };
  }
}

// ── Inclusión manual ─────────────────────────────────────────────────────────
export async function manualInclude({ ip, addedBy, reason, days = WATCHLIST_DAYS }) {
  if (!ip || !addedBy) throw new Error("ip + addedBy required");
  // A1 (audit 2026-06-15): NUNCA publicar infra propia/no-enrutable en el feed
  // saliente compartido, ni siquiera por inclusión manual. Antes el sync filtraba
  // reservadas pero manualInclude/force-include no → un operador podía inyectar
  // 10.x/192.168.x/IP de gestión.
  if (isReservedIp(ip)) {
    const e = new Error(`La IP ${ip} es interna/reservada (RFC1918/CGNAT/loopback) — no puede ir al feed saliente lgcrBL.`);
    e.code = "RESERVED";
    throw e;
  }
  // No permitir incluir una IP que está en la allowlist de exclusiones.
  if (await isExcluded(ip)) {
    const e = new Error(`La IP ${ip} está en la lista de exclusiones de lgcrBL; quítala de exclusiones antes de incluirla.`);
    e.code = "EXCLUDED";
    throw e;
  }
  const d = Math.min(90, Math.max(1, Number(days) || WATCHLIST_DAYS));
  await pgQuery(`
    INSERT INTO legacyhunt_soc.infragovpy_watchlist AS w (
      ip, first_seen, last_seen, expires_at,
      report_count, first_score, last_score, max_score,
      last_severity, origin, added_by, reason, updated_at
    ) VALUES (
      $1, NOW(), NOW(), NOW() + ($2 || ' days')::INTERVAL,
      1, 100, 100, 100,
      'MANUAL', 'manual', $3, $4, NOW()
    )
    ON CONFLICT (ip) DO UPDATE SET
      last_seen  = NOW(),
      expires_at = GREATEST(w.expires_at, NOW() + ($2 || ' days')::INTERVAL),
      origin     = 'manual',
      added_by   = EXCLUDED.added_by,
      reason     = EXCLUDED.reason,
      updated_at = NOW()
  `, [String(ip), String(d), String(addedBy), String(reason ?? "manual include")]);
}

export async function manualRemove(ip) {
  if (!ip) throw new Error("ip required");
  const rows = await pgQuery(
    `UPDATE legacyhunt_soc.infragovpy_watchlist
        SET expires_at = NOW(), updated_at = NOW()
      WHERE ip = $1 AND expires_at > NOW()
      RETURNING ip`,
    [String(ip)],
  );
  return rows.length > 0;
}
