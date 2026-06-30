/**
 * surveillanceNotifications — queries para watchlist sync + log de notificaciones.
 *
 * Tablas:
 *   - surveillance_watchlist_subs        (sync server-side de WatchlistEntry)
 *   - surveillance_notification_log      (bitácora de envíos)
 *   - surveillance_cti_snapshots         (último resultado CTI Cloud & Olé / dominio)
 */

import { pgQuery } from "./postgres.mjs";

// ── Watchlist subscriptions ──────────────────────────────────────────────────

/** Upsert de una entrada del watchlist desde el cliente. */
export async function upsertWatchlistSub(input) {
  const {
    domain,
    ownerLabel,
    ownerCi = null,
    frequency,
    channel,
    alertOn = [],
    notes = null,
    addedAt,
    notifyEmail = null,
    webhookUrl = null,
    autoOpenSeverity = "medium",
    visibility = "shared",
  } = input;

  const sql = `
    INSERT INTO surveillance_watchlist_subs (
      domain, owner_label, owner_ci, frequency, channel, alert_on, notes,
      added_at, notify_email, webhook_url, auto_open_severity, visibility
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    ON CONFLICT (domain) DO UPDATE SET
      owner_label        = EXCLUDED.owner_label,
      owner_ci           = EXCLUDED.owner_ci,
      frequency          = EXCLUDED.frequency,
      channel            = EXCLUDED.channel,
      alert_on           = EXCLUDED.alert_on,
      notes              = EXCLUDED.notes,
      added_at           = EXCLUDED.added_at,
      notify_email       = EXCLUDED.notify_email,
      webhook_url        = EXCLUDED.webhook_url,
      auto_open_severity = EXCLUDED.auto_open_severity,
      visibility         = EXCLUDED.visibility,
      updated_at         = now()
    RETURNING id, domain, owner_label, frequency, channel, visibility,
              last_notified_at, updated_at
  `;
  const params = [
    domain.toLowerCase().slice(0, 253),
    ownerLabel.slice(0, 255),
    ownerCi,
    frequency,
    channel,
    alertOn,
    notes,
    addedAt,
    notifyEmail ? String(notifyEmail).slice(0, 255) : null,
    webhookUrl ? String(webhookUrl).slice(0, 512) : null,
    autoOpenSeverity,
    visibility,
  ];
  const rows = await pgQuery(sql, params);
  return rows[0];
}

/** Lee una sub por dominio para chequear permisos antes de update/delete. */
export async function getWatchlistSubByDomain(domain) {
  const rows = await pgQuery(
    `SELECT id, domain, owner_ci, visibility FROM surveillance_watchlist_subs WHERE domain = $1`,
    [String(domain).toLowerCase()],
  );
  return rows[0] ?? null;
}

export async function deleteWatchlistSub(domain) {
  const sql = `DELETE FROM surveillance_watchlist_subs WHERE domain = $1 RETURNING id`;
  const rows = await pgQuery(sql, [domain.toLowerCase()]);
  return rows[0] ?? null;
}

/**
 * Listado filtrado por visibilidad y rol del solicitante (#9).
 *   - private → sólo si owner_ci = viewerCi
 *   - shared  → cualquier hunter+ (asumido por endpoint).
 *   - global  → cualquier autenticado.
 * Si `viewerCi` no es proveído (legacy/lab), devolvemos todo (compat).
 */
export async function listWatchlistSubs(opts = {}) {
  const { viewerCi = null, viewerCanSeeShared = true } = opts;
  const where = [];
  const params = [];
  if (viewerCi !== null) {
    if (viewerCanSeeShared) {
      params.push(viewerCi);
      where.push(`(visibility = 'global' OR visibility = 'shared' OR (visibility = 'private' AND owner_ci = $${params.length}))`);
    } else {
      params.push(viewerCi);
      where.push(`(visibility = 'global' OR (visibility = 'private' AND owner_ci = $${params.length}))`);
    }
  }
  const sql = `
    SELECT id, domain, owner_label, owner_ci, frequency, channel, alert_on, notes,
           added_at, last_notified_at, last_analyzed_at, notify_email, webhook_url,
           auto_open_severity, visibility
    FROM surveillance_watchlist_subs
    ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
    ORDER BY added_at DESC
  `;
  return pgQuery(sql, params);
}

/**
 * Snapshot del set de finding-IDs detectados en el ciclo actual para una
 * sub. Persiste para delta-detection en el ciclo siguiente.
 *
 * Sobreescribe `last_finding_ids` siempre — incluso cuando el set actual está
 * vacío. Eso evita que un sub que pasó de "tenía findings" a "ya no tiene"
 * quede con basura del pasado y delta-skip-ee incorrectamente cuando los
 * findings vuelvan.
 */
export async function updateLastFindingIds(domain, findingIds) {
  const sql = `
    UPDATE surveillance_watchlist_subs
       SET last_finding_ids = $2::text[]
     WHERE domain = $1
  `;
  await pgQuery(sql, [domain.toLowerCase(), Array.isArray(findingIds) ? findingIds : []]);
}

/**
 * Lista subscripciones cuyo próximo slot de análisis ya pasó.
 *
 * El criterio "due" es: tiempo transcurrido desde el último análisis (o desde
 * `added_at` si nunca se analizó) ≥ intervalo de la frecuencia.
 *
 * El cron luego, por cada sub, calcula el timestamp del slot exacto
 * (`added_at + N×interval`) y bumpea `last_analyzed_at` a ese valor (no a
 * `now()`), de modo que la cadencia coincide con el countdown del UI.
 *
 * `instant` no se barre por cron — se dispara desde el endpoint cuando un
 * finding nuevo entra al feed. Acá filtramos hourly/daily/weekly.
 */
export async function listSubsDueForAnalysis(now = new Date()) {
  const sql = `
    SELECT id, domain, owner_label, owner_ci, frequency, channel, alert_on, notes,
           added_at, last_analyzed_at, last_notified_at, notify_email,
           webhook_url, auto_open_severity, last_finding_ids
    FROM surveillance_watchlist_subs
    WHERE
      (frequency = 'hourly'  AND $1::timestamptz - added_at >= INTERVAL '1 hour'  AND (last_analyzed_at IS NULL OR last_analyzed_at < $1::timestamptz - INTERVAL '1 hour'))
   OR (frequency = 'daily'   AND $1::timestamptz - added_at >= INTERVAL '1 day'   AND (last_analyzed_at IS NULL OR last_analyzed_at < $1::timestamptz - INTERVAL '1 day'))
   OR (frequency = 'weekly'  AND $1::timestamptz - added_at >= INTERVAL '7 days'  AND (last_analyzed_at IS NULL OR last_analyzed_at < $1::timestamptz - INTERVAL '7 days'))
    ORDER BY added_at ASC
  `;
  return pgQuery(sql, [now.toISOString()]);
}

/**
 * Bumpea `last_analyzed_at` al timestamp del slot procesado. NO a now() —
 * usar siempre el slot exacto (`addedAt + N×interval`) para que la cadencia
 * del cron coincida con el countdown del UI sin acumular drift.
 */
export async function bumpLastAnalyzed(domain, slotIso) {
  const sql = `
    UPDATE surveillance_watchlist_subs
       SET last_analyzed_at = $2::timestamptz
     WHERE domain = $1
  `;
  await pgQuery(sql, [domain.toLowerCase(), slotIso]);
}

/** Bumpea `last_notified_at` (dedup de envíos Slack — separado del análisis). */
export async function bumpLastNotified(domain) {
  const sql = `UPDATE surveillance_watchlist_subs SET last_notified_at = now() WHERE domain = $1`;
  await pgQuery(sql, [domain.toLowerCase()]);
}

// ── Notification log ──────────────────────────────────────────────────────────

/**
 * Devuelve la última notificación con status='sent' para `domain` dentro de
 * `windowHours`, cuyo set de `finding_ids` se solapa con `findingIds`.
 *
 * Usa el operador Postgres `&&` (array overlap) — TRUE si los arreglos
 * comparten al menos un elemento. Eso es lo que queremos para dedup: si la
 * última alerta envió IDs A,B,C y ahora venimos con B,D,E → solapan en B,
 * es la misma alerta acumulada → skip.
 *
 * Retorna null si no hay match (no es error).
 *
 * Costos: full scan sobre la ventana de tiempo. Aceptable hasta unos pocos
 * miles de filas/día. Si crece, indexar `(domain, sent_at DESC)` ya existe
 * (`idx_notification_log_domain`) y agregar GIN sobre `finding_ids` si hace
 * falta.
 */
export async function findRecentSentNotification(domain, findingIds, windowHours = 24) {
  if (!Array.isArray(findingIds) || findingIds.length === 0) return null;
  const sql = `
    SELECT id, domain, channel, finding_ids, severity_max, sent_at
    FROM surveillance_notification_log
    WHERE domain = $1
      AND status = 'sent'
      AND sent_at >= now() - ($2::int * INTERVAL '1 hour')
      AND finding_ids && $3::text[]
    ORDER BY sent_at DESC
    LIMIT 1
  `;
  const rows = await pgQuery(sql, [domain.toLowerCase(), windowHours, findingIds]);
  return rows[0] ?? null;
}

export async function logNotification(input) {
  const {
    domain,
    channel,
    findingIds = [],
    severityMax = null,
    status,
    detail = null,
  } = input;
  const sql = `
    INSERT INTO surveillance_notification_log (
      domain, channel, finding_ids, severity_max, status, detail
    ) VALUES ($1, $2, $3, $4, $5, $6)
    RETURNING id, sent_at
  `;
  try {
    const rows = await pgQuery(sql, [
      domain.toLowerCase(),
      channel,
      findingIds,
      severityMax,
      status,
      detail,
    ]);
    return rows[0];
  } catch (err) {
    console.error("[notify log] insert failed:", err.message);
    return null;
  }
}

// ── CTI Cloud & Olé snapshots ────────────────────────────────────────────────

/**
 * Upsert del resultado del cron CTI por dominio. Una fila por dominio, se
 * sobreescribe en cada ciclo. Para auditar histórico se conserva el JSON crudo
 * en S3 (campo `s3_key` apunta ahí).
 */
export async function upsertCtiSnapshot(input) {
  const {
    domain,
    hitsCount = 0,
    s3Key = null,
    topLeakNames = [],
    error = null,
    queriedAt = new Date(),
  } = input;
  const sql = `
    INSERT INTO surveillance_cti_snapshots (
      domain, hits_count, s3_key, top_leak_names, error, queried_at
    ) VALUES ($1, $2, $3, $4, $5, $6)
    ON CONFLICT (domain) DO UPDATE SET
      hits_count     = EXCLUDED.hits_count,
      s3_key         = EXCLUDED.s3_key,
      top_leak_names = EXCLUDED.top_leak_names,
      error          = EXCLUDED.error,
      queried_at     = EXCLUDED.queried_at,
      updated_at     = now()
    RETURNING id, domain, hits_count, queried_at, s3_key
  `;
  const params = [
    domain.toLowerCase().slice(0, 253),
    Number.isFinite(hitsCount) ? hitsCount : 0,
    s3Key,
    Array.isArray(topLeakNames) ? topLeakNames.slice(0, 10).map(String) : [],
    error,
    queriedAt instanceof Date ? queriedAt.toISOString() : queriedAt,
  ];
  const rows = await pgQuery(sql, params);
  return rows[0];
}

/** Devuelve snapshots para los dominios pasados. Sin coincidencias → array vacío. */
export async function listCtiSnapshotsForDomains(domains) {
  if (!Array.isArray(domains) || domains.length === 0) return [];
  const lowered = domains.map((d) => String(d).toLowerCase());
  const sql = `
    SELECT domain, hits_count, queried_at, s3_key, top_leak_names, error
    FROM surveillance_cti_snapshots
    WHERE domain = ANY($1::text[])
  `;
  return pgQuery(sql, [lowered]);
}

// ── Push subscriptions (Web Push RFC 8030) ───────────────────────────────────

export async function upsertPushSubscription(input) {
  const { endpoint, p256dhKey, authKey, operatorCi = null, userAgent = null } = input;
  const sql = `
    INSERT INTO surveillance_push_subscriptions (
      endpoint, p256dh_key, auth_key, operator_ci, user_agent
    ) VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (endpoint) DO UPDATE SET
      p256dh_key  = EXCLUDED.p256dh_key,
      auth_key    = EXCLUDED.auth_key,
      operator_ci = EXCLUDED.operator_ci,
      user_agent  = EXCLUDED.user_agent
    RETURNING id, endpoint, operator_ci, created_at
  `;
  const params = [
    String(endpoint).slice(0, 2000),
    String(p256dhKey),
    String(authKey),
    operatorCi,
    userAgent ? String(userAgent).slice(0, 255) : null,
  ];
  const rows = await pgQuery(sql, params);
  return rows[0];
}

export async function deletePushSubscription(endpoint) {
  const sql = `DELETE FROM surveillance_push_subscriptions WHERE endpoint = $1 RETURNING id`;
  const rows = await pgQuery(sql, [String(endpoint)]);
  return rows[0] ?? null;
}

export async function listPushSubscriptions() {
  const sql = `
    SELECT id, endpoint, p256dh_key, auth_key, operator_ci, user_agent, last_used_at
    FROM surveillance_push_subscriptions
  `;
  return pgQuery(sql);
}

export async function bumpPushSubscriptionUsed(id) {
  await pgQuery(
    `UPDATE surveillance_push_subscriptions SET last_used_at = now() WHERE id = $1`,
    [id],
  );
}

// ── Dead-letter queue (#8) ───────────────────────────────────────────────────

/**
 * Append-or-merge: si ya existe una DLQ entry pendiente para (source, target_ref)
 * con mismo payload, incrementa attempts y bumpea last_failed_at en lugar de
 * crear duplicados. Eso mantiene la cola corta cuando un endpoint flakea.
 */
export async function recordDeadLetter(input) {
  const { source, targetRef, payload, lastError } = input;
  const sql = `
    WITH existing AS (
      SELECT id FROM surveillance_dead_letters
      WHERE source = $1
        AND target_ref = $2
        AND resolved_at IS NULL
        AND payload @> $3::jsonb AND $3::jsonb @> payload
      ORDER BY last_failed_at DESC
      LIMIT 1
    ),
    bumped AS (
      UPDATE surveillance_dead_letters
         SET attempts = attempts + 1,
             last_failed_at = now(),
             last_error = $4
       WHERE id IN (SELECT id FROM existing)
       RETURNING id, 'merged' AS kind
    ),
    inserted AS (
      INSERT INTO surveillance_dead_letters (source, target_ref, payload, last_error)
      SELECT $1, $2, $3::jsonb, $4
      WHERE NOT EXISTS (SELECT 1 FROM existing)
      RETURNING id, 'inserted' AS kind
    )
    SELECT * FROM bumped UNION ALL SELECT * FROM inserted LIMIT 1
  `;
  try {
    const rows = await pgQuery(sql, [
      String(source).slice(0, 32),
      String(targetRef).slice(0, 255),
      JSON.stringify(payload ?? {}),
      String(lastError ?? "").slice(0, 4000),
    ]);
    return rows[0] ?? null;
  } catch (err) {
    console.error("[dlq] insert failed:", err.message);
    return null;
  }
}

export async function listDeadLetters(opts = {}) {
  const { source = null, includeResolved = false, limit = 100 } = opts;
  const where = [];
  const params = [];
  if (source)            { params.push(source);            where.push(`source = $${params.length}`); }
  if (!includeResolved)  { where.push(`resolved_at IS NULL`); }
  params.push(Math.min(500, Math.max(1, limit)));
  const sql = `
    SELECT id, source, target_ref, payload, last_error, attempts,
           first_failed_at, last_failed_at, resolved_at, resolution
    FROM surveillance_dead_letters
    ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
    ORDER BY last_failed_at DESC
    LIMIT $${params.length}
  `;
  return pgQuery(sql, params);
}

export async function resolveDeadLetter(id, resolution) {
  const sql = `
    UPDATE surveillance_dead_letters
       SET resolved_at = now(), resolution = $2
     WHERE id = $1 AND resolved_at IS NULL
     RETURNING id, resolution
  `;
  const rows = await pgQuery(sql, [id, resolution]);
  return rows[0] ?? null;
}
