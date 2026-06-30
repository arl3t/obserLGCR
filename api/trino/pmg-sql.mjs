/**
 * pmg-sql.mjs — Consultas SQL para Proxmox Mail Gateway (phishing / email security).
 * Fuente: minio.hunting.pmg_phishing (vista sobre tabla externa pmg/).
 *
 * El JSON que escribe Vector incluye campos explícitos en la raíz del evento:
 *   sender_ip, sender_email, sender_domain, recipient_email, spam_score,
 *   action, dmarc_result, spf_result, dkim_result, blocklist_ref, etc.
 * La vista pmg_phishing añade campos derivados: is_blocked, auth_failed, spam_category.
 *
 * Particionado por year/month/day/hour (igual que syslog/wazuh_alerts).
 */
import { stringStyleWindow } from "./time-window.mjs";

export function createPmgSql(catalog, schema) {
  const t = `${catalog}.${schema}.pmg_phishing`;

  // pmg_phishing ya expone `ts` (timestamp with time zone) computado desde ingest_time.
  // Usar directamente en lugar de reconstruir la expresión sobre la columna raw.
  const { INGEST_TS, PART_2D, W24 } = stringStyleWindow({ ingestTsExpr: `ts` });

  // ── Poda de partición: N días atrás ──────────────────────────────────────
  function partNDays(n) {
    return `trim(cast(coalesce(year,'') AS varchar)) >= date_format(current_timestamp - INTERVAL '${n}' DAY, '%Y')`;
  }

  return {
    /**
     * KPIs globales (24 h):
     *   total_events, blocked, quarantined, auth_failed,
     *   avg_spam_score, max_spam_score, unique_sender_ips, unique_sender_domains.
     */
    kpis24h() {
      return `
SELECT
  COUNT(*)                                                       AS total_events,
  COUNT(*) FILTER (WHERE is_blocked = true)                     AS blocked,
  COUNT(*) FILTER (WHERE is_quarantined = true)                 AS quarantined,
  COUNT(*) FILTER (WHERE is_blocked = true AND is_quarantined = false) AS rejected,
  COUNT(*) FILTER (WHERE auth_failed = true)                    AS auth_failures,
  COUNT(*) FILTER (WHERE lower(action) = 'accepted')            AS accepted,
  ROUND(CAST(AVG(spam_score) AS DOUBLE), 2)                     AS avg_spam_score,
  MAX(spam_score)                                               AS max_spam_score,
  COUNT(DISTINCT sender_ip)                                     AS unique_sender_ips,
  COUNT(DISTINCT sender_domain)                                 AS unique_sender_domains,
  COUNT(DISTINCT recipient_email)                               AS unique_recipients
FROM ${t}
WHERE ${PART_2D}
  AND ${W24}
`.trim();
    },

    /**
     * Top N remitentes (IP/dominio) bloqueados — útil para threat hunting.
     */
    topSenders24h(limit) {
      return `
SELECT
  COALESCE(sender_ip, '(desconocida)')       AS sender_ip,
  COALESCE(sender_domain, '(sin dominio)')   AS sender_domain,
  COUNT(*)                                   AS total_events,
  COUNT(*) FILTER (WHERE is_blocked = true)  AS blocked,
  MAX(spam_score)                            AS max_spam_score,
  ROUND(CAST(AVG(spam_score) AS DOUBLE), 2) AS avg_spam_score,
  COUNT(DISTINCT recipient_email)            AS unique_recipients,
  BOOL_OR(auth_failed)                       AS has_auth_failure
FROM ${t}
WHERE ${PART_2D}
  AND ${W24}
  AND sender_ip IS NOT NULL
GROUP BY sender_ip, sender_domain
ORDER BY blocked DESC, total_events DESC
LIMIT ${limit}
`.trim();
    },

    /**
     * Timeline de acciones por hora (24 h) — para gráfico de área/barras.
     */
    actionsByHour24h() {
      return `
SELECT
  date_format(date_trunc('hour', ${INGEST_TS}), '%H:00')  AS hour,
  COUNT(*)                                                  AS total,
  COUNT(*) FILTER (WHERE is_blocked = true)                AS blocked,
  COUNT(*) FILTER (WHERE is_quarantined = true)            AS quarantined,
  COUNT(*) FILTER (WHERE lower(action) = 'accepted')       AS accepted,
  COUNT(*) FILTER (WHERE auth_failed = true)               AS auth_failures,
  ROUND(CAST(AVG(spam_score) AS DOUBLE), 2)               AS avg_spam_score
FROM ${t}
WHERE ${PART_2D}
  AND ${W24}
GROUP BY date_trunc('hour', ${INGEST_TS})
ORDER BY date_trunc('hour', ${INGEST_TS}) ASC
`.trim();
    },

    /**
     * Top N eventos con fallos de autenticación de email (DMARC/SPF/DKIM fail).
     * Indica posibles dominios falsificados o configuración incorrecta en origen legítimo.
     */
    authFailures24h(limit) {
      return `
SELECT
  COALESCE(sender_domain, '(desconocido)')  AS sender_domain,
  COALESCE(sender_ip,     '(desconocida)')  AS sender_ip,
  auth_fail_type,
  dmarc_result,
  spf_result,
  dkim_result,
  action,
  COUNT(*)                                   AS events,
  COUNT(DISTINCT recipient_email)            AS unique_recipients
FROM ${t}
WHERE ${PART_2D}
  AND ${W24}
  AND auth_failed = true
GROUP BY sender_domain, sender_ip, auth_fail_type, dmarc_result, spf_result, dkim_result, action
ORDER BY events DESC
LIMIT ${limit}
`.trim();
    },

    /**
     * Top blocklists activadas (Spamhaus zen, SBL, XBL, DBL, etc.).
     */
    topBlocklists24h(limit) {
      return `
SELECT
  COALESCE(blocklist_ref, '(sin referencia)') AS blocklist,
  COUNT(*)                                     AS hits,
  COUNT(DISTINCT sender_ip)                    AS unique_ips,
  COUNT(DISTINCT sender_domain)               AS unique_domains
FROM ${t}
WHERE ${PART_2D}
  AND ${W24}
  AND blocklist_ref IS NOT NULL
GROUP BY blocklist_ref
ORDER BY hits DESC
LIMIT ${limit}
`.trim();
    },

    /**
     * Top URLs sospechosas detectadas en el cuerpo/encabezados del email.
     *
     * Pre-selecciona top N URLs con COUNT(*) (barato) y luego JOIN para
     * calcular los agregados caros (COUNT DISTINCT, FILTER) sobre sólo esas
     * N ganadoras. La cardinalidad de suspicious_url puede ser 100k+ —
     * agrupar todas antes del LIMIT era el cuello de botella.
     *
     * Colapsa `url_malicious` con BOOL_OR (una sola fila por URL).
     */
    topSuspiciousUrls24h(limit) {
      return `
WITH top_urls AS (
  SELECT
    suspicious_url,
    COUNT(*) AS hits
  FROM ${t}
  WHERE ${PART_2D}
    AND ${W24}
    AND suspicious_url IS NOT NULL
  GROUP BY suspicious_url
  ORDER BY hits DESC
  LIMIT ${limit}
)
SELECT
  t.suspicious_url,
  t.hits,
  COUNT(DISTINCT m.sender_domain)              AS unique_senders,
  COUNT(*) FILTER (WHERE m.is_blocked = true)  AS blocked,
  BOOL_OR(m.url_malicious)                     AS url_malicious
FROM top_urls t
JOIN ${t} m
  ON m.suspicious_url = t.suspicious_url
WHERE ${PART_2D}
  AND ${W24}
  AND m.suspicious_url IS NOT NULL
GROUP BY t.suspicious_url, t.hits
ORDER BY t.hits DESC
`.trim();
    },

    /**
     * Distribución de spam score en buckets (para histograma).
     */
    spamScoreDistribution24h() {
      return `
SELECT
  CASE
    WHEN spam_score IS NULL     THEN 'sin_score'
    WHEN spam_score < 0         THEN 'negativo'
    WHEN spam_score < 2         THEN '0-2 (limpio)'
    WHEN spam_score < 5         THEN '2-5 (sospechoso)'
    WHEN spam_score < 10        THEN '5-10 (probable_spam)'
    WHEN spam_score < 20        THEN '10-20 (spam_alto)'
    ELSE                             '20+ (spam_definitivo)'
  END                   AS bucket,
  COUNT(*) AS eventos
FROM ${t}
WHERE ${PART_2D}
  AND ${W24}
GROUP BY 1
ORDER BY MIN(COALESCE(spam_score, -999)) ASC
`.trim();
    },

    /**
     * Eventos recientes (tabla de actividad live) con los campos más relevantes.
     * Incluye message_size para detección de attachments grandes (malware delivery).
     */
    recentEvents(limit) {
      // Filtramos el ruido de scanners: el puerto 9025/tcp también recibe
      // tráfico de port-scanners externos (GIOP/MQTT/etc.) que no son SMTP.
      // Solo retornamos eventos con al menos un campo email parseado para no
      // mostrar 200 filas de "?" al operador.
      return `
SELECT
  ${INGEST_TS}                                                  AS ts,
  COALESCE(sender_ip,     '?')                                 AS sender_ip,
  COALESCE(sender_email,  '?')                                 AS sender_email,
  COALESCE(sender_domain, '?')                                 AS sender_domain,
  COALESCE(recipient_email, '?')                               AS recipient_email,
  action,
  is_blocked,
  is_quarantined,
  spam_score,
  spam_category,
  auth_failed,
  auth_fail_type,
  dmarc_result,
  spf_result,
  dkim_result,
  COALESCE(pmg_process,   '?')                                 AS pmg_process,
  COALESCE(blocklist_ref, null)                                AS blocklist_ref,
  suspicious_url,
  sensor_host,
  queue_id,
  message_size
FROM ${t}
WHERE ${PART_2D}
  AND ${W24}
  AND (
    NULLIF(TRIM(sender_email),    '') IS NOT NULL OR
    NULLIF(TRIM(recipient_email), '') IS NOT NULL OR
    NULLIF(TRIM(sender_ip),       '') IS NOT NULL OR
    spam_score IS NOT NULL OR
    NULLIF(TRIM(action),          '') IS NOT NULL
  )
ORDER BY ${INGEST_TS} DESC
LIMIT ${limit}
`.trim();
    },

    /**
     * Resumen por proceso PMG (postfix/smtpd, pmg-smtp-filter, opendkim, etc.).
     * Ayuda a entender qué componente está bloqueando más.
     */
    byProcess24h(limit) {
      return `
SELECT
  COALESCE(pmg_process, '(desconocido)')   AS pmg_process,
  COUNT(*)                                  AS total,
  COUNT(*) FILTER (WHERE is_blocked = true) AS blocked
FROM ${t}
WHERE ${PART_2D}
  AND ${W24}
GROUP BY pmg_process
ORDER BY total DESC
LIMIT ${limit}
`.trim();
    },

    /**
     * Top N destinatarios más atacados — quién recibe más correos bloqueados/spam.
     * Útil para detectar usuarios de alto valor que son objetivos persistentes.
     */
    topRecipients24h(limit) {
      return `
SELECT
  COALESCE(recipient_email, '(desconocido)')     AS recipient_email,
  COUNT(*)                                        AS total_received,
  COUNT(*) FILTER (WHERE is_blocked = true)       AS blocked,
  COUNT(*) FILTER (WHERE is_quarantined = true)   AS quarantined,
  ROUND(CAST(AVG(spam_score) AS DOUBLE), 2)      AS avg_spam_score,
  COUNT(DISTINCT sender_ip)                       AS unique_senders,
  BOOL_OR(url_malicious)                          AS received_malicious_url
FROM ${t}
WHERE ${PART_2D}
  AND ${W24}
  AND recipient_email IS NOT NULL
  AND recipient_email <> '?'
GROUP BY recipient_email
ORDER BY blocked DESC, total_received DESC
LIMIT ${limit}
`.trim();
    },

    /**
     * Detección de campañas: IPs que atacan 2+ dominios distintos en 24 h.
     * Indica actividad coordinada de spam/phishing a múltiples organizaciones.
     */
    campaignClusters24h(limit) {
      return `
SELECT
  COALESCE(sender_ip, '(desconocida)')           AS sender_ip,
  COUNT(DISTINCT sender_domain)                   AS targeted_domains,
  COUNT(*)                                        AS total_emails,
  COUNT(*) FILTER (WHERE is_blocked = true)       AS blocked,
  MAX(spam_score)                                 AS max_spam_score,
  BOOL_OR(auth_failed)                            AS has_auth_fail,
  BOOL_OR(url_malicious)                          AS has_malicious_url,
  COUNT(DISTINCT recipient_email)                 AS unique_recipients
FROM ${t}
WHERE ${PART_2D}
  AND ${W24}
  AND sender_ip IS NOT NULL
GROUP BY sender_ip
HAVING COUNT(DISTINCT sender_domain) >= 2
ORDER BY targeted_domains DESC, total_emails DESC
LIMIT ${limit}
`.trim();
    },

    /**
     * Resumen de autenticación de email: DMARC / SPF / DKIM pass/fail/none.
     * Devuelve una sola fila con todos los contadores — para KPI inline o gráfico barras.
     */
    authBreakdown24h() {
      return `
SELECT
  COUNT(*) FILTER (WHERE lower(cast(coalesce(dmarc_result,'') AS varchar)) = 'fail') AS dmarc_fail,
  COUNT(*) FILTER (WHERE lower(cast(coalesce(dmarc_result,'') AS varchar)) = 'pass') AS dmarc_pass,
  COUNT(*) FILTER (WHERE dmarc_result IS NULL
    OR lower(cast(coalesce(dmarc_result,'') AS varchar)) NOT IN ('pass','fail'))      AS dmarc_none,
  COUNT(*) FILTER (WHERE lower(cast(coalesce(spf_result,'') AS varchar)) = 'fail')   AS spf_fail,
  COUNT(*) FILTER (WHERE lower(cast(coalesce(spf_result,'') AS varchar)) = 'pass')   AS spf_pass,
  COUNT(*) FILTER (WHERE spf_result IS NULL
    OR lower(cast(coalesce(spf_result,'') AS varchar)) NOT IN ('pass','fail'))        AS spf_none,
  COUNT(*) FILTER (WHERE lower(cast(coalesce(dkim_result,'') AS varchar)) = 'fail')  AS dkim_fail,
  COUNT(*) FILTER (WHERE lower(cast(coalesce(dkim_result,'') AS varchar)) = 'pass')  AS dkim_pass,
  COUNT(*) FILTER (WHERE dkim_result IS NULL
    OR lower(cast(coalesce(dkim_result,'') AS varchar)) NOT IN ('pass','fail'))       AS dkim_none
FROM ${t}
WHERE ${PART_2D}
  AND ${W24}
`.trim();
    },

    /**
     * Top N direcciones email remitentes (sender_email completo).
     * Permite detectar spoofing de direcciones conocidas y campañas dirigidas.
     */
    topSenderEmails24h(limit) {
      return `
SELECT
  COALESCE(sender_email,  '(desconocido)')   AS sender_email,
  COALESCE(sender_domain, '(sin dominio)')   AS sender_domain,
  COALESCE(sender_ip,     '(desconocida)')   AS sender_ip,
  COUNT(*)                                   AS total_events,
  COUNT(*) FILTER (WHERE is_blocked = true)  AS blocked,
  COUNT(*) FILTER (WHERE is_quarantined = true) AS quarantined,
  MAX(spam_score)                            AS max_spam_score,
  ROUND(CAST(AVG(spam_score) AS DOUBLE), 2) AS avg_spam_score,
  COUNT(DISTINCT recipient_email)            AS unique_recipients,
  BOOL_OR(auth_failed)                       AS has_auth_failure,
  BOOL_OR(url_malicious)                     AS has_malicious_url
FROM ${t}
WHERE ${PART_2D}
  AND ${W24}
  AND sender_email IS NOT NULL
  AND sender_email <> '?'
GROUP BY sender_email, sender_domain, sender_ip
ORDER BY blocked DESC, total_events DESC
LIMIT ${limit}
`.trim();
    },

    /**
     * Detección de spike de volumen: compara la última hora completa contra la anterior.
     * Devuelve una fila por hora (las 2 últimas) + ratio para detectar bursts.
     */
    volumeSpike2h() {
      return `
WITH hourly AS (
  SELECT
    date_trunc('hour', ${INGEST_TS})          AS hour_bucket,
    COUNT(*)                                   AS total,
    COUNT(*) FILTER (WHERE is_blocked = true)  AS blocked,
    COUNT(*) FILTER (WHERE auth_failed = true) AS auth_failures
  FROM ${t}
  WHERE ${PART_2D}
    AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '2' HOUR
  GROUP BY date_trunc('hour', ${INGEST_TS})
  ORDER BY hour_bucket DESC
  LIMIT 2
)
SELECT
  date_format(hour_bucket, '%H:00')   AS hora,
  total,
  blocked,
  auth_failures,
  LAG(total)   OVER (ORDER BY hour_bucket) AS prev_total,
  LAG(blocked) OVER (ORDER BY hour_bucket) AS prev_blocked,
  CASE
    WHEN LAG(total) OVER (ORDER BY hour_bucket) > 0
    THEN ROUND(CAST(total AS DOUBLE) / LAG(total) OVER (ORDER BY hour_bucket), 2)
    ELSE NULL
  END AS ratio_vs_prev
FROM hourly
ORDER BY hour_bucket DESC
`.trim();
    },

    /**
     * Tendencia diaria de eventos PMG (para gráfico de N días).
     */
    dailyTrend(days) {
      return `
SELECT
  date_format(date_trunc('day', ${INGEST_TS}), '%Y-%m-%d')  AS day_label,
  COUNT(*)                                                    AS total,
  COUNT(*) FILTER (WHERE is_blocked = true)                  AS blocked,
  COUNT(*) FILTER (WHERE auth_failed = true)                 AS auth_failures,
  ROUND(CAST(AVG(spam_score) AS DOUBLE), 2)                 AS avg_spam_score
FROM ${t}
WHERE ${partNDays(days)}
  AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${days}' DAY
GROUP BY date_trunc('day', ${INGEST_TS})
ORDER BY date_trunc('day', ${INGEST_TS}) ASC
`.trim();
    },
  };
}
