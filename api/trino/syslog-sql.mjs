/**
 * SQL syslog/filterlog — fuente canónica de verdad (backend).
 * El frontend ya no genera SQL propio; usa /api/trino/run con ids nombrados.
 */
import { stringStyleWindow } from "./time-window.mjs";

export function createSyslogSql(catalog, schema) {
  const s = `${catalog}.${schema}.syslog`;
  const { INGEST_TS, PART_2D, PART_3D, PART_TODAY, PART_CURRENT_YEAR } =
    stringStyleWindow();
  const FL_APP =
    "lower(trim(cast(coalesce(appname, '') AS varchar))) = 'filterlog'";
  const FL_MATCH = `(
  ${FL_APP}
  OR strpos(lower(cast(coalesce(message, '') AS varchar)), 'filterlog') > 0
)`;
  // Filterlog day-session: top del día por ingest_ts, fallback a partition hoy.
  // (Variante de PART_TODAY con start-of-day truncation; específico para syslog.)
  const FL_DAY_SESSION = `(
  ${INGEST_TS} >= date_trunc('day', current_timestamp)
  OR ${PART_TODAY}
)`;
  const WINDOW_24H_OR_TODAY = `(
  ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
  OR ${FL_DAY_SESSION}
)`;

  return {
    blocksLast24h() {
      return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${WINDOW_24H_OR_TODAY}
      AND ${PART_2D}
  `.trim();
    },
    blocksPrevious24h() {
      return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '48' HOUR
      AND ${INGEST_TS} < CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND ${PART_3D}
  `.trim();
    },
    uniqueBlockedIps24h() {
      return `
    SELECT COUNT(DISTINCT SPLIT_PART(message, ',', 19)) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND SPLIT_PART(message, ',', 19) NOT IN ('', '0.0.0.0')
      AND ${PART_2D}
  `.trim();
    },

    /**
     * KPIs perimetrales consolidados en 1 fila (1 scan en vez de 3).
     * Reemplaza el trío blocksLast24h + uniqueBlockedIps24h + topAttackedPorts.count
     * en dashboards tipo "resumen" donde sólo se necesitan los totales.
     * Devuelve: total_events, blocks, allowed, unique_src_ips, unique_dest_ports.
     */
    perimeterKpis24h() {
      return `
    SELECT
      COUNT(*)                                                    AS total_events,
      COUNT(*) FILTER (WHERE SPLIT_PART(message, ',', 7) = 'block') AS blocks,
      COUNT(*) FILTER (WHERE SPLIT_PART(message, ',', 7) = 'pass')  AS allowed,
      COUNT(DISTINCT CASE
        WHEN SPLIT_PART(message, ',', 7) = 'block'
         AND SPLIT_PART(message, ',', 19) NOT IN ('', '0.0.0.0')
         AND SPLIT_PART(message, ',', 19) NOT LIKE '192.168.%'
         AND SPLIT_PART(message, ',', 19) NOT LIKE '10.%'
        THEN SPLIT_PART(message, ',', 19)
      END)                                                        AS unique_attacker_ips,
      COUNT(DISTINCT CASE
        WHEN SPLIT_PART(message, ',', 7) = 'block'
         AND TRIM(SPLIT_PART(message, ',', 22)) NOT IN ('', '0')
        THEN TRIM(SPLIT_PART(message, ',', 22))
      END)                                                        AS unique_dest_ports
    FROM ${s}
    WHERE ${FL_MATCH}
      AND ${WINDOW_24H_OR_TODAY}
      AND ${PART_2D}
  `.trim();
    },
    uniqueBlockedIpsPrevious24h() {
      return `
    SELECT COUNT(DISTINCT SPLIT_PART(message, ',', 19)) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '48' HOUR
      AND ${INGEST_TS} < CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND SPLIT_PART(message, ',', 19) NOT IN ('', '0.0.0.0')
      AND ${PART_3D}
  `.trim();
    },
    /** Conteo de bloqueos en ventana de N horas. */
    blocksLastNh(hours) {
      const partHint = hours <= 25 ? `AND ${PART_2D}` : hours <= 49 ? `AND ${PART_3D}` : `AND ${PART_CURRENT_YEAR}`;
      return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
      ${partHint}
  `.trim();
    },

    /** IPs atacantes únicas en ventana de N horas. */
    uniqueBlockedIpsNh(hours) {
      const partHint = hours <= 25 ? `AND ${PART_2D}` : hours <= 49 ? `AND ${PART_3D}` : `AND ${PART_CURRENT_YEAR}`;
      return `
    SELECT COUNT(DISTINCT SPLIT_PART(message, ',', 19)) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
      AND SPLIT_PART(message, ',', 19) NOT IN ('', '0.0.0.0')
      ${partHint}
  `.trim();
    },

    blocksByDay(days) {
      // Para ventanas ≤30 d se incluye hint de año en curso para podar años anteriores.
      const yearHint = days <= 366 ? `AND ${PART_CURRENT_YEAR}` : "";
      return `
    SELECT
      DATE(${INGEST_TS}) AS day,
      COUNT(*) AS blocks
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${days}' DAY
      ${yearHint}
    GROUP BY 1
    ORDER BY 1
  `.trim();
    },
    blocksByHourLast24h() {
      return `
    SELECT
      date_trunc('hour', ${INGEST_TS}) AS hour,
      COUNT(*) AS blocks
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND ${PART_2D}
    GROUP BY 1
    ORDER BY 1
  `.trim();
    },
    uniqueBlockedIpsByHourLast24h() {
      return `
    SELECT
      date_trunc('hour', ${INGEST_TS}) AS hour,
      COUNT(DISTINCT SPLIT_PART(message, ',', 19)) AS uniq_ips
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND SPLIT_PART(message, ',', 19) NOT IN ('', '0.0.0.0')
      AND ${PART_2D}
    GROUP BY 1
    ORDER BY 1
  `.trim();
    },
    topBlockedIps(limit, hours) {
      // Partition hint: cubrir los días exactos del período solicitado (hasta 31 días = año actual).
      const partHint = hours <= 25 ? `AND ${PART_2D}` : hours <= 49 ? `AND ${PART_3D}` : `AND ${PART_CURRENT_YEAR}`;
      return `
    SELECT
      SPLIT_PART(message, ',', 19) AS src_ip,
      COUNT(*) AS hits
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
      AND SPLIT_PART(message, ',', 19) NOT LIKE '192.168.%'
      AND SPLIT_PART(message, ',', 19) NOT LIKE '10.%'
      AND SPLIT_PART(message, ',', 19) != ''
      ${partHint}
    GROUP BY 1
    ORDER BY hits DESC
    LIMIT ${limit}
  `.trim();
    },

    /**
     * Top IPs bloqueadas enriquecidas con sensor de origen y las interfaces que reportaron el bloqueo.
     *
     * Campos de origen disponibles en filterlog (CSV dentro de `message`):
     *   pos 5  → interfaz del firewall (e.g. "igc0", "vtnet0", "em1")
     *   pos 7  → acción ("block" / "pass")
     *   pos 9  → versión IP (4 / 6)
     *   pos 17 → protocolo nombre (tcp, udp, icmp)
     *   pos 19 → IP origen del atacante
     *   pos 20 → IP destino
     *   pos 22 → puerto destino
     *
     * Campos de nivel syslog:
     *   source_ip  → IP del dispositivo OPNsense que envió el syslog (identifica el sensor)
     *   appname    → aplicación (filterlog / openvpn / etc.)
     *
     * @param {number} limit
     * @param {number} hours
     */
    topBlockedIpsWithSensor(limit, hours) {
      const partHint = hours <= 25 ? `AND ${PART_2D}` : hours <= 49 ? `AND ${PART_3D}` : `AND ${PART_CURRENT_YEAR}`;
      return `
    WITH fl AS (
      SELECT
        TRIM(SPLIT_PART(message, ',', 19))                          AS src_ip,
        TRIM(CAST(COALESCE(source_ip, '') AS varchar))              AS sensor_ip,
        TRIM(SPLIT_PART(message, ',', 5))                           AS iface,
        TRIM(SPLIT_PART(message, ',', 17))                          AS proto,
        TRIM(SPLIT_PART(message, ',', 20))                          AS dst_ip,
        TRIM(SPLIT_PART(message, ',', 22))                          AS dst_port
      FROM ${s}
      WHERE ${FL_MATCH}
        AND SPLIT_PART(message, ',', 7) = 'block'
        AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
        AND SPLIT_PART(message, ',', 19) NOT LIKE '192.168.%'
        AND SPLIT_PART(message, ',', 19) NOT LIKE '10.%'
        AND SPLIT_PART(message, ',', 19) != ''
        ${partHint}
    )
    SELECT
      src_ip,
      COUNT(*)                                                      AS hits,
      ARRAY_JOIN(
        ARRAY_DISTINCT(FILTER(ARRAY_AGG(sensor_ip), x -> x != '')),
        ', '
      )                                                             AS sensor_ips,
      ARRAY_JOIN(
        ARRAY_DISTINCT(FILTER(ARRAY_AGG(iface), x -> x != '')),
        ', '
      )                                                             AS ifaces,
      ARRAY_JOIN(
        ARRAY_DISTINCT(FILTER(ARRAY_AGG(proto), x -> x != '')),
        ', '
      )                                                             AS protos,
      -- dst_port es la única alta cardinalidad real del query: una IP
      -- haciendo port-scan puede generar miles de puertos distintos. SLICE
      -- a 20 evita arrays gigantes antes del JOIN (worker OOM).
      ARRAY_JOIN(
        SLICE(
          ARRAY_DISTINCT(FILTER(
            ARRAY_AGG(dst_port),
            x -> x != '' AND x != '0'
          )),
          1, 20
        ),
        ', '
      )                                                             AS dst_ports_sample
    FROM fl
    WHERE src_ip != ''
    GROUP BY src_ip
    ORDER BY hits DESC
    LIMIT ${limit}
  `.trim();
    },

    /**
     * Desglose por sensor (source_ip + interfaz) para una IP atacante específica.
     * Útil en el panel de investigación para mostrar "quién reportó esta IP".
     *
     * @param {string} ip  — ya validada como IPv4/IPv6 limpia
     * @param {number} hours
     */
    sensorBreakdownForIp(ip, hours) {
      const partHint = hours <= 25 ? `AND ${PART_2D}` : hours <= 49 ? `AND ${PART_3D}` : `AND ${PART_CURRENT_YEAR}`;
      return `
    SELECT
      TRIM(CAST(COALESCE(source_ip, '') AS varchar))               AS sensor_ip,
      TRIM(SPLIT_PART(message, ',', 5))                            AS iface,
      TRIM(SPLIT_PART(message, ',', 17))                           AS proto,
      COUNT(*)                                                     AS hits,
      CAST(MIN(${INGEST_TS}) AS varchar)                           AS first_seen,
      CAST(MAX(${INGEST_TS}) AS varchar)                           AS last_seen,
      ARRAY_JOIN(
        ARRAY_DISTINCT(FILTER(
          ARRAY_AGG(TRIM(SPLIT_PART(message, ',', 22))),
          x -> x != '' AND x != '0'
        )),
        ', '
      )                                                            AS dst_ports
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND SPLIT_PART(message, ',', 19) = '${ip}'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
      ${partHint}
    GROUP BY
      TRIM(CAST(COALESCE(source_ip, '') AS varchar)),
      TRIM(SPLIT_PART(message, ',', 5)),
      TRIM(SPLIT_PART(message, ',', 17))
    ORDER BY hits DESC
  `.trim();
    },
    topAttackedPorts(limit, hours) {
      const partHint = hours <= 25 ? `AND ${PART_2D}` : hours <= 49 ? `AND ${PART_3D}` : `AND ${PART_CURRENT_YEAR}`;
      return `
    SELECT
      SPLIT_PART(message, ',', 22) AS dst_port,
      COUNT(*) AS hits
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
      ${partHint}
    GROUP BY 1
    ORDER BY hits DESC
    LIMIT ${limit}
  `.trim();
    },

    /**
     * Bundle del Centro de mando: blocks + uniqueIps + topIps + topPorts en
     * una sola query con un único scan sobre `syslog`. Reemplaza 4 scans
     * paralelos (~10s c/u serializados por Trino → ~20-40s) por 1 scan +
     * 3 agregaciones (~3-5s).
     *
     * Shape de la respuesta (UNION ALL):
     *   kind='total'    label=NULL     hits=total_blocks   unique_ips=unique
     *   kind='top_ip'   label=src_ip   hits=count          unique_ips=NULL
     *   kind='top_port' label=dst_port hits=count          unique_ips=NULL
     */
    overviewBundleNh(hours, topIpLimit, topPortLimit) {
      const partHint = hours <= 25 ? `AND ${PART_2D}` : hours <= 49 ? `AND ${PART_3D}` : `AND ${PART_CURRENT_YEAR}`;
      return `
    WITH base AS (
      SELECT
        SPLIT_PART(message, ',', 19) AS src_ip,
        SPLIT_PART(message, ',', 22) AS dst_port
      FROM ${s}
      WHERE ${FL_MATCH}
        AND SPLIT_PART(message, ',', 7) = 'block'
        AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
        ${partHint}
    ),
    totals AS (
      SELECT
        COUNT(*)                                                  AS hits,
        COUNT(DISTINCT CASE
          WHEN src_ip NOT IN ('', '0.0.0.0') THEN src_ip
        END)                                                      AS unique_ips
      FROM base
    ),
    top_ips AS (
      SELECT src_ip AS label, COUNT(*) AS hits
      FROM base
      WHERE src_ip <> ''
        AND src_ip NOT LIKE '192.168.%'
        AND src_ip NOT LIKE '10.%'
      GROUP BY src_ip
      ORDER BY COUNT(*) DESC
      LIMIT ${topIpLimit}
    ),
    top_ports AS (
      SELECT dst_port AS label, COUNT(*) AS hits
      FROM base
      GROUP BY dst_port
      ORDER BY COUNT(*) DESC
      LIMIT ${topPortLimit}
    )
    SELECT 'total'    AS kind, CAST(NULL AS varchar) AS label, hits, unique_ips           FROM totals
    UNION ALL
    SELECT 'top_ip'   AS kind, label,                          hits, CAST(NULL AS bigint) FROM top_ips
    UNION ALL
    SELECT 'top_port' AS kind, label,                          hits, CAST(NULL AS bigint) FROM top_ports
  `.trim();
    },
    lateralMovementCandidatesToday(limit) {
      return `
    SELECT
      TRIM(SPLIT_PART(message, ',', 19)) AS src_ip,
      COUNT(DISTINCT COALESCE(TRIM(SPLIT_PART(message, ',', 22)), '')) AS unique_dst_ports,
      COUNT(*) AS events
    FROM ${s}
    WHERE ${FL_MATCH}
      AND ${FL_DAY_SESSION}
      AND TRIM(SPLIT_PART(message, ',', 19)) <> ''
      AND (
        TRIM(SPLIT_PART(message, ',', 19)) LIKE '192.168.%'
        OR TRIM(SPLIT_PART(message, ',', 19)) LIKE '10.%'
        OR REGEXP_LIKE(TRIM(SPLIT_PART(message, ',', 19)), '^172\\.(1[6-9]|2[0-9]|3[01])\\.')
      )
    GROUP BY 1
    HAVING COUNT(DISTINCT COALESCE(TRIM(SPLIT_PART(message, ',', 22)), '')) >= 4
    ORDER BY unique_dst_ports DESC, events DESC
    LIMIT ${limit}
  `.trim();
    },
    filterlogEventsLast24h() {
      return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND ${WINDOW_24H_OR_TODAY}
      AND ${PART_2D}
  `.trim();
    },
    syslogRowsLast168hOrTodayPartition() {
      return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE (${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '168' HOUR
      OR ${FL_DAY_SESSION})
      AND ${PART_CURRENT_YEAR}
  `.trim();
    },
    syslogSendersLast24h() {
      return `
WITH base AS (
  SELECT
    TRIM(CAST(source_ip AS varchar))                                    AS source_ip,
    COALESCE(TRIM(CAST(hostname AS varchar)),
             TRIM(CAST(host     AS varchar)), '—')                     AS hostname,
    -- Inferir tipo de sensor desde appname (lo escribe el propio dispositivo)
    CASE
      WHEN lower(TRIM(CAST(COALESCE(appname,'') AS varchar))) = 'filterlog'
        THEN 'opnsense_filterlog'
      WHEN lower(TRIM(CAST(COALESCE(appname,'') AS varchar)))
           IN ('ossec','wazuh','wazuh-manager')
        THEN 'wazuh_alert'
      WHEN lower(TRIM(CAST(COALESCE(appname,'') AS varchar)))
           LIKE '%suricata%'
        THEN 'suricata_eve'
      ELSE 'syslog_other'
    END                                                                AS log_family,
    TRIM(CAST(COALESCE(appname,'—') AS varchar))                       AS appname,
    COUNT(*)                                                           AS c
  FROM ${s}
  WHERE (
      ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      OR ${FL_DAY_SESSION}
    )
    AND source_ip IS NOT NULL
    AND TRIM(CAST(source_ip AS varchar)) <> ''
    AND ${PART_2D}
  GROUP BY 1, 2, 3, 4
),
totals AS (
  SELECT source_ip, SUM(c) AS total
  FROM base GROUP BY source_ip
),
dominant AS (
  SELECT DISTINCT
    source_ip,
    max_by(log_family, c) OVER (PARTITION BY source_ip) AS log_family,
    max_by(appname,    c) OVER (PARTITION BY source_ip) AS appname,
    max_by(hostname,   c) OVER (PARTITION BY source_ip) AS hostname
  FROM base
)
SELECT
  t.source_ip,
  d.hostname,
  t.total    AS c,
  d.log_family,
  d.appname
FROM totals t
JOIN dominant d ON d.source_ip = t.source_ip
ORDER BY t.total DESC
LIMIT 20
  `.trim();
    },
    syslogAnyRowSql() {
      return `SELECT 1 AS ok FROM ${s} LIMIT 1`;
    },
    filterlogAnyRowSql() {
      return `
    SELECT 1 AS ok
    FROM ${s}
    WHERE ${FL_MATCH}
    LIMIT 1
  `.trim();
    },
    filterlogEventsToday() {
      return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND ${FL_DAY_SESSION}
  `.trim();
    },
    /**
     * @param {string} ip — ya validado como IP en registry (regex IPv4/IPv6; sin comillas externas).
     * @param {number} hours
     */
    blockCountForIp(ip, hours) {
      // La IP llega validada desde registry (solo chars [0-9a-fA-F.:]); se embebe como literal SQL.
      return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND SPLIT_PART(message, ',', 19) = '${ip}'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
  `.trim();
    },
    /**
     * Feed de IPs bloqueadas para el panel "Live Logs" (polling).
     * @param {number} limit
     * @param {number} minutes
     */
    recentBlockedIpsForLiveFeed(limit, minutes) {
      return `
    SELECT
      SPLIT_PART(message, ',', 19) AS src_ip,
      COUNT(*) AS hits,
      MAX(ingest_time) AS last_seen
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${minutes}' MINUTE
      AND SPLIT_PART(message, ',', 19) IS NOT NULL
      AND TRIM(SPLIT_PART(message, ',', 19)) <> ''
      AND ${PART_2D}
    GROUP BY 1
    ORDER BY MAX(${INGEST_TS}) DESC
    LIMIT ${limit}
  `.trim();
    },
    /**
     * Líneas filterlog recientes (texto crudo para feed SOC).
     * @param {number} limit
     * @param {number} minutes
     */
    recentFilterlogLines(limit, minutes) {
      return `
    SELECT CAST(ingest_time AS varchar) AS ingest_time, message
    FROM ${s}
    WHERE ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${minutes}' MINUTE
      AND ${PART_2D}
    ORDER BY ${INGEST_TS} DESC
    LIMIT ${limit}
  `.trim();
    },
    // ── VPN events (OPNsense OpenVPN / IPsec / WireGuard) ─────────────────
    vpnEventsLast24h() {
      const VPN = `lower(trim(cast(coalesce(appname,'') AS varchar))) IN ('openvpn','charon','wireguard','ppp','ipsec','l2tp','xl2tpd','ipsec-starter','strongswan')`;
      return `
    SELECT COUNT(*) AS c
    FROM ${s}
    WHERE (${VPN} OR strpos(lower(cast(coalesce(message,'') AS varchar)), 'openvpn') > 0)
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND ${PART_2D}
    `.trim();
    },
    vpnConnectionEvents(limit, hours) {
      const VPN = `lower(trim(cast(coalesce(appname,'') AS varchar))) IN ('openvpn','charon','wireguard','ppp','ipsec','l2tp','xl2tpd','ipsec-starter','strongswan')`;
      const partHint = hours <= 25 ? `AND ${PART_2D}` : hours <= 49 ? `AND ${PART_3D}` : `AND ${PART_CURRENT_YEAR}`;
      return `
    SELECT
      CAST(${INGEST_TS} AS varchar) AS ts,
      TRIM(CAST(COALESCE(appname,'vpn') AS varchar)) AS service,
      TRIM(CAST(COALESCE(source_ip,'') AS varchar)) AS source_ip,
      SUBSTRING(TRIM(CAST(COALESCE(message,'') AS varchar)), 1, 200) AS message,
      CASE
        WHEN regexp_like(lower(CAST(message AS varchar)), 'authenticated|peer connection initiated|login succeed|connected')
          THEN 'connect'
        WHEN regexp_like(lower(CAST(message AS varchar)), 'connection closed|connection reset|disconnected|terminated|closing|exiting')
          THEN 'disconnect'
        WHEN regexp_like(lower(CAST(message AS varchar)), 'auth.?fail|authentication fail|tls error|tls_error|no matching|denied|refused|invalid user')
          THEN 'failed'
        ELSE 'info'
      END AS event_type
    FROM ${s}
    WHERE (${VPN} OR strpos(lower(cast(coalesce(message,'') AS varchar)), 'openvpn') > 0)
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '${hours}' HOUR
      ${partHint}
    ORDER BY ${INGEST_TS} DESC
    LIMIT ${limit}
    `.trim();
    },
    vpnFailedAuthLast24h(limit) {
      const VPN = `lower(trim(cast(coalesce(appname,'') AS varchar))) IN ('openvpn','charon','wireguard','ppp','ipsec','l2tp','xl2tpd','ipsec-starter','strongswan')`;
      return `
    SELECT
      CAST(${INGEST_TS} AS varchar) AS ts,
      TRIM(CAST(COALESCE(appname,'vpn') AS varchar)) AS service,
      TRIM(CAST(COALESCE(source_ip,'') AS varchar)) AS source_ip,
      SUBSTRING(TRIM(CAST(COALESCE(message,'') AS varchar)), 1, 200) AS message
    FROM ${s}
    WHERE (${VPN} OR strpos(lower(cast(coalesce(message,'') AS varchar)), 'openvpn') > 0)
      AND regexp_like(lower(CAST(message AS varchar)), 'auth.?fail|authentication fail|tls error|tls_error|no matching|denied|refused|invalid user')
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND ${PART_2D}
    ORDER BY ${INGEST_TS} DESC
    LIMIT ${limit}
    `.trim();
    },
    vpnEventsByHour24h() {
      const VPN = `lower(trim(cast(coalesce(appname,'') AS varchar))) IN ('openvpn','charon','wireguard','ppp','ipsec','l2tp','xl2tpd','ipsec-starter','strongswan')`;
      return `
    SELECT
      date_trunc('hour', ${INGEST_TS}) AS hour,
      COUNT(*) AS events
    FROM ${s}
    WHERE (${VPN} OR strpos(lower(cast(coalesce(message,'') AS varchar)), 'openvpn') > 0)
      AND ${INGEST_TS} >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
      AND ${PART_2D}
    GROUP BY 1
    ORDER BY 1
    `.trim();
    },

    /**
     * Top IPs bloqueadas en un mes calendario (año/mes como VARCHAR; ya validados en registry).
     * @param {number} limit
     * @param {string} year  — YYYY
     * @param {string} month — MM o M (lpad en la query)
     */
    topBlockedIpsCalendar(limit, year, month) {
      return `
    SELECT
      SPLIT_PART(message, ',', 19) AS src_ip,
      COUNT(*) AS hits
    FROM ${s}
    WHERE year = '${year}'
      AND lpad(trim(cast(coalesce(month, '') AS varchar)), 2, '0') = lpad('${month}', 2, '0')
      AND ${FL_MATCH}
      AND SPLIT_PART(message, ',', 7) = 'block'
      AND SPLIT_PART(message, ',', 19) NOT LIKE '192.168.%'
      AND SPLIT_PART(message, ',', 19) NOT LIKE '10.%'
      AND SPLIT_PART(message, ',', 19) != ''
    GROUP BY 1
    ORDER BY hits DESC
    LIMIT ${limit}
  `.trim();
    },
  };
}
