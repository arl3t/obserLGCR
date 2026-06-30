/**
 * Hunts MITRE ATT&CK → CTAS en hunting.ioc_* (misma lógica que scripts/sql/soc-mitre/*.sql).
 * Mantener sincronizado con los .sql del repo al cambiar consultas.
 */
export const SOC_MITRE_HUNTS = [
  {
    id: "ta0001",
    tactic: "TA0001",
    title: "Reconnaissance — escaneo de puertos (filterlog bloqueado, in)",
    description:
      "IPs externas con muchos puertos destino distintos en el día calendario anterior.",
    table: "ioc_port_scanners",
    namedQueryId: "lh.soc.ioc_port_scanners",
    requiresLeakIntel: false,
    sql: `CREATE TABLE ioc_port_scanners AS
SELECT
  TRIM(SPLIT_PART(message, ',', 19)) AS src_ip,
  COUNT(DISTINCT TRIM(SPLIT_PART(message, ',', 22))) AS ports_scanned,
  COUNT(*) AS total_attempts,
  array_agg(DISTINCT TRIM(SPLIT_PART(message, ',', 5))) AS interfaces
FROM syslog
WHERE (lower(trim(appname)) = 'filterlog' OR strpos(lower(cast(message AS varchar)), 'filterlog') > 0)
  AND TRIM(SPLIT_PART(message, ',', 7)) = 'block'
  AND lower(TRIM(SPLIT_PART(message, ',', 8))) = 'in'
  AND TRIM(SPLIT_PART(message, ',', 19)) NOT LIKE '192.168.%'
  AND TRIM(SPLIT_PART(message, ',', 19)) NOT LIKE '10.%'
  AND TRIM(SPLIT_PART(message, ',', 19)) <> ''
  AND year = date_format(current_date - INTERVAL '1' DAY, '%Y')
  AND lpad(trim(cast(month AS varchar)), 2, '0') = date_format(current_date - INTERVAL '1' DAY, '%m')
  AND lpad(trim(cast(day AS varchar)), 2, '0') = date_format(current_date - INTERVAL '1' DAY, '%d')
GROUP BY TRIM(SPLIT_PART(message, ',', 19))
HAVING COUNT(DISTINCT TRIM(SPLIT_PART(message, ',', 22))) > 15`,
  },
  {
    id: "ta0002",
    tactic: "TA0002",
    title: "Initial Access — puertos de exposición (SSH, RDP, SMB, …)",
    description: "Bloqueos entrantes ≥5 en 7 días hacia puertos sensibles.",
    table: "ioc_initial_access_attempts",
    namedQueryId: "lh.soc.ioc_initial_access_attempts",
    requiresLeakIntel: false,
    sql: `CREATE TABLE ioc_initial_access_attempts AS
SELECT
  TRIM(SPLIT_PART(message, ',', 19)) AS src_ip,
  TRIM(SPLIT_PART(message, ',', 22)) AS dst_port,
  lower(TRIM(SPLIT_PART(message, ',', 17))) AS protocol,
  COUNT(*) AS attempts,
  max(TRY(from_iso8601_timestamp(trim(cast(ingest_time AS varchar))))) AS last_attempt
FROM syslog
WHERE (lower(trim(appname)) = 'filterlog' OR strpos(lower(cast(message AS varchar)), 'filterlog') > 0)
  AND TRIM(SPLIT_PART(message, ',', 7)) = 'block'
  AND lower(TRIM(SPLIT_PART(message, ',', 8))) = 'in'
  AND TRY_CAST(TRIM(SPLIT_PART(message, ',', 22)) AS integer) IN (22, 3389, 445, 139, 3260, 5985, 5986)
  AND TRY(from_iso8601_timestamp(trim(cast(ingest_time AS varchar)))) >= current_timestamp - INTERVAL '7' DAY
  AND year = date_format(current_date, '%Y')
GROUP BY 1, 2, 3
HAVING COUNT(*) >= 5`,
  },
  {
    id: "ta0003",
    tactic: "TA0003",
    title: "Persistence — conexiones recurrentes mismo puerto",
    description: "Varios días de actividad y volumen alto (posible C2 ruidoso).",
    table: "ioc_persistent_connections",
    namedQueryId: "lh.soc.ioc_persistent_connections",
    requiresLeakIntel: false,
    sql: `CREATE TABLE ioc_persistent_connections AS
SELECT
  TRIM(SPLIT_PART(message, ',', 19)) AS src_ip,
  TRIM(SPLIT_PART(message, ',', 22)) AS dst_port,
  COUNT(DISTINCT concat(trim(year), '-', lpad(trim(cast(month AS varchar)), 2, '0'), '-', lpad(trim(cast(day AS varchar)), 2, '0'))) AS days_active,
  COUNT(*) AS total_connections
FROM syslog
WHERE (lower(trim(appname)) = 'filterlog' OR strpos(lower(cast(message AS varchar)), 'filterlog') > 0)
  AND TRIM(SPLIT_PART(message, ',', 7)) = 'block'
  AND lower(TRIM(SPLIT_PART(message, ',', 8))) = 'in'
  AND year = date_format(current_date, '%Y')
GROUP BY 1, 2
HAVING COUNT(DISTINCT concat(trim(year), '-', lpad(trim(cast(month AS varchar)), 2, '0'), '-', lpad(trim(cast(day AS varchar)), 2, '0'))) >= 3
   AND COUNT(*) >= 20`,
  },
  {
    id: "ta0004",
    tactic: "TA0004 / TA0005",
    title: "Defense Evasion — alto volumen UDP (puertos altos)",
    description: "Muchos eventos UDP bloqueados; revisar falsos positivos.",
    table: "ioc_defense_evasion_udp",
    namedQueryId: "lh.soc.ioc_defense_evasion_udp",
    requiresLeakIntel: false,
    sql: `CREATE TABLE ioc_defense_evasion_udp AS
SELECT
  TRIM(SPLIT_PART(message, ',', 19)) AS src_ip,
  COUNT(*) AS udp_events,
  avg(TRY_CAST(TRIM(SPLIT_PART(message, ',', 18)) AS double)) AS avg_declared_length
FROM syslog
WHERE (lower(trim(appname)) = 'filterlog' OR strpos(lower(cast(message AS varchar)), 'filterlog') > 0)
  AND lower(TRIM(SPLIT_PART(message, ',', 17))) = 'udp'
  AND TRIM(SPLIT_PART(message, ',', 7)) = 'block'
  AND TRY_CAST(TRIM(SPLIT_PART(message, ',', 22)) AS integer) > 1024
  AND year = date_format(current_date - INTERVAL '1' DAY, '%Y')
  AND lpad(trim(cast(month AS varchar)), 2, '0') = date_format(current_date - INTERVAL '1' DAY, '%m')
  AND lpad(trim(cast(day AS varchar)), 2, '0') = date_format(current_date - INTERVAL '1' DAY, '%d')
GROUP BY 1
HAVING COUNT(*) > 500`,
  },
  {
    id: "ta0006",
    tactic: "TA0006",
    title: "Credential Access — correlación con leak_intel",
    description: "Requiere tabla hunting.leak_intel (src_ip, leak_name).",
    table: "ioc_credential_stuffing",
    namedQueryId: "lh.soc.ioc_credential_stuffing",
    requiresLeakIntel: true,
    sql: `CREATE TABLE ioc_credential_stuffing AS
SELECT
  TRIM(SPLIT_PART(f.message, ',', 19)) AS src_ip,
  l.leak_name,
  COUNT(*) AS correlation_hits
FROM syslog f
INNER JOIN leak_intel l
  ON TRIM(SPLIT_PART(f.message, ',', 19)) = l.src_ip
WHERE (lower(trim(f.appname)) = 'filterlog' OR strpos(lower(cast(f.message AS varchar)), 'filterlog') > 0)
  AND TRIM(SPLIT_PART(f.message, ',', 7)) = 'block'
  AND f.year = date_format(current_date - INTERVAL '1' DAY, '%Y')
  AND lpad(trim(cast(f.month AS varchar)), 2, '0') = date_format(current_date - INTERVAL '1' DAY, '%m')
  AND lpad(trim(cast(f.day AS varchar)), 2, '0') = date_format(current_date - INTERVAL '1' DAY, '%d')
GROUP BY 1, 2`,
  },
  {
    id: "ta0007",
    tactic: "TA0007 / TA0008",
    title: "Discovery / Lateral movement — multicast y broadcast",
    description: "Destinos 224.x, 239.x o 255.255.255.255 en bloqueos.",
    table: "ioc_lateral_movement",
    namedQueryId: "lh.soc.ioc_lateral_movement",
    requiresLeakIntel: false,
    sql: `CREATE TABLE ioc_lateral_movement AS
SELECT
  TRIM(SPLIT_PART(message, ',', 19)) AS src_ip,
  TRIM(SPLIT_PART(message, ',', 20)) AS dst_ip,
  COUNT(*) AS attempts
FROM syslog
WHERE (lower(trim(appname)) = 'filterlog' OR strpos(lower(cast(message AS varchar)), 'filterlog') > 0)
  AND TRIM(SPLIT_PART(message, ',', 7)) = 'block'
  AND (
    TRIM(SPLIT_PART(message, ',', 20)) LIKE '224.%'
    OR TRIM(SPLIT_PART(message, ',', 20)) LIKE '239.%'
    OR TRIM(SPLIT_PART(message, ',', 20)) = '255.255.255.255'
  )
  AND year = date_format(current_date, '%Y')
GROUP BY 1, 2
HAVING COUNT(*) > 10`,
  },
];

const byId = new Map(SOC_MITRE_HUNTS.map((h) => [h.id, h]));

export function listSocMitreHunts() {
  return SOC_MITRE_HUNTS.map(({ sql, ...rest }) => rest);
}

export function getSocMitreHunt(idRaw) {
  const id = String(idRaw ?? "")
    .trim()
    .toLowerCase();
  return byId.get(id) ?? null;
}
