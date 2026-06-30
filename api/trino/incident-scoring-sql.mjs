/**
 * Consultas sobre `v_incident_score` e `incident_classifications` (Iceberg hunting).
 * La vista calcula el score compuesto: mitre_pts (0-40) + evidence_pts (0-35) + wazuh_pts (0-25).
 * Severidad: CRITICAL ≥ 75 | HIGH ≥ 50 | MEDIUM ≥ 25 | LOW < 25
 */
// Nota: previo a 2026-05-27 se importaban syslogIngestTimestampExpr y
// partitionFilter para el WITH inline de mttdMultiSensor. Ahora la lógica
// vive en mv_first_alert_per_ioc (DAG cross-source) y la query queda como
// SELECT directo sobre esa tabla — sin necesidad de los helpers en runtime.

/**
 * @param {string} catalog       — Iceberg hunting catalog (incident_classifications, etc.)
 * @param {string} schema        — Iceberg hunting schema
 * @param {object|string} sources — Tablas de sensores que aportan first-alert para MTTD.
 *   Forma nueva (recomendada): { wazuh, syslog, fortigate, pmgPhishing } — strings FQN.
 *   Forma legacy: string con la FQN de wazuh_alerts (back-compat).
 *   Si ninguna se aporta, mttdMultiSensor devuelve NULL sin error.
 */
export function createIncidentScoringSql(catalog, schema, sources = "") {
  const tv = `${catalog}.${schema}.v_incident_score`;
  const tv2 = `${catalog}.${schema}.v_incident_score_v2_runtime`;
  /** Vista v2 base (bootstrap `21_v2_view`); `live_meta` en managedIncidents usa esto para no depender de `v_incident_score_v2_runtime` (solo API + scoring_formula_config). */
  const tv2Base = `${catalog}.${schema}.v_incident_score_v2`;
  /** Tabla materializada diaria: snapshot post-enriquecimiento del DAG diario.
   *  Sustituye a tv2 para las consultas del dashboard en tiempo real.
   *  Generada por scripts/sql/threat-hunt/28_materialize_incident_score_v2.sql */
  const tv2mat = `${catalog}.${schema}.incident_score_v2_mat`;
  /** Tabla materializada v4 — scoring con bonos Trino-native.
   *  Generada por scripts/sql/threat-hunt/44_materialize_incident_score_v4.sql
   *  Incluye: score_v4 (kill-chain + temporal + geo-risk), severity_v4.
   *  Requires DAG task t_materialize_score_v4 ejecutado al menos una vez. */
  const tv4mat = `${catalog}.${schema}.incident_score_v4_mat`;
  const tc = `${catalog}.${schema}.incident_classifications`;
  const tScoringCfg = `${catalog}.${schema}.scoring_formula_config`;
  const tBusinessTags = `${catalog}.${schema}.business_ip_tags`;

  // Normalizar sources: aceptamos string legacy (solo wazuh) o objeto multi-fuente.
  const sensors = typeof sources === "string"
    ? { wazuh: sources, syslog: "", fortigate: "", pmgPhishing: "" }
    : {
        wazuh:       sources.wazuh       ?? "",
        syslog:      sources.syslog      ?? "",
        fortigate:   sources.fortigate   ?? "",
        pmgPhishing: sources.pmgPhishing ?? "",
      };

  /**
   * Devuelve una cláusula SQL `AND severity IN (...)` para filtrar por severidad
   * mínima. Si `min` es falsy / 'NEGLIGIBLE' / desconocida, devuelve "" (sin
   * filtro). Mantengo los valores válidos acá en una sola lista para no
   * divergir del router.
   */
  function chatSeverityFilter(min) {
    const order = ["NEGLIGIBLE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
    const upper = String(min ?? "").toUpperCase().trim();
    const idx = order.indexOf(upper);
    if (idx <= 0) return ""; // NEGLIGIBLE o inválido → sin filtro
    const allowed = order.slice(idx).map((s) => `'${s}'`).join(",");
    return `AND severity IN (${allowed})`;
  }

  return {
    /**
     * KPIs globales: total IOCs, distribución de severidad, score promedio.
     * @param {number} days
     */
    kpis(days) {
      const d = Number(days);
      return `
SELECT
  COUNT(*)                                                         AS total_iocs,
  SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END)          AS critical_count,
  SUM(CASE WHEN severity = 'HIGH'     THEN 1 ELSE 0 END)          AS high_count,
  SUM(CASE WHEN severity = 'MEDIUM'   THEN 1 ELSE 0 END)          AS medium_count,
  SUM(CASE WHEN severity = 'LOW'      THEN 1 ELSE 0 END)          AS low_count,
  ROUND(AVG(CAST(score AS double)), 1)                             AS avg_score,
  MAX(score)                                                       AS max_score,
  CAST(MAX(dt) AS varchar)                                         AS last_dt
FROM ${tv2}
WHERE dt >= current_date - INTERVAL '${d}' DAY
`.trim();
    },

    /**
     * Top N incidentes por score descendente.
     *
     * Fuente: `incident_score_v2_mat` (materializada refrescada cada 6h por
     * el DAG incident_score_v2_refresh_6h). Antes usaba `v_incident_score_v2_runtime`
     * que recalculaba el score en vivo (~15-20s para LIMIT 200).
     *
     * IMPORTANTE — sin JOIN a Iceberg `incident_cases`: el JOIN `MAX_BY(case_id,
     * last_seen) GROUP BY ioc_value` sobre esa tabla tarda 2-3 minutos por
     * metadata explotada (Trino 435 no auto-limpia; ver iceberg_metadata_maintenance
     * memory note). Las columnas `case_id` / `case_status` se devuelven como
     * NULL y se enriquecen client-side desde `/api/incidents/open` (PG, <100ms).
     *
     * @param {number} limit
     * @param {number} days
     */
    topIncidents(limit, days) {
      const l = Number(limit);
      const d = Number(days);
      return `
SELECT
  v.ioc_value,
  v.ioc_type,
  v.source_log,
  v.mitre_technique_id,
  v.mitre_tactic_id,
  v.mitre_tactic_name,
  v.score,
  v.score_mitre,
  v.score_evidence,
  v.score_wazuh,
  v.severity,
  v.recommended_action,
  v.vt_malicious,
  v.vt_suspicious,
  v.vt_permalink,
  v.shodan_ports,
  v.shodan_vulns,
  v.abuse_confidence,
  v.in_urlhaus,
  v.in_openphish,
  CAST(v.dt AS varchar) AS dt,
  CAST(NULL AS varchar) AS case_id,
  CAST(NULL AS varchar) AS case_status
FROM ${tv2mat} v
WHERE v.dt >= current_date - INTERVAL '${d}' DAY
ORDER BY v.score DESC, v.dt DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Top N desde v_incident_score_v2 (umbrales NEGLIGIBLE/LOW/MEDIUM+).
     * Para panel en vivo del dashboard junto a incidentes adoptados.
     * @param {number} limit
     * @param {number} days
     */
    liveTopIncidentsV2(limit, days) {
      const l = Number(limit);
      const d = Number(days);
      const tcases = `${catalog}.${schema}.incident_cases`;
      return `
SELECT
  v.ioc_value,
  v.ioc_type,
  v.source_log,
  v.source_event_id,
  v.origen_sistema,
  v.origen_tabla,
  v.ip_origen_log,
  v.ip_destino_log,
  v.host_agente_log,
  v.mitre_technique_id,
  v.mitre_tactic_id,
  v.mitre_tactic_name,
  v.score_mitre,
  v.score_evidence,
  v.score_wazuh,
  v.score_context,
  v.score_tor,
  v.score_misp,
  v.in_misp,
  v.score,
  v.severity,
  v.confidence_level,
  v.recommended_action,
  v.vt_malicious,
  v.vt_suspicious,
  v.vt_permalink,
  v.shodan_ports,
  v.shodan_vulns,
  v.abuse_confidence,
  v.in_urlhaus,
  v.in_openphish,
  v.n_sources,
  v.source_category,
  v.alert_count,
  CAST(v.dt AS varchar) AS dt,
  ic.case_id,
  ic.case_status
FROM ${tv2} v
LEFT JOIN (
  SELECT
    ioc_value,
    MAX_BY(case_id, last_seen) AS case_id,
    MAX_BY(status,  last_seen) AS case_status
  FROM ${tcases}
  WHERE UPPER(COALESCE(status, '')) NOT IN ('CERRADO', 'CLOSED', 'RECHAZADO', 'REJECTED', 'FALSO_POSITIVO')
  GROUP BY ioc_value
) ic ON ic.ioc_value = v.ioc_value
WHERE v.dt >= current_date - INTERVAL '${d}' DAY
ORDER BY v.score DESC, v.dt DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Top N desde incident_score_v2_mat (tabla materializada — snapshot diaria).
     * Idéntica proyección que liveTopIncidentsV2 pero lee la tabla física en lugar
     * de recalcular los 6-7 JOINs de la vista. Latencia esperada: <300 ms vs 5-15 s.
     * Requiere que el DAG haya ejecutado t_materialize_score_v2 al menos una vez.
     * @param {number} limit
     * @param {number} days
     */
    liveTopIncidentsV2Mat(limit, days) {
      const l = Number(limit);
      const d = Number(days);
      return `
SELECT
  ioc_value,
  ioc_type,
  source_log,
  mitre_technique_id,
  mitre_tactic_id,
  mitre_tactic_name,
  score_mitre,
  score_evidence,
  score_wazuh,
  score_context,
  score_tor,
  score_misp,
  in_misp,
  score,
  severity,
  confidence_level,
  recommended_action,
  vt_malicious,
  vt_suspicious,
  vt_permalink,
  shodan_ports,
  shodan_vulns,
  abuse_confidence,
  in_urlhaus,
  in_openphish,
  n_sources,
  source_category,
  alert_count,
  CAST(dt AS varchar) AS dt
FROM ${tv2mat}
WHERE dt >= current_date - INTERVAL '${d}' DAY
ORDER BY score DESC, dt DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Distribución de IOCs por nivel de severidad (para gráfico de barras).
     * @param {number} days
     */
    bySeverity(days) {
      const d = Number(days);
      return `
SELECT
  severity,
  COUNT(*)                              AS cnt,
  ROUND(AVG(CAST(score AS double)), 1)  AS avg_score,
  MAX(score)                            AS max_score
FROM ${tv2mat}
WHERE dt >= current_date - INTERVAL '${d}' DAY
GROUP BY severity
ORDER BY
  CASE severity
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH'     THEN 2
    WHEN 'MEDIUM'   THEN 3
    WHEN 'LOW'      THEN 4
    ELSE 5
  END
`.trim();
    },

    /**
     * Breakdown detallado de score para un IOC/IP concreto.
     * @param {string} ip - Valor IPv4 validado externamente antes de llamar esta función
     */
    // Multiplicadores del scoring v4 (geo/novelty/killchain) por IP — fuente
    // aislada para que IncidentScoringBreakdown muestre la fórmula completa sin
    // tocar la query UNION de scoreBreakdown. Última fecha disponible.
    scoreMultipliers(ip) {
      // ip validado con regex /^[0-9a-fA-F.:]+$/ en el schema Zod del registry
      return `
SELECT
  ioc_value,
  score_base,
  score_killchain,
  n_kc_phases,
  novelty_mult,
  geo_mult,
  country_code,
  score_v4,
  CAST(first_seen_dt AS varchar) AS first_seen_dt,
  CAST(dt AS varchar)            AS dt
FROM ${tv4mat}
WHERE ioc_value = '${ip}'
ORDER BY dt DESC
LIMIT 1`;
    },
    scoreBreakdown(ip) {
      // ip ya fue validado con regex /^[0-9a-fA-F.:]+$/ en el schema Zod del registry
      return `
SELECT
  ioc_value,
  ioc_type,
  source_log,
  mitre_technique_id,
  mitre_tactic_id,
  mitre_tactic_name,
  score_mitre,
  score_evidence,
  score_wazuh,
  score,
  severity,
  recommended_action,
  vt_malicious,
  vt_suspicious,
  vt_permalink,
  shodan_ports,
  shodan_vulns,
  abuse_confidence,
  in_urlhaus,
  in_openphish,
  CAST(dt AS varchar) AS dt
FROM ${tv2}
WHERE ioc_value = '${ip}'
ORDER BY dt DESC
LIMIT 10
`.trim();
    },

    /**
     * Tendencia diaria de incidentes por severidad (para sparkline/área).
     * @param {number} days
     */
    dailyTrend(days) {
      const d = Number(days);
      return `
SELECT
  CAST(dt AS varchar)                                               AS dt,
  COUNT(*)                                                          AS total,
  SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END)           AS critical,
  SUM(CASE WHEN severity = 'HIGH'     THEN 1 ELSE 0 END)           AS high,
  SUM(CASE WHEN severity = 'MEDIUM'   THEN 1 ELSE 0 END)           AS medium,
  SUM(CASE WHEN severity = 'LOW'      THEN 1 ELSE 0 END)           AS low
FROM ${tv2mat}
WHERE dt >= current_date - INTERVAL '${d}' DAY
GROUP BY dt
ORDER BY dt
`.trim();
    },

    /**
     * Score promedio por componente (MITRE / evidencia / Wazuh) — útil para calibrar pesos.
     * @param {number} days
     */
    scoreComponents(days) {
      const d = Number(days);
      return `
SELECT
  ROUND(AVG(CAST(score_mitre    AS double)), 1) AS avg_mitre,
  ROUND(AVG(CAST(score_evidence AS double)), 1) AS avg_evidence,
  ROUND(AVG(CAST(score_wazuh    AS double)), 1) AS avg_wazuh,
  ROUND(AVG(CAST(score_misp     AS double)), 1) AS avg_misp,
  ROUND(AVG(CAST(score          AS double)), 1) AS avg_total,
  SUM(CASE WHEN in_misp = true THEN 1 ELSE 0 END) AS misp_hits,
  COUNT(*)                                       AS n_iocs
FROM ${tv2}
WHERE dt >= current_date - INTERVAL '${d}' DAY
`.trim();
    },

    /**
     * Incidentes adoptados vía force-ack (filas con adopted_by IS NOT NULL).
     * Alimenta el botón de notificación y el KPI del panel de mando.
     * @param {number} limit
     * @param {number} days
     */
    adoptedIncidents(limit, days) {
      const l = Number(limit);
      const d = Number(days);
      return `
SELECT
  incident_key,
  ioc_value,
  ioc_type,
  source_log,
  score,
  severity,
  mitre_tactic_name,
  recommended_action,
  adopted_by,
  CAST(adopted_at    AS varchar) AS adopted_at,
  CAST(classified_at AS varchar) AS classified_at,
  CAST(dt            AS varchar) AS dt
FROM ${tc}
WHERE dt >= current_date - INTERVAL '${d}' DAY
  AND adopted_by IS NOT NULL
ORDER BY adopted_at DESC NULLS LAST
LIMIT ${l}
`.trim();
    },

    /**
     * Lista completa para Gestión de Incidentes — todos los campos operativos.
     * Incluye adopted_by/adopted_at para calcular tiempos de respuesta.
     * @param {number} limit
     * @param {number} days
     */
    managedIncidents(limit, days) {
      const l = Number(limit);
      const d = Number(days);
      // incident_cases: DAG incident_cases_sync_daily + force-ack (case_id).
      // incident_classifications (v1): filas que aún no tienen fila en incident_cases (misma clave lake).
      const tcases = `${catalog}.${schema}.incident_cases`;
      return `
WITH ic_latest AS (
  SELECT *
  FROM (
    SELECT
      ic.*,
      row_number() OVER (
        PARTITION BY ic.case_id
        ORDER BY ic.updated_at DESC NULLS LAST
      ) AS rn
    FROM ${tcases} ic
    -- Siempre incluir casos no cerrados (abiertos/en análisis/confirmados),
    -- independientemente de last_seen; para cerrados/FP solo la ventana de días.
    WHERE ic.last_seen >= current_date - INTERVAL '${d}' DAY
       OR ic.status NOT IN (
            'CLOSED','FALSE_POSITIVE','RESUELTO','RESOLVED','CERRADO','FALSO_POSITIVO'
          )
  )
  WHERE rn = 1
),
v1_latest AS (
  SELECT *
  FROM (
    SELECT
      v.*,
      row_number() OVER (
        PARTITION BY v.incident_key
        ORDER BY v.classified_at DESC NULLS LAST
      ) AS v1_rn
    FROM ${tc} v
    -- Incluir clasificaciones activas fuera de la ventana de días
    WHERE v.dt >= current_date - INTERVAL '${d}' DAY
       OR v.status NOT IN (
            'CERRADO','CLOSED','RESOLVED','FALSE_POSITIVE','FALSO_POSITIVO'
          )
  )
  WHERE v1_rn = 1
),
-- v1_only: excluir clasificaciones que ya tienen caso Iceberg. incident_key en classifications
-- suele ser hash(ioc|dt), mientras case_id en incident_cases es UUID (DAG): igualdad directa fallaba
-- y duplicaba filas / ocultaba el caso canónico.
v1_only AS (
  SELECT v1.*
  FROM v1_latest v1
  WHERE NOT EXISTS (
    SELECT 1 FROM ${tcases} ic
    WHERE CAST(ic.case_id AS varchar) = CAST(v1.incident_key AS varchar)
       OR (
            ic.ioc_value = v1.ioc_value
        AND ic.source_log = v1.source_log
        AND TRY_CAST(v1.dt AS date) IS NOT NULL
        AND ic.anchor_dt = TRY_CAST(v1.dt AS date)
       )
  )
),
raw_latest AS (
  SELECT
    ioc_value,
    dt,
    MAX_BY(CAST(raw_context AS varchar), COALESCE(source_event_id, '')) AS raw_event,
    MAX_BY(
      COALESCE(
        NULLIF(json_extract_scalar(try(json_parse(raw_context)), '$.src_ip'), ''),
        NULLIF(json_extract_scalar(try(json_parse(raw_context)), '$.srcip'), ''),
        NULLIF(json_extract_scalar(try(json_parse(raw_context)), '$.data.srcip'), '')
      ),
      COALESCE(source_event_id, '')
    ) AS src_ip
  FROM ${catalog}.${schema}.enriched_ioc
  WHERE dt >= current_date - INTERVAL '${d}' DAY
  GROUP BY ioc_value, dt
),
live_meta AS (
  SELECT
    ioc_value,
    dt,
    MAX_BY(source_event_id,    score) AS source_event_id,
    MAX_BY(origen_sistema,     score) AS origen_sistema,
    MAX_BY(origen_tabla,       score) AS origen_tabla,
    MAX_BY(ip_origen_log,      score) AS ip_origen_log,
    MAX_BY(ip_destino_log,     score) AS ip_destino_log,
    MAX_BY(host_agente_log,    score) AS host_agente_log,
    MAX_BY(recommended_action, score) AS recommended_action,
    MAX(vt_malicious)                 AS vt_malicious,
    MAX(vt_suspicious)                AS vt_suspicious,
    MAX_BY(vt_permalink,       score) AS vt_permalink,
    MAX_BY(shodan_ports,       score) AS shodan_ports,
    MAX_BY(shodan_vulns,       score) AS shodan_vulns,
    MAX(abuse_confidence)             AS abuse_confidence,
    BOOL_OR(in_urlhaus)               AS in_urlhaus,
    BOOL_OR(in_openphish)             AS in_openphish
  FROM ${tv2Base}
  WHERE dt >= current_date - INTERVAL '${d}' DAY
  GROUP BY ioc_value, dt
),
biz_tags AS (
  SELECT
    source_ip,
    business_tag,
    business_name,
    service_name
  FROM ${tBusinessTags}
  WHERE enabled = true
),
managed_rows AS (
  SELECT
    CAST(ic.case_id AS varchar)  AS incident_key,
    ic.ioc_value,
    ic.ioc_type,
    ic.source_log,
    ic.severity_score            AS score,
    CAST(TRY(json_extract_scalar(ic.score_breakdown, '$.score_mitre'))    AS INTEGER) AS score_mitre,
    CAST(TRY(json_extract_scalar(ic.score_breakdown, '$.score_evidence')) AS INTEGER) AS score_evidence,
    CAST(TRY(json_extract_scalar(ic.score_breakdown, '$.score_wazuh'))    AS INTEGER) AS score_wazuh,
    ic.severity_text             AS severity,
    ic.mitre_technique_id,
    ic.mitre_tactic_id,
    ic.mitre_tactic_name,
    COALESCE(live_meta.vt_malicious, 0)     AS vt_malicious,
    COALESCE(live_meta.vt_suspicious, 0)    AS vt_suspicious,
    live_meta.vt_permalink,
    live_meta.shodan_ports,
    live_meta.shodan_vulns,
    COALESCE(live_meta.abuse_confidence, 0) AS abuse_confidence,
    COALESCE(live_meta.in_urlhaus, false)   AS in_urlhaus,
    COALESCE(live_meta.in_openphish, false) AS in_openphish,
    live_meta.recommended_action,
    CAST(NULL AS varchar)                   AS adopted_by,
    CAST(NULL AS varchar)                   AS adopted_at,
    CAST(ic.first_seen AS varchar)          AS classified_at,
    CAST(ic.anchor_dt  AS varchar)          AS dt,
    CASE ic.status
      WHEN 'OPEN'           THEN 'NUEVO'
      WHEN 'IN_PROGRESS'    THEN 'EN_ANALISIS'
      WHEN 'UNDER_REVIEW'   THEN 'EN_ANALISIS'
      WHEN 'ABIERTO'        THEN 'NUEVO'
      WHEN 'EN_CURSO'       THEN 'EN_ANALISIS'
      WHEN 'CONTENIDO'      THEN 'CONFIRMADO'
      WHEN 'RESUELTO'       THEN 'CERRADO'
      WHEN 'RESOLVED'       THEN 'CERRADO'
      WHEN 'CLOSED'         THEN 'CERRADO'
      WHEN 'FALSE_POSITIVE' THEN 'FALSO_POSITIVO'
      ELSE COALESCE(ic.status, 'NUEVO')
    END                                     AS status,
    CAST(NULL AS varchar)                   AS resolved_at,
    ic.closure_reason                       AS closure_notes,
    CAST(NULL AS varchar)                   AS detection_type,
    CAST(NULL AS varchar)                   AS rule_family,
    ic.confidence_level,
    live_meta.source_event_id,
    live_meta.origen_sistema,
    live_meta.origen_tabla,
    live_meta.ip_origen_log,
    live_meta.ip_destino_log,
    live_meta.host_agente_log,
    CASE
      WHEN ic.severity_score >= 30 AND ic.severity_text IN ('MEDIUM', 'HIGH', 'CRITICAL')
        THEN true
      ELSE false
    END AS opening_validated,
    CASE
      WHEN ic.severity_score >= 30 AND ic.severity_text IN ('MEDIUM', 'HIGH', 'CRITICAL')
        THEN 'Validado para apertura: score >= 30 y severidad MEDIUM/HIGH/CRITICAL.'
      ELSE 'Fuera del umbral de apertura automática.'
    END AS opening_validation_summary,
    COALESCE(raw_latest.raw_event, '') AS raw_event,
    biz_tags.business_tag,
    biz_tags.business_name,
    biz_tags.service_name
  FROM ic_latest ic
  LEFT JOIN raw_latest
    ON raw_latest.ioc_value = ic.ioc_value
   AND raw_latest.dt = ic.anchor_dt
  LEFT JOIN live_meta
    ON live_meta.ioc_value = ic.ioc_value
   AND live_meta.dt = ic.anchor_dt
  LEFT JOIN biz_tags
    ON biz_tags.source_ip = COALESCE(
      NULLIF(raw_latest.src_ip, ''),
      CASE WHEN ic.ioc_type = 'ip' THEN ic.ioc_value END
    )
  -- ic_latest ya filtra por ventana + casos abiertos; condición espejo para claridad
  WHERE ic.last_seen >= current_date - INTERVAL '${d}' DAY
     OR ic.status NOT IN (
          'CLOSED','FALSE_POSITIVE','RESUELTO','RESOLVED','CERRADO','FALSO_POSITIVO'
        )

  UNION ALL

  SELECT
    v1.incident_key,
    v1.ioc_value,
    v1.ioc_type,
    v1.source_log,
    v1.score,
    v1.score_mitre,
    v1.score_evidence,
    v1.score_wazuh,
    v1.severity,
    v1.mitre_technique_id,
    v1.mitre_tactic_id,
    v1.mitre_tactic_name,
    COALESCE(live_meta.vt_malicious, v1.vt_malicious, 0)     AS vt_malicious,
    COALESCE(live_meta.vt_suspicious, v1.vt_suspicious, 0)    AS vt_suspicious,
    COALESCE(live_meta.vt_permalink, v1.vt_permalink)        AS vt_permalink,
    COALESCE(live_meta.shodan_ports, v1.shodan_ports)        AS shodan_ports,
    COALESCE(live_meta.shodan_vulns, v1.shodan_vulns)        AS shodan_vulns,
    COALESCE(live_meta.abuse_confidence, v1.abuse_confidence, 0) AS abuse_confidence,
    COALESCE(live_meta.in_urlhaus, v1.in_urlhaus, false)   AS in_urlhaus,
    COALESCE(live_meta.in_openphish, v1.in_openphish, false) AS in_openphish,
    COALESCE(live_meta.recommended_action, v1.recommended_action) AS recommended_action,
    CAST(v1.adopted_by AS varchar)          AS adopted_by,
    CAST(v1.adopted_at AS varchar)          AS adopted_at,
    CAST(v1.classified_at AS varchar)       AS classified_at,
    CAST(v1.dt AS varchar)                  AS dt,
    CASE v1.status
      WHEN 'OPEN'           THEN 'NUEVO'
      WHEN 'IN_PROGRESS'    THEN 'EN_ANALISIS'
      WHEN 'UNDER_REVIEW'   THEN 'EN_ANALISIS'
      WHEN 'ABIERTO'        THEN 'NUEVO'
      WHEN 'EN_CURSO'       THEN 'EN_ANALISIS'
      WHEN 'CONTENIDO'      THEN 'CONFIRMADO'
      WHEN 'RESUELTO'       THEN 'CERRADO'
      WHEN 'RESOLVED'       THEN 'CERRADO'
      WHEN 'CLOSED'         THEN 'CERRADO'
      WHEN 'FALSE_POSITIVE' THEN 'FALSO_POSITIVO'
      ELSE COALESCE(v1.status, 'NUEVO')
    END                                     AS status,
    CAST(v1.resolved_at AS varchar)         AS resolved_at,
    v1.closure_notes                        AS closure_notes,
    v1.detection_type                       AS detection_type,
    v1.rule_family                          AS rule_family,
    v1.confidence_level,
    live_meta.source_event_id,
    live_meta.origen_sistema,
    live_meta.origen_tabla,
    live_meta.ip_origen_log,
    live_meta.ip_destino_log,
    live_meta.host_agente_log,
    CASE
      WHEN v1.score >= 30 AND v1.severity IN ('MEDIUM', 'HIGH', 'CRITICAL')
        THEN true
      ELSE false
    END AS opening_validated,
    CASE
      WHEN v1.score >= 30 AND v1.severity IN ('MEDIUM', 'HIGH', 'CRITICAL')
        THEN 'Validado para apertura: score >= 30 y severidad MEDIUM/HIGH/CRITICAL.'
      ELSE 'Fuera del umbral de apertura automática.'
    END AS opening_validation_summary,
    COALESCE(raw_latest.raw_event, '') AS raw_event,
    biz_tags.business_tag,
    biz_tags.business_name,
    biz_tags.service_name
  FROM v1_only v1
  LEFT JOIN raw_latest
    ON raw_latest.ioc_value = v1.ioc_value
   AND raw_latest.dt = v1.dt
  LEFT JOIN live_meta
    ON live_meta.ioc_value = v1.ioc_value
   AND live_meta.dt = v1.dt
  LEFT JOIN biz_tags
    ON biz_tags.source_ip = COALESCE(
      NULLIF(raw_latest.src_ip, ''),
      CASE WHEN v1.ioc_type = 'ip' THEN v1.ioc_value END
    )

  UNION ALL

  -- IOCs de v2_runtime sin caso ni clasificación: pendientes de adopción (incluye LOW/NEGLIGIBLE)
  SELECT
    TO_HEX(MD5(TO_UTF8(v2.ioc_value || '|' || CAST(v2.dt AS varchar)))) AS incident_key,
    v2.ioc_value,
    v2.ioc_type,
    v2.source_log,
    v2.score,
    v2.score_mitre,
    v2.score_evidence,
    v2.score_wazuh,
    v2.severity,
    v2.mitre_technique_id,
    v2.mitre_tactic_id,
    v2.mitre_tactic_name,
    COALESCE(v2.vt_malicious, 0)     AS vt_malicious,
    COALESCE(v2.vt_suspicious, 0)    AS vt_suspicious,
    v2.vt_permalink,
    v2.shodan_ports,
    v2.shodan_vulns,
    COALESCE(v2.abuse_confidence, 0) AS abuse_confidence,
    COALESCE(v2.in_urlhaus, false)   AS in_urlhaus,
    COALESCE(v2.in_openphish, false) AS in_openphish,
    v2.recommended_action,
    CAST(NULL AS varchar)            AS adopted_by,
    CAST(NULL AS varchar)            AS adopted_at,
    CAST(v2.dt AS varchar)           AS classified_at,
    CAST(v2.dt AS varchar)           AS dt,
    'NUEVO'                          AS status,
    CAST(NULL AS varchar)            AS resolved_at,
    CAST(NULL AS varchar)            AS closure_notes,
    CAST(NULL AS varchar)            AS detection_type,
    CAST(NULL AS varchar)            AS rule_family,
    v2.confidence_level,
    v2.source_event_id,
    v2.origen_sistema,
    v2.origen_tabla,
    v2.ip_origen_log,
    v2.ip_destino_log,
    v2.host_agente_log,
    CASE
      WHEN v2.score >= 30 AND v2.severity IN ('MEDIUM', 'HIGH', 'CRITICAL')
        THEN true
      ELSE false
    END AS opening_validated,
    CASE
      WHEN v2.score >= 30 AND v2.severity IN ('MEDIUM', 'HIGH', 'CRITICAL')
        THEN 'Validado para apertura: score >= 30 y severidad MEDIUM/HIGH/CRITICAL.'
      ELSE 'Fuera del umbral de apertura automática.'
    END AS opening_validation_summary,
    COALESCE(raw_latest.raw_event, '') AS raw_event,
    biz_tags.business_tag,
    biz_tags.business_name,
    biz_tags.service_name
  FROM ${tv2} v2
  LEFT JOIN raw_latest
    ON raw_latest.ioc_value = v2.ioc_value
   AND raw_latest.dt = v2.dt
  LEFT JOIN biz_tags
    ON biz_tags.source_ip = COALESCE(
      v2.ip_origen_log,
      CASE WHEN v2.ioc_type = 'ip' THEN v2.ioc_value END
    )
  WHERE v2.dt >= current_date - INTERVAL '${d}' DAY
    AND NOT EXISTS (
      SELECT 1 FROM ${tcases} ic
      WHERE ic.ioc_value = v2.ioc_value
        AND ic.anchor_dt = v2.dt
    )
    AND NOT EXISTS (
      SELECT 1 FROM ${tc} cl
      WHERE cl.ioc_value = v2.ioc_value
        AND cl.dt = v2.dt
    )
)
SELECT *
FROM managed_rows
ORDER BY
  CASE severity
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH'     THEN 2
    WHEN 'MEDIUM'   THEN 3
    WHEN 'LOW'      THEN 4
    ELSE 5
  END,
  classified_at DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Conteo agregado para badge de navegación: casos severos/medios sin
     * adoptar en ventana reciente.
     *
     * Corrección 2026-04-17: la query apuntaba a `incident_classifications`
     * (clasificaciones por evento, antes del dedup del DAG), lo que producía
     * números inflados (405 vs ~70 casos reales). Ahora consulta
     * `incident_cases` — una fila por case_id después de dedup, que es lo
     * que el operador realmente puede adoptar en /gestion.
     *
     * @param {number} days
     */
    openSevereUnadoptedCount(days) {
      const d = Number(days);
      const tcases = `${catalog}.${schema}.incident_cases`;
      return `
SELECT COUNT(*) AS c
FROM ${tcases}
WHERE anchor_dt >= current_date - INTERVAL '${d}' DAY
  AND adopted_at IS NULL
  AND severity_text IN ('CRITICAL', 'HIGH', 'MEDIUM')
  AND COALESCE(status, 'NUEVO') NOT IN ('CERRADO', 'FALSO_POSITIVO')
`.trim();
    },

    /**
     * Métricas de tiempo de respuesta por severidad (SLA ACK).
     * Calcula avg/min/max minutos desde classified_at hasta adopted_at
     * y cuántos cumplieron el SLA objetivo (CRITICAL 15min, HIGH 30min…).
     * @param {number} days
     */
    responseMetrics(days) {
      const d = Number(days);
      return `
SELECT
  severity,
  COUNT(*)                                                               AS total,
  COUNT(adopted_by)                                                      AS adopted_count,
  ROUND(AVG(CASE WHEN adopted_by IS NOT NULL
    THEN date_diff('second', classified_at, adopted_at) / 60.0
    ELSE NULL END), 1)                                                   AS avg_ack_min,
  MIN(CASE WHEN adopted_by IS NOT NULL
    THEN date_diff('second', classified_at, adopted_at) / 60.0
    ELSE NULL END)                                                       AS min_ack_min,
  MAX(CASE WHEN adopted_by IS NOT NULL
    THEN date_diff('second', classified_at, adopted_at) / 60.0
    ELSE NULL END)                                                       AS max_ack_min,
  SUM(CASE WHEN adopted_by IS NOT NULL
    AND date_diff('second', classified_at, adopted_at) <=
      CASE severity
        WHEN 'CRITICAL' THEN 900
        WHEN 'HIGH'     THEN 1800
        WHEN 'MEDIUM'   THEN 3600
        ELSE 86400
      END
    THEN 1 ELSE 0 END)                                                   AS within_sla
FROM ${tc}
WHERE dt >= current_date - INTERVAL '${d}' DAY
GROUP BY severity
ORDER BY
  CASE severity
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH'     THEN 2
    WHEN 'MEDIUM'   THEN 3
    ELSE 4
  END
`.trim();
    },

    /**
     * Métricas globales para el Centro de Mando SOC.
     * MTTA  = avg(adopted_at  - classified_at)
     * MTTI  = avg(resolved_at - adopted_at)     — requiere columna resolved_at (v2)
     * MTTR  = avg(resolved_at - classified_at)  — requiere columna resolved_at (v2)
     * SLA   = % dentro de los umbrales por severidad
     * @param {number} days
     */
    socMetrics(days) {
      const d = Number(days);
      return `
SELECT
  COUNT(*)                                                               AS total_classified,
  COUNT(adopted_by)                                                      AS total_adopted,
  COUNT(CASE WHEN status IN ('CERRADO','RESUELTO','FALSO_POSITIVO','MONITOREADO')
             THEN 1 END)                                                 AS total_resolved,
  /* MTTA: tiempo entre clasificación y adopción */
  ROUND(AVG(CASE WHEN adopted_by IS NOT NULL
    THEN date_diff('second', classified_at, adopted_at) / 60.0
    ELSE NULL END), 1)                                                   AS avg_mtta_min,
  /* MTTI: tiempo entre adopción y resolución (requiere resolved_at) */
  ROUND(AVG(CASE WHEN resolved_at IS NOT NULL AND adopted_at IS NOT NULL
    THEN date_diff('second', adopted_at, resolved_at) / 60.0
    ELSE NULL END), 1)                                                   AS avg_mtti_min,
  /* MTTR: tiempo entre clasificación y resolución */
  ROUND(AVG(CASE WHEN resolved_at IS NOT NULL
    THEN date_diff('second', classified_at, resolved_at) / 60.0
    ELSE NULL END), 1)                                                   AS avg_mttr_min,
  /* SLA compliance */
  SUM(CASE
    WHEN adopted_by IS NOT NULL
      AND date_diff('second', classified_at, adopted_at) <=
        CASE severity
          WHEN 'CRITICAL' THEN 900
          WHEN 'HIGH'     THEN 1800
          WHEN 'MEDIUM'   THEN 3600
          ELSE 86400
        END
    THEN 1 ELSE 0 END)                                                   AS within_sla,
  ROUND(
    100.0 * SUM(CASE
      WHEN adopted_by IS NOT NULL
        AND date_diff('second', classified_at, adopted_at) <=
          CASE severity
            WHEN 'CRITICAL' THEN 900
            WHEN 'HIGH'     THEN 1800
            WHEN 'MEDIUM'   THEN 3600
            ELSE 86400
          END
      THEN 1 ELSE 0 END)
    / NULLIF(COUNT(adopted_by), 0), 1)                                   AS sla_pct
FROM ${tc}
WHERE dt >= current_date - INTERVAL '${d}' DAY
`.trim();
    },

    /**
     * IOCs MEDIUM/LOW/NEGLIGIBLE que aún no están en incident_classifications.
     * Candidatos para apertura + cierre automático.
     *
     * 2026-05-27: ahora hace LEFT JOIN a mv_first_alert_per_ioc (DAG cross-source
     * refrescado cada 30 min) para devolver first_alert_ts. El consumer
     * (autoClassifyController.persistCase) lo usa como detected_at en el INSERT
     * PG, resolviendo el MTTD vacío del audit.
     *
     * 2026-06-22 (raíz deadlock saturación): la base pasó de `v_incident_score_v2_runtime`
     * (vista on-the-fly que recomputaba el scoring v2 sobre `days` completos en CADA
     * ciclo del scheduler → 30+ min en el nodo único de Trino) a la materializada
     * `incident_score_v2_mat`, igual que ya se hizo con topIncidents/kpis. La query
     * viva clavaba el nodo y hacía timeout a `extract_iocs_trino` y a las MV de
     * dashboard, lo que a su vez impedía refrescar los mats → bucle. Para auto-monitoreo
     * de severidades bajas la frescura de la mat (refresh del chain) es más que suficiente;
     * el hot-path CRITICAL/HIGH no pasa por acá. Las columnas requeridas existen 1:1 en
     * la mat (verificado). Alias `tv2` conservado para no tocar el resto de la query.
     *
     * @param {number} days
     */
    pendingAutoProcess(days) {
      const d = Number(days);
      const tFirstAlert = `${catalog}.${schema}.mv_first_alert_per_ioc`;
      const tEnriched   = `${catalog}.${schema}.enriched_ioc`;
      // detected_at anchor: preferimos mv_first_alert_per_ioc (cross-source), pero
      // esa MV es single-day y no cubre IOCs cuya detección fue en un dt anterior
      // (recurrencias, backlog) → first_alert_ts quedaba NULL y el caso sin
      // detected_at (MTTD vacío). enriched_ioc es la MISMA fuente de la que se
      // construye v_incident_score_v2, así que el JOIN por (ioc_value, dt) SIEMPRE
      // matchea y aporta first_seen_ts (timestamp real del primer avistamiento del
      // sensor ese dt). COALESCE → todo caso nace con un ancla de detección precisa,
      // sin depender de la frescura de la MV ni de Trino en el scheduler.
      return `
SELECT
  tv2.ioc_value, tv2.ioc_type, tv2.source_log,
  tv2.score, tv2.score_mitre, tv2.score_evidence, tv2.score_wazuh, tv2.severity,
  tv2.mitre_technique_id, tv2.mitre_tactic_id, tv2.mitre_tactic_name,
  tv2.vt_malicious, tv2.vt_suspicious, tv2.shodan_ports, tv2.shodan_vulns,
  tv2.abuse_confidence, tv2.in_urlhaus, tv2.in_openphish,
  tv2.recommended_action,
  CAST(tv2.dt AS varchar) AS dt,
  CAST(COALESCE(fa.first_alert_ts, ei.first_seen_ts) AS varchar) AS first_alert_ts
FROM ${tv2mat} tv2
LEFT JOIN ${tc} ic
  ON ic.ioc_value = tv2.ioc_value
  AND ic.dt = tv2.dt
LEFT JOIN ${tFirstAlert} fa
  ON fa.ioc_value = tv2.ioc_value
  AND fa.dt = tv2.dt
LEFT JOIN (
  SELECT ioc_value, dt, MIN(first_seen_ts) AS first_seen_ts
  FROM ${tEnriched}
  WHERE dt >= current_date - INTERVAL '${d}' DAY
  GROUP BY ioc_value, dt
) ei
  ON ei.ioc_value = tv2.ioc_value
  AND ei.dt = tv2.dt
WHERE tv2.dt >= current_date - INTERVAL '${d}' DAY
  AND tv2.severity IN ('MEDIUM', 'LOW', 'NEGLIGIBLE')
  AND ic.ioc_value IS NULL
ORDER BY tv2.score DESC
`.trim();
    },

    /**
     * MTTD cross-source: tiempo desde la primera alerta (wazuh+fortigate+syslog)
     * hasta classified_at del caso.
     *
     * 2026-05-27: ahora lee de mv_first_alert_per_ioc (DAG refresca cada 30 min,
     * ventana 2d). Antes hacía un WITH inline sobre wazuh_alerts que (a) era
     * solo Wazuh y (b) re-escaneaba el día completo en cada request. La
     * materializada es cross-source (incluye fortigate + syslog/filterlog/
     * suricata) y entrega la query en <100ms.
     *
     * Clamp 0–86400s mantiene paridad con soc_kpis_window post-mig 063.
     *
     * @param {number} days
     */
    mttdMultiSensor(days) {
      const d = Number(days);
      const tFirstAlert = `${catalog}.${schema}.mv_first_alert_per_ioc`;
      return `
SELECT
  ROUND(AVG(
    CASE WHEN date_diff('second', fa.first_alert_ts, ic.classified_at) BETWEEN 0 AND 86400
      THEN date_diff('second', fa.first_alert_ts, ic.classified_at) / 60.0
      ELSE NULL
    END
  ), 1) AS avg_mttd_min,
  COUNT(
    CASE WHEN date_diff('second', fa.first_alert_ts, ic.classified_at) BETWEEN 0 AND 86400
      THEN 1
    END
  ) AS n_samples
FROM ${tc} ic
JOIN ${tFirstAlert} fa
  ON fa.ioc_value = ic.ioc_value
 AND fa.dt = ic.dt
WHERE ic.dt >= current_date - INTERVAL '${d}' DAY
`.trim();
    },

    /** Alias back-compat — registry/tests viejos pueden seguir llamando a este nombre. */
    mttdFromWazuh(days) {
      return this.mttdMultiSensor(days);
    },

    /**
     * Candidatos a Falso Positivo — escanea v_incident_score MEDIUM/LOW
     * y asigna fp_confidence: CONFIRMED | PROBABLE | POSSIBLE | INSUFFICIENT.
     *
     * Criterios:
     *   CONFIRMED  — IP known-safe (DNS/CDN públicos) O score<10 con intel limpia
     *   PROBABLE   — LOW + intel limpia (VT=0, no feeds, sin puertos críticos)
     *   POSSIBLE   — MEDIUM + intel limpia
     *   INSUFFICIENT — datos insuficientes para decidir
     *
     * @param {number} days
     */
    fpCandidates(days) {
      const d = Number(days);
      return `
WITH base AS (
  SELECT
    ioc_value, ioc_type, source_log,
    score, score_mitre, score_evidence, score_wazuh, severity,
    mitre_technique_id, mitre_tactic_id, mitre_tactic_name,
    vt_malicious, vt_suspicious, shodan_ports, shodan_vulns,
    abuse_confidence, in_urlhaus, in_openphish,
    recommended_action,
    CAST(dt AS varchar) AS dt,
    /* ── Clasificar confianza FP ── */
    CASE
      WHEN ioc_value IN (
        '8.8.8.8','8.8.4.4',                    -- Google DNS
        '1.1.1.1','1.0.0.1',                    -- Cloudflare DNS
        '9.9.9.9','149.112.112.112',             -- Quad9
        '208.67.222.222','208.67.220.220',       -- OpenDNS
        '4.2.2.1','4.2.2.2'                     -- Level3 DNS
      ) THEN 'CONFIRMED'
      WHEN score < 10
        AND (vt_malicious IS NULL OR vt_malicious = 0)
        AND (abuse_confidence IS NULL OR abuse_confidence < 10)
        AND in_urlhaus = false AND in_openphish = false
        AND (shodan_ports IS NULL OR (
          CAST(shodan_ports AS varchar) NOT LIKE '%4444%'
          AND CAST(shodan_ports AS varchar) NOT LIKE '%3389%'
          AND CAST(shodan_ports AS varchar) NOT LIKE '%,445,%'
        ))
      THEN 'CONFIRMED'
      WHEN severity = 'NEGLIGIBLE'
      THEN 'CONFIRMED'
      WHEN severity = 'LOW'
        AND (vt_malicious IS NULL OR vt_malicious = 0)
        AND (abuse_confidence IS NULL OR abuse_confidence < 20)
        AND in_urlhaus = false AND in_openphish = false
        AND (shodan_ports IS NULL OR (
          CAST(shodan_ports AS varchar) NOT LIKE '%4444%'
          AND CAST(shodan_ports AS varchar) NOT LIKE '%3389%'
          AND CAST(shodan_ports AS varchar) NOT LIKE '%,445,%'
        ))
      THEN 'PROBABLE'
      WHEN severity = 'MEDIUM'
        AND (vt_malicious IS NULL OR vt_malicious = 0)
        AND (abuse_confidence IS NULL OR abuse_confidence < 25)
        AND in_urlhaus = false AND in_openphish = false
      THEN 'POSSIBLE'
      ELSE 'INSUFFICIENT'
    END AS fp_confidence,
    CASE
      WHEN ioc_value IN (
        '8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1',
        '9.9.9.9','149.112.112.112',
        '208.67.222.222','208.67.220.220','4.2.2.1','4.2.2.2'
      ) THEN 'IP_KNOWN_SAFE'
      WHEN score < 10
        AND (vt_malicious IS NULL OR vt_malicious = 0)
        AND (abuse_confidence IS NULL OR abuse_confidence < 10)
        AND in_urlhaus = false AND in_openphish = false
      THEN 'CLEAN_INTEL_LOW_SCORE'
      WHEN severity = 'LOW'
        AND (vt_malicious IS NULL OR vt_malicious = 0)
        AND in_urlhaus = false AND in_openphish = false
      THEN 'LOW_CLEAN_INTEL'
      WHEN severity = 'MEDIUM'
        AND (vt_malicious IS NULL OR vt_malicious = 0)
        AND in_urlhaus = false AND in_openphish = false
      THEN 'MEDIUM_CLEAN_INTEL'
      ELSE NULL
    END AS fp_reason
  FROM ${tv2}
  WHERE dt >= current_date - INTERVAL '${d}' DAY
    AND severity IN ('MEDIUM', 'LOW', 'NEGLIGIBLE')
)
SELECT *
FROM base
ORDER BY
  CASE fp_confidence
    WHEN 'CONFIRMED'    THEN 1
    WHEN 'PROBABLE'     THEN 2
    WHEN 'POSSIBLE'     THEN 3
    ELSE 4
  END,
  score DESC
`.trim();
    },

    /**
     * Clasificaciones materializadas (tabla física, no vista).
     * @param {number} limit
     * @param {number} days
     */
    savedClassifications(limit, days) {
      const l = Number(limit);
      const d = Number(days);
      return `
SELECT
  ioc_value,
  ioc_type,
  source_log,
  score,
  severity,
  recommended_action,
  vt_malicious,
  abuse_confidence,
  CAST(classified_at AS varchar) AS classified_at,
  CAST(dt AS varchar)            AS dt
FROM ${tc}
WHERE dt >= current_date - INTERVAL '${d}' DAY
ORDER BY score DESC, classified_at DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Flujo explicable de apertura de casos (score, severidad, deduplicacion).
     * Usa CTEs inline sobre incident_classifications + incident_cases para evitar
     * dependencia de la vista v_incident_analysis_flow que puede no existir en
     * entornos nuevos o tras recreaciones de schema.
     *
     * Criterios de apertura (alineados con incident_cases_sync_daily.py DAG):
     *   1) score >= 30
     *   2) severity IN ('MEDIUM', 'HIGH', 'CRITICAL')
     *   3) NO existe dedup_key activo en ventana 15 dias
     *
     * @param {number} limit
     * @param {number} days
     */
    analysisFlow(days) {
      const d = Number(days);
      const tc     = `${catalog}.${schema}.incident_classifications`;
      const tcases = `${catalog}.${schema}.incident_cases`;
      return `
WITH all_events AS (
  -- Fuente 1: casos ya abiertos en incident_cases (pasaron TODOS los criterios)
  SELECT
    c.case_id                                                 AS ioc_id,
    c.ioc_value,
    c.ioc_type,
    CAST(COALESCE(c.first_seen, c.last_seen) AS varchar)      AS timestamp_evento,
    c.source_log,
    c.dedup_key,
    CAST(COALESCE(c.severity_score, 0) AS INTEGER)            AS score,
    UPPER(COALESCE(c.severity_text, ''))                      AS severidad,
    c.mitre_tactic_id,
    c.mitre_tactic_name,
    c.source_category                                         AS detection_type,
    c.confidence_level,
    true                                                      AS es_caso_abierto,
    c.status                                                  AS case_status,
    c.assigned_to,
    c.case_id                                                 AS self_case_id
  FROM ${tcases} c
  WHERE c.anchor_dt >= current_date - INTERVAL '${d}' DAY

  UNION ALL

  -- Fuente 2: clasificaciones automáticas (incident_classifications)
  -- Solo incluir IOCs que NO tienen ya un caso abierto en incident_cases (evitar duplicados)
  SELECT
    ic.incident_key                                           AS ioc_id,
    ic.ioc_value,
    ic.ioc_type,
    CAST(COALESCE(ic.classified_at,
         CAST(ic.dt AS TIMESTAMP(6) WITH TIME ZONE)) AS varchar) AS timestamp_evento,
    ic.source_log,
    CASE
      WHEN UPPER(COALESCE(ic.severity, '')) IN ('CRITICAL', 'HIGH')
        THEN LOWER(TO_HEX(SHA256(TO_UTF8(CONCAT(
          COALESCE(ic.ioc_value, ''), '|', COALESCE(TRIM(ic.mitre_tactic_id), '')
        )))))
      ELSE LOWER(TO_HEX(SHA256(TO_UTF8(CONCAT(
          COALESCE(ic.ioc_value, ''), '|', COALESCE(ic.source_log, '')
      )))))
    END                                                       AS dedup_key,
    CAST(COALESCE(ic.score, 0) AS INTEGER)                    AS score,
    UPPER(COALESCE(ic.severity, ''))                          AS severidad,
    ic.mitre_tactic_id,
    ic.mitre_tactic_name,
    ic.detection_type,
    ic.confidence_level,
    false                                                     AS es_caso_abierto,
    ic.status                                                 AS case_status,
    ic.adopted_by                                             AS assigned_to,
    CAST(NULL AS varchar)                                     AS self_case_id
  FROM ${tc} ic
  WHERE ic.dt >= current_date - INTERVAL '${d}' DAY
    AND ic.dt IS NOT NULL
),
dedup_hits AS (
  -- Casos activos en ventana 15 días para detección de duplicados
  SELECT
    c.dedup_key,
    MAX_BY(c.case_id,       c.last_seen) AS incident_case_id,
    MAX_BY(c.status,        c.last_seen) AS incident_status,
    MAX_BY(c.severity_text, c.last_seen) AS incident_severity
  FROM ${tcases} c
  WHERE UPPER(COALESCE(c.status, '')) IN (
      'OPEN', 'IN_PROGRESS', 'UNDER_REVIEW', 'EN_CURSO', 'EN_REVISION',
      'NUEVO', 'EN_ANALISIS', 'CONFIRMADO', 'MONITOREADO', 'ESCALADO'
  )
    AND c.last_seen >= CURRENT_TIMESTAMP - INTERVAL '15' DAY
  GROUP BY c.dedup_key
)
SELECT
  b.ioc_id,
  b.ioc_value,
  b.ioc_type,
  b.timestamp_evento,
  b.source_log,
  b.dedup_key,
  b.score,
  b.severidad,
  b.mitre_tactic_id,
  b.mitre_tactic_name,
  b.detection_type,
  b.confidence_level,
  b.es_caso_abierto,
  b.self_case_id,
  (b.score IS NOT NULL AND b.score >= 30)           AS cumple_score,
  (b.severidad IN ('MEDIUM', 'HIGH', 'CRITICAL'))   AS cumple_severidad,
  (b.es_caso_abierto OR d.dedup_key IS NOT NULL)    AS existe_caso_duplicado,
  -- Diagnóstico legible
  CASE
    WHEN b.es_caso_abierto
      THEN CONCAT('Caso activo — estado: ',
                  COALESCE(b.case_status, 'NUEVO'),
                  CASE WHEN b.assigned_to IS NOT NULL
                       THEN CONCAT(' · adoptado por: ', b.assigned_to)
                       ELSE ' · sin adoptar' END)
    WHEN b.score IS NULL OR b.severidad = ''
      THEN 'Datos insuficientes (sin score o severidad)'
    WHEN b.score < 30
      THEN CONCAT('NO cumple score mínimo (', CAST(b.score AS varchar), ' < 30)')
    WHEN b.severidad NOT IN ('MEDIUM', 'HIGH', 'CRITICAL')
      THEN CONCAT('NO cumple severidad requerida (es ', b.severidad, ')')
    WHEN d.dedup_key IS NOT NULL
      THEN CONCAT('Score y severidad OK — caso duplicado activo: ',
                  COALESCE(d.incident_case_id, 'ventana 15 días'))
    ELSE 'TODOS los criterios OK → Caso debería abrirse'
  END AS criterio_fallido,
  -- Estado del flujo
  CASE
    WHEN b.es_caso_abierto                                            THEN 'ABIERTO'
    WHEN b.score IS NULL OR b.severidad = ''                          THEN 'NO_ABIERTO'
    WHEN b.score >= 30
     AND b.severidad IN ('MEDIUM', 'HIGH', 'CRITICAL')
     AND d.dedup_key IS NULL                                          THEN 'ABIERTO'
    WHEN b.score >= 30
     AND b.severidad IN ('MEDIUM', 'HIGH', 'CRITICAL')
     AND d.dedup_key IS NOT NULL                                      THEN 'DEDUPLICADO'
    ELSE                                                                   'NO_ABIERTO'
  END AS flujo_estado,
  COALESCE(b.self_case_id, d.incident_case_id) AS incident_case_id,
  COALESCE(b.case_status, d.incident_status)   AS incident_status,
  d.incident_severity
FROM all_events b
LEFT JOIN dedup_hits d ON d.dedup_key = b.dedup_key
ORDER BY
  -- Casos ya abiertos siempre primero, luego por timestamp descendente
  b.es_caso_abierto DESC,
  CASE b.severidad
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH'     THEN 2
    WHEN 'MEDIUM'   THEN 3
    WHEN 'LOW'      THEN 4
    ELSE 5
  END ASC,
  b.timestamp_evento DESC
`.trim();
    },

    /**
     * Chat SOC: hosts con más ataques en ventana.
     * @param {number} limit
     * @param {number} days
     */
    chatTopAttackedHosts(limit, days) {
      const l = Number(limit);
      const d = Number(days);
      return `
SELECT
  COALESCE(NULLIF(host_agente_log, ''), 'host-desconocido') AS host,
  COUNT(*) AS attacks,
  SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
  SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high
FROM ${tv2mat}
WHERE dt >= current_date - INTERVAL '${d}' DAY
GROUP BY 1
ORDER BY attacks DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Chat SOC: CVEs observados con mayor score asociado.
     * @param {number} limit
     * @param {number} days
     */
    chatHighestCves(limit, days) {
      const l = Number(limit);
      const d = Number(days);
      return `
WITH base AS (
  SELECT
    score,
    regexp_extract_all(
      upper(COALESCE(CAST(shodan_vulns AS varchar), '')),
      'CVE-[0-9]{4}-[0-9]{4,7}'
    ) AS cves
  FROM ${tv2mat}
  WHERE dt >= current_date - INTERVAL '${d}' DAY
),
flat AS (
  SELECT score, cve
  FROM base
  CROSS JOIN UNNEST(cves) AS u(cve)
)
SELECT
  cve,
  COUNT(*) AS hits,
  MAX(score) AS max_score,
  ROUND(AVG(CAST(score AS double)), 1) AS avg_score
FROM flat
GROUP BY cve
ORDER BY max_score DESC, hits DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Chat SOC: IPs origen con más eventos/ataques.
     * @param {number} limit
     * @param {number} days
     */
    chatTopAttackerIps(limit, days) {
      const l = Number(limit);
      const d = Number(days);
      return `
SELECT
  COALESCE(NULLIF(ip_origen_log, ''), ioc_value) AS src_ip,
  COUNT(*) AS attacks,
  SUM(CASE WHEN severity IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) AS high_risk,
  MAX(score) AS max_score
FROM ${tv2mat}
WHERE dt >= current_date - INTERVAL '${d}' DAY
GROUP BY 1
ORDER BY attacks DESC, max_score DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Chat SOC: negocio/servicio más atacado según mapping business_ip_tags.
     * @param {number} limit
     * @param {number} days
     */
    chatBusinessMostAttacked(limit, days) {
      const l = Number(limit);
      const d = Number(days);
      return `
SELECT
  COALESCE(NULLIF(t.business_tag, ''), 'SIN_TAG') AS business_tag,
  COALESCE(NULLIF(t.business_name, ''), 'SIN_EMPRESA') AS business_name,
  COALESCE(NULLIF(t.service_name, ''), 'SIN_SERVICIO') AS service_name,
  COUNT(*) AS attacks,
  SUM(CASE WHEN v.severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) AS high_risk
FROM ${tv2mat} v
LEFT JOIN ${tBusinessTags} t
  ON t.source_ip = COALESCE(NULLIF(v.ip_origen_log, ''), v.ioc_value)
 AND t.enabled = true
WHERE v.dt >= current_date - INTERVAL '${d}' DAY
GROUP BY 1,2,3
ORDER BY attacks DESC, high_risk DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Chat SOC: incidentes críticos recientes para explicación.
     * @param {number} limit
     * @param {number} days
     */
    chatRecentCritical(limit, days) {
      const l = Number(limit);
      const d = Number(days);
      return `
SELECT
  ioc_value,
  source_log,
  severity,
  score,
  mitre_tactic_name,
  ip_origen_log,
  CAST(dt AS varchar) AS dt
FROM ${tv2mat}
WHERE dt >= current_date - INTERVAL '${d}' DAY
  AND severity = 'CRITICAL'
ORDER BY score DESC, dt DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Chat SOC: países origen con más eventos (geo breakdown sobre tv2.country_code).
     * Si `severityMin` viene, filtra por severidad mínima usando el orden canónico.
     * @param {number} limit
     * @param {number} days
     * @param {string} [severityMin] uno de CRITICAL/HIGH/MEDIUM/LOW/NEGLIGIBLE
     */
    chatTopSourceCountries(limit, days, severityMin) {
      const d = Number(days);
      const sev = chatSeverityFilter(severityMin);
      // El lake NO almacena geo (no hay `country_code` en las vistas ni en
      // enriched_ioc) — el país se resuelve con MaxMind en Node. Esta query
      // devuelve las IPs origen top; el handler de /api/soc-chat/ask las agrupa
      // por país (geoEnrichTopCountries) y recorta al `limit` del usuario. El
      // LIMIT acá es un cap amplio de IPs a geolocalizar, NO el top-N de países.
      return `
SELECT
  COALESCE(NULLIF(ip_origen_log, ''), ioc_value)                  AS src_ip,
  COUNT(*)                                                         AS attacks,
  SUM(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) AS high_risk,
  MAX(score)                                                       AS max_score
FROM ${tv2mat}
WHERE dt >= current_date - INTERVAL '${d}' DAY
  ${sev}
GROUP BY 1
ORDER BY attacks DESC
LIMIT 1000
`.trim();
    },

    /**
     * Chat SOC: tácticas MITRE ATT&CK más frecuentes en la ventana. Útil para
     * entender qué fase del kill-chain está activa (initial access, lateral,
     * exfil, etc.).
     * @param {number} limit
     * @param {number} days
     * @param {string} [severityMin]
     */
    chatTopMitreTactics(limit, days, severityMin) {
      const l = Number(limit);
      const d = Number(days);
      const sev = chatSeverityFilter(severityMin);
      return `
SELECT
  COALESCE(NULLIF(mitre_tactic_name, ''), 'SIN_MAPEO')            AS tactic,
  COUNT(*)                                                         AS attacks,
  SUM(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END)  AS high_risk,
  MAX(score)                                                       AS max_score,
  COUNT(DISTINCT ioc_value)                                         AS unique_iocs
FROM ${tv2mat}
WHERE dt >= current_date - INTERVAL '${d}' DAY
  ${sev}
GROUP BY 1
ORDER BY attacks DESC, high_risk DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Chat SOC: breakdown por origen_sistema (WAZUH/FORTIGATE/SURICATA/…) —
     * responde "¿qué sensor está reportando más?" y ayuda al SOC a decidir
     * dónde invertir tuning.
     * @param {number} limit
     * @param {number} days
     * @param {string} [severityMin]
     */
    chatTopSourceLogs(limit, days, severityMin) {
      const l = Number(limit);
      const d = Number(days);
      const sev = chatSeverityFilter(severityMin);
      return `
SELECT
  COALESCE(NULLIF(origen_sistema, ''), 'DESCONOCIDO')              AS origen_sistema,
  COUNT(*)                                                          AS attacks,
  SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END)            AS critical,
  SUM(CASE WHEN severity = 'HIGH'     THEN 1 ELSE 0 END)            AS high,
  SUM(CASE WHEN severity = 'MEDIUM'   THEN 1 ELSE 0 END)            AS medium,
  COUNT(DISTINCT ioc_value)                                          AS unique_iocs
FROM ${tv2mat}
WHERE dt >= current_date - INTERVAL '${d}' DAY
  ${sev}
GROUP BY 1
ORDER BY attacks DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Logins de VPN (SSL-VPN FortiGate) por USUARIO: fallidos vs exitosos en la
     * ventana. Responde "usuarios con intentos fallidos/exitosos de VPN".
     *
     * No hay tabla VPN-auth modelada: el dato vive en el `message` crudo de
     * `minio.hunting.fortigate` (key=value FortiGate) como `subtype="vpn"` +
     * `action="ssl-login-fail"` / `"tunnel-up"` / `logdesc="SSL VPN login
     * successful"`, con `user=` y `remip=`. El raw es ~12.5M filas/día, así que:
     *   - poda de partición a HOY + AYER (zero-padded varchar, pushdown real;
     *     mismo patrón que el MV slim 58) → cap ~48h.
     *   - ventana fina por `eventtime` (ns del firewall) en segundos.
     * @param {number} limit
     * @param {number} days  ventana en días; capeada a 2 (48h) por costo del raw.
     */
    chatFortigateVpnLogins(limit, days) {
      const l = Math.max(1, Math.min(Number(limit) || 20, 50));
      const d = Math.max(1, Math.min(Number(days) || 1, 2));
      const hours = d * 24;
      return `
WITH vpn AS (
  SELECT
    regexp_extract(message, 'user="([^"]*)"', 1)                          AS usuario,
    message,
    TRY_CAST(regexp_extract(message, 'eventtime=([0-9]+)', 1) AS DOUBLE) / 1e9 AS evt_sec
  FROM minio.hunting.fortigate
  WHERE (
        (year = CAST(YEAR(CURRENT_DATE) AS varchar)
          AND month = lpad(CAST(MONTH(CURRENT_DATE) AS varchar), 2, '0')
          AND day = lpad(CAST(DAY(CURRENT_DATE) AS varchar), 2, '0'))
     OR (year = CAST(YEAR(CURRENT_DATE - INTERVAL '1' DAY) AS varchar)
          AND month = lpad(CAST(MONTH(CURRENT_DATE - INTERVAL '1' DAY) AS varchar), 2, '0')
          AND day = lpad(CAST(DAY(CURRENT_DATE - INTERVAL '1' DAY) AS varchar), 2, '0'))
      )
    AND strpos(message, 'subtype="vpn"') > 0
    AND (strpos(message, 'ssl-login') > 0 OR strpos(message, 'action="tunnel-up"') > 0)
)
SELECT
  COALESCE(NULLIF(usuario, ''), 'N/A')                                       AS usuario,
  COUNT(*) FILTER (WHERE strpos(message, 'action="ssl-login-fail"') > 0)     AS fallidos,
  COUNT(*) FILTER (WHERE strpos(message, 'SSL VPN login successful') > 0
                      OR strpos(message, 'action="tunnel-up"') > 0)          AS exitosos,
  arbitrary(regexp_extract(message, 'remip=([0-9.]+)', 1))                   AS ip_origen,
  arbitrary(regexp_extract(message, 'devname="([^"]*)"', 1))                 AS firewall
FROM vpn
WHERE evt_sec >= to_unixtime(current_timestamp) - ${hours} * 3600
  AND COALESCE(NULLIF(usuario, ''), '') <> ''
GROUP BY 1
HAVING COUNT(*) FILTER (WHERE strpos(message, 'action="ssl-login-fail"') > 0) > 0
    OR COUNT(*) FILTER (WHERE strpos(message, 'SSL VPN login successful') > 0
                           OR strpos(message, 'action="tunnel-up"') > 0) > 0
ORDER BY fallidos DESC, exitosos DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Patrones en casos abiertos: distribución por fuente, MITRE, IP pública vs interna.
     * Responde "¿por qué casi todo son IPs públicas?" y muestra tendencias de duplicados.
     * @param {number} days
     */
    casePatterns(days) {
      const d = Number(days);
      return `
WITH base AS (
  SELECT
    ic.ioc_value,
    ic.source_log,
    ic.severity_text,
    ic.severity_score,
    ic.mitre_tactic_id,
    ic.mitre_tactic_name,
    ic.source_category,
    ic.confidence_level,
    ic.status,
    -- Clasificar IP interna vs pública (RFC1918)
    CASE
      WHEN ic.ioc_type = 'ip' AND (
        ic.ioc_value LIKE '10.%'
        OR ic.ioc_value LIKE '192.168.%'
        OR ic.ioc_value LIKE '172.16.%' OR ic.ioc_value LIKE '172.17.%'
        OR ic.ioc_value LIKE '172.18.%' OR ic.ioc_value LIKE '172.19.%'
        OR ic.ioc_value LIKE '172.20.%' OR ic.ioc_value LIKE '172.21.%'
        OR ic.ioc_value LIKE '172.22.%' OR ic.ioc_value LIKE '172.23.%'
        OR ic.ioc_value LIKE '172.24.%' OR ic.ioc_value LIKE '172.25.%'
        OR ic.ioc_value LIKE '172.26.%' OR ic.ioc_value LIKE '172.27.%'
        OR ic.ioc_value LIKE '172.28.%' OR ic.ioc_value LIKE '172.29.%'
        OR ic.ioc_value LIKE '172.30.%' OR ic.ioc_value LIKE '172.31.%'
        OR ic.ioc_value LIKE '127.%'    OR ic.ioc_value LIKE '169.254.%'
      ) THEN 'INTERNA'
      ELSE 'PUBLICA'
    END AS ip_scope,
    -- Etiqueta sistema de origen
    CASE
      WHEN ic.source_log IN ('wazuh_alerts','wazuh')        THEN 'Wazuh SIEM'
      WHEN ic.source_log LIKE '%filterlog%'
        OR ic.source_log LIKE '%opnsense%'                  THEN 'OPNsense FW'
      WHEN ic.source_log = 'suricata'                       THEN 'Suricata IDS'
      WHEN ic.source_log = 'fortigate'                      THEN 'FortiGate FW'
      ELSE UPPER(COALESCE(ic.source_log, 'DESCONOCIDO'))
    END AS origen_sistema
  FROM ${tcases} ic
  WHERE ic.anchor_dt >= current_date - INTERVAL '${d}' DAY
    AND UPPER(COALESCE(ic.status,'')) NOT IN ('CERRADO','CLOSED','FALSO_POSITIVO','FALSE_POSITIVE')
),
-- Distribución pública vs interna
scope_dist AS (
  SELECT ip_scope, COUNT(*) AS total,
    SUM(CASE WHEN severity_text = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
    SUM(CASE WHEN severity_text = 'HIGH'     THEN 1 ELSE 0 END) AS high,
    SUM(CASE WHEN severity_text = 'MEDIUM'   THEN 1 ELSE 0 END) AS medium,
    ROUND(AVG(CAST(severity_score AS double)), 1) AS avg_score
  FROM base GROUP BY ip_scope
),
-- Distribución por sistema origen
source_dist AS (
  SELECT origen_sistema, ip_scope, COUNT(*) AS total,
    ROUND(AVG(CAST(severity_score AS double)), 1) AS avg_score
  FROM base GROUP BY origen_sistema, ip_scope
),
-- Top MITRE tácticas activas
mitre_dist AS (
  SELECT
    COALESCE(mitre_tactic_id, 'SIN_MITRE')   AS tactic_id,
    COALESCE(mitre_tactic_name, 'Sin mapeo') AS tactic_name,
    COUNT(*)                                  AS total,
    ROUND(AVG(CAST(severity_score AS double)), 1) AS avg_score
  FROM base
  GROUP BY mitre_tactic_id, mitre_tactic_name
  ORDER BY total DESC
  LIMIT 10
),
-- Top source_category (protocolo/puerto más atacado)
category_dist AS (
  SELECT
    COALESCE(source_category, 'desconocido') AS category,
    COUNT(*) AS total,
    ip_scope
  FROM base
  GROUP BY source_category, ip_scope
  ORDER BY total DESC
  LIMIT 15
)
SELECT 'scope'    AS chart, CAST(NULL AS varchar) AS label2,
       ip_scope   AS label,
       total, critical, high, medium,
       CAST(NULL AS bigint) AS total_b, avg_score,
       CAST(NULL AS varchar) AS extra
FROM scope_dist
UNION ALL
SELECT 'source', ip_scope,
       origen_sistema,
       total, CAST(NULL AS bigint), CAST(NULL AS bigint), CAST(NULL AS bigint),
       CAST(NULL AS bigint), avg_score, CAST(NULL AS varchar)
FROM source_dist
UNION ALL
SELECT 'mitre', CAST(NULL AS varchar),
       CONCAT(tactic_id, ' — ', tactic_name),
       total, CAST(NULL AS bigint), CAST(NULL AS bigint), CAST(NULL AS bigint),
       CAST(NULL AS bigint), avg_score, tactic_id
FROM mitre_dist
UNION ALL
SELECT 'category', ip_scope,
       category,
       total, CAST(NULL AS bigint), CAST(NULL AS bigint), CAST(NULL AS bigint),
       CAST(NULL AS bigint), CAST(NULL AS double), CAST(NULL AS varchar)
FROM category_dist
`.trim();
    },

    /**
     * Candidatos a duplicado: misma ioc_value con > 1 case_id activo en la ventana.
     * Ayuda al operador a consolidar y cerrar casos redundantes.
     * @param {number} days
     */
    duplicateCandidates(days) {
      const d = Number(days);
      return `
WITH open_cases AS (
  SELECT
    ioc_value,
    ioc_type,
    case_id,
    severity_text,
    severity_score,
    status,
    source_log,
    source_category,
    first_seen,
    last_seen,
    assigned_to,
    dedup_key
  FROM ${tcases}
  WHERE anchor_dt >= current_date - INTERVAL '${d}' DAY
    AND UPPER(COALESCE(status,'')) NOT IN ('CERRADO','CLOSED','FALSO_POSITIVO','FALSE_POSITIVE')
),
grouped AS (
  SELECT
    ioc_value,
    ioc_type,
    COUNT(DISTINCT case_id)    AS n_casos,
    COUNT(DISTINCT dedup_key)  AS n_dedup_keys,
    COUNT(DISTINCT source_log) AS n_fuentes,
    array_join(array_distinct(array_agg(CAST(case_id AS varchar))), ' | ')       AS case_ids,
    array_join(array_distinct(array_agg(CAST(severity_text AS varchar))), ' / ') AS severidades,
    array_join(array_distinct(array_agg(CAST(status AS varchar))), ' / ')        AS estados,
    array_join(array_distinct(array_agg(CAST(source_log AS varchar))), ' / ')    AS fuentes,
    MAX(severity_score) AS max_score,
    CAST(MIN(first_seen) AS varchar) AS primera_vez,
    CAST(MAX(last_seen)  AS varchar) AS ultima_vez,
    -- Caso canónico: el de mayor score / más reciente
    MAX_BY(CAST(case_id AS varchar), severity_score) AS caso_canonico,
    COUNT(CASE WHEN assigned_to IS NOT NULL THEN 1 END) AS n_adoptados
  FROM open_cases
  GROUP BY ioc_value, ioc_type
  HAVING COUNT(DISTINCT case_id) > 1
)
SELECT
  ioc_value,
  ioc_type,
  n_casos,
  n_dedup_keys,
  n_fuentes,
  max_score,
  severidades,
  estados,
  fuentes,
  primera_vez,
  ultima_vez,
  caso_canonico,
  n_adoptados,
  case_ids,
  -- Diagnóstico de causa del duplicado
  CASE
    WHEN n_dedup_keys = 1 THEN 'Misma dedup_key — ventana 15d expiró entre aperturas'
    WHEN n_fuentes > 1    THEN 'Múltiples fuentes (OPNsense + Wazuh) — mismo IOC detectado en sistemas distintos'
    ELSE                       'Distintas source_category o tácticas MITRE — mismo IOC, diferente contexto'
  END AS causa_duplicado
FROM grouped
ORDER BY n_casos DESC, max_score DESC
`.trim();
    },

    /**
     * Desglose público vs interno con análisis del scoring gap.
     * Explica por qué las IPs internas obtienen scores bajos.
     * @param {number} days
     */
    internalVsPublicBreakdown(days) {
      const d = Number(days);
      return `
WITH scored AS (
  SELECT
    ioc_value,
    source_log,
    severity,
    score,
    score_evidence,
    score_wazuh,
    score_mitre,
    score_context,
    alert_count,
    source_category,
    CASE
      WHEN (
        ioc_value LIKE '10.%'
        OR ioc_value LIKE '192.168.%'
        OR ioc_value LIKE '172.16.%' OR ioc_value LIKE '172.17.%'
        OR ioc_value LIKE '172.18.%' OR ioc_value LIKE '172.19.%'
        OR ioc_value LIKE '172.20.%' OR ioc_value LIKE '172.21.%'
        OR ioc_value LIKE '172.22.%' OR ioc_value LIKE '172.23.%'
        OR ioc_value LIKE '172.24.%' OR ioc_value LIKE '172.25.%'
        OR ioc_value LIKE '172.26.%' OR ioc_value LIKE '172.27.%'
        OR ioc_value LIKE '172.28.%' OR ioc_value LIKE '172.29.%'
        OR ioc_value LIKE '172.30.%' OR ioc_value LIKE '172.31.%'
        OR ioc_value LIKE '127.%'    OR ioc_value LIKE '169.254.%'
      ) THEN 'INTERNA'
      ELSE 'PUBLICA'
    END AS ip_scope
  FROM ${tv2Base}
  WHERE dt >= current_date - INTERVAL '${d}' DAY
    AND ioc_type = 'ip'
)
SELECT
  ip_scope,
  COUNT(*)                                        AS total_iocs,
  SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
  SUM(CASE WHEN severity = 'HIGH'     THEN 1 ELSE 0 END) AS high,
  SUM(CASE WHEN severity = 'MEDIUM'   THEN 1 ELSE 0 END) AS medium,
  SUM(CASE WHEN severity = 'LOW'      THEN 1 ELSE 0 END) AS low,
  ROUND(AVG(CAST(score           AS double)), 1) AS avg_score,
  ROUND(AVG(CAST(score_evidence  AS double)), 1) AS avg_score_evidence,
  ROUND(AVG(CAST(score_wazuh     AS double)), 1) AS avg_score_wazuh,
  ROUND(AVG(CAST(score_mitre     AS double)), 1) AS avg_score_mitre,
  ROUND(AVG(CAST(score_context   AS double)), 1) AS avg_score_context,
  -- Porcentaje con score_evidence = 0 (sin datos VT/Shodan/AbuseIPDB)
  ROUND(100.0 * SUM(CASE WHEN COALESCE(score_evidence, 0) = 0 THEN 1 ELSE 0 END) / COUNT(*), 1)
    AS pct_sin_evidencia_externa,
  ROUND(AVG(CAST(COALESCE(alert_count, 0) AS double)), 0) AS avg_alert_count
FROM scored
GROUP BY ip_scope
ORDER BY ip_scope
`.trim();
    },

    /**
     * Historial visual de versiones de fórmula de scoring.
     * @param {number} limit
     */
    scoringFormulaHistory(limit) {
      const l = Number(limit);
      return `
SELECT
  CAST(applied_at AS varchar) AS applied_at,
  applied_by,
  w_mitre,
  w_evidence,
  w_wazuh,
  w_context,
  w_tor,
  bonus_vt_positive,
  bonus_abuse_high,
  abuse_high_threshold,
  bonus_urlhaus,
  bonus_openphish,
  threshold_critical,
  threshold_high,
  threshold_medium,
  threshold_low
FROM ${tScoringCfg}
ORDER BY applied_at DESC
LIMIT ${l}
`.trim();
    },

    // ── Scoring v4 — Bonos Trino-native (kill-chain + temporal + geo-risk) ──────

    /**
     * KPIs de scoring v4: distribución de severidad_v4, score_v4 promedio,
     * uplift medio de los bonos respecto al score_base.
     * @param {number} days
     */
    kpisV4(days) {
      const d = Number(days);
      return `
SELECT
  COUNT(*)                                                              AS total_iocs,
  SUM(CASE WHEN severity_v4 = 'CRITICAL'   THEN 1 ELSE 0 END)         AS critical_count,
  SUM(CASE WHEN severity_v4 = 'HIGH'       THEN 1 ELSE 0 END)         AS high_count,
  SUM(CASE WHEN severity_v4 = 'MEDIUM'     THEN 1 ELSE 0 END)         AS medium_count,
  SUM(CASE WHEN severity_v4 = 'LOW'        THEN 1 ELSE 0 END)         AS low_count,
  SUM(CASE WHEN severity_v4 = 'NEGLIGIBLE' THEN 1 ELSE 0 END)         AS negligible_count,
  ROUND(AVG(CAST(score_v4  AS DOUBLE)), 1)                             AS avg_score_v4,
  ROUND(AVG(CAST(score_base AS DOUBLE)), 1)                            AS avg_score_base,
  ROUND(AVG(CAST(score_v4 - score_base AS DOUBLE)), 2)                 AS avg_bonus_uplift,
  MAX(score_v4)                                                        AS max_score_v4,
  SUM(CASE WHEN score_killchain > 0 THEN 1 ELSE 0 END)                AS with_killchain_bonus,
  SUM(CASE WHEN novelty_mult > CAST(1.0 AS DOUBLE) THEN 1 ELSE 0 END) AS with_novelty_bonus,
  SUM(CASE WHEN geo_mult     > CAST(1.0 AS DOUBLE) THEN 1 ELSE 0 END) AS with_geo_bonus,
  CAST(MAX(dt) AS VARCHAR)                                             AS last_dt
FROM ${tv4mat}
WHERE dt >= current_date - INTERVAL '${d}' DAY
`.trim();
    },

    /**
     * Top N incidentes por score_v4 descendente (tabla materializada v4).
     * Incluye todos los campos de bonus para desglose en el panel.
     * @param {number} limit
     * @param {number} days
     */
    liveTopIncidentsV4Mat(limit, days) {
      const l = Number(limit);
      const d = Number(days);
      return `
SELECT
  ioc_value,
  ioc_type,
  source_log,
  origen_sistema,
  mitre_technique_id,
  mitre_tactic_id,
  mitre_tactic_name,
  score_base,
  score_v4,
  score_mitre,
  score_evidence,
  score_wazuh,
  score_context,
  score_tor,
  score_misp,
  score_email,
  score_killchain,
  n_kc_phases,
  CAST(novelty_mult AS VARCHAR) AS novelty_mult,
  CAST(geo_mult     AS VARCHAR) AS geo_mult,
  COALESCE(country_code, '') AS country_code,
  CAST(first_seen_dt AS VARCHAR) AS first_seen_dt,
  severity_base,
  severity_v4,
  confidence_level,
  recommended_action,
  vt_malicious,
  vt_suspicious,
  vt_permalink,
  shodan_ports,
  shodan_vulns,
  abuse_confidence,
  in_urlhaus,
  in_openphish,
  n_sources,
  source_category,
  alert_count,
  CAST(dt AS VARCHAR) AS dt
FROM ${tv4mat}
WHERE dt >= current_date - INTERVAL '${d}' DAY
ORDER BY score_v4 DESC, dt DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Distribución de IOCs por severity_v4 — para comparar con severity_base (v3).
     * @param {number} days
     */
    bySeverityV4(days) {
      const d = Number(days);
      return `
SELECT
  severity_v4,
  severity_base,
  COUNT(*)                              AS cnt,
  ROUND(AVG(CAST(score_v4  AS DOUBLE)), 1) AS avg_score_v4,
  ROUND(AVG(CAST(score_base AS DOUBLE)), 1) AS avg_score_base,
  MAX(score_v4)                         AS max_score_v4
FROM ${tv4mat}
WHERE dt >= current_date - INTERVAL '${d}' DAY
GROUP BY severity_v4, severity_base
ORDER BY
  CASE severity_v4
    WHEN 'CRITICAL'   THEN 1
    WHEN 'HIGH'       THEN 2
    WHEN 'MEDIUM'     THEN 3
    WHEN 'LOW'        THEN 4
    WHEN 'NEGLIGIBLE' THEN 5
    ELSE 6
  END,
  CASE severity_base
    WHEN 'CRITICAL'   THEN 1
    WHEN 'HIGH'       THEN 2
    WHEN 'MEDIUM'     THEN 3
    WHEN 'LOW'        THEN 4
    WHEN 'NEGLIGIBLE' THEN 5
    ELSE 6
  END
`.trim();
    },

    /**
     * Top sensores por volumen de IOCs — agrupa enriched_ioc por sensor_host + source_log.
     * Útil para detectar qué dispositivo está generando más detecciones.
     * @param {number} days
     * @param {number} limit
     */
    bySensor(days, limit) {
      const d = Number(days);
      const l = Number(limit);
      const te = `${catalog}.${schema}.enriched_ioc`;
      return `
SELECT
  COALESCE(sensor_host, '(sin sensor)')        AS sensor_host,
  source_log,
  COUNT(*)                                      AS total_iocs,
  COUNT(DISTINCT ioc_value)                     AS unique_iocs,
  CAST(MAX(dt) AS VARCHAR)                      AS last_dt
FROM ${te}
WHERE dt >= current_date - INTERVAL '${d}' DAY
GROUP BY 1, 2
ORDER BY total_iocs DESC
LIMIT ${l}
`.trim();
    },

    /**
     * Timeline diario de IOCs para un sensor específico.
     * Permite observar la actividad de un dispositivo a lo largo del tiempo.
     * @param {string} sensorKey  — sensor_host exacto (hostname o IP)
     * @param {number} days
     */
    sensorTimeline(sensorKey, days) {
      const d = Number(days);
      const te = `${catalog}.${schema}.enriched_ioc`;
      const sk = String(sensorKey).replace(/'/g, "''");
      return `
SELECT
  CAST(dt AS VARCHAR)            AS dt,
  source_log,
  COUNT(*)                       AS total_iocs,
  COUNT(DISTINCT ioc_value)      AS unique_iocs
FROM ${te}
WHERE dt >= current_date - INTERVAL '${d}' DAY
  AND sensor_host = '${sk}'
GROUP BY 1, 2
ORDER BY dt DESC
`.trim();
    },

    /**
     * Desglose de bonos v4: muestra los IOCs donde los bonos cambiaron la severidad.
     * Útil para auditar el impacto de kill-chain, novelty y geo-risk en la priorización.
     * @param {number} days
     */
    bonusBreakdown(days) {
      const d = Number(days);
      return `
SELECT
  ioc_value,
  ioc_type,
  origen_sistema,
  score_base,
  score_v4,
  score_v4 - score_base                                        AS total_delta,
  score_killchain,
  n_kc_phases,
  CAST(novelty_mult AS VARCHAR)                                AS novelty_mult,
  CAST(geo_mult     AS VARCHAR)                                AS geo_mult,
  COALESCE(country_code, 'N/A')                               AS country_code,
  CAST(first_seen_dt AS VARCHAR)                               AS first_seen_dt,
  severity_base,
  severity_v4,
  -- Indica si el bono cambió la severidad (upgrade de severidad)
  CASE WHEN severity_v4 != severity_base THEN true ELSE false END AS severity_upgraded,
  CASE
    WHEN severity_v4 = 'CRITICAL' AND severity_base != 'CRITICAL' THEN 'BASE→CRITICAL'
    WHEN severity_v4 = 'HIGH'     AND severity_base NOT IN ('CRITICAL','HIGH') THEN 'BASE→HIGH'
    WHEN severity_v4 = 'MEDIUM'   AND severity_base IN ('LOW','NEGLIGIBLE') THEN 'BASE→MEDIUM'
    ELSE 'SIN_CAMBIO'
  END AS upgrade_label,
  CAST(dt AS VARCHAR) AS dt
FROM ${tv4mat}
WHERE dt >= current_date - INTERVAL '${d}' DAY
  AND (
    score_killchain > 0
    OR novelty_mult > CAST(1.0 AS DOUBLE)
    OR geo_mult     > CAST(1.0 AS DOUBLE)
  )
ORDER BY total_delta DESC, score_v4 DESC
LIMIT 200
`.trim();
    },
  };
}
