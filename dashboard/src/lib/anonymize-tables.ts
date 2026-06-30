/**
 * anonymize-tables.ts — oculta los nombres internos de tablas/catálogos del
 * lake (minio_iceberg.hunting.*, vistas de scoring, etc.) en cualquier texto
 * que se muestre al operador (SQL de verificación, labels, mensajes de error).
 *
 * No expone la estructura del stack: reemplaza identificadores reales por
 * alias genéricos en snake_case (siguen leyéndose bien en un contexto SQL pero
 * no revelan catálogo/esquema/tabla reales).
 *
 * Orden importante: las reglas específicas van ANTES del catch-all genérico.
 */
const RULES: Array<[RegExp, string]> = [
  // Vistas de scoring (v_incident_score / _v2 / _v4) → motor de scoring
  [/\b(minio(_iceberg)?\.\w+\.)?v_incident_score(_v\d+)?\b/gi, "motor_scoring"],
  // Tablas de enriquecimiento / reputación
  [/\b(minio(_iceberg)?\.\w+\.)?enriched_ioc\b/gi, "ioc_enriquecido"],
  [/\b(minio(_iceberg)?\.\w+\.)?vt_results\b/gi, "reputacion_vt"],
  [/\b(minio(_iceberg)?\.\w+\.)?abuseipdb_results\b/gi, "reputacion_ip"],
  [/\b(minio(_iceberg)?\.\w+\.)?shodan_results\b/gi, "exposicion_red"],
  [/\b(minio(_iceberg)?\.\w+\.)?(abusech_urlhaus_urls|openphish_urls|threatfox\w*)\b/gi, "feeds_amenaza"],
  [/\b(minio(_iceberg)?\.\w+\.)?thc_rdns_results\b/gi, "rdns"],
  [/\b(minio(_iceberg)?\.\w+\.)?misp_(iocs|events)\b/gi, "intel_misp"],
  // Fuentes de detección
  [/\b(minio(_iceberg)?\.\w+\.)?wazuh_(alerts|fluent\w*)\b/gi, "eventos_siem"],
  [/\b(minio(_iceberg)?\.\w+\.)?(syslog_events|syslog|filterlog|opnsense\w*)\b/gi, "logs_perimetro"],
  [/\b(minio(_iceberg)?\.\w+\.)?fortigate\w*\b/gi, "logs_firewall"],
  [/\b(minio(_iceberg)?\.\w+\.)?suricata\w*\b/gi, "logs_ids"],
  [/\b(minio(_iceberg)?\.\w+\.)?pmg_\w+\b/gi, "logs_correo"],
  // Casos / clasificación / anomalías
  [/\b(minio(_iceberg)?\.\w+\.)?incident_classifications\b/gi, "clasificaciones"],
  [/\b(minio(_iceberg)?\.\w+\.)?incident_cases(_pg)?\b/gi, "casos"],
  [/\b(minio(_iceberg)?\.\w+\.)?outliers\b/gi, "anomalias"],
  // Catch-all: cualquier minio(_iceberg).<schema>.<tabla> restante → fuente_datos
  [/\bminio(_iceberg)?\.\w+\.\w+\b/gi, "fuente_datos"],
  // Catálogo/esquema sueltos
  [/\bminio_iceberg\b/gi, "lake"],
];

/** Reemplaza nombres internos de tablas por alias genéricos en `text`. */
export function anonymizeTables(text: string | null | undefined): string {
  let out = String(text ?? "");
  for (const [re, repl] of RULES) out = out.replace(re, repl);
  return out;
}
