/**
 * Snapshot de fuentes de inteligencia: conteos S3 (prefijos) + agregados Trino (syslog / Wazuh).
 */

import { ListObjectsV2Command } from "@aws-sdk/client-s3";
import { syslogIngestTimestampExpr } from "./trino/ingest-time.mjs";
import { ping as ctiPing, ctiConfigured } from "./services/ctiCloudyoleService.mjs";
import {
  getKpis as getInfragovpyKpis,
  getLgcrblLastPush,
} from "./services/infragovpyWatchlistService.mjs";

const DEFAULT_SYSLOG_TABLE = "minio.hunting.syslog";

function ingestTimeForFilter(column = "ingest_time") {
  return syslogIngestTimestampExpr(column);
}

/**
 * WHERE clause usando columnas de partición year/month/day (varchar) para
 * habilitar partition pruning real en Trino/Hive.
 *
 * IMPORTANT: Trino sólo aplica partition pruning cuando la columna de partición
 * aparece en el predicado de forma LITERAL (p.ej. `year = '2026'`).
 * Cualquier expresión aritmética (TRY_CAST(year)* 10000 + ...) desactiva el
 * pruning y fuerza un full table scan → las queries nunca terminan.
 *
 * Estrategia: comparar `year` (varchar) directamente como string. Para rangos
 * que cruzan años generamos una cláusula `year IN ('YYYY', 'YYYY+1', ...)`.
 * Los años 4 dígitos ordenan correctamente como strings.
 *
 * @param {number} days
 */
function partitionDateFilter(days) {
  if (days <= 0) return "1=1";
  const now = new Date();
  const cutoff = new Date();
  cutoff.setUTCDate(cutoff.getUTCDate() - days);

  const cutoffYear = cutoff.getUTCFullYear();
  const currentYear = now.getUTCFullYear();

  if (cutoffYear === currentYear) {
    // Mismo año — un único predicado de igualdad: partición pruning óptimo
    return `year = '${currentYear}'`;
  }

  // Años distintos — construimos IN ('YYYY', 'YYYY+1', ...) para cubrir el rango
  const years = [];
  for (let y = cutoffYear; y <= currentYear; y++) years.push(`'${y}'`);
  return `year IN (${years.join(", ")})`;
}

/**
 * SELECT para daily breakdown usando columnas de partición year/month/day.
 * Devuelve filas {d: 'YYYY-MM-DD', c: number}.
 * @param {string} table
 * @param {number} days
 */
function syslogDailyQuery(table, days) {
  const filter = partitionDateFilter(days);
  return `
    SELECT year || '-' || lpad(month, 2, '0') || '-' || lpad(day, 2, '0') AS d,
           COUNT(*) AS c
    FROM ${table}
    WHERE ${filter}
    GROUP BY 1
    ORDER BY 1
  `.trim();
}

/**
 * Ejecuta una query con timeout máximo. Devuelve null si el timeout se alcanza.
 * @param {(q: string) => Promise<Record<string,unknown>[]>} runTrinoQuery
 * @param {string} sql
 * @param {number} timeoutMs
 * @param {string} label — para logging
 */
/**
 * Envuelve una promesa con un timeout duro. Rechaza si no resuelve a tiempo.
 * @template T
 * @param {Promise<T>} promise
 * @param {number} ms
 * @param {string} label
 * @returns {Promise<T>}
 */
function withTimeout(promise, ms, label = "op") {
  return Promise.race([
    promise,
    new Promise((_, rej) =>
      setTimeout(() => rej(new Error(`[intel-sources] timeout ${label} (${ms}ms)`)), ms),
    ),
  ]);
}

async function trinoQueryWithTimeout(runTrinoQuery, sql, timeoutMs = 12_000, label = "query") {
  try {
    const result = await Promise.race([
      runTrinoQuery(sql),
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error(`[intel-sources] timeout ${label} (${timeoutMs}ms)`)), timeoutMs),
      ),
    ]);
    return result;
  } catch (e) {
    console.warn("[intel-sources] query failed:", label, e instanceof Error ? e.message : e);
    return null;
  }
}

function leakIntelRawScanPrefix() {
  const base = (process.env.S3_LAKE_LEAK_INTEL_RAW_PREFIX ?? "leak_intel/raw").replace(/^\/+/, "");
  return base.endsWith("/") ? base : `${base}/`;
}
const S3_LIST_CAP = Math.min(
  100_000,
  Math.max(100, parseInt(process.env.INTEL_SOURCES_S3_MAX_KEYS ?? "8000", 10) || 8000),
);
const rawSyslogDays = parseInt(process.env.INTEL_SOURCES_SYSLOG_COUNT_DAYS ?? "30", 10);
const rawWazuhDays = parseInt(process.env.INTEL_SOURCES_WAZUH_COUNT_DAYS ?? "30", 10);

/** Identificador Trino (catálogo/esquema) seguro para interpolar en SQL. */
function safeTrinoIdent(raw, fallback) {
  const t = String(raw ?? fallback).trim();
  return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(t) ? t : fallback;
}

/**
 * @param {((q: string) => Promise<Record<string, unknown>[]>) | null} runTrinoQuery
 * @param {string} fqtn — `catalog.schema.table`
 * @param {number} days
 * @returns {Promise<number | null>}
 */
async function trinoCountIcebergByDt(runTrinoQuery, fqtn, days) {
  if (!runTrinoQuery) return null;
  try {
    const rows = await Promise.race([
      runTrinoQuery(
        `SELECT COUNT(*) AS c FROM ${fqtn} WHERE dt >= CURRENT_DATE - INTERVAL '${days}' DAY`,
      ),
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error(`timeout iceberg count ${fqtn}`)), 10_000),
      ),
    ]);
    return Number(rows[0]?.c ?? 0);
  } catch (e) {
    console.warn("[intel-sources] iceberg count", fqtn, e instanceof Error ? e.message : e);
    return null;
  }
}

function sparkFlat() {
  return Array.from({ length: 8 }, () => 0.25);
}

/** Últimos `days` días calendario (UTC) como YYYY-MM-DD */
function lastNDaysIso(days) {
  const out = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date();
    d.setUTCDate(d.getUTCDate() - i);
    out.push(d.toISOString().slice(0, 10));
  }
  return out;
}

/** rows: [{ d: '2025-03-20', c: 12 }] — d puede venir como date o varchar */
function sparkFromDailyRows(rows, days = 8) {
  const keys = lastNDaysIso(days);
  const map = new Map();
  for (const r of rows ?? []) {
    const raw = r.d ?? r.day;
    let k;
    if (raw == null) continue;
    if (typeof raw === "string") k = raw.slice(0, 10);
    else if (raw instanceof Date) k = raw.toISOString().slice(0, 10);
    else k = String(raw).slice(0, 10);
    map.set(k, Number(r.c ?? r.cnt ?? 0));
  }
  const vals = keys.map((key) => map.get(key) ?? 0);
  const max = Math.max(...vals, 1);
  return vals.map((v) => 0.12 + (v / max) * 0.85);
}

async function scanPrefix(s3, bucket, prefix) {
  let count = 0;
  let csv = 0;
  let pdf = 0;
  let pcap = 0;
  /** @type {Date | null} */
  let maxTime = null;
  let truncated = false;
  let token;
  do {
    const out = await s3.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        ContinuationToken: token,
        MaxKeys: 1000,
      }),
    );
    for (const o of out.Contents ?? []) {
      count++;
      const lk = (o.Key ?? "").toLowerCase();
      if (lk.endsWith(".csv")) csv++;
      if (lk.endsWith(".pdf")) pdf++;
      if (lk.endsWith(".pcap") || lk.endsWith(".pcapng")) pcap++;
      if (o.LastModified && (!maxTime || o.LastModified > maxTime)) maxTime = o.LastModified;
      if (count >= S3_LIST_CAP) {
        truncated = true;
        break;
      }
    }
    if (truncated) break;
    token = out.IsTruncated ? out.NextContinuationToken : undefined;
  } while (token && count < S3_LIST_CAP);
  return { count, csv, pdf, pcap, maxTime, truncated };
}

/**
 * Escanea el prefijo S3 de syslog leyendo SÓLO metadatos de objetos (sin leer datos).
 * Extrae fecha de la ruta `year=YYYY/month=MM/day=DD/` y agrega por día.
 *
 * Mucho más rápido que `SELECT COUNT(*) FROM minio.hunting.syslog` sobre
 * ficheros JSON (que requiere leer cada byte para contar filas).
 *
 * @param {import("@aws-sdk/client-s3").S3Client} s3
 * @param {string} bucket
 * @param {string} prefix — ej. "syslog/"
 * @param {number} days — ventana de días a incluir en dailyStats (0 = todos)
 * @returns {Promise<{
 *   totalFiles: number,
 *   totalBytes: number,
 *   lastSeen: Date | null,
 *   truncated: boolean,
 *   dailyStats: Array<{d: string, files: number, bytes: number}>
 * }>}
 */
async function scanSyslogDailyS3(s3, bucket, prefix, days = 30) {
  const cutoffDate = days > 0
    ? new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10)
    : null;

  // day → { files, bytes }
  /** @type {Map<string, {files: number, bytes: number}>} */
  const dayMap = new Map();
  let totalFiles = 0;
  let totalBytes = 0;
  /** @type {Date | null} */
  let lastSeen = null;
  let truncated = false;
  let token;

  // Regex para extraer año/mes/día de path tipo year=2026/month=04/day=08/
  const dayRe = /year=(\d{4})\/month=(\d{2})\/day=(\d{2})\//;

  do {
    /** @type {import("@aws-sdk/client-s3").ListObjectsV2CommandOutput} */
    const out = await s3.send(new ListObjectsV2Command({
      Bucket: bucket,
      Prefix: prefix,
      ContinuationToken: token,
      MaxKeys: 1000,
    }));

    for (const o of out.Contents ?? []) {
      // Extraer fecha de la clave S3
      const m = dayRe.exec(o.Key ?? "");
      const dayStr = m ? `${m[1]}-${m[2]}-${m[3]}` : null;

      // Filtrar fuera del rango si hay cutoff
      if (cutoffDate && dayStr && dayStr < cutoffDate) continue;

      totalFiles++;
      totalBytes += o.Size ?? 0;
      if (o.LastModified && (!lastSeen || o.LastModified > lastSeen)) lastSeen = o.LastModified;

      if (dayStr) {
        const entry = dayMap.get(dayStr) ?? { files: 0, bytes: 0 };
        entry.files++;
        entry.bytes += o.Size ?? 0;
        dayMap.set(dayStr, entry);
      }

      if (totalFiles >= S3_LIST_CAP) { truncated = true; break; }
    }
    if (truncated) break;
    token = out.IsTruncated ? out.NextContinuationToken : undefined;
  } while (token);

  const dailyStats = Array.from(dayMap.entries())
    .map(([d, v]) => ({ d, files: v.files, bytes: v.bytes }))
    .sort((a, b) => a.d.localeCompare(b.d));

  return { totalFiles, totalBytes, lastSeen, truncated, dailyStats };
}

/** Construye sparkline normalizado [0..1]^8 a partir de dailyStats de syslog. */
function sparkFromSyslogDailyS3(dailyStats, days = 8) {
  const keys = lastNDaysIso(days);
  const fileMap = new Map(dailyStats.map((r) => [r.d, r.files]));
  const vals = keys.map((k) => fileMap.get(k) ?? 0);
  const max = Math.max(...vals, 1);
  return vals.map((v) => 0.12 + (v / max) * 0.85);
}

function iso(d) {
  return d ? d.toISOString() : new Date(0).toISOString();
}

function baseSourcesMeta() {
  return [
    {
      id: "syslog",
      name: "Syslog / perímetro",
      shortName: "Syslog",
      description:
        "Eventos OPNsense y syslog hacia el lake (tabla Hive/JSON en Trino).",
      tooltip:
        "Conteo de ficheros en S3 (prefijo INTEL_SOURCES_SYSLOG_S3_PREFIX, default 'syslog/'). " +
        "Se usa ListObjectsV2 sobre metadatos para evitar full scan del JSON.",
      recordUnit: "ficheros",
      detailHref: "/live-activity",
    },
    {
      id: "shadowserver",
      name: "Shadowserver",
      shortName: "Shadowserver",
      description: "CSV y reportes bajo `shadowserver/raw/` en el bucket.",
      tooltip: "Conteo de objetos en S3/MinIO (listado; tope INTEL_SOURCES_S3_MAX_KEYS).",
      recordUnit: "objetos",
      detailHref: "/shadowserver-feeds",
    },
    {
      id: "abusech",
      name: "Abuse.ch — URLhaus",
      shortName: "URLhaus",
      description: "URLs recientes URLhaus en Iceberg (Airflow DAG threat_intel_feeds_12h).",
      tooltip:
        "Conteo en `INTEL_SOURCES_ICEBERG_CATALOG.INTEL_SOURCES_ICEBERG_SCHEMA.abusech_urlhaus_urls` (ventana INTEL_SOURCES_ENRICHMENT_LOOKBACK_DAYS).",
      recordUnit: "URLs",
    },
    {
      id: "otx",
      name: "AlienVault OTX",
      shortName: "OTX",
      description: "Pulsos OTX — sin datos en el lake local.",
      tooltip: "Conector pendiente.",
      recordUnit: "pulsos",
    },
    {
      id: "spamhaus",
      name: "Spamhaus",
      shortName: "Spamhaus",
      description: "Listas DROP/EDROP — sin ingesta lake en este repo.",
      tooltip: "Conector batch pendiente.",
      recordUnit: "entradas",
    },
    {
      id: "openphish",
      name: "OpenPhish",
      shortName: "OpenPhish",
      description: "Feed público de URLs (raw.githubusercontent.com) → tabla Iceberg openphish_urls.",
      tooltip:
        "Ingesta cada 12 h vía Airflow. Conteo en catálogo Iceberg (`openphish_urls`).",
      recordUnit: "URLs",
    },
    {
      id: "virustotal",
      name: "VirusTotal",
      shortName: "VT",
      description: "Reputación IP (API v3) sobre IOCs del lake → tabla vt_results.",
      tooltip: "Airflow `threat_hunt_enrichment_daily`. Requiere clave en Connection virustotal_api o VT_API_KEY.",
      recordUnit: "consultas",
    },
    {
      id: "shodan-enrichment",
      name: "Shodan — hosts IOC",
      shortName: "Shodan",
      description: "Exposición/banners por IP desde IOCs enriquecidos → shodan_results.",
      tooltip: "Diferente del dominio Shodan del API legacyhunt-api. Connection shodan_default o SHODAN_API_KEY.",
      recordUnit: "consultas",
    },
    {
      id: "abuseipdb",
      name: "AbuseIPDB",
      shortName: "AbuseIPDB",
      description: "Reputación y reportes de IP (API v2) → abuseipdb_results.",
      tooltip: "Connection abuseipdb_api o ABUSEIPDB_API_KEY. DAG threat_hunt_enrichment_daily.",
      recordUnit: "consultas",
    },
    {
      id: "thc-rdns",
      name: "THC — reverse DNS (ip.thc.org)",
      shortName: "THC",
      description:
        "Dominios asociados a IPs IOC vía API pública POST /api/v1/lookup → tabla Iceberg thc_rdns_results; también en casos (Gestión).",
      tooltip:
        "Sin API key. Rate limit ~0,5 req/s. Airflow `threat_hunt_enrichment_daily` (enrich_thc_rdns). En UI: DNS bajo la IP al abrir un caso. Doc: https://ip.thc.org/docs/API/reverse-dns-lookup",
      recordUnit: "consultas",
      detailHref: "/gestion",
    },
    {
      id: "wazuh",
      name: "Wazuh — alertas SIEM",
      shortName: "Wazuh",
      description: "Alertas en tabla Trino opcional (JSON en message).",
      tooltip:
        "Defina `INTEL_SOURCES_WAZUH_TABLE` (p. ej. minio.hunting.wazuh_alerts). Sin tabla: pendiente.",
      recordUnit: "alertas",
      detailHref: "/wazuh-intelligence",
    },
    {
      id: "csv-ingest",
      name: "CSV estructurados",
      shortName: "CSV",
      description: "Archivos .csv bajo leak_intel y shadowserver (objetos S3).",
      tooltip: "Suma de claves .csv en prefijos raw (mismo tope de listado).",
      recordUnit: "archivos",
      detailHref: "/shadowserver-feeds",
    },
    {
      id: "pdf-reports",
      name: "Informes PDF",
      shortName: "PDF",
      description: "PDF bajo `leak_intel/raw/` (conteo por sufijo .pdf).",
      tooltip: "Basado en listado S3; parsing/IOC en pipeline pendiente.",
      recordUnit: "documentos",
      detailHref: "/hunting-insights",
    },
    {
      id: "pcap",
      name: "PCAP — capturas de red",
      shortName: "PCAP",
      description: "Objetos .pcap/.pcapng en prefijos de ingesta.",
      tooltip: "Conteo por sufijo en leak_intel y shadowserver; prefijo pcap/raw/ opcional.",
      recordUnit: "capturas",
      detailHref: "/pcap-analyzer",
    },
    {
      id: "raw-leaks",
      name: "Expert Search / Raw Leaks",
      shortName: "Raw leaks",
      description: "Objetos raw en `leak_intel/raw/`.",
      tooltip: "Conteo S3 de objetos bajo leak_intel/raw/.",
      recordUnit: "objetos",
    },
    {
      id: "credentials",
      name: "Credentials Leaks",
      shortName: "Credenciales",
      description: "Ingesta leak_intel (ZIP/CSV) vía API → S3.",
      tooltip: "Mismo conteo que objetos bajo leak_intel/raw/.",
      recordUnit: "objetos",
      detailHref: "/credential-exposure",
    },
    {
      id: "ssh-invalid-users",
      name: "SSH BruteForce — Usuarios Inválidos",
      shortName: "SSH BF",
      description:
        "Intentos SSH con usuarios inexistentes detectados por Wazuh (reglas 5710–5758), guardados en Iceberg ssh_invalid_users.",
      tooltip:
        "Conteo de filas en minio_iceberg.hunting.ssh_invalid_users (ventana INTEL_SOURCES_ENRICHMENT_LOOKBACK_DAYS).",
      recordUnit: "intentos",
      detailHref: "/wazuh-intelligence",
    },
    {
      id: "misp",
      name: "MISP — Threat Intelligence",
      shortName: "MISP",
      description:
        "Eventos e IOCs sincronizados desde MISP (Malware Information Sharing Platform) → tablas Iceberg misp_events y misp_iocs.",
      tooltip:
        "DAG Airflow: threat_hunt_misp_sync_daily (01:15 UTC). Configura MISP_BASE_URL + MISP_API_KEY. " +
        "Requiere: bash scripts/bootstrap-misp.sh + bash scripts/bootstrap-trino-misp.sh.",
      recordUnit: "IOCs",
      detailHref: "/intelligence-sources",
    },
    {
      id: "brand24",
      name: "Brand24 — Social Listening",
      shortName: "Brand24",
      description:
        "Social Listening y análisis de reputación de marca en redes sociales, noticias, blogs y foros.",
      tooltip:
        "Requiere BRAND24_API_KEY. Monitoriza menciones, sentimiento y Share of Voice en tiempo real vía API Brand24. Ver: https://developers.brand24.com/",
      recordUnit: "menciones",
      detailHref: "/vigilancia",
    },
    {
      id: "cti-cloudyole",
      name: "CTI Cloud & Olé (Kaduu)",
      shortName: "CTI C&O",
      description:
        "Dark Web Monitoring y detección de leaks: credenciales filtradas, stealer logs, sitios phishing y exposición de infraestructura.",
      tooltip:
        "Requiere CTI_CLOUDYOLE_BASE_URL + CTI_CLOUDYOLE_API_KEY. API especializada en dark web, paste sites y mercados underground. Ver: https://cti.cloudyole.es/docs",
      recordUnit: "hallazgos",
      detailHref: "/vigilancia",
    },
    {
      id: "infragovpy",
      name: "lgcrBL — Blacklist CERT-PY",
      shortName: "lgcrBL",
      description:
        "IPs penalizadas (≥ 2 reportes en 7 d) del feed saliente lgcrBL, publicadas a la blacklist CERT-PY vía push diario a GitLab.",
      tooltip:
        "Penalizadas = IPs con report_count ≥ 2 y vigentes (watchlist lgcrBL, PG). " +
        "Push: DAG infragovpy_daily_push (07:00 PY) + botón Publicar → repo GitLab del feed. " +
        "El timestamp es la hora del último commit (push) al repo.",
      recordUnit: "IPs penalizadas",
      lastProcessedLabel: "Último push al git",
      detailHref: "/estado-fuentes?tab=lgcrbl",
    },
  ];
}

/**
 * @param {{ bucket: string, s3: import('@aws-sdk/client-s3').S3Client, runTrinoQuery: ((q: string) => Promise<Record<string, unknown>[]>) | null, env: Record<string, string | undefined> }} ctx
 */
export async function buildIntelligenceSourcesSummary(ctx) {
  const { bucket, s3, runTrinoQuery, env } = ctx;
  const snapshotAt = new Date().toISOString();
  const syslogRaw = (env.INTEL_SOURCES_SYSLOG_TABLE ?? "").trim();
  const syslogTable = syslogRaw.length > 0 ? syslogRaw : DEFAULT_SYSLOG_TABLE;
  const wazuhTable = (env.INTEL_SOURCES_WAZUH_TABLE ?? "").trim();
  const syslogCountDays = Number.isFinite(rawSyslogDays) && rawSyslogDays >= 0 ? rawSyslogDays : 30;
  const wazuhCountDays = Number.isFinite(rawWazuhDays) && rawWazuhDays >= 0 ? rawWazuhDays : 30;

  // ── Timeout por escaneo S3 ───────────────────────────────────────────────
  // Un único `ListObjectsV2` lento (bucket grande, MinIO saturado) no debe
  // agotar el build global de 30 s. Cada escaneo se acota a S3_SCAN_TIMEOUT y,
  // si falla/expira, degrada a vacío sin tumbar el resto de fuentes.
  const S3_SCAN_TIMEOUT = Math.max(
    4_000,
    parseInt(env.INTEL_SOURCES_S3_SCAN_TIMEOUT_MS ?? "12000", 10) || 12_000,
  );
  const emptyScan = {
    count: 0, csv: 0, pdf: 0, pcap: 0,
    maxTime: /** @type {Date | null} */ (null), truncated: false,
  };
  /** @type {Awaited<ReturnType<typeof scanSyslogDailyS3>> & { _err?: boolean }} */
  const emptyDaily = { totalFiles: 0, totalBytes: 0, lastSeen: null, truncated: false, dailyStats: [] };

  // ── Syslog: escaneo S3 en lugar de COUNT(*) sobre JSON ───────────────────────
  // SELECT COUNT(*) sobre la tabla JSON de syslog requiere leer cada byte →
  // siempre > 30 s con 3 M+ registros. En su lugar usamos ListObjectsV2 sobre
  // el prefijo S3 que es una operación de metadatos (sin leer datos) y tarda
  // ~200-500 ms para miles de ficheros.
  //
  // Se configura con INTEL_SOURCES_SYSLOG_S3_PREFIX (default "syslog/").
  // El bucket es el mismo que el resto de fuentes (BUCKET / MINIO_BUCKET).
  const syslogS3Prefix = ((env.INTEL_SOURCES_SYSLOG_S3_PREFIX ?? "syslog/")
    .trim()
    .replace(/^\/+/, "")
    .replace(/\/?$/, "/"));

  // Wazuh: S3 scan por defecto (igual que syslog) para evitar COUNT(*) lento sobre JSON.
  // Prioridad: INTEL_SOURCES_WAZUH_S3_PREFIX explícito > auto wazuh_alerts/ (cuando tabla configurada)
  //            > vacío → fallback Trino (solo si tabla configurada y Trino disponible).
  const wazuhS3PrefixRaw = (env.INTEL_SOURCES_WAZUH_S3_PREFIX ?? "").trim()
    || (wazuhTable ? "wazuh_alerts" : "");
  const wazuhS3Prefix = wazuhS3PrefixRaw
    .replace(/^\/+/, "")
    .replace(/\/?$/, "/");
  const wazuhUsesS3 = Boolean(wazuhS3Prefix && wazuhS3Prefix !== "/");

  const iceCat = safeTrinoIdent(env.INTEL_SOURCES_ICEBERG_CATALOG, "minio_iceberg");
  const iceSch = safeTrinoIdent(env.INTEL_SOURCES_ICEBERG_SCHEMA, "hunting");
  const rawIceDays = parseInt(env.INTEL_SOURCES_ENRICHMENT_LOOKBACK_DAYS ?? "30", 10);
  const iceDays =
    Number.isFinite(rawIceDays) && rawIceDays >= 1 && rawIceDays <= 365 ? rawIceDays : 30;
  const ice = (t) => `${iceCat}.${iceSch}.${t}`;

  // Ping CTI CloudYole en paralelo con todo lo demás (timeout interno 10 s)
  /** @type {{ ok: boolean, detail?: string, error?: string } | null} */
  let ctiPingResult = null;
  const ctiPingPromise = ctiConfigured()
    ? ctiPing().then((r) => { ctiPingResult = r; }).catch(() => { ctiPingResult = { ok: false, error: "timeout" }; })
    : Promise.resolve();

  // ── Batch Iceberg Trino (cada conteo tiene su propio timeout de 10 s) ──
  const icebergBatchPromise = runTrinoQuery
    ? Promise.all([
        trinoCountIcebergByDt(runTrinoQuery, ice("vt_results"), iceDays),
        trinoCountIcebergByDt(runTrinoQuery, ice("shodan_results"), iceDays),
        trinoCountIcebergByDt(runTrinoQuery, ice("abuseipdb_results"), iceDays),
        trinoCountIcebergByDt(runTrinoQuery, ice("openphish_urls"), iceDays),
        trinoCountIcebergByDt(runTrinoQuery, ice("abusech_urlhaus_urls"), iceDays),
        trinoCountIcebergByDt(runTrinoQuery, ice("ssh_invalid_users"), iceDays),
        trinoCountIcebergByDt(runTrinoQuery, ice("thc_rdns_results"), iceDays),
        trinoCountIcebergByDt(runTrinoQuery, ice("misp_iocs"), iceDays),
        trinoCountIcebergByDt(runTrinoQuery, ice("misp_events"), iceDays),
      ])
    : Promise.resolve([null, null, null, null, null, null, null, null, null]);

  // ── Wazuh Trino fallback (sólo cuando NO hay prefijo S3) ──
  const wazuhFallbackPromise = (!wazuhUsesS3 && runTrinoQuery && wazuhTable)
    ? Promise.all([
        trinoQueryWithTimeout(
          runTrinoQuery,
          `SELECT COUNT(*) AS c FROM ${wazuhTable} WHERE ${wazuhCountDays > 0 ? partitionDateFilter(wazuhCountDays) : "1=1"}`,
          10_000, "wazuh-count",
        ),
        trinoQueryWithTimeout(runTrinoQuery, syslogDailyQuery(wazuhTable, 8), 10_000, "wazuh-daily"),
      ])
    : Promise.resolve([/** @type {{ c: unknown }[] | null} */ (null), /** @type {Record<string, unknown>[] | null} */ (null)]);

  // ── Lanzar TODO en paralelo: 5 escaneos S3 + batch Iceberg + wazuh fallback + cti ping ──
  // Antes corrían en secuencia (leak → shadow → pcap → syslog → wazuh → Trino),
  // sumando latencias y disparando el build timeout de 30 s. Ahora el coste es
  // el del paso más lento (~12 s acotado), no la suma.
  const [
    leakStats,
    shadowStats,
    pcapExtra,
    syslogS3Stats,
    wazuhS3Stats,
    icebergCounts,
    [wazuhCountRows, wazuhDailyRows],
  ] = await Promise.all([
    withTimeout(scanPrefix(s3, bucket, leakIntelRawScanPrefix()), S3_SCAN_TIMEOUT, "leak_intel")
      .catch((e) => { console.error("[intel-sources] leak_intel scan", e instanceof Error ? e.message : e); return emptyScan; }),
    withTimeout(scanPrefix(s3, bucket, "shadowserver/raw/"), S3_SCAN_TIMEOUT, "shadowserver")
      .catch((e) => { console.error("[intel-sources] shadowserver scan", e instanceof Error ? e.message : e); return emptyScan; }),
    withTimeout(scanPrefix(s3, bucket, "pcap/raw/"), S3_SCAN_TIMEOUT, "pcap")
      .catch(() => emptyScan), // prefijo opcional
    withTimeout(scanSyslogDailyS3(s3, bucket, syslogS3Prefix, syslogCountDays || 30), S3_SCAN_TIMEOUT, "syslog")
      .catch((e) => { console.error("[intel-sources] syslog S3 scan", e instanceof Error ? e.message : e); return { ...emptyDaily, _err: true }; }),
    wazuhUsesS3
      ? withTimeout(scanSyslogDailyS3(s3, bucket, wazuhS3Prefix, wazuhCountDays || 30), S3_SCAN_TIMEOUT, "wazuh")
          .catch((e) => {
            const msg = e instanceof Error ? e.message : String(e);
            console.error("[intel-sources] wazuh S3 scan", msg);
            return { ...emptyDaily, _err: true, _timeout: /timeout/i.test(msg) };
          })
      : Promise.resolve(emptyDaily),
    icebergBatchPromise,
    wazuhFallbackPromise,
    ctiPingPromise,
  ]);

  const syslogTrinoError = Boolean(syslogS3Stats && syslogS3Stats._err);
  const wazuhTrinoError = wazuhUsesS3
    ? Boolean(wazuhS3Stats && wazuhS3Stats._err)
    : Boolean(!wazuhUsesS3 && runTrinoQuery && wazuhTable && wazuhCountRows === null);

  const [
    vtCount,
    shodanEnrichCount,
    abuseipdbCount,
    openphishCount,
    urlhausCount,
    sshInvalidCount,
    thcRdnsCount,
    mispIocsCount,
    mispEventsCount,
  ] = icebergCounts;

  // InfraGOVPY: la tarjeta ahora refleja el feed saliente lgcrBL (no la tabla
  // Iceberg infragovpy_blacklist, cuyo COUNT(*) tardaba 3+ min y estaba desactivado).
  //   · recordCount  = IPs penalizadas (≥2 reportes en 7 d) del watchlist PG
  //   · lastProcessedAt = hora del último push (commit) al repo GitLab del feed
  // Ambos degradan a null sin tumbar el resto de fuentes (Promise.allSettled).
  const [penalizedRes, lastPushRes] = await Promise.allSettled([
    getInfragovpyKpis(),
    getLgcrblLastPush(),
  ]);
  const infragovpyPenalized =
    penalizedRes.status === "fulfilled" ? Number(penalizedRes.value?.penalized ?? 0) : null;
  const infragovpyLastPush =
    lastPushRes.status === "fulfilled" && lastPushRes.value?.ok ? lastPushRes.value : null;

  // Syslog: usar estadísticas S3 (ficheros + bytes) en lugar de COUNT(*) Trino
  const syslogCount = syslogS3Stats.totalFiles;
  const syslogSpark = syslogS3Stats.dailyStats.length
    ? sparkFromSyslogDailyS3(syslogS3Stats.dailyStats, 8)
    : sparkFlat();

  // Wazuh: S3 si se configuró prefijo, sino Trino
  const wazuhCount = wazuhS3Prefix && wazuhS3Prefix !== "/"
    ? wazuhS3Stats.totalFiles
    : Number(wazuhCountRows?.[0]?.c ?? 0);
  const wazuhSpark = wazuhS3Prefix && wazuhS3Prefix !== "/" && wazuhS3Stats.dailyStats.length
    ? sparkFromSyslogDailyS3(wazuhS3Stats.dailyStats, 8)
    : wazuhDailyRows?.length
      ? sparkFromDailyRows(wazuhDailyRows, 8)
      : sparkFlat();

  const csvTotal = leakStats.csv + shadowStats.csv;
  const pcapTotal = leakStats.pcap + shadowStats.pcap + pcapExtra.count;

  const meta = baseSourcesMeta();
  const sources = meta.map((m) => {
    let recordCount = 0;
    let lastProcessedAt = snapshotAt;
    let status = /** @type {'processed' | 'pending' | 'error' | 'partial'} */ ("pending");
    let progress = 0;
    let activitySeries = sparkFlat();
    let tooltip = m.tooltip;

    switch (m.id) {
      case "syslog":
        if (syslogTrinoError) {
          status = "error";
          tooltip = `Error al escanear S3 (prefijo '${syslogS3Prefix}'). Compruebe INTEL_SOURCES_SYSLOG_S3_PREFIX y acceso al bucket.`;
        } else {
          recordCount = syslogCount;
          activitySeries = syslogSpark;
          lastProcessedAt = syslogS3Stats.lastSeen ? iso(syslogS3Stats.lastSeen) : snapshotAt;
          status = syslogCount > 0 ? "processed" : "partial";
          progress = syslogCount > 0 ? 100 : 40;
          if (syslogS3Stats.truncated) tooltip += " Recuento truncado (tope S3_LIST_CAP).";
          if (syslogCount === 0) {
            tooltip = `Sin ficheros en '${syslogS3Prefix}' (bucket: ${bucket}). Ajusta INTEL_SOURCES_SYSLOG_S3_PREFIX.`;
          }
        }
        break;
      case "shadowserver":
        recordCount = shadowStats.count;
        lastProcessedAt =
          shadowStats.count > 0 && shadowStats.maxTime
            ? iso(shadowStats.maxTime)
            : snapshotAt;
        activitySeries = sparkFlat();
        status = shadowStats.truncated
          ? "partial"
          : shadowStats.count > 0
            ? "processed"
            : "partial";
        progress = shadowStats.count > 0 ? 100 : 25;
        if (shadowStats.truncated) tooltip += " Recuento truncado por tope de listado.";
        break;
      case "credentials":
      case "raw-leaks":
        recordCount = leakStats.count;
        lastProcessedAt =
          leakStats.count > 0 && leakStats.maxTime ? iso(leakStats.maxTime) : snapshotAt;
        activitySeries = sparkFlat();
        status = leakStats.count > 0 ? "processed" : "partial";
        progress = leakStats.count > 0 ? 100 : 20;
        if (leakStats.truncated) tooltip += " Recuento truncado por tope.";
        break;
      case "csv-ingest": {
        const csvDates = [leakStats.maxTime, shadowStats.maxTime].filter(Boolean);
        const csvLatest =
          csvDates.length > 0
            ? new Date(Math.max(...csvDates.map((d) => d.getTime())))
            : null;
        recordCount = csvTotal;
        lastProcessedAt = csvLatest ? iso(csvLatest) : snapshotAt;
        activitySeries = sparkFlat();
        status = csvTotal > 0 ? "processed" : "partial";
        progress = csvTotal > 0 ? 100 : 30;
        break;
      }
      case "pdf-reports":
        recordCount = leakStats.pdf;
        lastProcessedAt =
          leakStats.pdf > 0 && leakStats.maxTime
            ? iso(leakStats.maxTime)
            : snapshotAt;
        activitySeries = sparkFlat();
        status = leakStats.pdf > 0 ? "processed" : "pending";
        progress = leakStats.pdf > 0 ? 100 : 10;
        break;
      case "pcap": {
        const pcapLatest = [leakStats.maxTime, shadowStats.maxTime, pcapExtra.maxTime].filter(
          Boolean,
        );
        const latest =
          pcapLatest.length > 0
            ? new Date(Math.max(...pcapLatest.map((d) => d.getTime())))
            : null;
        recordCount = pcapTotal;
        lastProcessedAt = latest ? iso(latest) : snapshotAt;
        activitySeries = sparkFlat();
        status = pcapTotal > 0 ? "partial" : "pending";
        progress = pcapTotal > 0 ? 55 : 15;
        break;
      }
      case "wazuh":
        if (!wazuhTable) {
          status = "pending";
          progress = 0;
          if (runTrinoQuery) {
            tooltip =
              "Defina INTEL_SOURCES_WAZUH_TABLE en .env (p. ej. minio.hunting.wazuh_alerts) y VITE_TRINO_WAZUH_TABLE. Vista unión syslog+alerts: ./scripts/bootstrap-trino-wazuh-view.sh → minio.hunting.wazuh. Ver docs/INGESTA-OPNSENSE-WAZUH-TRINO.md.";
          }
        } else if (wazuhUsesS3 && wazuhS3Stats?._timeout) {
          // El prefijo S3 de Wazuh tiene demasiados objetos para listarlos dentro
          // del timeout de escaneo → recuento parcial, no un fallo de Trino.
          status = "partial";
          progress = 35;
          tooltip =
            `Recuento Wazuh incompleto: el prefijo S3 '${wazuhS3Prefix}' supera el límite de listado en ${S3_SCAN_TIMEOUT / 1000}s. ` +
            "Ajusta INTEL_SOURCES_WAZUH_S3_PREFIX a una ruta más acotada (p. ej. con partición de día), sube INTEL_SOURCES_S3_SCAN_TIMEOUT_MS, o define INTEL_SOURCES_WAZUH_TABLE para contar vía Trino.";
        } else if (wazuhTrinoError) {
          status = "error";
          tooltip = wazuhUsesS3
            ? `Error al escanear el prefijo S3 '${wazuhS3Prefix}' de Wazuh.`
            : `Error Trino en ${wazuhTable}.`;
          progress = 0;
        } else {
          recordCount = wazuhCount;
          activitySeries = wazuhSpark;
          status = wazuhCount > 0 ? "processed" : "partial";
          progress = wazuhCount > 0 ? 100 : 35;
          if (wazuhCount === 0) {
            tooltip = `${m.tooltip} 0 filas en ventana (${wazuhCountDays} días): confirme reenvío syslog de Wazuh a vector_public (VM :9002/:514), sync S3→MinIO si usa catálogo minio, o ajuste el filtro de la vista.`;
          }
        }
        break;
      case "abusech": {
        if (!runTrinoQuery) {
          status = "pending";
          tooltip = "Trino no configurado (TRINO_URL).";
        } else if (urlhausCount === null) {
          status = "error";
          tooltip = `${m.tooltip} Error al consultar ${ice("abusech_urlhaus_urls")}: ¿DDL 11_intel_vendor_tables.sql aplicado?`;
          progress = 0;
        } else {
          recordCount = urlhausCount;
          status = urlhausCount > 0 ? "processed" : "partial";
          progress = urlhausCount > 0 ? 100 : 35;
          if (urlhausCount === 0) {
            tooltip = `${m.tooltip} 0 filas en los últimos ${iceDays} días: ejecute DAG threat_intel_feeds_12h y defina Connection abusech_urlhaus o ABUSECH_URLHAUS_AUTH_KEY.`;
          }
        }
        activitySeries = sparkFlat();
        break;
      }
      case "openphish": {
        if (!runTrinoQuery) {
          status = "pending";
          tooltip = "Trino no configurado (TRINO_URL).";
        } else if (openphishCount === null) {
          status = "error";
          tooltip = `${m.tooltip} Error al consultar ${ice("openphish_urls")}.`;
          progress = 0;
        } else {
          recordCount = openphishCount;
          status = openphishCount > 0 ? "processed" : "partial";
          progress = openphishCount > 0 ? 100 : 35;
          if (openphishCount === 0) {
            tooltip = `${m.tooltip} 0 filas en ventana (${iceDays} días): ejecute threat_intel_feeds_12h.`;
          }
        }
        activitySeries = sparkFlat();
        break;
      }
      case "virustotal": {
        const vtKey = (env.VT_API_KEY ?? env.VIRUSTOTAL_TOKEN ?? "").trim();
        if (!runTrinoQuery) {
          status = vtKey ? "partial" : "pending";
          progress = vtKey ? 35 : 0;
          tooltip = vtKey
            ? "API key configurada (VT_API_KEY). Trino no disponible — sin conteo de resultados."
            : "Trino no configurado.";
        } else if (vtCount === null) {
          status = vtKey ? "partial" : "error";
          progress = vtKey ? 30 : 0;
          tooltip = vtKey
            ? `${m.tooltip} API key presente. Tabla ${ice("vt_results")} no encontrada: ejecuta el DAG threat_hunt_enrichment_daily al menos una vez.`
            : `${m.tooltip} Fallo SQL en ${ice("vt_results")}.`;
        } else {
          recordCount = vtCount;
          status = vtCount > 0 ? "processed" : (vtKey ? "partial" : "partial");
          progress = vtCount > 0 ? 100 : (vtKey ? 45 : 30);
          if (vtCount === 0) {
            tooltip = vtKey
              ? `${m.tooltip} API key configurada. Sin resultados en ${iceDays} días: ejecuta el DAG threat_hunt_enrichment_daily.`
              : `${m.tooltip} Sin filas en ${iceDays} días: clave VT + DAG threat_hunt_enrichment_daily.`;
          }
        }
        activitySeries = sparkFlat();
        break;
      }
      case "shodan-enrichment": {
        const shodanKey = (env.SHODAN_API_KEY ?? "").trim();
        if (!runTrinoQuery) {
          status = shodanKey ? "partial" : "pending";
          progress = shodanKey ? 35 : 0;
          tooltip = shodanKey
            ? "SHODAN_API_KEY configurada. Trino no disponible — sin conteo de resultados."
            : "Trino no configurado.";
        } else if (shodanEnrichCount === null) {
          status = shodanKey ? "partial" : "error";
          progress = shodanKey ? 30 : 0;
          tooltip = shodanKey
            ? `${m.tooltip} API key presente. Tabla ${ice("shodan_results")} no encontrada: ejecuta el DAG threat_hunt_enrichment_daily.`
            : `${m.tooltip} Fallo SQL en ${ice("shodan_results")}.`;
        } else {
          recordCount = shodanEnrichCount;
          status = shodanEnrichCount > 0 ? "processed" : (shodanKey ? "partial" : "partial");
          progress = shodanEnrichCount > 0 ? 100 : (shodanKey ? 45 : 30);
          if (shodanEnrichCount === 0) {
            tooltip = shodanKey
              ? `${m.tooltip} API key configurada. Sin resultados en ${iceDays} días: ejecuta DAG threat_hunt_enrichment_daily.`
              : `${m.tooltip} Sin filas en ${iceDays} días: Connection shodan_default / SHODAN_API_KEY y DAG diario.`;
          }
        }
        activitySeries = sparkFlat();
        break;
      }
      case "abuseipdb": {
        const abuseKey = (env.ABUSEIPDB_API_KEY ?? "").trim();
        if (!runTrinoQuery) {
          status = abuseKey ? "partial" : "pending";
          progress = abuseKey ? 35 : 0;
          tooltip = abuseKey
            ? "ABUSEIPDB_API_KEY configurada. Trino no disponible — sin conteo de resultados."
            : "Trino no configurado.";
        } else if (abuseipdbCount === null) {
          status = abuseKey ? "partial" : "error";
          progress = abuseKey ? 30 : 0;
          tooltip = abuseKey
            ? `${m.tooltip} API key presente. Tabla ${ice("abuseipdb_results")} no encontrada: ejecuta el DAG threat_hunt_enrichment_daily.`
            : `${m.tooltip} Fallo SQL en ${ice("abuseipdb_results")}.`;
        } else {
          recordCount = abuseipdbCount;
          status = abuseipdbCount > 0 ? "processed" : (abuseKey ? "partial" : "partial");
          progress = abuseipdbCount > 0 ? 100 : (abuseKey ? 45 : 30);
          if (abuseipdbCount === 0) {
            tooltip = abuseKey
              ? `${m.tooltip} API key configurada. Sin resultados en ${iceDays} días: ejecuta DAG threat_hunt_enrichment_daily.`
              : `${m.tooltip} Sin filas en ${iceDays} días: Connection abuseipdb_api / ABUSEIPDB_API_KEY.`;
          }
        }
        activitySeries = sparkFlat();
        break;
      }
      case "thc-rdns": {
        if (!runTrinoQuery) {
          status = "pending";
          tooltip = "Trino no configurado.";
        } else if (thcRdnsCount === null) {
          status = "error";
          tooltip = `${m.tooltip} Fallo SQL en ${ice("thc_rdns_results")}: ¿DDL 12_intel_thc_rdns_results.sql aplicado?`;
          progress = 0;
        } else {
          recordCount = thcRdnsCount;
          status = thcRdnsCount > 0 ? "processed" : "partial";
          progress = thcRdnsCount > 0 ? 100 : 25;
          if (thcRdnsCount === 0) {
            tooltip = `${m.tooltip} 0 filas en ${iceDays} días: ejecute threat_hunt_enrichment_daily (THC_RDNS_ENABLED=1).`;
          }
        }
        activitySeries = sparkFlat();
        break;
      }
      case "ssh-invalid-users": {
        if (!runTrinoQuery) {
          status = "pending";
          tooltip = "Trino no configurado (TRINO_URL).";
        } else if (sshInvalidCount === null) {
          status = "error";
          tooltip = `${m.tooltip} Error al consultar ${ice("ssh_invalid_users")}: ¿DDL 13_iceberg_ddl_ssh_invalid_users.sql aplicado?`;
          progress = 0;
        } else {
          recordCount = sshInvalidCount;
          status = sshInvalidCount > 0 ? "processed" : "partial";
          progress = sshInvalidCount > 0 ? 100 : 20;
          if (sshInvalidCount === 0) {
            tooltip = `${m.tooltip} 0 filas: use el botón "Enriquecer" en Wazuh Intelligence para guardar intentos SSH o ejecute el endpoint POST /api/wazuh/enrich-ssh-invalid.`;
          }
        }
        activitySeries = sparkFlat();
        break;
      }
      case "misp": {
        const mispBaseUrl = (env.MISP_BASE_URL ?? "").trim();
        const mispApiKey  = (env.MISP_API_KEY  ?? "").trim();
        if (!mispBaseUrl || !mispApiKey) {
          status   = "pending";
          progress = 0;
          tooltip  = "MISP no configurado: define MISP_BASE_URL y MISP_API_KEY en .env. Activa con: bash scripts/bootstrap-misp.sh";
        } else if (!runTrinoQuery) {
          status   = "pending";
          progress = 5;
          tooltip  = "MISP configurado pero Trino no disponible (TRINO_URL). Sin conteo Iceberg.";
        } else if (mispIocsCount === null) {
          status   = "partial";
          progress = 40;
          tooltip  = `${m.tooltip} Credenciales configuradas (${mispBaseUrl}). Tablas Iceberg misp_iocs/misp_events no encontradas: ejecuta bash scripts/bootstrap-trino-misp.sh para crearlas.`;
        } else {
          recordCount = mispIocsCount;
          const evCount = mispEventsCount ?? 0;
          status   = mispIocsCount > 0 ? "processed" : "partial";
          progress = mispIocsCount > 0 ? 100 : 40;
          tooltip  = mispIocsCount > 0
            ? `${m.tooltip} ${mispIocsCount.toLocaleString("es")} IOCs y ${evCount.toLocaleString("es")} eventos en los últimos ${iceDays} días. URL: ${mispBaseUrl}`
            : `${m.tooltip} Tablas presentes pero sin datos en ${iceDays} días: ejecuta el DAG threat_hunt_misp_sync_daily o trigger manual.`;
        }
        activitySeries = sparkFlat();
        break;
      }
      case "brand24": {
        const brand24Key = (env.BRAND24_API_KEY ?? "").trim();
        if (!brand24Key) {
          status = "pending";
          progress = 0;
          tooltip = "Brand24 no configurado: agrega BRAND24_API_KEY en .env (raíz). Obtén la clave en https://app.brand24.com/settings/api. Social Listening requiere cuenta Brand24 activa.";
        } else {
          status = "partial";
          progress = 65;
          tooltip = `${m.tooltip} BRAND24_API_KEY configurada. Conector de menciones y sentimiento activo para búsquedas bajo demanda. Ingesta periódica pendiente de DAG Airflow.`;
        }
        activitySeries = sparkFlat();
        break;
      }
      case "cti-cloudyole": {
        const ctiBase = (env.CTI_CLOUDYOLE_BASE_URL ?? "").trim();
        const ctiKey  = (env.CTI_CLOUDYOLE_API_KEY  ?? "").trim();
        if (!ctiBase || !ctiKey) {
          status = "pending";
          progress = 0;
          tooltip = "CTI Cloud & Olé no configurado: define CTI_CLOUDYOLE_BASE_URL y CTI_CLOUDYOLE_API_KEY en .env. Dark Web Monitoring (Kaduu) requiere credenciales de acceso.";
        } else if (ctiPingResult?.ok) {
          status = "processed";
          progress = 100;
          tooltip = `${m.tooltip} API conectada (${ctiBase}). Búsquedas IOC activas. Ingesta batch pendiente de pipeline Airflow.`;
        } else if (ctiPingResult && !ctiPingResult.ok) {
          status = "partial";
          progress = 55;
          tooltip = `${m.tooltip} Credenciales configuradas pero API no responde (${ctiPingResult.error ?? "sin respuesta"}). Verifica conectividad con ${ctiBase}.`;
        } else {
          // ping aún no resuelto (no debería llegar aquí tras await)
          status = "partial";
          progress = 60;
          tooltip = `${m.tooltip} Credenciales configuradas; conector activo para búsquedas IOC. Ingesta batch en pipeline pendiente.`;
        }
        activitySeries = sparkFlat();
        break;
      }
      case "infragovpy": {
        if (infragovpyPenalized === null) {
          // PG no respondió (degradación)
          status   = "partial";
          progress = 25;
          recordCount = 0;
          activitySeries = sparkFlat();
          tooltip  = `${m.tooltip} (No se pudo leer el watchlist lgcrBL en PostgreSQL.)`;
        } else {
          recordCount    = infragovpyPenalized;
          activitySeries = sparkFlat();
          // lastProcessedAt = hora del último push al repo GitLab del feed.
          lastProcessedAt = infragovpyLastPush?.last_push_at ?? lastProcessedAt;
          if (infragovpyLastPush) {
            status   = "processed";
            progress = 100;
            tooltip  = `${m.tooltip} Último push: ${infragovpyLastPush.commit_sha ?? "—"}` +
              (infragovpyLastPush.commit_title ? ` · ${infragovpyLastPush.commit_title}` : "");
          } else {
            // Penalizadas OK pero sin confirmación de push (token GitLab ausente / GitLab caído)
            status   = "partial";
            progress = 60;
            tooltip  = `${m.tooltip} (Sin confirmación del último push: revisar LGCRBL_GIT_TOKEN o la instancia GitLab.)`;
          }
        }
        break;
      }
      case "otx":
      case "spamhaus":
      default:
        recordCount = 0;
        status = "pending";
        progress = 0;
        activitySeries = sparkFlat();
        break;
    }

    return {
      ...m,
      recordCount,
      lastProcessedAt,
      status,
      progress,
      activitySeries,
      tooltip,
    };
  });

  return { snapshotAt, sources };
}
