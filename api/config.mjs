/**
 * Carga .env (raíz + legacyhunt-api) y valida variables críticas con Zod.
 * Falla en arranque si TRINO_URL (si no vacía) no parece URL http(s).
 */
import dotenv from "dotenv";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: join(__dirname, "../.env") });
dotenv.config({ path: join(__dirname, ".env") });

const schema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(8787),
  S3_BUCKET: z.string().trim().optional(),
  MINIO_BUCKET: z.string().trim().optional(),
  S3_LAKE_LEAK_INTEL_RAW_PREFIX: z.string().trim().default("leak_intel/raw"),
  /** Prefijo raíz para búsqueda de archivos (más amplio que el prefijo de ingesta). */
  S3_LAKE_LEAK_INTEL_SEARCH_PREFIX: z.string().trim().default("leak_intel"),
  AWS_DEFAULT_REGION: z.string().trim().default("us-east-1"),
  S3_ENDPOINT: z.string().trim().optional(),
  AWS_ACCESS_KEY_ID: z.string().trim().optional(),
  AWS_SECRET_ACCESS_KEY: z.string().trim().optional(),
  INGEST_API_KEY: z.string().trim().optional(),
  TRINO_URL: z
    .string()
    .default("")
    .transform((s) => s.trim().replace(/\/+$/, ""))
    .superRefine((s, ctx) => {
      if (s && !/^https?:\/\/.+/i.test(s)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "TRINO_URL debe estar vacía o ser una URL http(s)://…",
        });
      }
    }),
  TRINO_USER: z.string().trim().default("legacyhunt-api"),
  SHODAN_API_KEY: z.string().trim().optional(),
  SHODAN_TOKEN: z.string().trim().optional(),
  SHODAN_SNAPSHOT_DIR: z.string().trim().optional(),
  MISP_BASE_URL: z.string().trim().optional(),
  MISP_API_KEY: z.string().trim().optional(),
  MISP_VERIFY_SSL: z.string().trim().optional(),
  MISP_TIMEOUT_SEC: z.coerce.number().int().min(5).max(120).default(30),
  INTEL_SOURCES_SYSLOG_TABLE: z.string().trim().optional(),
  INTEL_SOURCES_WAZUH_TABLE: z.string().trim().optional(),
  INTEL_SOURCES_ICEBERG_CATALOG: z.string().trim().optional(),
  INTEL_SOURCES_ICEBERG_SCHEMA: z.string().trim().optional(),
  INTEL_SOURCES_ENRICHMENT_LOOKBACK_DAYS: z.coerce.number().int().min(1).max(365).optional(),
  // Subido de 300→600s y 512→1024 MB en F1.1 del plan de detection-performance
  // (docs/DETECTION-PERFORMANCE-OPTIMIZATION.md). El refetch típico del
  // dashboard es 60s — con TTL 600 los batches Fortigate/PMG/Suricata que
  // tardan 10-30s pegan en cache 10× antes de refrescar.
  TRINO_QUERY_CACHE_TTL_SEC: z.coerce.number().int().min(0).max(3600).default(600),
  TRINO_QUERY_CACHE_SOC_KPI_TTL_SEC: z.coerce.number().int().min(0).max(21600).default(7200),
  TRINO_QUERY_CACHE_MEMORY_MAX: z.coerce.number().int().min(0).max(10_000).default(1024),
  TRINO_CATALOG: z.string().trim().default("minio"),
  TRINO_SCHEMA: z.string().trim().default("hunting"),
  /** Cabecera X-Trino-Session (propiedades separadas por coma). Ej.: optimize_metadata_queries=true */
  TRINO_SESSION_PROPERTIES: z.string().trim().optional(),
  // Slack
  SLACK_WEBHOOK_URL: z.string().trim().optional(),
  SLACK_CHANNEL: z.string().trim().optional(),
  SLACK_NOTIFY_ENABLED: z.string().trim().default("true"),
  SLACK_NOTIFY_MIN_SSH_ATTEMPTS: z.coerce.number().int().min(1).default(100),
  SLACK_NOTIFY_MIN_WAZUH_LEVEL: z.coerce.number().int().min(1).max(16).default(12),
  SLACK_NOTIFY_MIN_IOC_SCORE: z.coerce.number().int().min(0).max(100).default(80),
  DASHBOARD_URL: z.string().trim().default("http://localhost:5173"),
  /** Orígenes extra para CORS de Socket.io (coma-separados). Útil si abres el dashboard por IP o dominio distinto a DASHBOARD_URL. */
  SOCKETIO_CORS_ORIGINS: z.string().trim().optional(),
  // Force-ack: secreto para el endpoint de iniciación (Wazuh webhook / DAG Airflow)
  // Vacío = sin autenticación (lab). En producción: string aleatorio largo.
  FORCE_ACK_SECRET: z.string().trim().default(""),
  // Scheduler auto-proceso LOW/MEDIUM/NEGLIGIBLE
  AUTO_PROCESS_LOW_MEDIUM_ENABLED: z.string().trim().default("true"),
  AUTO_PROCESS_LOW_MEDIUM_INTERVAL_HOURS: z.coerce.number().int().min(1).max(24).default(3),
  AUTO_PROCESS_LOW_MEDIUM_LOOKBACK_DAYS: z.coerce.number().int().min(1).max(30).default(1),
  // SOC Chat (80/20 híbrido: intents + LLM opcional)
  SOC_CHAT_LLM_ENABLED: z.string().trim().default("false"),
  // URL OpenAI-compatible para chat completions. El router y la capa de
  // generación de respuesta usan tool-calling / messages[], así que el endpoint
  // debe hablar /v1/chat/completions. Los providers soportados verificados son
  // OpenAI, OpenRouter, vLLM, Ollama (OpenAI-compat), LocalAI.
  SOC_CHAT_LLM_API_URL: z.string().trim().default("https://api.openai.com/v1/chat/completions"),
  SOC_CHAT_LLM_API_KEY: z.string().trim().optional(),
  SOC_CHAT_LLM_MODEL: z.string().trim().default("gpt-4o-mini"),
  // Si "true", el router usa tool-calling del LLM para elegir queryId + params.
  // Con "false" (default) el chat sigue siendo 100% determinístico (regex).
  SOC_CHAT_LLM_ROUTER_ENABLED: z.string().trim().default("false"),
  // Informe diario SOC (email)
  REPORT_ENABLED: z.string().trim().default("false"),
  REPORT_SMTP_HOST: z.string().trim().optional(),
  REPORT_SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(587),
  REPORT_SMTP_SECURE: z.string().trim().default("false"),
  REPORT_SMTP_USER: z.string().trim().optional(),
  REPORT_SMTP_PASS: z.string().trim().optional(),
  REPORT_FROM: z.string().trim().optional(),
  REPORT_TO: z.string().trim().optional(),
  REPORT_SCHEDULE_UTC: z.string().trim().default("09:00"),
  // CTI Cloud & Olé
  CTI_CLOUDYOLE_BASE_URL: z.string().trim().optional(),
  CTI_CLOUDYOLE_API_KEY: z.string().trim().optional(),
  // Brand24 Social Listening
  BRAND24_API_KEY: z.string().trim().optional(),
  // ── PMG — Proxmox Mail Gateway (email phishing) ────────────────────────────
  // MXTOOLBOX_API_KEY: API key MXToolbox para consultas DNSBL multi-lista.
  //   Free tier: ~100 lookups/mes.  https://mxtoolbox.com/user/dashboard/
  MXTOOLBOX_API_KEY: z.string().trim().optional(),
  // PMG_OPENPHISH_FEED_URL: URL del feed OpenPhish (default: feed público gratuito).
  PMG_OPENPHISH_FEED_URL: z.string().trim().optional(),
  // PMG_OPENPHISH_TTL_SEC: TTL de la caché del feed OpenPhish en segundos (default: 14400 = 4 h).
  PMG_OPENPHISH_TTL_SEC: z.coerce.number().int().min(300).max(86400).default(14400),
  // PMG_ENRICH_CACHE_TTL_SEC: TTL de la caché de enriquecimiento por IOC (default: 3600 = 1 h).
  PMG_ENRICH_CACHE_TTL_SEC: z.coerce.number().int().min(60).max(86400).default(3600),
  // ── OIDC / Keycloak (Opción 2 — SSO para SOC maduro) ──────────────────────
  // OIDC_ENABLED=false (default) → sin auth, retrocompatible con el stack actual.
  // OIDC_ENABLED=true → valida JWT en rutas protegidas con requireAuth/requireRole.
  OIDC_ENABLED: z.string().trim().default("false"),
  // Issuer del token JWT (debe coincidir con KC_HOSTNAME_URL del servicio keycloak).
  // Ejemplo lab: "http://localhost:8180/realms/legacyhunt-soc"
  // Ejemplo prod: "https://auth.empresa.com/realms/legacyhunt-soc"
  OIDC_ISSUER: z.string().trim().default(""),
  // URI JWKS interna (Docker network) para obtener claves públicas sin pasar por el host.
  // Ejemplo: "http://keycloak:8080/realms/legacyhunt-soc/protocol/openid-connect/certs"
  OIDC_JWKS_URI: z.string().trim().default(""),
  // "true" → acepta TRINO_PROXY_API_KEY como fallback (fase de migración gradual).
  OIDC_ALLOW_API_KEY_FALLBACK: z.string().trim().default("true"),
  // ── R11 (audit 2026-05-13): umbrales de scoring externalizados ─────────────
  // workflowEngine.shouldAutoEscalate dispara a partir de SOC_AUTO_ESCALATE_SCORE.
  // Severity buckets (auto-clasificación por score) en incidents.mjs:4192-4194.
  // Mantenemos los defaults históricos; los SOCs maduros pueden tunearlos sin
  // tocar código.
  SOC_AUTO_ESCALATE_SCORE:   z.coerce.number().int().min(1).max(200).default(70),
  SOC_SEVERITY_CRITICAL_MIN: z.coerce.number().int().min(1).max(200).default(80),
  SOC_SEVERITY_HIGH_MIN:     z.coerce.number().int().min(1).max(200).default(60),
  SOC_SEVERITY_MEDIUM_MIN:   z.coerce.number().int().min(1).max(200).default(35),
});

const raw = {
  PORT: process.env.PORT,
  SLACK_WEBHOOK_URL: process.env.SLACK_WEBHOOK_URL,
  SLACK_CHANNEL: process.env.SLACK_CHANNEL,
  SLACK_NOTIFY_ENABLED: process.env.SLACK_NOTIFY_ENABLED,
  SLACK_NOTIFY_MIN_SSH_ATTEMPTS: process.env.SLACK_NOTIFY_MIN_SSH_ATTEMPTS,
  SLACK_NOTIFY_MIN_WAZUH_LEVEL: process.env.SLACK_NOTIFY_MIN_WAZUH_LEVEL,
  SLACK_NOTIFY_MIN_IOC_SCORE: process.env.SLACK_NOTIFY_MIN_IOC_SCORE,
  DASHBOARD_URL: process.env.DASHBOARD_URL,
  SOCKETIO_CORS_ORIGINS: process.env.SOCKETIO_CORS_ORIGINS,
  S3_BUCKET: process.env.S3_BUCKET,
  MINIO_BUCKET: process.env.MINIO_BUCKET,
  S3_LAKE_LEAK_INTEL_RAW_PREFIX: process.env.S3_LAKE_LEAK_INTEL_RAW_PREFIX,
  AWS_DEFAULT_REGION: process.env.AWS_DEFAULT_REGION,
  S3_ENDPOINT: process.env.S3_ENDPOINT,
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  INGEST_API_KEY: process.env.INGEST_API_KEY,
  TRINO_URL: process.env.TRINO_URL ?? "",
  TRINO_USER: process.env.TRINO_USER,
  SHODAN_API_KEY: process.env.SHODAN_API_KEY,
  SHODAN_TOKEN: process.env.SHODAN_TOKEN,
  SHODAN_SNAPSHOT_DIR: process.env.SHODAN_SNAPSHOT_DIR,
  NVD_API_KEY: process.env.NVD_API_KEY,
  MISP_BASE_URL: process.env.MISP_BASE_URL,
  MISP_API_KEY: process.env.MISP_API_KEY,
  MISP_VERIFY_SSL: process.env.MISP_VERIFY_SSL,
  MISP_TIMEOUT_SEC: process.env.MISP_TIMEOUT_SEC,
  INTEL_SOURCES_SYSLOG_TABLE: process.env.INTEL_SOURCES_SYSLOG_TABLE,
  INTEL_SOURCES_WAZUH_TABLE: process.env.INTEL_SOURCES_WAZUH_TABLE,
  INTEL_SOURCES_ICEBERG_CATALOG: process.env.INTEL_SOURCES_ICEBERG_CATALOG,
  INTEL_SOURCES_ICEBERG_SCHEMA: process.env.INTEL_SOURCES_ICEBERG_SCHEMA,
  INTEL_SOURCES_ENRICHMENT_LOOKBACK_DAYS: process.env.INTEL_SOURCES_ENRICHMENT_LOOKBACK_DAYS,
  TRINO_QUERY_CACHE_TTL_SEC: process.env.TRINO_QUERY_CACHE_TTL_SEC,
  TRINO_QUERY_CACHE_SOC_KPI_TTL_SEC: process.env.TRINO_QUERY_CACHE_SOC_KPI_TTL_SEC,
  TRINO_QUERY_CACHE_MEMORY_MAX: process.env.TRINO_QUERY_CACHE_MEMORY_MAX,
  TRINO_CATALOG: process.env.TRINO_CATALOG,
  TRINO_SCHEMA: process.env.TRINO_SCHEMA,
  TRINO_SESSION_PROPERTIES: process.env.TRINO_SESSION_PROPERTIES,
  AUTO_PROCESS_LOW_MEDIUM_ENABLED: process.env.AUTO_PROCESS_LOW_MEDIUM_ENABLED,
  AUTO_PROCESS_LOW_MEDIUM_INTERVAL_HOURS: process.env.AUTO_PROCESS_LOW_MEDIUM_INTERVAL_HOURS,
  AUTO_PROCESS_LOW_MEDIUM_LOOKBACK_DAYS: process.env.AUTO_PROCESS_LOW_MEDIUM_LOOKBACK_DAYS,
  SOC_CHAT_LLM_ENABLED: process.env.SOC_CHAT_LLM_ENABLED,
  SOC_CHAT_LLM_API_URL: process.env.SOC_CHAT_LLM_API_URL,
  SOC_CHAT_LLM_API_KEY: process.env.SOC_CHAT_LLM_API_KEY,
  SOC_CHAT_LLM_MODEL: process.env.SOC_CHAT_LLM_MODEL,
  SOC_CHAT_LLM_ROUTER_ENABLED: process.env.SOC_CHAT_LLM_ROUTER_ENABLED,
  REPORT_ENABLED: process.env.REPORT_ENABLED,
  REPORT_SMTP_HOST: process.env.REPORT_SMTP_HOST,
  REPORT_SMTP_PORT: process.env.REPORT_SMTP_PORT,
  REPORT_SMTP_SECURE: process.env.REPORT_SMTP_SECURE,
  REPORT_SMTP_USER: process.env.REPORT_SMTP_USER,
  REPORT_SMTP_PASS: process.env.REPORT_SMTP_PASS,
  REPORT_FROM: process.env.REPORT_FROM,
  REPORT_TO: process.env.REPORT_TO,
  REPORT_SCHEDULE_UTC: process.env.REPORT_SCHEDULE_UTC,
  CTI_CLOUDYOLE_BASE_URL: process.env.CTI_CLOUDYOLE_BASE_URL,
  CTI_CLOUDYOLE_API_KEY: process.env.CTI_CLOUDYOLE_API_KEY,
  BRAND24_API_KEY: process.env.BRAND24_API_KEY,
  MXTOOLBOX_API_KEY: process.env.MXTOOLBOX_API_KEY,
  PMG_OPENPHISH_FEED_URL: process.env.PMG_OPENPHISH_FEED_URL,
  PMG_OPENPHISH_TTL_SEC: process.env.PMG_OPENPHISH_TTL_SEC,
  PMG_ENRICH_CACHE_TTL_SEC: process.env.PMG_ENRICH_CACHE_TTL_SEC,
  // R11 audit 2026-05-13 — umbrales de scoring externos
  SOC_AUTO_ESCALATE_SCORE:   process.env.SOC_AUTO_ESCALATE_SCORE,
  SOC_SEVERITY_CRITICAL_MIN: process.env.SOC_SEVERITY_CRITICAL_MIN,
  SOC_SEVERITY_HIGH_MIN:     process.env.SOC_SEVERITY_HIGH_MIN,
  SOC_SEVERITY_MEDIUM_MIN:   process.env.SOC_SEVERITY_MEDIUM_MIN,
};

const parsed = schema.safeParse(raw);
if (!parsed.success) {
  console.error("[legacyhunt-api] Config inválida (.env):");
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

const p = parsed.data;

/** Identificador de catálogo Trino estable (minúsculas; typo `3` o vacío → minio). No reescribe `s3` aquí: el registry mapea s3→minio al generar SQL. */
function normalizeTrinoCatalogKey(raw) {
  const c = String(raw ?? "minio").trim().toLowerCase();
  if (!c || c === "3") return "minio";
  return c;
}

const trinoCatalogNormalized = normalizeTrinoCatalogKey(p.TRINO_CATALOG);
/** Con S3_ENDPOINT (MinIO u S3-compatible), priorizar MINIO_BUCKET: muchos .env definen S3_BUCKET solo para AWS/Trino y rompen PutObject en el lab. */
const usingCustomEndpoint = Boolean((p.S3_ENDPOINT ?? "").trim());
const BUCKET = usingCustomEndpoint
  ? p.MINIO_BUCKET || p.S3_BUCKET || "iceberg-lakehouse"
  : p.S3_BUCKET || p.MINIO_BUCKET || "iceberg-lakehouse";
const S3_LAKE_LEAK_INTEL_RAW_PREFIX = p.S3_LAKE_LEAK_INTEL_RAW_PREFIX.replace(
  /\/+$/,
  "",
);
const S3_ENDPOINT = p.S3_ENDPOINT || undefined;
const INGEST_KEY = p.INGEST_API_KEY || undefined;
const TRINO_URL = p.TRINO_URL || "";
const TRINO_USER = p.TRINO_USER;
const REGION = p.AWS_DEFAULT_REGION;
const SHODAN_API_KEY = p.SHODAN_API_KEY || p.SHODAN_TOKEN || undefined;
const SHODAN_SNAPSHOT_DIR =
  p.SHODAN_SNAPSHOT_DIR || join(__dirname, "data", "shodan_snapshots");

/** Normaliza URL de origen (sin barra final) para comparar con cabecera `Origin` del navegador. */
function normalizeOriginUrl(s) {
  const t = String(s ?? "").trim().replace(/\/+$/, "");
  return t || null;
}

/** Orígenes permitidos para Socket.io (adopción / modal crítico). Incluye DASHBOARD_URL, Vite dev/preview y SOCKETIO_CORS_ORIGINS. */
function buildSocketIoCorsOrigins(dashboardUrl, extraCsv) {
  const out = new Set();
  for (const x of [
    normalizeOriginUrl(dashboardUrl),
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
  ]) {
    if (x) out.add(x);
  }
  // Dominio de producción
  out.add("https://legacyhunt.lgcserver.net");
  if (extraCsv) {
    for (const part of String(extraCsv).split(",")) {
      const n = normalizeOriginUrl(part);
      if (n) out.add(n);
    }
  }
  return [...out];
}

export const config = {
  PORT: p.PORT,
  BUCKET,
  S3_LAKE_LEAK_INTEL_RAW_PREFIX,
  REGION,
  S3_ENDPOINT,
  INGEST_KEY,
  TRINO_URL,
  TRINO_USER,
  SHODAN_API_KEY,
  SHODAN_SNAPSHOT_DIR,
  mispBaseUrl: (p.MISP_BASE_URL ?? "").trim().replace(/\/+$/, "") || undefined,
  mispConfigured: Boolean(p.MISP_BASE_URL && p.MISP_API_KEY),
  INTEL_SOURCES_SYSLOG_TABLE: p.INTEL_SOURCES_SYSLOG_TABLE,
  INTEL_SOURCES_WAZUH_TABLE: p.INTEL_SOURCES_WAZUH_TABLE,
  INTEL_SOURCES_ICEBERG_CATALOG: p.INTEL_SOURCES_ICEBERG_CATALOG,
  INTEL_SOURCES_ICEBERG_SCHEMA: p.INTEL_SOURCES_ICEBERG_SCHEMA,
  INTEL_SOURCES_ENRICHMENT_LOOKBACK_DAYS: p.INTEL_SOURCES_ENRICHMENT_LOOKBACK_DAYS,
  trinoQueryCacheTtlSec: p.TRINO_QUERY_CACHE_TTL_SEC,
  trinoQueryCacheSocKpiTtlSec: p.TRINO_QUERY_CACHE_SOC_KPI_TTL_SEC,
  trinoQueryCacheMemoryMax: p.TRINO_QUERY_CACHE_MEMORY_MAX,
  trinoCatalog: trinoCatalogNormalized,
  trinoSchema: p.TRINO_SCHEMA,
  trinoSessionProperties: (p.TRINO_SESSION_PROPERTIES ?? "").trim() || undefined,
  intelWazuhTable: (p.INTEL_SOURCES_WAZUH_TABLE ?? "").trim(),
  hasAwsKeys: Boolean(p.AWS_ACCESS_KEY_ID && p.AWS_SECRET_ACCESS_KEY),
  awsAccessKeyId: p.AWS_ACCESS_KEY_ID,
  awsSecretAccessKey: p.AWS_SECRET_ACCESS_KEY,
  // Slack
  slackWebhookUrl: p.SLACK_WEBHOOK_URL || "",
  slackNotifyEnabled: p.SLACK_NOTIFY_ENABLED !== "false",
  slackNotifyMinSshAttempts: p.SLACK_NOTIFY_MIN_SSH_ATTEMPTS,
  slackNotifyMinWazuhLevel: p.SLACK_NOTIFY_MIN_WAZUH_LEVEL,
  slackNotifyMinIocScore: p.SLACK_NOTIFY_MIN_IOC_SCORE,
  dashboardUrl: p.DASHBOARD_URL,
  socketIoCorsOrigins: buildSocketIoCorsOrigins(p.DASHBOARD_URL, p.SOCKETIO_CORS_ORIGINS),
  autoProcessLowMediumEnabled: p.AUTO_PROCESS_LOW_MEDIUM_ENABLED !== "false",
  autoProcessLowMediumIntervalHours: p.AUTO_PROCESS_LOW_MEDIUM_INTERVAL_HOURS,
  autoProcessLowMediumLookbackDays: p.AUTO_PROCESS_LOW_MEDIUM_LOOKBACK_DAYS,
  socChatLlmEnabled: p.SOC_CHAT_LLM_ENABLED === "true",
  socChatLlmApiUrl: p.SOC_CHAT_LLM_API_URL,
  socChatLlmApiKey: p.SOC_CHAT_LLM_API_KEY || "",
  socChatLlmModel: p.SOC_CHAT_LLM_MODEL,
  socChatLlmRouterEnabled: p.SOC_CHAT_LLM_ROUTER_ENABLED === "true",
  reportEnabled: p.REPORT_ENABLED === "true",
  reportSmtpConfigured: Boolean(p.REPORT_SMTP_HOST && p.REPORT_SMTP_USER && p.REPORT_SMTP_PASS && p.REPORT_FROM && p.REPORT_TO),
  reportScheduleUtc: p.REPORT_SCHEDULE_UTC,
  ctiCloudyoleConfigured: Boolean(p.CTI_CLOUDYOLE_BASE_URL && p.CTI_CLOUDYOLE_API_KEY),
  ctiCloudyoleBaseUrl: (p.CTI_CLOUDYOLE_BASE_URL ?? "").trim().replace(/\/+$/, "") || undefined,
  // R11 audit 2026-05-13 — umbrales de scoring (escalación + severidad).
  // Consumidos por services/workflowEngine.shouldAutoEscalate y por la
  // auto-clasificación de severidad en routes/incidents.mjs (computeSeverityFromScore).
  socAutoEscalateScore:   p.SOC_AUTO_ESCALATE_SCORE,
  socSeverityCriticalMin: p.SOC_SEVERITY_CRITICAL_MIN,
  socSeverityHighMin:     p.SOC_SEVERITY_HIGH_MIN,
  socSeverityMediumMin:   p.SOC_SEVERITY_MEDIUM_MIN,
};
